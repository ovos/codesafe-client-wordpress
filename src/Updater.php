<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use PclZip;
use Throwable;
use WP_Error;
use ZipArchive;

use function base64_decode;
use function class_exists;
use function defined;
use function explode;
use function file_get_contents;
use function hex2bin;
use function is_array;
use function is_file;
use function is_string;
use function json_decode;
use function ltrim;
use function preg_match;
use function preg_replace;
use function rawurldecode;
use function sodium_crypto_sign_verify_detached;
use function str_starts_with;
use function strlen;
use function substr;
use function trim;
use function unlink;
use function version_compare;

/**
 * Self-update through WordPress core's Update URI mechanism (WP 5.8+):
 * the plugin header names github.com as its update source, core asks the
 * update_plugins_github.com filter whenever it rebuilds the plugin-update
 * transient, and the answer — version and zip of the latest GitHub
 * release — feeds the normal wp-admin update flow. No update server and
 * no updater plugin on the sites: the release workflow's zip IS the
 * package (git archive with the ovos-codesafe/ prefix, so the install
 * directory survives the swap).
 *
 * Fire-and-forget for the CHECK, like the rest of the plugin: any failure —
 * offline host, API rate limit, renamed asset, the repository not (yet)
 * public — returns $update unchanged and simply means "no update visible
 * right now".
 *
 * Not fire-and-forget for the INSTALL. Every release is signed (Ed25519 over
 * the whole zip, by the release workflow, with a key that lives in a GitHub
 * environment admitting v* tags only), and download() verifies the signature
 * before WordPress unpacks a byte. A package that does not verify is a
 * WP_Error, which WordPress renders in the update screen — nothing is
 * installed, and the admin sees why. There is no degraded mode: the check
 * runs on every install because WordPress bundles sodium_compat for its own
 * update signing, so sodium_crypto_sign_verify_detached() exists whether or
 * not ext/sodium does. A successful answer is cached for twelve hours: core's own
 * rebuild schedule is about as frequent, but the "Check again" button
 * bypasses it, and the unauthenticated GitHub API budget (60 requests
 * per hour) is shared by every site behind the same egress IP.
 */
class Updater
{
	protected const RELEASES = 'https://api.github.com/repos/ovos/codesafe-client-wordpress/releases/latest';
	
	protected const ASSET = 'ovos-codesafe.zip';
	
	/** the detached signature beside it — base64 of the 64 raw bytes, one line */
	protected const SIGNATURE = 'ovos-codesafe.zip.sig';
	
	/**
	 * The Ed25519 public key every release is verified against: 32 raw bytes
	 * as hex. Published where this repository cannot edit it — the console's
	 * docs/DEPLOY.md and docs/RELEASE.md here — so that a swapped key in a
	 * future version is visible rather than silent. Installed versions verify
	 * against THIS value; a rotation therefore ships one transitional release
	 * signed with the old key that carries the new one (docs/RELEASE.md).
	 */
	public const PUBLIC_KEY = '0d91f295c416a035bcf3c8a3477fef635b8f306eb0f25e3d49b61ec24b919c04';
	
	/**
	 * The only place a package may come from. A release's asset URL is
	 * github.com/<this repo>/releases/download/…, and a redirect from there
	 * lands on objects.githubusercontent.com — WordPress follows that itself.
	 * Anything else in the `package` field is not our release, whatever the
	 * API answer claims, and the tag beside it proves nothing: the version
	 * check is core's job, the ORIGIN check is this one.
	 */
	protected const PACKAGE_PREFIX = 'https://github.com/ovos/codesafe-client-wordpress/releases/download/';
	
	protected const CACHE_KEY = 'ovos_codesafe_latest_release';
	
	/** the plugin's main file inside a release zip — git archive's ovos-codesafe/ prefix */
	public const MAIN_FILE = 'ovos-codesafe/ovos-codesafe.php';
	
	public function __construct(
		protected string $file,
	)
	{
	}
	
	public function register(): void
	{
		add_filter('update_plugins_github.com', [$this, 'check'], 10, 3);
		add_filter('upgrader_pre_download', [$this, 'download'], 10, 4);
	}
	
	/**
	 * update_plugins_github.com: answer for this plugin only — the hook
	 * fires for every installed plugin whose Update URI points at GitHub.
	 * Core version_compare()s the answer against the installed version
	 * itself and sorts it into response (update offered) or no_update, so
	 * the latest release is always returned, never compared here.
	 *
	 * @param array|false $update whatever an earlier filter decided
	 * @return array|false
	 */
	public function check(
		$update,
		array $pluginData,
		string $pluginFile,
	)
	{
		if($pluginFile !== plugin_basename($this->file))
		{
			return $update;
		}
		
		$release = $this->latestRelease();
		
		if($release === null)
		{
			return $update;
		}
		
		// never offer a version at or below the installed one. Core sorts such
		// an answer into no_update by itself, so on a healthy day this line
		// changes nothing — it exists for the day the API answer is not
		// healthy, so that a re-served older zip is refused HERE, in code we
		// own and can test, rather than trusted to a comparison one hop away
		if(self::isDowngrade($release['version'], (string)($pluginData['Version'] ?? '')))
		{
			return $update;
		}
		
		return [
			'id' => 'github.com/ovos/codesafe-client-wordpress',
			'slug' => 'ovos-codesafe',
			'plugin' => $pluginFile,
			'version' => $release['version'],
			'url' => $release['url'],
			'package' => $release['package'],
		];
	}
	
	/**
	 * upgrader_pre_download, for OUR package only: fetch the zip and its
	 * signature, verify, and hand WordPress the verified file — or a WP_Error
	 * and nothing to install. Every other package, and any earlier filter's
	 * answer, passes through untouched: this hook fires for every plugin and
	 * theme update on the site, and none of them are this plugin's business.
	 *
	 * @param mixed $reply false, or whatever an earlier filter decided
	 * @param mixed $package the download URL WordPress is about to fetch
	 * @return mixed a local path, a WP_Error, or $reply unchanged
	 */
	public function download(
		$reply,
		$package,
		$upgrader = null,
		$hookExtra = [],
	)
	{
		if($reply !== false || is_string($package) === false || self::isOurs($package) === false)
		{
			return $reply;
		}
		
		$file = download_url($package);
		
		if(is_wp_error($file))
		{
			return $file;
		}
		
		// the signature is a sibling asset with a deterministic name; a missing
		// or unreadable one is simply a signature that does not verify
		$response = wp_remote_get($package . '.sig', ['timeout' => 15]);
		$signature = is_wp_error($response)
				|| (int)wp_remote_retrieve_response_code($response) !== 200
			? ''
			: trim((string)wp_remote_retrieve_body($response));
		
		if(self::verify((string)file_get_contents($file), $signature, static::publicKey()) === false)
		{
			@unlink($file);
			
			return new WP_Error('ovos_codesafe_unsigned',
				__('ovos codesafe: the update package is not signed by ovos, or its signature does not match the package. Nothing was installed. If this persists, download the release from github.com/ovos/codesafe-client-wordpress and compare its signature with the published key.', 'ovos-codesafe'));
		}
		
		// the signature covers the zip's bytes and nothing else: the version
		// came from the release's TAG, which whoever can cut a release names
		// freely — an old signed build re-released as a new tag would install
		// as an "update" and roll the site back to what it fixed. The version
		// the zip itself carries must be the one offered (security audit
		// 2026-10-03 M15); anything else, or nothing readable, installs nothing
		$offered = self::versionOfPackage($package);
		$carried = self::zipVersion($file);
		if($offered === null || $carried === null || $carried !== $offered)
		{
			@unlink($file);
			
			return new WP_Error('ovos_codesafe_version',
				__('ovos codesafe: the update package is signed, but the version inside it is not the version the release offered. Nothing was installed — a genuine old build re-released under a new number would roll this site back. If this persists, tell ovos.', 'ovos-codesafe'));
		}
		
		return $file;
	}
	
	/**
	 * The version a package URL offers: the tag its release asset sits under
	 * (…/releases/download/v1.0.3/ovos-codesafe.zip), without the v — null when
	 * the URL names none
	 */
	public static function versionOfPackage(
		string $package,
	): ?string
	{
		if(self::isOurs($package) === false)
		{
			return null;
		}
		$tag = explode('/', substr($package, strlen(self::PACKAGE_PREFIX)), 2)[0];
		$version = ltrim(rawurldecode($tag), 'v');
		
		return preg_match('~^\d+(?:\.\d+){1,3}$~', $version) === 1 ? $version : null;
	}
	
	/**
	 * The `Version:` header of the plugin's main file inside a zip
	 * (ovos-codesafe/ovos-codesafe.php, the release's own prefix) — null when
	 * the zip cannot be opened, holds no such file, or the file names no
	 * plausible version. ZipArchive where PHP has it, else WordPress's own
	 * PclZip, which every install ships for exactly this
	 */
	public static function zipVersion(
		string $file,
	): ?string
	{
		$source = null;
		try
		{
			if(class_exists('ZipArchive'))
			{
				$zip = new ZipArchive();
				if($zip->open($file) === true)
				{
					$read = $zip->getFromName(self::MAIN_FILE);
					$source = is_string($read) ? $read : null;
					$zip->close();
				}
			}
			elseif(defined('ABSPATH') && is_file(ABSPATH . 'wp-admin/includes/class-pclzip.php'))
			{
				require_once ABSPATH . 'wp-admin/includes/class-pclzip.php';
				$archive = new \PclZip($file);
				$read = $archive->extract(PCLZIP_OPT_BY_NAME, self::MAIN_FILE, PCLZIP_OPT_EXTRACT_AS_STRING);
				$source = is_array($read) && is_string($read[0]['content'] ?? null) ? $read[0]['content'] : null;
			}
		}
		catch(Throwable)
		{
			return null;
		}
		
		return $source === null ? null : self::headerVersion($source);
	}
	
	/**
	 * The `Version:` header of a plugin file, read the way WordPress's
	 * get_file_data() reads it — from the first 8 KB, a line that is the
	 * header name after comment markers — and kept only when it is a plausible
	 * version
	 */
	public static function headerVersion(
		string $source,
	): ?string
	{
		if(preg_match('~^[ \t/*#@]*Version:(.*)$~mi', substr($source, 0, 8192), $match) !== 1)
		{
			return null;
		}
		$version = trim(preg_replace('~\s*(?:\*/|\?>).*~', '', $match[1]) ?? '');
		
		return preg_match('~^\d+(?:\.\d+){1,3}$~', $version) === 1 ? $version : null;
	}
	
	/**
	 * Whether $signature (base64 of 64 raw bytes) is a valid Ed25519
	 * signature of $zip under $publicKey (32 raw bytes as hex). Pure, so the
	 * crypto is testable without WordPress.
	 *
	 * Anything odd is "not signed": a malformed input, a wrong length, a
	 * verifier exception. The catch does that work — sodium (and the
	 * sodium_compat polyfill alike) throws on a wrong-length signature or
	 * key — so there are deliberately no length checks of our own here: a
	 * guard the tests cannot tell from its absence is a guard that is not
	 * there. What IS checked first is the key's hex shape, because hex2bin()
	 * warns rather than throws, and a warning inside the upgrader is noise at
	 * best and a fatal under a strict error handler at worst.
	 */
	public static function verify(
		string $zip,
		string $signature,
		string $publicKey = self::PUBLIC_KEY,
	): bool
	{
		$raw = base64_decode($signature, true);
		$key = preg_match('~^[0-9a-f]{64}$~i', $publicKey) === 1 ? hex2bin($publicKey) : false;
		
		if($zip === '' || $raw === false || $key === false)
		{
			return false;
		}
		
		try
		{
			return sodium_crypto_sign_verify_detached($raw, $zip, $key);
		}
		catch(Throwable)
		{
			return false;
		}
	}
	
	/**
	 * The key download() verifies with — a method so a test can hold a key
	 * pair of its own; the plugin never overrides it
	 */
	protected static function publicKey(): string
	{
		return self::PUBLIC_KEY;
	}
	
	/**
	 * The latest GitHub release as [version, url, package]; null whenever
	 * it cannot be known, which the caller treats as "no update visible"
	 */
	protected function latestRelease(): ?array
	{
		$cached = get_transient(self::CACHE_KEY);
		
		if(is_array($cached))
		{
			return $cached;
		}
		
		$response = wp_remote_get(self::RELEASES, [
			'timeout' => 5,
			'headers' => ['Accept' => 'application/vnd.github+json'],
		]);
		
		if(is_wp_error($response)
			|| (int)wp_remote_retrieve_response_code($response) !== 200)
		{
			return null;
		}
		
		$body = json_decode(wp_remote_retrieve_body($response), true);
		$release = $this->parse(is_array($body) ? $body : []);
		
		if($release !== null)
		{
			set_transient(self::CACHE_KEY, $release, HOUR_IN_SECONDS * 12);
		}
		
		return $release;
	}
	
	/**
	 * The fields the updater needs, or null when the release does not carry
	 * a plausible version tag, the workflow-built zip asset AND its signature
	 * — a release with no .sig is not an update, whatever else it carries
	 */
	protected function parse(array $body): ?array
	{
		$version = ltrim(is_string($body['tag_name'] ?? null) ? $body['tag_name'] : '', 'v');
		
		if(preg_match('~^\d+(?:\.\d+){1,3}$~', $version) !== 1)
		{
			return null;
		}
		
		$package = '';
		$signed = false;
		$assets = is_array($body['assets'] ?? null) ? $body['assets'] : [];
		
		foreach($assets as $asset)
		{
			if(is_array($asset) === false || is_string($asset['browser_download_url'] ?? null) === false)
			{
				continue;
			}
			
			if(($asset['name'] ?? '') === self::ASSET)
			{
				$package = $asset['browser_download_url'];
			}
			else if(($asset['name'] ?? '') === self::SIGNATURE)
			{
				$signed = true;
			}
		}
		
		// a package from anywhere but our own releases is not an update, it
		// is a download of something else under our name; and an unsigned
		// release is not one either — download() would refuse it anyway, this
		// just stops it being OFFERED
		if($package === '' || $signed === false || self::isOurs($package) === false)
		{
			return null;
		}
		
		return [
			'version' => $version,
			'url' => is_string($body['html_url'] ?? null)
				? $body['html_url']
				: 'https://github.com/ovos/codesafe-client-wordpress/releases',
			'package' => $package,
		];
	}
	
	/**
	 * Whether a package URL points at this repository's own release assets
	 */
	public static function isOurs(
		string $package,
	): bool
	{
		return str_starts_with($package, self::PACKAGE_PREFIX);
	}
	
	/**
	 * Whether offering $offered to a site on $installed would move it
	 * backwards or nowhere. An unknown installed version refuses too: with
	 * nothing to compare against there is no such thing as "newer".
	 */
	public static function isDowngrade(
		string $offered,
		string $installed,
	): bool
	{
		return $installed === '' || version_compare($offered, $installed, '<=');
	}
}
