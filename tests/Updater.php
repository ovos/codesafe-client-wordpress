<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Plugin;
use Ovos\Codesafe\Updater as BaseUpdater;
use Ovos\Test;
use Ovos\Test\Exception\SkipException;
use Ovos\Test\Internal;
use Tests\Files\TestUpdater;
use WP_Error;
use ZipArchive;

use function base64_decode;
use function base64_encode;
use function bin2hex;
use function chr;
use function end;
use function file_get_contents;
use function hex2bin;
use function is_array;
use function is_file;
use function is_string;
use function openssl_pkey_get_details;
use function openssl_pkey_get_private;
use function openssl_sign;
use function ord;
use function preg_match;
use function preg_replace;
use function random_bytes;
use function restore_error_handler;
use function set_error_handler;
use function sodium_crypto_sign_detached;
use function sodium_crypto_sign_keypair;
use function sodium_crypto_sign_publickey;
use function sodium_crypto_sign_secretkey;
use function str_repeat;
use function substr;
use function substr_replace;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;
use const PHP_VERSION_ID;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'TestUpdater.file.php';

/**
 * The Updater, driven without WordPress: a REAL Ed25519 pair is generated per
 * run and the plugin verifies with sodium, as it does on every site. The
 * release workflow signs with openssl: that the two agree is its own claim,
 * on PHP 8.4+ — 8.3's openssl extension cannot make an Ed25519 signature
 * ("Unknown digest algorithm"), so the other claims sign with sodium.
 * Requires ext/openssl and ext/sodium.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Updater extends Test
{
	protected const string OURS = 'https://github.com/ovos/codesafe-client-wordpress/releases/download/v9.9.9/ovos-codesafe.zip';
	
	protected const string THEIRS = 'https://github.com/someone-else/codesafe-client-wordpress/releases/download/v9.9.9/ovos-codesafe.zip';
	
	protected const string ELSEWHERE = 'https://evil.example/ovos-codesafe.zip';
	
	protected const string PLUGIN_FILE = '/srv/wp/wp-content/plugins/ovos-codesafe/ovos-codesafe.php';
	
	/** a sodium secret key (seed + public key, 64 bytes) */
	protected string $secret;
	
	protected string $otherSecret;
	
	protected string $public;
	
	protected string $zip;
	
	protected string $good;
	
	public function __construct()
	{
		$pair = sodium_crypto_sign_keypair();
		$this->secret = sodium_crypto_sign_secretkey($pair);
		$this->otherSecret = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
		$this->public = bin2hex(sodium_crypto_sign_publickey($pair));
		// a real release zip: the plugin's main file under git archive's prefix,
		// carrying the version the release tag offers (M15)
		$this->zip = $this->zipOf('9.9.9');
		$this->good = $this->sign($this->zip, $this->secret);
		
		TestUpdater::$key = $this->public;
	}
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	#[Internal]
	public function finalize(): void
	{
		foreach($GLOBALS['wp']['downloaded'] as $path)
		{
			if(is_file($path))
			{
				unlink($path);
			}
		}
	}
	
	// ---- origin and downgrade floor ----------------------------------------
	
	public function offersNewerSignedReleaseFromOurAssets(): bool
	{
		return is_array($this->offered($this->release('v9.9.9', self::OURS), '0.6.4'));
	}
	
	public function offerNamesOurPackage(): bool
	{
		return ($this->offered($this->release('v9.9.9', self::OURS), '0.6.4')['package'] ?? '') === self::OURS;
	}
	
	public function refusesPackageFromAnotherRepositoryUnderOurName(): bool
	{
		return $this->offered($this->release('v9.9.9', self::THEIRS), '0.6.4') === false;
	}
	
	public function refusesPackageFromUnrelatedHost(): bool
	{
		return $this->offered($this->release('v9.9.9', self::ELSEWHERE), '0.6.4') === false;
	}
	
	public function refusedOriginLeavesNothingCached(): bool
	{
		return $this->offered($this->release('v9.9.9', self::THEIRS), '0.6.4') === false
			&& $GLOBALS['wp']['transient'] === null;
	}
	
	public function doesNotOfferTheSameVersion(): bool
	{
		return $this->offered($this->release('v0.6.4', self::OURS), '0.6.4') === false;
	}
	
	public function doesNotOfferAnOlderVersion(): bool
	{
		return $this->offered($this->release('v0.6.3', self::OURS), '0.6.4') === false;
	}
	
	public function unknownInstalledVersionRefusesRatherThanGuesses(): bool
	{
		return $this->offered($this->release('v9.9.9', self::OURS), '') === false;
	}
	
	public function plainHttpIsNotOurPrefixEvenOnOurHost(): bool
	{
		return BaseUpdater::isOurs('http://github.com/ovos/codesafe-client-wordpress/releases/download/v1/ovos-codesafe.zip') === false;
	}
	
	// ---- the signature -----------------------------------------------------
	
	public function releaseWithoutSigAssetIsNotOffered(): bool
	{
		return $this->offered($this->release('v9.9.9', self::OURS, signed: false), '0.6.4') === false;
	}
	
	public function genuineSignatureVerifies(): bool
	{
		return BaseUpdater::verify($this->zip, $this->good, $this->public) === true;
	}
	
	/**
	 * openssl signs, as the release workflow signs; sodium verifies, as the
	 * plugin verifies — on this run's key, and the key openssl derives from
	 * the seed is the one sodium made
	 */
	public function opensslSignsSodiumVerifies(): bool
	{
		if(PHP_VERSION_ID < 80400)
		{
			throw new SkipException('PHP 8.3 openssl cannot sign with Ed25519.');
		}
		
		// PKCS#8 around the 32-byte seed: the DER prefix of an Ed25519 private key
		$key = openssl_pkey_get_private("-----BEGIN PRIVATE KEY-----\n"
			. base64_encode(hex2bin('302e020100300506032b657004220420') . substr($this->secret, 0, 32))
			. "\n-----END PRIVATE KEY-----\n");
		$der = base64_decode(preg_replace('~-----[^-]+-----|\s~', '', openssl_pkey_get_details($key)['key']));
		openssl_sign($this->zip, $signature, $key, 0); // Ed25519 is one-shot: digest 0
		
		return bin2hex(substr($der, -32)) === $this->public
			&& BaseUpdater::verify($this->zip, base64_encode($signature) . "\n", $this->public) === true;
	}
	
	public function flippedByteInZipDoesNotVerify(): bool
	{
		$tampered = substr_replace($this->zip, chr(ord($this->zip[100]) ^ 1), 100, 1);
		
		return BaseUpdater::verify($tampered, $this->good, $this->public) === false;
	}
	
	public function flippedByteInSignatureDoesNotVerify(): bool
	{
		// a flip, never a write of \x00 — the byte may already be one (1 run in 256)
		$raw = base64_decode($this->good);
		$tampered = base64_encode(substr_replace($raw, chr(ord($raw[3]) ^ 1), 3, 1));
		
		return BaseUpdater::verify($this->zip, $tampered, $this->public) === false;
	}
	
	public function signatureByDifferentKeyDoesNotVerify(): bool
	{
		return BaseUpdater::verify($this->zip, $this->sign($this->zip, $this->otherSecret), $this->public) === false;
	}
	
	/**
	 * Any warning or notice is a failure too: the upgrader runs under
	 * WordPress's error handling, and a hex2bin() warning on a malformed key is
	 * exactly the kind of thing that turns into a fatal on a stranger's host
	 */
	public function malformedSignatureIsNotSignedNeverAnExceptionOrNotice(): bool
	{
		return $this->quietly(fn(): bool => BaseUpdater::verify($this->zip, '', $this->public) === false
			&& BaseUpdater::verify($this->zip, 'AAAA', $this->public) === false
			&& BaseUpdater::verify($this->zip, base64_encode(random_bytes(65)), $this->public) === false
			&& BaseUpdater::verify($this->zip, '!!!not base64!!!', $this->public) === false
			&& BaseUpdater::verify('', $this->good, $this->public) === false);
	}
	
	public function malformedPublicKeyIsNotSignedNeverAnExceptionOrNotice(): bool
	{
		return $this->quietly(fn(): bool => BaseUpdater::verify($this->zip, $this->good, 'zz') === false
			&& BaseUpdater::verify($this->zip, $this->good, 'abcd') === false
			&& BaseUpdater::verify($this->zip, $this->good, str_repeat('ab', 33)) === false);
	}
	
	public function shippedPublicKeyIs32BytesOfHex(): bool
	{
		return preg_match('~^[0-9a-f]{64}$~', BaseUpdater::PUBLIC_KEY) === 1
			&& hex2bin(BaseUpdater::PUBLIC_KEY) !== false;
	}
	
	// ---- the hook -----------------------------------------------------------
	
	public function verifiedDownloadHandsWordPressTheFileWithTheRightBytes(): bool
	{
		$verified = $this->downloaded(self::OURS, $this->zip, $this->good);
		
		return is_string($verified)
			&& is_file($verified)
			&& file_get_contents($verified) === $this->zip;
	}
	
	public function mismatchedSignatureIsWpErrorAndTheFileIsGone(): bool
	{
		$result = $this->downloaded(self::OURS, $this->zip, $this->sign($this->zip, $this->otherSecret));
		$path = end($GLOBALS['wp']['downloaded']);
		
		return $result instanceof WP_Error
			&& $result->code === 'ovos_codesafe_unsigned'
			&& is_string($path)
			&& is_file($path) === false;
	}
	
	public function missingSigIsWpErrorNotAnInstall(): bool
	{
		return $this->downloaded(self::OURS, $this->zip, null) instanceof WP_Error;
	}
	
	public function sigServedWithNon200IsNotTrustedEvenWhenItWouldVerify(): bool
	{
		return $this->downloaded(self::OURS, $this->zip, $this->good, false, 502) instanceof WP_Error
			&& $this->downloaded(self::OURS, $this->zip, $this->good, false, 404) instanceof WP_Error;
	}
	
	public function tamperedZipWithGenuineSignatureIsRefused(): bool
	{
		return $this->downloaded(self::OURS, $this->zip . 'x', $this->good) instanceof WP_Error;
	}
	
	public function failedDownloadIsHandedBackAsWordPressReportedIt(): bool
	{
		$result = $this->downloaded(self::OURS, null, null);
		
		return $result instanceof WP_Error
			&& $result->code === 'http_404';
	}
	
	public function packageNotOursIsLeftToWordPressUntouched(): bool
	{
		return $this->downloaded(self::THEIRS, $this->zip, $this->good) === false
			&& $this->downloaded(self::ELSEWHERE, $this->zip, $this->good) === false;
	}
	
	public function earlierFiltersAnswerIsRespected(): bool
	{
		return $this->downloaded(self::OURS, $this->zip, $this->good, '/already/decided.zip') === '/already/decided.zip';
	}
	
	// ---- the version inside the zip (M15) ------------------------------------
	
	/**
	 * A GENUINE signed build of another version, re-released under a newer
	 * tag, is not an update: the signature covers the bytes, the header inside
	 * them names the version, and it must be the one offered
	 */
	public function aSignedOldBuildUnderANewTagIsRefusedAndTheFileIsGone(): bool
	{
		$old = $this->zipOf('1.0.0');
		$result = $this->downloaded(self::OURS, $old, $this->sign($old, $this->secret));
		$path = end($GLOBALS['wp']['downloaded']);
		
		return $result instanceof WP_Error
			&& $result->code === 'ovos_codesafe_version'
			&& is_string($path)
			&& is_file($path) === false;
	}
	
	/** signed bytes that are no zip, or a zip without the plugin's main file, carry no version: refused */
	public function aSignedPackageWithoutAReadableVersionIsRefused(): bool
	{
		$bytes = "PK\x03\x04" . random_bytes(2000);
		$empty = $this->zipOf(null);
		
		return $this->downloaded(self::OURS, $bytes, $this->sign($bytes, $this->secret)) instanceof WP_Error
			&& $this->downloaded(self::OURS, $empty, $this->sign($empty, $this->secret)) instanceof WP_Error;
	}
	
	public function theOfferedVersionIsTheTagTheAssetSitsUnder(): bool
	{
		return BaseUpdater::versionOfPackage(self::OURS) === '9.9.9'
			&& BaseUpdater::versionOfPackage('https://github.com/ovos/codesafe-client-wordpress/releases/download/1.0.3/ovos-codesafe.zip') === '1.0.3'
			&& BaseUpdater::versionOfPackage('https://github.com/ovos/codesafe-client-wordpress/releases/download/latest/ovos-codesafe.zip') === null
			&& BaseUpdater::versionOfPackage(self::THEIRS) === null;
	}
	
	public function theHeaderVersionIsReadTheWayWordPressReadsIt(): bool
	{
		return BaseUpdater::headerVersion("<?php\n/**\n * Plugin Name: x\n * Version: 1.0.3\n */\n") === '1.0.3'
			&& BaseUpdater::headerVersion("<?php\n// Version: 2.1 */\n") === '2.1'
			&& BaseUpdater::headerVersion("<?php\n/* Version: 1.0.3-beta */") === null
			&& BaseUpdater::headerVersion("<?php\n/* Plugin Name: x */") === null
			&& BaseUpdater::headerVersion((string)file_get_contents(__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'ovos-codesafe.php')) === Plugin::VERSION;
	}
	
	// ---- helpers --------------------------------------------------------------
	
	/**
	 * The bytes of a release-shaped zip whose main file says Version: $version
	 * — null leaves the main file out
	 */
	protected function zipOf(
		?string $version,
	): string
	{
		$path = tempnam(sys_get_temp_dir(), 'zip');
		$zip = new ZipArchive();
		$zip->open($path, ZipArchive::OVERWRITE);
		$zip->addFromString('ovos-codesafe/readme.txt', random_bytes(64));
		if($version !== null)
		{
			$zip->addFromString(BaseUpdater::MAIN_FILE, "<?php\n/**\n * Plugin Name: ovos codesafe\n * Version: " . $version . "\n */\n");
		}
		$zip->close();
		$bytes = (string)file_get_contents($path);
		unlink($path);
		
		return $bytes;
	}
	
	/**
	 * The .sig the workflow publishes: base64 of the 64 raw bytes, one line
	 */
	protected function sign(
		string $bytes,
		string $secret,
	): string
	{
		return base64_encode(sodium_crypto_sign_detached($bytes, $secret)) . "\n";
	}
	
	protected function release(
		string $tag,
		string $package,
		bool $signed = true,
	): array
	{
		$assets = [['name' => 'ovos-codesafe.zip', 'browser_download_url' => $package]];
		if($signed)
		{
			$assets[] = ['name' => 'ovos-codesafe.zip.sig', 'browser_download_url' => $package . '.sig'];
		}
		
		return [
			'tag_name' => $tag,
			'html_url' => 'https://github.com/ovos/codesafe-client-wordpress/releases/tag/' . $tag,
			'assets' => $assets,
		];
	}
	
	protected function offered(
		array $api,
		string $installed,
	): mixed
	{
		$GLOBALS['wp']['api'] = $api;
		$GLOBALS['wp']['transient'] = null;
		
		return (new TestUpdater(self::PLUGIN_FILE))
			->check(false, ['Version' => $installed], 'ovos-codesafe/ovos-codesafe.php');
	}
	
	protected function downloaded(
		string $package,
		?string $zip,
		?string $sig,
		mixed $reply = false,
		int $sigStatus = 200,
	): mixed
	{
		$GLOBALS['wp']['zip_by_url'] = $zip === null ? [] : [$package => $zip];
		$GLOBALS['wp']['sig_by_url'] = $sig === null ? [] : [$package . '.sig' => $sig];
		$GLOBALS['wp']['sig_status'] = $sigStatus;
		
		return (new TestUpdater(self::PLUGIN_FILE))
			->download($reply, $package, null, []);
	}
	
	/**
	 * The claim holds AND nothing warned or noticed on the way
	 */
	protected function quietly(
		callable $claim,
	): bool
	{
		$noise = [];
		set_error_handler(static function(int $level, string $message) use (&$noise): bool
		{
			$noise[] = $message;
			
			return true;
		});
		
		try
		{
			$held = $claim();
		}
		finally
		{
			restore_error_handler();
		}
		
		return $held && $noise === [];
	}
}
