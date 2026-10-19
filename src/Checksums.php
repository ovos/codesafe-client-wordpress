<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function array_key_exists;
use function get_transient;
use function is_array;
use function is_string;
use function is_wp_error;
use function json_decode;
use function preg_match;
use function rawurlencode;
use function set_transient;
use function sprintf;
use function strlen;
use function strncmp;
use function strpos;
use function strtolower;
use function substr;
use function time;
use function wp_remote_get;
use function wp_remote_retrieve_body;
use function wp_remote_retrieve_response_code;

/**
 * The wordpress.org checksum lists — the authoritative half of the integrity
 * scan (docs/plans/wordpress-integrity-scan.md, WS2). Heuristics say where a
 * PHP file has no business; a checksum list says what a file SHOULD be, byte
 * for byte, for everything WordPress.org shipped: core (with the plugins and
 * themes bundled in it) by version and locale, and every wp.org plugin by
 * slug and version. Three verdicts fall out of a list — a file the list does
 * not know (FOREIGN: nobody shipped it), a file whose md5 differs (MODIFIED),
 * a listed file that is not on disk (MISSING, counted only) — and none of them
 * is a guess.
 *
 * A list is immutable per (slug, version), so it is fetched ONCE and kept in
 * a transient for a month; a 404 (a premium or custom plugin wp.org never had)
 * is remembered for a week so the scan does not ask again every pass; a
 * network failure is remembered for an hour. "Unavailable" is an honest
 * answer — the scan then says nothing about that root rather than guessing.
 *
 * The lists are the only network reads the scan ever makes, from
 * wordpress.org alone, and the fetch count is exposed so the runner can bound
 * a background chunk to one fetch: a first pass over a forty-plugin site
 * fetches forty lists, and a shutdown hook must not pay for them at once.
 */
class Checksums
{
	protected const TRANSIENT = 'ovos_codesafe_sums_';
	
	protected const CORE_API = 'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s';
	
	protected const PLUGIN_API = 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json';
	
	/** a list is immutable per version: a month is a cache, not a truth window */
	protected const TTL = 30 * 86400;
	
	/** wp.org never had this plugin (or this version): a week before asking again */
	protected const TTL_MISS = 7 * 86400;
	
	/** the network failed: an hour, then another try */
	protected const TTL_FAIL = 3600;
	
	/**
	 * Lists loaded this request, keyed by transient name — a chunk reads a
	 * list once, not per file
	 *
	 * @var array<string, array<string, string>|null>
	 */
	protected array $loaded = [];
	
	/**
	 * Network fetches performed this request — the runner's budget
	 */
	public int $fetches = 0;
	
	public function __construct(
		protected int $timeout = 4,
	)
	{
	}
	
	/**
	 * Core's list for a version and locale: path relative to ABSPATH → md5,
	 * or null when unavailable. A locale without a list falls back to en_US,
	 * which carries every PHP file (the locale lists add translations).
	 *
	 * @return array<string, string>|null
	 */
	public function core(
		string $version,
		string $locale,
	): ?array
	{
		$version = Inventory::version($version);
		$locale = preg_match('~^[A-Za-z_]{2,12}$~', $locale) === 1 ? $locale : 'en_US';
		
		if($version === '')
		{
			return null;
		}
		
		$list = $this->list('core_' . $version . '_' . strtolower($locale),
			sprintf(self::CORE_API, rawurlencode($version), rawurlencode($locale)),
			static fn(array $decoded): ?array => is_array($decoded['checksums'] ?? null)
				? self::flat($decoded['checksums'])
				: null);
		
		if($list === null && $locale !== 'en_US')
		{
			return $this->core($version, 'en_US');
		}
		
		return $list;
	}
	
	/**
	 * Whether the core list is known WITHOUT fetching — the background runner
	 * asks before it spends its one fetch
	 */
	public function coreCached(
		string $version,
		string $locale,
	): bool
	{
		$version = Inventory::version($version);
		$locale = preg_match('~^[A-Za-z_]{2,12}$~', $locale) === 1 ? $locale : 'en_US';
		
		return $this->cached('core_' . $version . '_' . strtolower($locale))
			|| $this->cached('core_' . $version . '_en_us');
	}
	
	/**
	 * A wp.org plugin's list for a version: path relative to the plugin
	 * directory → md5, or null when wp.org has no such plugin or version
	 *
	 * @return array<string, string>|null
	 */
	public function plugin(
		string $slug,
		string $version,
	): ?array
	{
		$slug = Inventory::slugOf($slug);
		$version = Inventory::version($version);
		
		if($slug === '' || $version === '')
		{
			return null;
		}
		
		return $this->list('plugin_' . $slug . '_' . $version,
			sprintf(self::PLUGIN_API, rawurlencode($slug), rawurlencode($version)),
			static function(array $decoded): ?array
			{
				if(is_array($decoded['files'] ?? null) === false)
				{
					return null;
				}
				
				$list = [];
				
				foreach($decoded['files'] as $path => $sums)
				{
					$md5 = is_array($sums) ? ($sums['md5'] ?? null) : null;
					
					if(is_string($path) && is_string($md5))
					{
						$list[$path] = strtolower($md5);
					}
				}
				
				return $list;
			});
	}
	
	public function pluginCached(
		string $slug,
		string $version,
	): bool
	{
		return $this->cached('plugin_' . Inventory::slugOf($slug) . '_' . Inventory::version($version));
	}
	
	/**
	 * The file names a list expects in one directory — the missing pass asks
	 * this for every directory it walks and checks each name against disk
	 *
	 * @param array<string, string> $list the list as core() or plugin() returned it
	 * @param string $directory relative directory, '' for the list's root
	 * @return list<string>
	 */
	public static function expected(
		array $list,
		string $directory,
	): array
	{
		$names = [];
		$prefix = $directory === '' ? '' : $directory . '/';
		$length = strlen($prefix);
		
		foreach($list as $path => $md5)
		{
			if($prefix !== '' && strncmp($path, $prefix, $length) !== 0)
			{
				continue;
			}
			
			$rest = substr($path, $length);
			
			if($rest !== '' && strpos($rest, '/') === false)
			{
				$names[] = $rest;
			}
		}
		
		return $names;
	}
	
	/**
	 * One list: memory, then the transient, then the network (counted). A
	 * fetched list is remembered for a month, a 404 for a week, a failure for
	 * an hour.
	 *
	 * @param callable(array): ?array $shape the endpoint's JSON → path → md5
	 * @return array<string, string>|null
	 */
	protected function list(
		string $key,
		string $url,
		callable $shape,
	): ?array
	{
		if(array_key_exists($key, $this->loaded))
		{
			return $this->loaded[$key];
		}
		
		$stored = get_transient(self::TRANSIENT . $key);
		
		if(is_array($stored) && array_key_exists('list', $stored))
		{
			return $this->loaded[$key] = is_array($stored['list']) ? $stored['list'] : null;
		}
		
		$this->fetches++;
		
		$response = wp_remote_get($url, [
			'timeout' => $this->timeout,
			'sslverify' => (bool)Legacy::filter('ovos_codesafe_sslverify_wporg', true),
		]);
		
		if(is_wp_error($response))
		{
			set_transient(self::TRANSIENT . $key, ['list' => null, 'at' => time()], self::TTL_FAIL);
			
			return $this->loaded[$key] = null;
		}
		
		$status = (int)wp_remote_retrieve_response_code($response);
		$decoded = $status === 200 ? json_decode((string)wp_remote_retrieve_body($response), true, 6) : null;
		$list = is_array($decoded) ? $shape($decoded) : null;
		
		// core answers 200 with `false` for a version it never had; a plugin
		// endpoint answers 404 — both are "wp.org does not know this", kept a week
		set_transient(self::TRANSIENT . $key, ['list' => $list, 'at' => time()],
			$list === null ? ($status === 200 || $status === 404 ? self::TTL_MISS : self::TTL_FAIL) : self::TTL);
		
		return $this->loaded[$key] = $list;
	}
	
	protected function cached(
		string $key,
	): bool
	{
		if(array_key_exists($key, $this->loaded))
		{
			return true;
		}
		
		$stored = get_transient(self::TRANSIENT . $key);
		
		return is_array($stored) && array_key_exists('list', $stored);
	}
	
	/**
	 * Core's `{path: md5}` map, paths as wordpress.org spells them (forward
	 * slashes) — copied through a shape check so a hostile answer cannot
	 * smuggle anything but strings
	 *
	 * @return array<string, string>
	 */
	protected static function flat(
		array $checksums,
	): array
	{
		$list = [];
		
		foreach($checksums as $path => $md5)
		{
			if(is_string($path) && is_string($md5) && preg_match('~^[0-9a-f]{32}$~i', $md5) === 1)
			{
				$list[$path] = strtolower($md5);
			}
		}
		
		return $list;
	}
}
