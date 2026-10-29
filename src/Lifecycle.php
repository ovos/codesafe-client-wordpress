<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Prepend;
use Throwable;

use function array_map;
use function constant;
use function defined;
use function delete_option;
use function delete_site_option;
use function delete_transient;
use function file_get_contents;
use function file_put_contents;
use function function_exists;
use function get_sites;
use function in_array;
use function ini_get;
use function is_dir;
use function is_file;
use function is_link;
use function is_multisite;
use function is_object;
use function restore_current_blog;
use function rmdir;
use function rtrim;
use function scandir;
use function str_contains;
use function str_replace;
use function strtolower;
use function switch_to_blog;
use function trim;
use function unlink;

use const DIRECTORY_SEPARATOR;
use const PHP_SAPI;

/**
 * What happens when the plugin stops (security audit 2026-10-03 M16).
 *
 * Deactivation: the prepend layer reads the consent the plugin last wrote and
 * runs whether or not the plugin does — before 1.0.3 a deactivated plugin
 * kept blocking and recording for as long as PHP prepended the stub. The
 * consent is rewritten with every box off, so the layer judges and records
 * nothing from the next request; the stub stays, because PHP fails every
 * request whose prepend file is gone.
 *
 * Uninstall: every option and transient the plugin ever writes, on every site
 * of a network, and the store with the visitors' addresses and user agents in
 * its queues. The stub alone may survive, rewritten to do nothing, while
 * PHP's configuration still names it — the operator removes the
 * auto_prepend_file line, then the directory.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
final class Lifecycle
{
	/**
	 * Every option the plugin writes — Config::OPTION and the state the
	 * features keep. Enumerated from the code: Config, Inventory, Plugin,
	 * ScanRunner, Entries, Hello, Rollup, CoreUpdate (a site option — on a
	 * single site the same row; on a network SITE_OPTIONS removes it once)
	 */
	public const OPTIONS = [
		Config::OPTION,
		'ovos_codesafe_inventory',
		'ovos_codesafe_inventory_dirty',
		Plugin::OPTION_ANNOUNCED,
		ScanRunner::OPTION,
		ScanRunner::LOCK,
		Entries::OPTION,
		Entries::LOCK,
		Hello::OPTION,
		Rollup::OPTION_REFUSED,
		CoreUpdate::OPTION,
		Inventory::OURS,
	];
	
	/** the network's own options a multisite uninstall removes once, after every site's */
	public const SITE_OPTIONS = [
		CoreUpdate::OPTION,
		Inventory::OURS,
	];
	
	/**
	 * The transients with a fixed name: the Updater's release cache and the
	 * two report budgets. The ones with a suffix — Checksums' `_sums_<version>`
	 * and Security's `_authfail_<scope>_<md5>` — go by PREFIX (TRANSIENT_PREFIXES)
	 */
	public const TRANSIENTS = [
		'ovos_codesafe_latest_release',
		'ovos_codesafe_security_rate',
		'ovos_codesafe_404_rate',
	];
	
	public const TRANSIENT_PREFIXES = [
		'ovos_codesafe_sums_',
		'ovos_codesafe_authfail_',
		Connect::TRANSIENT_PREFIX,
	];
	
	/**
	 * What the stub becomes on uninstall while PHP still names it: valid PHP
	 * that does nothing, and says what to do
	 */
	public const INERT_STUB = "<?php\n"
		. "// ovos codesafe was uninstalled. PHP's auto_prepend_file still names this file:\n"
		. "// remove that line from your PHP configuration (php.ini, .user.ini or .htaccess),\n"
		. "// then delete this directory. Until then this file does nothing.\n";
	
	/**
	 * register_deactivation_hook: every box of the consent off — unless this is
	 * one site of a network deactivating its own copy, whose word never drove
	 * the shared store (Config::ownsSharedStore)
	 */
	public static function deactivate(
		mixed $networkWide = false,
	): void
	{
		try
		{
			if($networkWide !== true && (new Config())->ownsSharedStore() === false)
			{
				return;
			}
			self::removeMuPlugin();
			$dir = Adapter::storeDir();
			if($dir === '')
			{
				return;
			}
			self::disable($dir);
		}
		catch(Throwable)
		{
			// a deactivation never fails on our account
		}
	}
	
	/**
	 * The consent with everything off: the layer reads it, judges nothing and
	 * records nothing. The ruleset's name is kept, so a reactivation finds its
	 * rules again
	 */
	public static function disable(
		string $dir,
	): bool
	{
		$current = Prepend::consent($dir);
		
		return Prepend::writeConsent($dir, [
			'detect' => false,
			'enforce' => false,
			'kill' => false,
			'prefix' => (string)($current['prefix'] ?? ''),
			'root' => (string)($current['root'] ?? ''),
			'entries' => false,
		]);
	}
	
	/** the Shield's mu-plugin stage goes with the plugin (Prepend::ensureMuPlugin) */
	protected static function removeMuPlugin(): void
	{
		if(defined('WPMU_PLUGIN_DIR'))
		{
			Prepend::removeMuPlugin((string)constant('WPMU_PLUGIN_DIR'));
		}
	}
	
	/**
	 * uninstall.php: the options and transients of every site, then the store
	 */
	public static function uninstall(): void
	{
		if(function_exists('is_multisite') && is_multisite())
		{
			foreach(get_sites(['fields' => 'ids', 'number' => 0]) as $site)
			{
				switch_to_blog((int)$site);
				self::forget();
				restore_current_blog();
			}
			foreach(self::SITE_OPTIONS as $option)
			{
				delete_site_option($option);
			}
		}
		else
		{
			self::forget();
		}
		
		self::removeMuPlugin();
		$stubDir = Adapter::stubDir();
		$dataDir = Adapter::storeDir();
		if($dataDir !== '' && $dataDir !== $stubDir)
		{
			self::removeStore($dataDir, null);
		}
		if($stubDir !== '')
		{
			// WP-CLI's configuration says nothing of the web server's: there the
			// stub is kept, inert, whatever the CLI's ini names
			self::removeStore($stubDir, PHP_SAPI === 'cli' ? null : (string)ini_get('auto_prepend_file'), PHP_SAPI === 'cli');
		}
	}
	
	/**
	 * This site's options and transients: the named ones through WordPress
	 * (an object cache forgets them too), the suffixed transients straight
	 * from the options table — an object cache lets those expire by
	 * themselves, the longest within thirty days
	 */
	public static function forget(): void
	{
		foreach(self::OPTIONS as $option)
		{
			delete_option($option);
		}
		foreach(self::TRANSIENTS as $transient)
		{
			delete_transient($transient);
		}
		
		global $wpdb;
		if(isset($wpdb) === false || is_object($wpdb) === false)
		{
			return;
		}
		foreach(self::TRANSIENT_PREFIXES as $prefix)
		{
			foreach(['_transient_', '_transient_timeout_'] as $kind)
			{
				$wpdb->query($wpdb->prepare(
					"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
					$wpdb->esc_like($kind . $prefix) . '%',
				));
			}
		}
	}
	
	/**
	 * The store's files gone, and the directory with them — unless $ini (PHP's
	 * auto_prepend_file) names one of its stubs (Prepend::STUB_NAMES), or
	 * $keepStub says PHP's configuration cannot be known: then every stub of
	 * this plugin's stays as INERT_STUB, the one not named too, since another
	 * directory's configuration may name it and removing a file PHP prepends
	 * fails every request. Only files directly in $dir are touched, never a
	 * subdirectory or what a link points at. Returns whether the directory
	 * itself is gone
	 */
	public static function removeStore(
		string $dir,
		?string $ini,
		bool $keepStub = false,
	): bool
	{
		$dir = rtrim($dir, '/\\');
		if(is_dir($dir) === false || is_link($dir))
		{
			return false;
		}
		$same = static fn(string $path): string => strtolower(rtrim(str_replace('\\', '/', trim($path)), '/'));
		$names = static fn(string $name): bool => $ini !== null && trim($ini) !== '' && $same($ini) === $same($dir . DIRECTORY_SEPARATOR . $name);
		// one stub named, or the configuration unknown: another directory's php.ini or .user.ini may name the other, so both stay
		$prepended = $keepStub || in_array(true, array_map($names, Prepend::STUB_NAMES), true);
		$keeps = static function(string $name, string $path) use ($prepended, $names): bool
		{
			if($prepended === false || in_array($name, Prepend::STUB_NAMES, true) === false)
			{
				return false;
			}
			// unreadable reads as no file of this plugin's
			$text = (string)@file_get_contents($path);
			
			// the one named, or this plugin's: its marker, or the inert text an earlier uninstall left
			return $names($name) || str_contains($text, Prepend::STUB_MARKER) || $text === self::INERT_STUB;
		};
		$kept = false;
		
		foreach(scandir($dir) ?: [] as $name)
		{
			$path = $dir . DIRECTORY_SEPARATOR . $name;
			if($name === '.' || $name === '..' || is_link($path) || is_file($path) === false)
			{
				continue;
			}
			if($keeps($name, $path))
			{
				$kept = @file_put_contents($path, self::INERT_STUB) !== false || $kept;
				
				continue;
			}
			@unlink($path);
		}
		
		return $kept === false && @rmdir($dir);
	}
}
