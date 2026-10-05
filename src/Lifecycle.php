<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Prepend;
use Throwable;

use function delete_option;
use function delete_transient;
use function file_put_contents;
use function function_exists;
use function get_sites;
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
	 * ScanRunner, Entries, Hello
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
		}
		else
		{
			self::forget();
		}
		
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
	 * auto_prepend_file) names its stub, or $keepStub says PHP's configuration
	 * cannot be known: then the stub stays as INERT_STUB, since removing a
	 * file PHP prepends fails every request. Only files directly in $dir are
	 * touched, never a subdirectory or what a link points at. Returns whether
	 * the directory itself is gone
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
		$stub = $dir . DIRECTORY_SEPARATOR . Prepend::STUB;
		$same = static fn(string $path): string => strtolower(rtrim(str_replace('\\', '/', trim($path)), '/'));
		$named = $keepStub || ($ini !== null && trim($ini) !== '' && $same($ini) === $same($stub));
		$kept = false;
		
		foreach(scandir($dir) ?: [] as $name)
		{
			$path = $dir . DIRECTORY_SEPARATOR . $name;
			if($name === '.' || $name === '..' || is_link($path) || is_file($path) === false)
			{
				continue;
			}
			if($named && $name === Prepend::STUB)
			{
				$kept = @file_put_contents($stub, self::INERT_STUB) !== false;
				
				continue;
			}
			@unlink($path);
		}
		
		return $kept === false && @rmdir($dir);
	}
}
