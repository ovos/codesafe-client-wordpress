<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function add_action;
use function add_option;
use function apply_filters;
use function current_user_can;
use function deactivate_plugins;
use function esc_html__;
use function function_exists;
use function get_option;
use function is_dir;
use function is_multisite;
use function is_plugin_active;
use function is_plugin_active_for_network;
use function rtrim;

use const DIRECTORY_SEPARATOR;
use const WP_PLUGIN_DIR;

/**
 * The switch from the plugin's first name, ovos-console (constants
 * OVOS_CONSOLE_*, options ovos_console*), to ovos-codesafe. WordPress sees a
 * new slug as a different plugin, so the sites that ran ovos-console install
 * this one beside it; everything here makes that one click: the settings
 * are copied, the old plugin is deactivated so no error is reported twice,
 * and the old names keep working where a site's own code or wp-config
 * uses them. Config reads the old constants, Adapter keeps the old prepend
 * stub working.
 */
final class Legacy
{
	/** the old plugin, as WordPress names it in active_plugins */
	public const BASENAME = 'ovos-console/ovos-console.php';
	
	/** the old wp-config constant prefix, read after CODESAFE_ */
	public const CONSTANT_PREFIX = 'OVOS_CONSOLE_';
	
	/** old option => new option; transients and locks rebuild by themselves */
	public const OPTIONS = [
		'ovos_console' => Config::OPTION,
		'ovos_console_inventory' => 'ovos_codesafe_inventory',
		'ovos_console_inventory_dirty' => 'ovos_codesafe_inventory_dirty',
		'ovos_console_announced_release' => Plugin::OPTION_ANNOUNCED,
		'ovos_console_scan' => 'ovos_codesafe_scan',
	];
	
	/** the old filter names, applied after the new ones */
	public const FILTERS = [
		'ovos_codesafe_sslverify' => 'ovos_console_sslverify',
		'ovos_codesafe_sslverify_wporg' => 'ovos_console_sslverify_wporg',
	];
	
	/**
	 * The settings, copied once per site: while this plugin's own option is
	 * missing, every old row that exists is copied under its new name, and
	 * the main option is created even when there was nothing to copy, so
	 * the check costs one autoloaded read from then on. The old rows stay —
	 * the old plugin's uninstall removes them
	 */
	public static function migrate(): void
	{
		if(get_option(Config::OPTION) !== false)
		{
			return;
		}
		
		foreach(self::OPTIONS as $old => $new)
		{
			if($new === Config::OPTION)
			{
				continue;
			}
			
			$value = get_option($old);
			
			if($value !== false && get_option($new) === false)
			{
				add_option($new, $value);
			}
		}
		
		$settings = get_option('ovos_console');
		
		add_option(Config::OPTION, is_array($settings) ? $settings : []);
	}
	
	/**
	 * A filter under its new name, then under its old one, so a site's
	 * add_filter('ovos_console_sslverify', …) keeps working
	 */
	public static function filter(
		string $name,
		mixed $value,
	): mixed
	{
		$value = apply_filters($name, $value);
		
		return isset(self::FILTERS[$name]) ? apply_filters(self::FILTERS[$name], $value) : $value;
	}
	
	/** admin only: the old plugin deactivated, and a notice while its directory is still there */
	public static function register(): void
	{
		add_action('admin_init', [self::class, 'deactivateOld']);
		add_action('admin_notices', [self::class, 'notice']);
		add_action('network_admin_notices', [self::class, 'notice']);
	}
	
	/**
	 * admin_init: the old plugin switched off, silently (its deactivation
	 * hook has nothing this plugin needs), network-wide where it was
	 * network-active. Until this runs both plugins report, which is one
	 * request after activation
	 */
	public static function deactivateOld(): void
	{
		if(function_exists('is_plugin_active') === false)
		{
			return;
		}
		
		if(is_multisite() && is_plugin_active_for_network(self::BASENAME))
		{
			deactivate_plugins(self::BASENAME, true, true);
		}
		
		if(is_plugin_active(self::BASENAME))
		{
			deactivate_plugins(self::BASENAME, true);
		}
	}
	
	/** admin_notices: the old plugin is still installed, and can go */
	public static function notice(): void
	{
		if(current_user_can('activate_plugins') === false || is_dir(self::oldDirectory()) === false)
		{
			return;
		}
		
		echo '<div class="notice notice-info"><p>'
			. esc_html__('ovos codesafe replaces the ovos console plugin: its settings were copied and it was deactivated. You can delete "ovos console" under Plugins. Constants named OVOS_CONSOLE_* in wp-config.php keep working; rename them to CODESAFE_* when convenient.', 'ovos-codesafe')
			. '</p></div>';
	}
	
	protected static function oldDirectory(): string
	{
		return rtrim(WP_PLUGIN_DIR, '/\\') . DIRECTORY_SEPARATOR . 'ovos-console';
	}
}
