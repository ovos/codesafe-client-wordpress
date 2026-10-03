<?php
declare(strict_types=1);
/**
 * Plugin Name: ovos codesafe
 * Description: Connects this site to an ovos codesafe instance — PHP and browser JavaScript errors, with grouping, alerting and issue lifecycle handled by the console.
 * Version: 1.0.3
 * Requires at least: 6.0
 * Requires PHP: 8.3
 * Author: ovos media gmbh
 * Author URI: https://www.ovos.at
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: ovos-codesafe
 * Update URI: https://github.com/ovos/codesafe-client-wordpress
 */

// this bootstrap file stays parseable on old PHP on purpose: the
// Requires PHP header stops activation, this guard stops execution
// if the plugin ended up active regardless
defined('ABSPATH') || exit;

if(PHP_VERSION_ID < 80300)
{
	return;
}

spl_autoload_register(static function ($class) {
	if(strpos($class, 'Ovos\\Codesafe\\') !== 0)
	{
		return;
	}
	
	$file = __DIR__ . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, substr($class, 14)) . '.php';
	
	if(is_file($file))
	{
		require $file;
	}
});

Ovos\Codesafe\Plugin::boot(__FILE__);

// the prepend layer runs whether or not the plugin does: deactivating switches
// it off through its consent file (security audit 2026-10-03 M16)
register_deactivation_hook(__FILE__, [Ovos\Codesafe\Lifecycle::class, 'deactivate']);

if(function_exists('ovos_codesafe') === false)
{
	/**
	 * Manual captures from theme or plugin code:
	 *
	 *   ovos_codesafe()->captureException($e, ['orderId' => 7]);
	 *   ovos_codesafe()->captureMessage('checkout step skipped', 4);
	 *
	 * @return Ovos\Codesafe\Sender|null
	 */
	function ovos_codesafe()
	{
		$plugin = Ovos\Codesafe\Plugin::instance();
		
		return $plugin !== null ? $plugin->sender : null;
	}
}

if(function_exists('ovos_console') === false)
{
	/**
	 * The helper under the plugin's first name, for theme and plugin code
	 * written against ovos-console
	 *
	 * @return Ovos\Codesafe\Sender|null
	 */
	function ovos_console()
	{
		return ovos_codesafe();
	}
}
