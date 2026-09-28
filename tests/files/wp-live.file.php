<?php
declare(strict_types=1);

/**
 * The signed-update path on a REAL WordPress: its own download_url(), its
 * HTTP API, its transient store, a real GitHub API answer, a real .sig
 * fetch, a real WP_Error. Nothing shimmed.
 *
 *   OVOS_WP_PATH=/path/to/wordpress php tests/files/wp-live.file.php
 *
 * Needs a WordPress install with this plugin ACTIVE (a junction or symlink to
 * this checkout is the usual shape) and network access to github.com. The
 * install's home URL is read from the database, so nothing here is served —
 * WordPress is bootstrapped headless. Exit 1 on any failed claim.
 */
$root = rtrim((string)(getenv('OVOS_WP_PATH') ?: ($argv[1] ?? '')), '/\\');
if($root === '' || is_file($root . DIRECTORY_SEPARATOR . 'wp-load.php') === false)
{
	fwrite(STDERR, "usage: OVOS_WP_PATH=/path/to/wordpress php tests/files/wp-live.file.php\n");
	exit(2);
}
$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['REQUEST_URI'] = '/';
define('WP_USE_THEMES', false);
require $root . DIRECTORY_SEPARATOR . 'wp-load.php';
require_once ABSPATH . 'wp-admin/includes/file.php';

use Ovos\Codesafe\Plugin;
use Ovos\Codesafe\Updater;

$fails = 0;
$ok = static function(string $claim, bool $pass) use (&$fails): void
{
	printf("%s  %s\n", $pass ? 'ok  ' : 'FAIL', $claim);
	$fails += $pass ? 0 : 1;
};

printf("WordPress %s, PHP %s, ext/sodium %s, plugin %s\n\n",
	get_bloginfo('version'), PHP_VERSION, extension_loaded('sodium') ? 'loaded' : 'absent (sodium_compat)', Plugin::VERSION);

$file = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . 'ovos-codesafe' . DIRECTORY_SEPARATOR . 'ovos-codesafe.php';
$basename = plugin_basename($file);
$ok('the plugin is active on this site', is_plugin_active($basename));
$ok('the update check is hooked (update_plugins_github.com)', has_filter('update_plugins_github.com') !== false);
$ok('the download gate is hooked (upgrader_pre_download)', has_filter('upgrader_pre_download') !== false);

$updater = new Updater($file);
delete_transient('ovos_codesafe_latest_release');

// ---- the check, against the real GitHub API ---------------------------------
$asInstalled = $updater->check(false, ['Version' => Plugin::VERSION], $basename);
$ok('a site on the current version is offered nothing', $asInstalled === false);
delete_transient('ovos_codesafe_latest_release');
$asOlder = $updater->check(false, ['Version' => '0.1.0'], $basename);
$ok('a site on an older version is offered a release', is_array($asOlder) && version_compare((string)($asOlder['version'] ?? '0'), '0.1.0', '>'));
$ok('the offer names our own release asset', is_array($asOlder) && Updater::isOurs((string)($asOlder['package'] ?? '')));
$package = is_array($asOlder) ? (string)$asOlder['package'] : '';

// ---- the gate, for real: WordPress downloads, we verify ---------------------
$verified = $updater->download(false, $package, null, []);
$ok('the signed latest package downloads and VERIFIES through WordPress',
	is_string($verified) && is_file($verified) && filesize($verified) > 100000);
if(is_string($verified) && is_file($verified))
{
	@unlink($verified);
}
elseif(is_wp_error($verified))
{
	printf("  WP_Error %s: %s\n", $verified->get_error_code(), $verified->get_error_message());
}


$foreign = $updater->download(false, 'https://downloads.wordpress.org/plugin/hello-dolly.1.7.3.zip', null, []);
$ok('another plugin\'s package is left to WordPress untouched', $foreign === false);

$decided = $updater->download('/tmp/already.zip', $package, null, []);
$ok('an earlier filter\'s answer is respected', $decided === '/tmp/already.zip');

printf("\n%d failed\n", $fails);
exit($fails === 0 ? 0 : 1);
