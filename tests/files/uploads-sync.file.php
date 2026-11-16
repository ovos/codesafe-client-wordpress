<?php
declare(strict_types=1);

/**
 * The plugin's init writer of the uploads directories in a process of its
 * own, where ABSPATH, WP_CONTENT_DIR and WP_PLUGIN_DIR can be defined
 * without reaching every other test. OVOS_UPLOADS_SYNC carries a JSON of
 * the store, the site root, the WordPress shims' state, UPLOADBLOGSDIR when
 * a test names one (`blogsdir`, a path below the site root) and the call:
 * `uploads` runs Adapter::syncUploads() and prints whether it wrote and the
 * consent's uploads after; `prepend` runs Adapter::syncPrepend() (php-cgi,
 * since it does nothing on the CLI) and prints the init callbacks it hooked.
 *
 * Under tests/files/, so the runner never takes it for a test.
 */

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Prepend;

spl_autoload_register(static function(string $class): void
{
	$file = dirname(__DIR__, 2) . '/src/' . str_replace('\\', '/', substr($class, 14)) . '.php';
	if(str_starts_with($class, 'Ovos\\Codesafe\\') && is_file($file))
	{
		require $file;
	}
});

require __DIR__ . '/wordpress.file.php';

$given = json_decode((string)getenv('OVOS_UPLOADS_SYNC'), true);
foreach($given['wp'] as $key => $value)
{
	$GLOBALS['wp'][$key] = $value;
}
define('ABSPATH', $given['root'] . '/');
define('WP_CONTENT_DIR', $given['root'] . '/wp-content');
define('WP_PLUGIN_DIR', $given['root'] . '/wp-content/plugins');
if(isset($given['blogsdir']))
{
	define('UPLOADBLOGSDIR', $given['blogsdir']);
}

if($given['call'] === 'prepend')
{
	Adapter::syncPrepend(new Config());
	$hooked = [];
	foreach($GLOBALS['wp']['hooked'] as [$hook, $callback])
	{
		if($hook === 'init' && is_array($callback))
		{
			$hooked[] = $callback[1];
		}
	}
	echo json_encode($hooked);
	
	return;
}

$wrote = Adapter::syncUploads($given['dir']);
echo json_encode([$wrote, Prepend::consent($given['dir'])['uploads'] ?? null, Adapter::consentOf(new Config())['plugins']]);
