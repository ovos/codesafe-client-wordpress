<?php
declare(strict_types=1);

defined('WP_UNINSTALL_PLUGIN') || exit;

if(PHP_VERSION_ID < 80300)
{
	return;
}

// WordPress includes this file alone, never the plugin's main file: the
// plugin's classes load the way ovos-codesafe.php loads them
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

// every option and transient on every site, and the store with the visitors'
// addresses in its queues (security audit 2026-10-03 M16); a stub PHP still
// prepends stays, doing nothing, until the auto_prepend_file line is removed
Ovos\Codesafe\Lifecycle::uninstall();
