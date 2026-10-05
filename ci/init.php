<?php
declare(strict_types=1);

namespace Ovos;

/**
 * Bootstrap initialization for the test application
 *
 * @author Marcin Gil <mg@ovos.at>
 */

use function date_default_timezone_get;
use function date_default_timezone_set;
use function is_file;
use function spl_autoload_register;
use function str_replace;
use function str_starts_with;
use function substr;

use const DIRECTORY_SEPARATOR;

if(date_default_timezone_get() === '')
{
	date_default_timezone_set('Europe/Vienna');
}

/**
 * The plugin's own classes, resolved the way ovos-codesafe.php resolves them.
 * Composer prepends its loader, so a name php-library also carries (the
 * vendored Shield kernel) reaches this one only because composer.json
 * excludes php-library's copy from the authoritative classmap — the
 * Tests\Shield pin says which file was loaded
 */
spl_autoload_register(static function(string $class): void
{
	if(str_starts_with($class, 'Ovos\\Codesafe\\') === false)
	{
		return;
	}
	
	$file = BASE_DIR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . str_replace('\\', DIRECTORY_SEPARATOR, substr($class, 14)) . '.php';
	
	if(is_file($file))
	{
		require $file;
	}
});

/**
 * Composer autoloader
 */
require_once BASE_DIR . 'vendor/autoload.php';
