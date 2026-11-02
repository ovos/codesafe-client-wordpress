<?php
declare(strict_types=1);

/**
 * WordPress at init for Tests\ShieldLoginCookie: a fake site (argv 1) whose
 * wp-includes/pluggable.php the test wrote, wp-config's salts and the
 * translation as the variant (argv 2) sets them, then the adapter's word on
 * the login cookie, printed in brackets: the cookie's name, or nothing.
 *
 *   core            unique salts in English
 *   localized-late  LOGGED_IN_KEY the localized sample's placeholder, the salt first asked for after the translations
 *   localized-early the same, the salt first asked for before them
 *   secret-early    no LOGGED_IN_KEY, SECRET_KEY the localized placeholder, the salt first asked for before the translations
 *   secret-shared   the same beside a LOGGED_IN_KEY that AUTH_KEY shares, so no secret
 *   secret-unread   SECRET_KEY the localized placeholder beside a LOGGED_IN_KEY of its own
 *   english         LOGGED_IN_SALT the English placeholder
 *   english-localized the same on a site in another language
 *   diverged        WordPress's salt another than the one the must-use stage reproduces, for any other reason
 *   salt, session   a filter on the salt or on the session store
 *   replaced        a plugin's own wp_validate_auth_cookie()
 *   unnamed         no LOGGED_IN_COOKIE
 *
 * Under tests/files/, so the runner never takes it for a test.
 */
[, $site, $variant] = $argv;
$translated = 'hier einen eindeutigen Begriff eingeben';
$constants = match($variant)
{
	'localized-late', 'localized-early' => ['LOGGED_IN_KEY' => $translated, 'LOGGED_IN_SALT' => 'salt-Rf4&Tg5*Yh6'],
	'secret-early' => ['SECRET_KEY' => $translated, 'LOGGED_IN_SALT' => 'salt-Rf4&Tg5*Yh6'],
	'secret-shared' => ['LOGGED_IN_KEY' => 'dup-Zx9!Cv8#Bn7', 'AUTH_KEY' => 'dup-Zx9!Cv8#Bn7', 'SECRET_KEY' => $translated, 'LOGGED_IN_SALT' => 'salt-Rf4&Tg5*Yh6'],
	'secret-unread' => ['LOGGED_IN_KEY' => 'key-Qa1!Ws2#Ed3', 'SECRET_KEY' => $translated, 'LOGGED_IN_SALT' => 'salt-Rf4&Tg5*Yh6'],
	'english', 'english-localized' => ['LOGGED_IN_KEY' => 'key-Qa1!Ws2#Ed3', 'LOGGED_IN_SALT' => 'put your unique phrase here'],
	default => ['LOGGED_IN_KEY' => 'key-Qa1!Ws2#Ed3', 'LOGGED_IN_SALT' => 'salt-Rf4&Tg5*Yh6'],
};
foreach($constants as $name => $value)
{
	define($name, $value);
}
$GLOBALS['salt_first'] = in_array($variant, ['localized-early', 'secret-early', 'secret-shared'], true) ? 'early' : 'late';
$GLOBALS['localized'] = str_starts_with($variant, 'localized') || str_starts_with($variant, 'secret') || $variant === 'english-localized';
$GLOBALS['variant'] = $variant;
$GLOBALS['salt_diverges'] = $variant === 'diverged' ? '-elsewhere' : '';
define('ABSPATH', $site . DIRECTORY_SEPARATOR);
define('WPINC', 'wp-includes');
if($variant !== 'unnamed')
{
	define('LOGGED_IN_COOKIE', 'wordpress_logged_in_0123');
}

function has_filter(
	string $hook,
	mixed $callback = false,
): bool
{
	return ($GLOBALS['variant'] === 'salt' && $hook === 'salt') || ($GLOBALS['variant'] === 'session' && $hook === 'session_token_manager');
}

// at init the default text domain is loaded: a localized site answers the sample's phrase in its language
function __(
	string $text,
	string $domain = 'default',
): string
{
	return $GLOBALS['localized'] && $text === 'put your unique phrase here' ? 'hier einen eindeutigen Begriff eingeben' : $text;
}

function get_site_option(
	string $name,
	mixed $default = false,
): mixed
{
	return ['logged_in_key' => 'option-Uj7@Ik8', 'logged_in_salt' => 'option-Ol9(Pm0'][$name] ?? $default;
}

if($variant === 'replaced')
{
	function wp_validate_auth_cookie(
		string $cookie = '',
		string $scheme = '',
	): int|false
	{
		return 1;
	}
}
require ABSPATH . WPINC . '/pluggable.php';
$shield = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR;
require $shield . 'Prepend.php';
require $shield . 'Adapter.php';
echo '[', Ovos\Codesafe\Shield\Adapter::loginCookie(), ']';
