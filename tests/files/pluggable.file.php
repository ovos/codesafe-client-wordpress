<?php
declare(strict_types=1);

/**
 * The five pluggable functions WordPress's check of its login cookie runs,
 * declared as wp-includes/pluggable.php declares them, for
 * Tests\ShieldLoginCookie: the test copies this file to a fake site's
 * wp-includes/pluggable.php. wp_salt() answers for the logged_in scheme as
 * WordPress does: the sample's placeholder is no secret, and in the site's
 * language too when the salt was first asked for after the translations
 * loaded ($GLOBALS['salt_first'] 'late'), nor is a value two of the ten
 * constants share; the site options stand in. $GLOBALS['salt_diverges']
 * stands for whatever else makes WordPress's salt another than the one the
 * must-use stage reproduces.
 *
 * Under tests/files/, so the runner never takes it for a test.
 */
if(function_exists('wp_validate_auth_cookie') === false)
{
	function wp_validate_auth_cookie(
		mixed ...$arguments,
	): mixed
	{
		return false;
	}
}

if(function_exists('wp_parse_auth_cookie') === false)
{
	function wp_parse_auth_cookie(
		mixed ...$arguments,
	): mixed
	{
		return false;
	}
}

if(function_exists('get_user_by') === false)
{
	function get_user_by(
		mixed ...$arguments,
	): mixed
	{
		return false;
	}
}

if(function_exists('wp_hash') === false)
{
	function wp_hash(
		mixed ...$arguments,
	): mixed
	{
		return false;
	}
}

if(function_exists('wp_salt') === false)
{
	function wp_salt(
		string $scheme = 'auth',
	): string
	{
		$phrases = ['put your unique phrase here'];
		if(($GLOBALS['salt_first'] ?? 'late') === 'late')
		{
			$phrases[] = __('put your unique phrase here');
		}
		$values = [];
		foreach(['AUTH', 'SECURE_AUTH', 'LOGGED_IN', 'NONCE', 'SECRET'] as $first)
		{
			foreach(['KEY', 'SALT'] as $second)
			{
				if(defined($first . '_' . $second))
				{
					$values[] = constant($first . '_' . $second);
				}
			}
		}
		$counts = array_count_values($values);
		$secret = static fn(string $name): bool => defined($name) && (bool)constant($name) && in_array(constant($name), $phrases, true) === false
			&& $counts[constant($name)] === 1;
		$key = match(true)
		{
			$secret('LOGGED_IN_KEY') => constant('LOGGED_IN_KEY'),
			$secret('SECRET_KEY') => constant('SECRET_KEY'),
			default => get_site_option('logged_in_key'),
		};
		
		return $key . ($secret('LOGGED_IN_SALT') ? constant('LOGGED_IN_SALT') : get_site_option('logged_in_salt')) . ($GLOBALS['salt_diverges'] ?? '');
	}
}
