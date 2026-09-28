<?php
declare(strict_types=1);

/**
 * The WordPress surface the plugin's tests drive it through, just enough.
 *
 * ONE file for every test class: these are global functions, a process
 * defines each once, and the harness runs every class in one process. What a
 * shim answers is read off $GLOBALS['wp'], which a test resets in prepare()
 * through wp_shim_reset().
 *
 * Under tests/files/, so the runner never takes it for a test.
 */

const HOUR_IN_SECONDS = 3600;

function wp_shim_reset(): void
{
	$GLOBALS['wp_version'] = '6.8';
	$GLOBALS['wp'] = [
		// the Updater's GitHub API answer, and the transient it caches it in
		'api' => null,
		'transient' => null,
		// .sig and zip downloads, by URL
		'sig_by_url' => [],
		'sig_status' => 200,
		'zip_by_url' => [],
		'downloaded' => [],
		// the Sender's settings
		'options' => [],
		// apply_filters() callbacks, by hook name
		'filters' => [],
	];
}

wp_shim_reset();

class WP_Error
{
	public function __construct(
		public string $code = '',
		public string $message = '',
	)
	{
	}
}

function add_filter(
	mixed ...$arguments,
): void
{
}

function __(
	string $text,
	string $domain = '',
): string
{
	return $text;
}

function plugin_basename(
	string $file,
): string
{
	return 'ovos-codesafe/ovos-codesafe.php';
}

function get_transient(
	string $key,
): mixed
{
	return $GLOBALS['wp']['transient'];
}

function set_transient(
	string $key,
	mixed $value,
	int $ttl,
): bool
{
	$GLOBALS['wp']['transient'] = $value;
	
	return true;
}

function is_wp_error(
	mixed $value,
): bool
{
	return $value instanceof WP_Error;
}

function wp_remote_retrieve_response_code(
	array $response,
): int
{
	return $response['code'];
}

function wp_remote_retrieve_body(
	array $response,
): string
{
	return $response['body'];
}

function wp_remote_get(
	string $url,
	array $args,
): mixed
{
	if(str_ends_with($url, '.sig'))
	{
		return array_key_exists($url, $GLOBALS['wp']['sig_by_url'])
			? ['code' => $GLOBALS['wp']['sig_status'], 'body' => $GLOBALS['wp']['sig_by_url'][$url]]
			: ['code' => 404, 'body' => 'Not Found'];
	}
	
	return ['code' => 200, 'body' => json_encode($GLOBALS['wp']['api'])];
}

function download_url(
	string $url,
): mixed
{
	if(array_key_exists($url, $GLOBALS['wp']['zip_by_url']) === false)
	{
		return new WP_Error('http_404', 'not found');
	}
	
	$path = tempnam(sys_get_temp_dir(), 'upd');
	file_put_contents($path, $GLOBALS['wp']['zip_by_url'][$url]);
	$GLOBALS['wp']['downloaded'][] = $path;
	
	return $path;
}

function get_option(
	string $name,
	mixed $default = false,
): mixed
{
	return $GLOBALS['wp']['options'][$name] ?? $default;
}

function add_option(
	string $name,
	mixed $value = '',
): bool
{
	if(array_key_exists($name, $GLOBALS['wp']['options']))
	{
		return false;
	}
	$GLOBALS['wp']['options'][$name] = $value;
	
	return true;
}

function apply_filters(
	string $name,
	mixed $value,
	mixed ...$arguments,
): mixed
{
	foreach($GLOBALS['wp']['filters'][$name] ?? [] as $callback)
	{
		$value = $callback($value, ...$arguments);
	}
	
	return $value;
}

function wp_unslash(
	mixed $value,
): mixed
{
	return is_array($value)
		? array_map('wp_unslash', $value)
		: (is_string($value) ? stripslashes($value) : $value);
}

// the real one also strips octets and collapses whitespace; for the plain
// header and URI strings of the fixtures, tags and trim are the difference
function sanitize_text_field(
	string $value,
): string
{
	return trim(strip_tags($value));
}

function wp_get_environment_type(): string
{
	return 'production';
}
