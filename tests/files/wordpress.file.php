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

const DAY_IN_SECONDS = 86400;

function wp_shim_reset(): void
{
	$GLOBALS['wp_version'] = '6.8';
	$GLOBALS['wp'] = [
		// the Updater's GitHub API answer, and the transient it caches it in
		'api' => null,
		// wp_remote_get(): every [url, args] asked for
		'got' => [],
		// what wp_remote_get() answers anything but a signature: its status and headers
		'get_status' => 200,
		'get_headers' => [],
		'transient' => null,
		// every transient by name, beside the one above (the Updater's tests read that)
		'transients' => [],
		// multisite: whether this is a network, whether the current site is its main
		// one, the user's id (is_super_admin), and the main site's options
		'multisite' => false,
		'main_site' => true,
		'user_id' => 0,
		'main_options' => [],
		// .sig and zip downloads, by URL
		'sig_by_url' => [],
		'sig_status' => 200,
		'zip_by_url' => [],
		'downloaded' => [],
		// the Sender's settings
		'options' => [],
		// apply_filters() callbacks, by hook name
		'filters' => [],
		// add_filter() and add_action() calls in order: [hook, callback, priority] — recorded, never run
		'hooked' => [],
		// the accounts get_user_by() finds: login => [ID, email, capabilities]
		'users' => [],
		// the ids is_super_admin() answers true for
		'super_admins' => [],
		// the roles get_role() finds: name => [capability => granted]
		'roles' => [],
		// wp_remote_post(): every [url, args] posted, the status it answers (0 = unreachable) and its body
		'posted' => [],
		'post_status' => 202,
		'post_body' => '',
		// application passwords: switched on, in use on the network, the users they are
		// refused to, each user's by id, and a throw for a store that cannot be read
		'app_passwords_available' => true,
		'app_passwords_in_use' => true,
		'app_passwords_refused' => [],
		'app_passwords' => [],
		'app_passwords_throw' => false,
		// wp_verify_nonce(): the valid nonce per action; current_user_can(): the current user's capabilities
		'nonces' => [],
		'current_caps' => [],
		// the network's options while 'multisite' is on (a single site keeps them in 'options'),
		// the site transients by name, and what WordPress's updater says it may do
		'site_options' => [],
		'site_transients' => [],
		'file_mods' => true,
		'updater_disabled' => false,
		'vcs' => false,
		// did_action() by hook, wp_doing_cron(), is_admin(), and _get_cron_array(): timestamp => hook => events
		'did' => [],
		'doing_cron' => false,
		'admin' => false,
		'cron' => [],
	];
	// WordPress's own: whether the login cookie settled the current user (rest_cookie_collect_status())
	unset($GLOBALS['wp_rest_auth_cookie'], $GLOBALS['pagenow']);
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

class WP_User
{
	public function __construct(
		public int $ID = 0,
		public string $user_login = '',
		public string $user_email = '',
		/** the capabilities user_can() grants, by name */
		public array $caps = [],
	)
	{
	}
}

function get_user_by(
	string $field,
	string $value,
): WP_User|false
{
	foreach($GLOBALS['wp']['users'] as $login => [$id, $email, $caps])
	{
		if(($field === 'login' && $login === $value) || ($field === 'email' && $email === $value))
		{
			return new WP_User($id, $login, $email, $caps);
		}
	}
	
	return false;
}

function user_can(
	WP_User $user,
	string $capability,
): bool
{
	return in_array($capability, $user->caps, true);
}

class WP_Role
{
	public function __construct(
		public string $name = '',
		/** capability => granted, as core keeps a role's */
		public array $capabilities = [],
	)
	{
	}
	
	public function has_cap(
		string $cap,
	): bool
	{
		return empty($this->capabilities[$cap]) === false;
	}
}

function get_role(
	string $role,
): ?WP_Role
{
	$capabilities = $GLOBALS['wp']['roles'][$role] ?? null;
	
	return $capabilities === null ? null : new WP_Role($role, $capabilities);
}

function is_super_admin(
	int $userId = 0,
): bool
{
	return in_array($userId === 0 ? $GLOBALS['wp']['user_id'] : $userId, $GLOBALS['wp']['super_admins'], true);
}

function add_filter(
	mixed ...$arguments,
): void
{
	$GLOBALS['wp']['hooked'][] = [$arguments[0] ?? '', $arguments[1] ?? null, $arguments[2] ?? 10];
}

function add_action(
	mixed ...$arguments,
): void
{
	$GLOBALS['wp']['hooked'][] = [$arguments[0] ?? '', $arguments[1] ?? null, $arguments[2] ?? 10];
}

// whether anything was hooked by that name, as add_action() recorded it
function has_action(
	string $hook,
	mixed $callback = false,
): bool
{
	foreach($GLOBALS['wp']['hooked'] as [$name])
	{
		if($name === $hook)
		{
			return true;
		}
	}

	return false;
}

function did_action(
	string $hook,
): int
{
	return $GLOBALS['wp']['did'][$hook] ?? 0;
}

function wp_doing_cron(): bool
{
	return $GLOBALS['wp']['doing_cron'];
}

function is_admin(): bool
{
	return $GLOBALS['wp']['admin'];
}

function _get_cron_array(): array
{
	return $GLOBALS['wp']['cron'];
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
	return array_key_exists($key, $GLOBALS['wp']['transients'])
		? $GLOBALS['wp']['transients'][$key]
		: $GLOBALS['wp']['transient'];
}

function set_transient(
	string $key,
	mixed $value,
	int $ttl,
): bool
{
	$GLOBALS['wp']['transient'] = $value;
	$GLOBALS['wp']['transients'][$key] = $value;
	
	return true;
}

function delete_transient(
	string $key,
): bool
{
	unset($GLOBALS['wp']['transients'][$key]);
	
	return true;
}

function delete_option(
	string $name,
): bool
{
	unset($GLOBALS['wp']['options'][$name]);
	
	return true;
}

function is_multisite(): bool
{
	return $GLOBALS['wp']['multisite'];
}

function is_main_site(): bool
{
	return $GLOBALS['wp']['main_site'];
}

function get_main_site_id(): int
{
	return 1;
}

function get_blog_option(
	int $id,
	string $name,
	mixed $default = false,
): mixed
{
	return $GLOBALS['wp']['main_options'][$name] ?? $default;
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
	
	$GLOBALS['wp']['got'][] = [$url, $args];
	
	return ['code' => $GLOBALS['wp']['get_status'], 'headers' => $GLOBALS['wp']['get_headers'], 'body' => json_encode($GLOBALS['wp']['api'])];
}

function wp_remote_retrieve_headers(
	array $response,
): array
{
	return $response['headers'] ?? [];
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

function update_option(
	string $name,
	mixed $value,
	mixed $autoload = null,
): bool
{
	$GLOBALS['wp']['options'][$name] = $value;
	
	return true;
}

function wp_remote_post(
	string $url,
	array $args,
): mixed
{
	$GLOBALS['wp']['posted'][] = [$url, $args];
	
	return $GLOBALS['wp']['post_status'] === 0
		? new WP_Error('http_request_failed', 'unreachable')
		: ['code' => $GLOBALS['wp']['post_status'], 'body' => $GLOBALS['wp']['post_body']];
}

/** a bare `&` as an entity, as WordPress writes it */
function wp_kses_normalize_entities(
	string $content,
	string $context = 'html',
): string
{
	return (string)preg_replace('/&(?![A-Za-z][A-Za-z0-9]{1,31};|#[0-9]{1,7};|#x[0-9A-Fa-f]{1,6};)/', '&amp;', $content);
}

/** the post filter's two moves the tests lean on: a script taken out, a stray bracket written as an entity */
function wp_kses_post(
	mixed $data,
): string
{
	$data = (string)preg_replace('~<script\b[^>]*>.*?</script>~is', '', wp_kses_normalize_entities((string)$data));
	
	return (string)preg_replace(['~<(?![A-Za-z/])~', '~(?<=\s)>~'], ['&lt;', '&gt;'], $data);
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

// the real one's damage, restated: tags out, whitespace collapsed, and every
// percent-encoded octet REMOVED (wp-includes/formatting.php
// _sanitize_text_fields) — the reason the plugin reads its report URLs raw
function sanitize_text_field(
	string $value,
): string
{
	$value = trim((string)preg_replace('/[\r\n\t ]+/', ' ', strip_tags($value)));
	$found = false;
	while(preg_match('/%[a-f0-9]{2}/i', $value, $match) === 1)
	{
		$value = str_replace($match[0], '', $value);
		$found = true;
	}
	
	return $found ? trim((string)preg_replace('/ +/', ' ', $value)) : $value;
}

/** core's esc_url() with a protocol list: a scheme outside it empties the URL */
function esc_url_raw(
	string $url,
	?array $protocols = null,
): string
{
	return $protocols === null || in_array(strtolower((string)parse_url($url, PHP_URL_SCHEME)), $protocols, true) ? $url : '';
}

function wp_get_environment_type(): string
{
	return 'production';
}

/** 6.8's surface: the hash a test stores is a plain sha256 of the password */
class WP_Application_Passwords
{
	public static function is_in_use(): bool
	{
		return $GLOBALS['wp']['app_passwords_in_use'];
	}
	
	public static function get_user_application_passwords(
		int $userId,
	): array
	{
		if($GLOBALS['wp']['app_passwords_throw'])
		{
			throw new RuntimeException('the user meta cannot be read');
		}
		
		return $GLOBALS['wp']['app_passwords'][$userId] ?? [];
	}
	
	public static function check_password(
		string $password,
		string $hash,
	): bool
	{
		return hash_equals($hash, hash('sha256', $password));
	}
}

function wp_is_application_passwords_available(): bool
{
	return $GLOBALS['wp']['app_passwords_available'];
}

function wp_is_application_passwords_available_for_user(
	WP_User $user,
): bool
{
	return $GLOBALS['wp']['app_passwords_available'] && in_array($user->ID, $GLOBALS['wp']['app_passwords_refused'], true) === false;
}

function is_email(
	string $email,
): string|false
{
	return filter_var($email, FILTER_VALIDATE_EMAIL) === false ? false : $email;
}

function wp_verify_nonce(
	mixed $nonce,
	string|int $action = -1,
): int|false
{
	return is_string($nonce) && $nonce !== '' && ($GLOBALS['wp']['nonces'][$action] ?? null) === $nonce ? 1 : false;
}

function current_user_can(
	string $capability,
): bool
{
	return in_array($capability, $GLOBALS['wp']['current_caps'], true);
}

function rest_get_url_prefix(): string
{
	return apply_filters('rest_url_prefix', 'wp-json');
}

/** the site's name and the core version, the two the plugin reads */
function get_bloginfo(
	string $show = '',
): string
{
	return $show === 'version' ? (string)$GLOBALS['wp_version'] : 'Test site';
}

/** a site option: the network's on a multisite network, else the site's own option, as core keeps it */
function get_site_option(
	string $name,
	mixed $default = false,
): mixed
{
	return $GLOBALS['wp']['multisite']
		? ($GLOBALS['wp']['site_options'][$name] ?? $default)
		: ($GLOBALS['wp']['options'][$name] ?? $default);
}

function update_site_option(
	string $name,
	mixed $value,
): bool
{
	if($GLOBALS['wp']['multisite'])
	{
		$GLOBALS['wp']['site_options'][$name] = $value;
	}
	else
	{
		$GLOBALS['wp']['options'][$name] = $value;
	}
	
	return true;
}

/** a site option gone: the network's on a multisite network, else the site's */
function delete_site_option(
	string $name,
): bool
{
	if($GLOBALS['wp']['multisite'])
	{
		unset($GLOBALS['wp']['site_options'][$name]);
	}
	else
	{
		unset($GLOBALS['wp']['options'][$name]);
	}
	
	return true;
}

function get_site_transient(
	string $name,
): mixed
{
	return $GLOBALS['wp']['site_transients'][$name] ?? false;
}

/** DISALLOW_FILE_MODS, as core answers it */
function wp_is_file_mod_allowed(
	string $context,
): bool
{
	return (bool)apply_filters('file_mod_allowed', $GLOBALS['wp']['file_mods'], $context);
}

/** core's: the updater not disabled, then the type's own filter */
function wp_is_auto_update_enabled_for_type(
	string $type,
): bool
{
	$enabled = (new WP_Automatic_Updater())->is_disabled() === false;
	
	return match($type)
	{
		'plugin' => (bool)apply_filters('plugins_auto_update_enabled', $enabled),
		'theme' => (bool)apply_filters('themes_auto_update_enabled', $enabled),
		default => false,
	};
}

/** core's: the auto_update_{type} filter's verdict, null when no filter decides */
function wp_is_auto_update_forced_for_item(
	string $type,
	mixed $update,
	object $item,
): mixed
{
	return apply_filters('auto_update_' . $type, $update, $item);
}

/** the updater's two answers the plugin reads, from the shim's state */
class WP_Automatic_Updater
{
	public function is_disabled(): bool
	{
		return wp_is_file_mod_allowed('automatic_updater') === false
			|| (bool)apply_filters('automatic_updater_disabled', $GLOBALS['wp']['updater_disabled']);
	}
	
	public function is_vcs_checkout(
		string $context,
	): bool
	{
		return (bool)apply_filters('automatic_updates_is_vcs_checkout', $GLOBALS['wp']['vcs'], $context);
	}
}
