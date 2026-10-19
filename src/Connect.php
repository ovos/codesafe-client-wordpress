<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function add_action;
use function add_query_arg;
use function admin_url;
use function array_filter;
use function base64_encode;
use function check_admin_referer;
use function current_user_can;
use function delete_transient;
use function esc_html__;
use function get_bloginfo;
use function get_current_user_id;
use function get_transient;
use function hash;
use function hash_equals;
use function home_url;
use function http_build_query;
use function in_array;
use function is_array;
use function is_bool;
use function is_string;
use function is_wp_error;
use function json_decode;
use function json_encode;
use function mb_substr;
use function parse_url;
use function preg_match;
use function random_bytes;
use function rawurlencode;
use function rtrim;
use function set_transient;
use function strtolower;
use function strtr;
use function trim;
use function update_option;
use function wp_die;
use function wp_redirect;
use function wp_remote_post;
use function wp_remote_retrieve_body;
use function wp_remote_retrieve_response_code;
use function wp_safe_redirect;
use function wp_specialchars_decode;
use function wp_unslash;

use const ENT_QUOTES;
use const PHP_QUERY_RFC3986;

/**
 * CONNECT: the keys arrive by themselves. The admin types the codesafe URL;
 * the site sends the browser to codesafe's #/connect with a state and a
 * PKCE challenge (RFC 7636, S256), an operator picks the project there, and
 * codesafe sends the browser back with a one-time code. The site trades the
 * code and the verifier — which never left its server — for the project's
 * keys in one server-to-server call, saves them and sends a test error.
 *
 * The browser only ever carries the code, useless without the verifier; the
 * state, bound to the WordPress user in a transient, stops a forged return.
 * Nothing is offered while wp-config.php defines the URL or the API key:
 * there the connection is the server's.
 */
class Connect
{
	/** the connect form posts here */
	public const ACTION_START = 'ovos_codesafe_connect_start';
	
	/** codesafe sends the browser back here */
	public const ACTION_RETURN = 'ovos_codesafe_connect';
	
	/** the pending connect of one WordPress user: the URL, the state, the verifier */
	public const TRANSIENT_PREFIX = 'ovos_codesafe_connect_';
	
	/** how long a started connect waits for codesafe's answer */
	protected const TTL = 600;
	
	public function __construct(
		protected Config $config,
		protected Sender $sender,
		protected Settings $settings,
	)
	{
	}
	
	public function register(): void
	{
		add_action('admin_post_' . self::ACTION_START, [$this, 'handleStart']);
		add_action('admin_post_' . self::ACTION_RETURN, [$this, 'handleReturn']);
	}
	
	/** whether the settings page offers CONNECT: not while the wp-config holds the connection */
	public function available(): bool
	{
		return $this->config->isConstant('url') === false && $this->config->isConstant('api_key') === false;
	}
	
	/**
	 * admin-post, from the connect form: the pending connect remembered for
	 * this user, the browser sent to codesafe
	 */
	public function handleStart(): void
	{
		if(current_user_can('manage_options') === false)
		{
			wp_die(esc_html__('Insufficient permissions.', 'ovos-codesafe'));
		}
		
		if($this->available() === false)
		{
			wp_die(esc_html__('The codesafe connection is set in wp-config.php (CODESAFE_URL / CODESAFE_API_KEY).', 'ovos-codesafe'));
		}
		
		check_admin_referer(self::ACTION_START);
		
		$url = self::url((string)wp_unslash($_POST['url'] ?? ''));
		if($url === '')
		{
			$this->back(['outcome' => 'url']);
		}
		
		$state = self::random(16);
		$verifier = self::random(32);
		set_transient(self::TRANSIENT_PREFIX . get_current_user_id(),
			['url' => $url, 'state' => $state, 'verifier' => $verifier], self::TTL);
		
		// codesafe is another host, which wp_safe_redirect() refuses
		wp_redirect(self::authorizeUrl(
			$url,
			home_url('/'),
			// stored with HTML entities, which codesafe would print as they are
			wp_specialchars_decode((string)get_bloginfo('name'), ENT_QUOTES),
			admin_url('admin-post.php?action=' . self::ACTION_RETURN),
			$state,
			self::challenge($verifier),
		));
		
		exit;
	}
	
	/**
	 * admin-post, codesafe's redirect back: the pending connect is used
	 * once, whatever the outcome — unless the return is not this user's,
	 * which leaves a connect in progress alone
	 */
	public function handleReturn(): void
	{
		if(current_user_can('manage_options') === false)
		{
			wp_die(esc_html__('Insufficient permissions.', 'ovos-codesafe'));
		}
		
		$key = self::TRANSIENT_PREFIX . get_current_user_id();
		$pending = get_transient($key);
		
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- the state is this flow's nonce, compared in finish()
		$query = [
			'state' => (string)wp_unslash($_GET['state'] ?? ''),
			'code' => (string)wp_unslash($_GET['code'] ?? ''),
			'error' => (string)wp_unslash($_GET['error'] ?? ''),
		];
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		
		$outcome = $this->finish(is_array($pending) ? $pending : null, $query);
		
		// a forged GET to this URL must not end the admin's connect in progress
		if($outcome['outcome'] !== 'state')
		{
			delete_transient($key);
		}
		
		$this->back($outcome);
	}
	
	/**
	 * The return judged: `state` when it is not the one this user started
	 * with, `cancelled` when the operator said no, `failed` when codesafe
	 * gave no keys, `done` with the project's name, whether reporting is on
	 * (a constant may keep it off) and the test error's HTTP status once the
	 * keys are saved
	 *
	 * @param array{url?: string, state?: string, verifier?: string}|null $pending
	 * @param array{state: string, code: string, error: string} $query
	 * @return array{outcome: string, project?: string, enabled?: bool, test?: int}
	 */
	public function finish(
		?array $pending,
		array $query,
	): array
	{
		if($pending === null || $query['state'] === '' || hash_equals((string)($pending['state'] ?? ''), $query['state']) === false)
		{
			return ['outcome' => 'state'];
		}
		
		if($query['error'] !== '' || $query['code'] === '')
		{
			return ['outcome' => 'cancelled'];
		}
		
		// the URL the admin typed, kept on this server — never one from the query
		$url = (string)($pending['url'] ?? '');
		$answer = $this->exchange($url, $query['code'], (string)($pending['verifier'] ?? ''));
		if($answer === null)
		{
			return ['outcome' => 'failed'];
		}
		
		$this->save($url, $answer['api_key'], $answer['js_key']);
		
		return [
			'outcome' => 'done',
			'project' => $answer['project'],
			'enabled' => $this->config->enabled(),
			'test' => $this->sender->isEnabled() ? $this->sender->sendTest() : -1,
		];
	}
	
	/**
	 * The server-to-server half: the code and the verifier for the project's
	 * keys — null for anything but a well-formed 200
	 *
	 * @return array{api_key: string, js_key: string, project: string}|null
	 */
	public function exchange(
		string $url,
		string $code,
		string $verifier,
	): ?array
	{
		$response = wp_remote_post($url . '/api/v1/connect/exchange', [
			'timeout' => 10,
			// the answer is codesafe's own, from the URL the admin typed
			'redirection' => 0,
			'headers' => ['Content-Type' => 'application/json'],
			'body' => (string)json_encode(['code' => $code, 'verifier' => $verifier]),
			'sslverify' => (bool)Legacy::filter('ovos_codesafe_sslverify', true),
		]);
		
		if(is_wp_error($response) || (int)wp_remote_retrieve_response_code($response) !== 200)
		{
			return null;
		}
		
		$answer = json_decode((string)wp_remote_retrieve_body($response), true);
		$apiKey = is_array($answer) && is_string($answer['api_key'] ?? null) ? $answer['api_key'] : '';
		$jsKey = is_array($answer) && is_string($answer['js_key'] ?? null) ? $answer['js_key'] : '';
		$project = is_array($answer) && is_string($answer['project']['name'] ?? null) ? $answer['project']['name'] : '';
		
		// a project without a JS key still connects its PHP side
		if(self::isKey($apiKey) === false || ($jsKey !== '' && self::isKey($jsKey) === false))
		{
			return null;
		}
		
		return ['api_key' => $apiKey, 'js_key' => $jsKey, 'project' => mb_substr($project, 0, 120)];
	}
	
	/**
	 * The URL as the connect needs it: http(s), a host, no credentials, query
	 * or fragment, no trailing slash — '' for anything else
	 */
	public static function url(
		string $typed,
	): string
	{
		$url = rtrim(trim($typed), '/');
		$parts = parse_url($url);
		
		if(is_array($parts) === false
			|| in_array(strtolower((string)($parts['scheme'] ?? '')), ['https', 'http'], true) === false
			|| (string)($parts['host'] ?? '') === ''
			|| isset($parts['user']) || isset($parts['query']) || isset($parts['fragment']))
		{
			return '';
		}
		
		return $url;
	}
	
	/**
	 * Where the browser goes: codesafe's #/connect, its parameters in the
	 * fragment, which no server logs
	 */
	public static function authorizeUrl(
		string $url,
		string $site,
		string $name,
		string $return,
		string $state,
		string $challenge,
	): string
	{
		return $url . '/#/connect?' . http_build_query([
			'site' => $site,
			'name' => $name,
			'return' => $return,
			'state' => $state,
			'challenge' => $challenge,
		], '', '&', PHP_QUERY_RFC3986);
	}
	
	/** RFC 7636 S256: base64url of the verifier's SHA-256 */
	public static function challenge(
		string $verifier,
	): string
	{
		return self::base64url(hash('sha256', $verifier, true));
	}
	
	/**
	 * URL, keys and the master switch, through the settings page's own
	 * sanitize: every other field keeps what the page shows, and a constant
	 * still wins
	 */
	protected function save(
		string $url,
		string $apiKey,
		string $jsKey,
	): void
	{
		$input = [];
		foreach(Config::DEFAULTS as $key => $default)
		{
			$value = $this->config->get($key);
			// a box shows (bool) of its value: a hand-patched 1 stays ticked
			$input[$key] = is_bool($default) ? (bool)$value : $value;
		}
		
		$fresh = ['url' => $url, 'api_key' => $apiKey, 'enabled' => true];
		// a project without a JS key keeps the one pasted here
		if($jsKey !== '')
		{
			$fresh['js_key'] = $jsKey;
		}
		
		update_option(Config::OPTION, $this->settings->sanitize($fresh + $input));
		
		// the Sender reads this Config: the test error goes out with the new keys
		$this->config->refresh();
	}
	
	/** the settings page, saying how the connect went */
	protected function back(
		array $outcome,
	): never
	{
		wp_safe_redirect(add_query_arg(array_filter([
			'ovos-codesafe-connect' => $outcome['outcome'],
			'ovos-codesafe-project' => isset($outcome['project']) ? rawurlencode($outcome['project']) : null,
			'ovos-codesafe-off' => ($outcome['enabled'] ?? true) === false ? '1' : null,
			'ovos-codesafe-test' => isset($outcome['test']) ? (string)$outcome['test'] : null,
		], static fn(?string $value): bool => $value !== null), admin_url('options-general.php?page=' . Settings::PAGE)));
		
		exit;
	}
	
	/** what codesafe mints: hex, and room for a longer alphabet */
	protected static function isKey(
		string $key,
	): bool
	{
		return preg_match('~^[A-Za-z0-9_-]{16,128}$~', $key) === 1;
	}
	
	protected static function random(
		int $bytes,
	): string
	{
		return self::base64url(random_bytes($bytes));
	}
	
	protected static function base64url(
		string $raw,
	): string
	{
		return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
	}
}
