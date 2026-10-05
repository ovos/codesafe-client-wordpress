<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use WP_Error;
use WP_User;

use function implode;
use function in_array;
use function is_array;
use function is_object;
use function is_scalar;
use function max;
use function md5;
use function method_exists;
use function str_contains;
use function strtolower;

/**
 * Security-event hooks — reports what WordPress REFUSED, beside what broke,
 * as type=security events (see Sender::reportRefusal). Unlike the console's
 * PHP-library senders, where placing the reportRefusal() call is itself the
 * developer's opt-in, this plugin places every hook — so the whole layer is
 * gated by the security_events setting and none of these callbacks are even
 * registered while it is off.
 *
 * Failed logins funnel through wp_login_failed regardless of the door
 * (wp-login form, XML-RPC, REST basic auth); rejected nonce checks are the
 * CSRF signal; forbidden REST calls surface permission probing; and the
 * privileged_action family records the changes an attacker makes AFTER
 * getting in (role grants, plugin installs, signup/URL option flips, file
 * editor saves, admin application passwords) — routine for an admin, an
 * audit trail during an incident.
 *
 * The one SUCCESS this class reports is auth_success: a login that worked
 * AFTER recent failures for the same account or from the same address —
 * the credential-stuffing success, the only login that matters. Failures
 * are counted in short-lived transients; a clean login reports nothing,
 * because reporting every login would be volume and surveillance, not
 * security.
 */
class Security
{
	/**
	 * Options whose change is a classic post-compromise move — new admins
	 * via open signup, redirected site URLs, hijacked recovery e-mail
	 */
	protected const SENSITIVE_OPTIONS = [
		'users_can_register',
		'default_role',
		'admin_email',
		'siteurl',
		'home',
	];
	
	/**
	 * How long a failed login stays on the books for the success-after-
	 * failures signal — long enough to span a slow spray, short enough
	 * that this morning's typo is forgotten by lunch
	 */
	protected const FAILURE_WINDOW = 900;
	
	/**
	 * The priority a failed login on an ADMINISTRATOR account is reported at:
	 * WARNING, where every other refusal stays at codesafe's default for the
	 * kind (INFO). An admin's wrong password is the one worth an issue and an
	 * alert — the account an intruder wants, and one that is rarely mistyped
	 * twice (codesafe docs/plans/sender-security-priority.md)
	 */
	protected const ADMIN_FAILURE_PRIORITY = 4;
	
	public function __construct(
		protected Sender $sender,
	)
	{
	}
	
	public function register(): void
	{
		add_action('wp_login_failed', [$this, 'reportLoginFailed'], 10, 2);
		add_action('wp_login', [$this, 'reportLoginAfterFailures'], 10, 2);
		add_action('application_password_failed_authentication', [$this, 'reportAppPasswordFailed']);
		add_action('check_admin_referer', [$this, 'reportNonceFailure'], 10, 2);
		add_action('check_ajax_referer', [$this, 'reportNonceFailure'], 10, 2);
		add_filter('rest_request_after_callbacks', [$this, 'inspectRestResponse'], 10, 3);
		add_action('set_user_role', [$this, 'reportRoleChange'], 10, 3);
		add_action('activated_plugin', [$this, 'reportPluginActivated']);
		add_action('upgrader_process_complete', [$this, 'reportUpgrade'], 10, 2);
		add_action('updated_option', [$this, 'reportOptionChange']);
		// priority 0: observe the save attempt before core's handler wp_dies
		add_action('wp_ajax_edit-theme-plugin-file', [$this, 'reportFileEditorSave'], 0);
		add_action('wp_create_application_password', [$this, 'reportApplicationPassword'], 10, 2);
	}
	
	/**
	 * wp_login_failed — every failed credential presentation passes here,
	 * whatever the door (wp-login, XML-RPC, REST basic auth). The username
	 * is masked in the line — a name in prose is the one identity codesafe
	 * cannot recognise, so it would be stored in clear — and an e-mail typed
	 * as the name travels as written, for codesafe to mask and keep
	 * (Redactor::proseName()); the WP_Error CODES (invalid_username,
	 * incorrect_password) say why without quoting core's HTML error messages.
	 *
	 * When the name belongs to an account, the account travels as
	 * context.userId — codesafe groups a security event by kind and account,
	 * so each account's failures are one issue, and many accounts refused at
	 * once can be counted as many. A name no account carries stays nameless.
	 * An administrator's failure is raised to WARNING.
	 */
	public function reportLoginFailed(
		$username,
		$error = null,
	): void
	{
		$username = is_scalar($username) ? (string)$username : '';
		$message = 'login failed for ' . Redactor::proseName($username);
		
		if($error instanceof WP_Error && $error->get_error_codes() !== [])
		{
			$message .= ': ' . implode(', ', $error->get_error_codes());
		}
		
		// remember the failure for the success-after-failures signal — per
		// account and per address, so both a targeted account and a spray
		// from one machine are seen
		$this->countFailure('user', $username);
		$this->countFailure('ip', $this->clientIp());
		
		$account = $this->account($username);
		
		$this->sender->reportRefusal('auth_failure', $message, [],
			$account === null ? [] : ['userId' => (string)$account->ID],
			$account !== null && $this->isAdministrator($account) ? self::ADMIN_FAILURE_PRIORITY : null);
	}
	
	/**
	 * The account a presentation named — by login, or by e-mail, the other
	 * name wp-login accepts; null for a name no account carries
	 */
	protected function account(
		string $username,
	): ?WP_User
	{
		if($username === '')
		{
			return null;
		}
		
		$user = get_user_by('login', $username);
		if($user instanceof WP_User === false && str_contains($username, '@'))
		{
			$user = get_user_by('email', $username);
		}
		
		return $user instanceof WP_User && (int)$user->ID > 0 ? $user : null;
	}
	
	/**
	 * Whether the account runs the site — manage_options, or a multisite
	 * super admin, who holds it on every site of the network
	 */
	protected function isAdministrator(
		WP_User $user,
	): bool
	{
		return user_can($user, 'manage_options') || is_super_admin((int)$user->ID);
	}
	
	/**
	 * wp_login — the credential-stuffing SUCCESS: the failures each fired
	 * auth_failure, but the one presentation that WORKED is the only one
	 * that matters, and it is silent by default. Reported ONLY when recent
	 * failures preceded it (same account or same address, FAILURE_WINDOW);
	 * a clean login reports nothing — that would be surveillance, not
	 * security. The counters clear on report so one success reports once.
	 */
	public function reportLoginAfterFailures(
		$login,
		$user = null,
	): void
	{
		$login = is_scalar($login) ? (string)$login : '';
		
		$account = $this->failures('user', $login);
		$address = $this->failures('ip', $this->clientIp());
		
		if($account === 0 && $address === 0)
		{
			return;
		}
		
		$this->clearFailures('user', $login);
		$this->clearFailures('ip', $this->clientIp());
		
		// extra.failures is the EVIDENCE the console's rules ask about
		// ("failures >= 3"): the larger of the two counts, since either a
		// sprayed account or a hammering address is the stuffing signal.
		// context.userId names the ACCOUNT — wp_login fires before the current
		// user is set, so the flush's get_current_user_id() is 0 here; the
		// console groups a security event by kind and account, never by the
		// masked line, so the id is what makes one account's logins one issue
		$this->sender->reportRefusal('auth_success',
			'login succeeded for ' . Redactor::proseName($login)
			. ' after recent failures (account: ' . $account
			. ', address: ' . $address . ')',
			['failures' => max($account, $address)],
			$user instanceof WP_User && (int)$user->ID > 0 ? ['userId' => (string)$user->ID] : []);
	}
	
	/**
	 * A rejected application password — the API-access door, separate from
	 * interactive logins
	 */
	public function reportAppPasswordFailed(
		$error = null,
	): void
	{
		$message = 'application password rejected';
		
		if($error instanceof WP_Error && $error->get_error_codes() !== [])
		{
			$message .= ': ' . implode(', ', $error->get_error_codes());
		}
		
		$this->sender->reportRefusal('auth_failure', $message);
	}
	
	/**
	 * check_admin_referer / check_ajax_referer fire their action on every
	 * check — $result is false only when the nonce was missing or invalid,
	 * which is the CSRF (or expired-session replay) signal
	 */
	public function reportNonceFailure(
		$action,
		$result = null,
	): void
	{
		if($result !== false)
		{
			return;
		}
		
		$this->sender->reportRefusal('csrf_reject',
			'nonce check failed for action '
			. (is_scalar($action) ? (string)$action : '?'));
	}
	
	/**
	 * rest_request_after_callbacks (filter — the response passes through
	 * untouched): a WP_Error answered 401/403 is a permission refusal, the
	 * signal of REST probing (user enumeration, capability testing)
	 */
	public function inspectRestResponse(
		$response,
		$handler = null,
		$request = null,
	)
	{
		if($response instanceof WP_Error)
		{
			$data = $response->get_error_data();
			$status = is_array($data) ? (int)($data['status'] ?? 0) : 0;
			
			if($status === 401 || $status === 403)
			{
				$route = is_object($request) && method_exists($request, 'get_route')
					? (string)$request->get_route()
					: '';
					
				$this->sender->reportRefusal('permission_denied',
					'REST request refused (' . $status . '): '
					. (string)$response->get_error_code()
					. ($route !== '' ? ' on ' . $route : ''));
			}
		}
		
		return $response;
	}
	
	/**
	 * set_user_role — a role grant is the classic post-compromise move;
	 * user id and role names only, never the account's identity. WP core
	 * fires this for NEW users too (wp_insert_user always calls set_role),
	 * so a born-admin account is seen here — the message says created vs
	 * changed so the operator reads which move it was.
	 */
	public function reportRoleChange(
		$userId,
		$role = '',
		$oldRoles = [],
	): void
	{
		$oldRoles = (array)$oldRoles;
		$role = is_scalar($role) ? (string)$role : '?';
		
		// extra.action names the sub-kind for the console's rules ("action = X")
		$action = $oldRoles === []
			? ($role === 'administrator' ? 'admin_created' : 'user_created')
			: 'role_change';
		
		$this->sender->reportRefusal('privileged_action', $oldRoles === []
			? 'user created: #' . (int)$userId . ' as ' . $role
			: 'user role changed: #' . (int)$userId
				. ' ' . implode(',', $oldRoles) . ' -> ' . $role,
			['action' => $action]);
	}
	
	/**
	 * wp_ajax_edit-theme-plugin-file at priority 0 — a save from the theme
	 * or plugin FILE EDITOR, observed before core's handler runs (and
	 * wp_dies). The webshell-by-editor move: legitimate on almost no
	 * production site, and even a refused attempt is worth the line. The
	 * file name is the signal; the content is deliberately not touched.
	 */
	public function reportFileEditorSave(): void
	{
		// phpcs:disable WordPress.Security.NonceVerification -- observation only, before core's own nonce check; nothing here mutates state
		$file = isset($_POST['file'])
			? sanitize_text_field(wp_unslash((string)$_POST['file']))
			: '?';
		$container = isset($_POST['theme']) ? 'theme' : 'plugin';
		// phpcs:enable WordPress.Security.NonceVerification
		
		$this->sender->reportRefusal('privileged_action',
			'file editor save: ' . $container . ' ' . $file,
			['action' => 'file_edit']);
	}
	
	/**
	 * wp_create_application_password — persistent API access is what an
	 * intruder mints for durability. Reported for ADMIN accounts only:
	 * an app password for a shop's order-sync user is routine, one for
	 * the administrator is the incident line.
	 */
	public function reportApplicationPassword(
		$userId,
		$item = [],
	): void
	{
		$userId = (int)$userId;
		
		if(user_can($userId, 'manage_options') === false)
		{
			return;
		}
		
		$name = is_array($item) && is_scalar($item['name'] ?? null)
			? (string)$item['name']
			: '?';
		
		$this->sender->reportRefusal('privileged_action',
			'application password created for admin #' . $userId . ': ' . $name,
			['action' => 'app_password']);
	}
	
	public function reportPluginActivated(
		$plugin = '',
	): void
	{
		$this->sender->reportRefusal('privileged_action',
			'plugin activated: ' . (is_scalar($plugin) ? (string)$plugin : '?'),
			['action' => 'plugin_activated']);
	}
	
	/**
	 * upgrader_process_complete — plugin/theme/core installs and updates
	 * (a webshell often arrives AS a plugin upload); routine translation
	 * downloads are skipped
	 */
	public function reportUpgrade(
		$upgrader = null,
		$extra = [],
	): void
	{
		if(is_array($extra) === false)
		{
			return;
		}
		
		$type = is_scalar($extra['type'] ?? null) ? (string)$extra['type'] : '';
		$action = is_scalar($extra['action'] ?? null) ? (string)$extra['action'] : '';
		
		if(in_array($type, ['plugin', 'theme', 'core'], true) === false)
		{
			return;
		}
		
		$this->sender->reportRefusal('privileged_action',
			'upgrader: ' . ($action !== '' ? $action : '?') . ' ' . $type,
			['action' => 'upgrade_' . $type]);
	}
	
	/**
	 * updated_option fires only on an actual change; the values are
	 * deliberately not reported (admin_email is an address, siteurl may
	 * embed credentials) — the fact of the change is the signal
	 */
	public function reportOptionChange(
		$option = '',
	): void
	{
		if(in_array($option, self::SENSITIVE_OPTIONS, true) === false)
		{
			return;
		}
		
		$this->sender->reportRefusal('privileged_action',
			'option changed: ' . (string)$option,
			['action' => 'option_change']);
	}
	
	/**
	 * One failure remembered — a transient per subject (account or address)
	 * whose whole value is a count. Each failure refreshes the window: the
	 * signal is "failures RECENTLY", not "failures since exactly the first"
	 */
	protected function countFailure(
		string $scope,
		string $subject,
	): void
	{
		if($subject === '')
		{
			return;
		}
		
		$key = $this->failureKey($scope, $subject);
		
		set_transient($key, (int)get_transient($key) + 1, self::FAILURE_WINDOW);
	}
	
	protected function failures(
		string $scope,
		string $subject,
	): int
	{
		return $subject === ''
			? 0
			: (int)get_transient($this->failureKey($scope, $subject));
	}
	
	protected function clearFailures(
		string $scope,
		string $subject,
	): void
	{
		if($subject !== '')
		{
			delete_transient($this->failureKey($scope, $subject));
		}
	}
	
	/**
	 * The transient key never carries the subject itself — a username in
	 * an options-table key would be stored in the clear
	 */
	protected function failureKey(
		string $scope,
		string $subject,
	): string
	{
		return 'ovos_codesafe_authfail_' . $scope . '_' . md5(strtolower($subject));
	}
	
	/** the visitor's address by the Sender's one rule — a trusted proxy's header only when the site named one */
	protected function clientIp(): string
	{
		return $this->sender->clientIp();
	}
}
