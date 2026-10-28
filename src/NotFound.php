<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Throwable;

use function add_action;
use function add_filter;
use function function_exists;
use function get_transient;
use function has_action;
use function http_response_code;
use function is_404;
use function is_array;
use function is_int;
use function is_object;
use function is_scalar;
use function is_user_logged_in;
use function ltrim;
use function mb_substr;
use function method_exists;
use function preg_match;
use function rawurlencode;
use function rest_get_url_prefix;
use function set_transient;
use function str_starts_with;
use function strlen;
use function strtok;
use function strtolower;
use function trim;
use function wp_doing_ajax;
use function wp_unslash;

/**
 * Requests for what this site does not have, as not_found access events:
 * front-end pages WordPress resolved to a 404, REST routes the REST server
 * has no handler for, admin-ajax actions nothing handles. One budget of
 * MAX_PER_MINUTE serves the three: the rollups carry the full counts, these
 * rows are the samples.
 *
 * Neither REST nor admin-ajax reaches template_redirect — rest_api_loaded()
 * serves and dies at parse_request, admin-ajax.php never runs the template
 * loader — so each has its own hook:
 *
 * - REST: rest_pre_serve_request at priority 0. It fires once per served
 *   request with the main request's final result, before the response is
 *   echoed; rest_post_dispatch also fires for every _embed and batch
 *   sub-request. Priority 0, so a plugin that serves and exits in the same
 *   filter cannot lose the row.
 * - admin-ajax: WordPress's shutdown action. A miss ends in wp_die('0', 400)
 *   and die(); PHP then runs the shutdown functions in the order they were
 *   registered, and core registers shutdown_action_hook in wp-settings.php
 *   before any plugin loads, so the action runs before the Sender's flush.
 *   Only core's own refusal is a miss — status 400 with no handler for the
 *   action; a WAF's or the Shield's 403, or a handler's 200, is not.
 */
final class NotFound
{
	/** reports per 60 seconds, pages, REST and ajax together, so a hard scan cannot turn this reporter into the flood it surfaces */
	public const MAX_PER_MINUTE = 30;
	
	protected const RATE_KEY = 'ovos_codesafe_404_rate';
	
	/** the action in the row's message */
	public const ACTION_MAX = 64;
	
	/** the route or the action in the row's extra */
	public const EXTRA_MAX = 200;
	
	/** the REST server's answer for a path, or a method, it has no handler for */
	protected const REST_NO_ROUTE = 'rest_no_route';
	
	public function __construct(
		protected Config $config,
		protected Sender $sender,
	)
	{
	}
	
	public function register(): void
	{
		if($this->config->report404() === false)
		{
			return;
		}
		
		add_action('template_redirect', [$this, 'reportPage']);
		add_filter('rest_pre_serve_request', [$this, 'reportRest'], 0, 4);
		// no argument: do_action('shutdown') would hand the callback an empty string
		add_action('shutdown', [$this, 'reportAjax'], 10, 0);
	}
	
	/**
	 * template_redirect: a resolved front-end 404 is an access event. Skips
	 * static-asset paths (broken images and the like are noise) and rate-limits
	 * so a scan cannot flood; the queued report ships from the shutdown handler.
	 */
	public function reportPage(): void
	{
		if(is_404() === false || $this->isStaticAsset() || $this->throttled())
		{
			return;
		}
		
		$this->sender->capture404();
	}
	
	/**
	 * rest_pre_serve_request: a route the REST server has no handler for —
	 * an unknown path, or a known one asked with a method it does not serve
	 * — named under the site's REST prefix whatever spelling the request used
	 * (`/wp-json/…` or `?rest_route=`), so both are one group. Hands the
	 * filter's value back untouched
	 */
	public function reportRest(
		mixed $served,
		mixed $result = null,
		mixed $request = null,
		mixed $server = null,
	): mixed
	{
		try
		{
			if(is_object($result) === false || method_exists($result, 'get_status') === false || method_exists($result, 'get_data') === false
				|| is_object($request) === false || method_exists($request, 'get_route') === false)
			{
				return $served;
			}
			
			$namespaces = is_object($server) && method_exists($server, 'get_namespaces') ? (array)$server->get_namespaces() : [];
			$miss = self::restMiss((int)$result->get_status(), $result->get_data(), (string)$request->get_route(), $namespaces);
			
			if($miss === null || $this->throttled())
			{
				return $served;
			}
			
			$prefix = function_exists('rest_get_url_prefix') ? trim((string)rest_get_url_prefix(), '/') : 'wp-json';
			
			$this->sender->capture404('/' . $prefix . '/' . ltrim((string)$request->get_route(), '/'), ['miss' => 'rest'] + $miss);
		}
		catch(Throwable)
		{
			// never break the host site
		}
		
		return $served;
	}
	
	/**
	 * Whether a served REST answer is a miss: a 404 whose first error is
	 * rest_no_route (rest_convert_error_to_response() puts it in `code`).
	 * Any other 404 — rest_post_invalid_id and the like — is a route that
	 * exists answering for a resource, not a miss. A request with _envelope
	 * is answered 200 before this filter runs, the real status and body
	 * inside the data, and is read from there. The route as the extra
	 * carries it, and the registered namespace it falls under: empty says no
	 * such plugin here, a name says the plugin is here and that route is not
	 *
	 * @param list<string> $namespaces the REST server's registered namespaces
	 * @return ?array{route: string, namespace: string}
	 */
	public static function restMiss(
		int $status,
		mixed $data,
		string $route,
		array $namespaces,
	): ?array
	{
		if($status === 200 && is_array($data) && is_array($data['body'] ?? null) && ($data['status'] ?? 0) === 404)
		{
			$status = 404;
			$data = $data['body'];
		}
		
		if($status !== 404 || is_array($data) === false || ($data['code'] ?? '') !== self::REST_NO_ROUTE)
		{
			return null;
		}
		
		return ['route' => mb_substr($route, 0, self::EXTRA_MAX), 'namespace' => self::namespaceOf($route, $namespaces)];
	}
	
	/**
	 * The longest registered namespace a route falls under — the route is
	 * `/<namespace>` itself or starts with `/<namespace>/`, compared without
	 * case as the REST server matches routes; '' for none. Stricter than
	 * core's own prefix test, which lets `wp` take `/wp-site-health/…`
	 *
	 * @param list<string> $namespaces
	 */
	public static function namespaceOf(
		string $route,
		array $namespaces,
	): string
	{
		$route = strtolower($route);
		$best = '';
		
		foreach($namespaces as $namespace)
		{
			$namespace = (string)$namespace;
			$lower = strtolower($namespace);
			
			if($namespace === '' || strlen($namespace) <= strlen($best))
			{
				continue;
			}
			
			if($route === '/' . $lower || str_starts_with($route, '/' . $lower . '/'))
			{
				$best = $namespace;
			}
		}
		
		return $best;
	}
	
	/**
	 * WordPress's shutdown action: an admin-ajax action nothing handles for
	 * this caller, refused by core with 400. The row names the action in the
	 * one query parameter kept — the path alone would fold every unknown
	 * action into one group — and says whether the action exists for
	 * signed-in users only (`signed_in`: the plugin is here) or not at all
	 * (`none`). $status is the test's: WordPress hands no argument, or an
	 * empty string where the hook's argument count is lost — anything but an
	 * int reads the response's own status
	 */
	public function reportAjax(
		mixed $status = null,
	): void
	{
		try
		{
			// admin-ajax.php itself: a plugin's own file that defines DOING_AJAX is no admin-ajax request
			if(($GLOBALS['pagenow'] ?? '') !== 'admin-ajax.php' || function_exists('wp_doing_ajax') === false || wp_doing_ajax() === false)
			{
				return;
			}
			
			if((is_int($status) ? $status : http_response_code()) !== 400)
			{
				return;
			}
			
			$action = self::ajaxAction($_REQUEST);
			
			if($action === '')
			{
				return;
			}
			
			$handler = self::ajaxHandler($action, function_exists('is_user_logged_in') && is_user_logged_in());
			
			if($handler === null || $this->throttled())
			{
				return;
			}
			
			$this->sender->capture404('/wp-admin/admin-ajax.php?action=' . rawurlencode(mb_substr($action, 0, self::ACTION_MAX)),
				['miss' => 'ajax', 'action' => mb_substr($action, 0, self::EXTRA_MAX), 'handler' => $handler], true);
		}
		catch(Throwable)
		{
			// never break the host site
		}
	}
	
	/**
	 * The action as admin-ajax.php reads it: a scalar `action` that is not
	 * empty() — anything else core refuses before any plugin is asked, and
	 * names nothing; '' then
	 *
	 * @param array<string, mixed> $request $_REQUEST
	 */
	public static function ajaxAction(
		array $request,
	): string
	{
		$action = $request['action'] ?? null;
		
		return is_scalar($action) && (bool)$action ? (string)$action : '';
	}
	
	/**
	 * Who handles an action for this caller: null when a handler answers
	 * it (wp_ajax_<action> for a signed-in user, wp_ajax_nopriv_<action>
	 * for anyone else); `signed_in` when an anonymous caller asked for one
	 * that exists for signed-in users only; `none` when nothing handles it
	 */
	public static function ajaxHandler(
		string $action,
		bool $signedIn,
	): ?string
	{
		$private = has_action('wp_ajax_' . $action) !== false;
		
		if($signedIn)
		{
			return $private ? null : 'none';
		}
		
		if(has_action('wp_ajax_nopriv_' . $action) !== false)
		{
			return null;
		}
		
		return $private ? 'signed_in' : 'none';
	}
	
	/**
	 * Whether the current request targets a static asset (a broken image,
	 * stylesheet or script) rather than a page — those 404s are noise, not
	 * scanner signal
	 */
	protected function isStaticAsset(): bool
	{
		$uri = isset($_SERVER['REQUEST_URI'])
			? (string)wp_unslash($_SERVER['REQUEST_URI'])
			: '';
		$path = (string)strtok($uri, '?');
		
		return preg_match(
			'~\.(?:jpe?g|png|gif|webp|svg|ico|css|js|map|woff2?|ttf|eot)$~i',
			$path) === 1;
	}
	
	/**
	 * Fixed 60-second window cap on not-found reports (a transient counter),
	 * so a hard scan cannot turn this reporter into the flood it surfaces
	 */
	protected function throttled(): bool
	{
		$count = (int)get_transient(self::RATE_KEY);
		
		if($count >= self::MAX_PER_MINUTE)
		{
			return true;
		}
		
		set_transient(self::RATE_KEY, $count + 1, 60);
		
		return false;
	}
}
