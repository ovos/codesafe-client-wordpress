<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\NotFound as PluginNotFound;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;
use WP_REST_Request;
use WP_REST_Response;

use function add_action;
use function array_column;
use function count;
use function rest_get_server;
use function str_contains;
use function str_repeat;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * Requests for what the site does not have, without WordPress: a REST route
 * the server has no handler for, read off rest_pre_serve_request's own
 * arguments; an admin-ajax action nothing handles, read at shutdown; a page
 * WordPress resolved to a 404. Each a not_found row queued on the Sender, the
 * three under one budget, nothing hooked with the switch off.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class NotFound extends Test
{
	/** the REST server's answer for a route it has no handler for, as rest_convert_error_to_response() builds it */
	protected const array NO_ROUTE = ['code' => 'rest_no_route', 'message' => 'No route was found matching the URL and request method.', 'data' => ['status' => 404]];
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		$_REQUEST = [];
	}
	
	#[Internal]
	public function finalize(): void
	{
		wp_shim_reset();
		$_REQUEST = [];
	}
	
	/**
	 * RULE: a REST answer of rest_no_route is one not_found row named under
	 * the site's REST prefix, its extra naming the route and the registered
	 * namespace it falls under — none when the route only shares a prefix
	 * with one; another 404 of a route that exists, or a 200, is no row; the
	 * filter's value goes back as it came. A miss asked with _envelope,
	 * answered 200 with the 404 inside, is the same row. Falsify: drop the
	 * code test — the invalid-id 404 queues; test the namespace without its
	 * slash — `/foo/v1x/bar` names foo/v1; read the envelope's outer status
	 * alone — its miss is lost.
	 */
	public function aRestMissIsARowNamingTheRouteUnderThePrefix(): bool
	{
		$sender = $this->sender();
		$found = new PluginNotFound(new Config, $sender);
		$GLOBALS['wp']['rest_namespaces'] = ['wp/v2', 'foo/v1'];
		$served = $found->reportRest(false, new WP_REST_Response(self::NO_ROUTE, 404), new WP_REST_Request('GET', '/foo/v1/bar'), rest_get_server());
		$GLOBALS['wp']['rest_namespaces'] = ['wp/v2'];
		$this->restMiss($found, '/foo/v1/bar');
		$GLOBALS['wp']['rest_namespaces'] = ['foo/v1'];
		$this->restMiss($found, '/foo/v1x/bar');
		$invalid = $found->reportRest(true, new WP_REST_Response(['code' => 'rest_post_invalid_id', 'data' => ['status' => 404]], 404), new WP_REST_Request('GET', '/wp/v2/posts/99'), rest_get_server());
		$found->reportRest(false, new WP_REST_Response(['id' => 1], 200), new WP_REST_Request('GET', '/foo/v1/bar'), rest_get_server());
		$GLOBALS['wp']['filters']['rest_url_prefix'] = [static fn(): string => 'api'];
		$this->restMiss($found, '/foo/v1/bar');
		$GLOBALS['wp']['filters'] = [];
		// ?_envelope: the answer is a 200 whose data carries the real status and body
		$found->reportRest(false, new WP_REST_Response(['body' => self::NO_ROUTE, 'status' => 404, 'headers' => []], 200), new WP_REST_Request('GET', '/foo/v1/env'), rest_get_server());
		$found->reportRest(false, new WP_REST_Response(['body' => ['id' => 1], 'status' => 200, 'headers' => []], 200), new WP_REST_Request('GET', '/foo/v1/env'), rest_get_server());
		// the envelope's own status decides, not the code its body carries
		$found->reportRest(false, new WP_REST_Response(['body' => self::NO_ROUTE, 'status' => 200, 'headers' => []], 200), new WP_REST_Request('GET', '/foo/v1/env'), rest_get_server());
		$found->reportRest(false, new WP_REST_Response(['body' => ['code' => 'rest_post_invalid_id'], 'status' => 404, 'headers' => []], 200), new WP_REST_Request('GET', '/wp/v2/posts/9'), rest_get_server());
		$rows = $sender->queued();
		
		return $served === false
			&& $invalid === true
			&& count($rows) === 5
			&& $rows[0]['kind'] === 'not_found'
			&& $rows[0]['message'] === '404 Not Found: /wp-json/foo/v1/bar'
			&& $rows[0]['extra'] === ['miss' => 'rest', 'route' => '/foo/v1/bar', 'namespace' => 'foo/v1']
			&& $rows[1]['extra']['namespace'] === ''
			&& $rows[2]['extra'] === ['miss' => 'rest', 'route' => '/foo/v1x/bar', 'namespace' => '']
			&& $rows[3]['message'] === '404 Not Found: /api/foo/v1/bar'
			&& $rows[4]['message'] === '404 Not Found: /wp-json/foo/v1/env'
			&& $rows[4]['extra'] === ['miss' => 'rest', 'route' => '/foo/v1/env', 'namespace' => 'foo/v1'];
	}
	
	/**
	 * RULE: on admin-ajax.php, an action core refused with 400 because
	 * nothing handles it for this caller is one not_found row naming the
	 * action — `none` when nothing handles it at all, `signed_in` when only
	 * signed-in users have it; a handler for the caller, another status, an
	 * empty or non-scalar action, another page or a request that is not ajax
	 * is no row; an empty string where the status goes reads the
	 * response's own and throws nothing. Falsify: drop the pagenow guard —
	 * admin.php reports; drop the 400 test — the Shield's 403 reports; swap
	 * the two hooks — the anonymous caller with a nopriv handler reports;
	 * type the status ?int — the empty string throws.
	 */
	public function anAjaxMissIsARowNamingTheAction(): bool
	{
		$sender = $this->sender();
		$found = new PluginNotFound(new Config, $sender);
		$GLOBALS['pagenow'] = 'admin-ajax.php';
		$GLOBALS['wp']['doing_ajax'] = true;
		$_REQUEST = ['action' => 'zz_upload'];
		$found->reportAjax(400);
		add_action('wp_ajax_zz_upload', 'strlen');
		$found->reportAjax(400);
		$GLOBALS['wp']['logged_in'] = true;
		$found->reportAjax(400);
		$GLOBALS['wp']['logged_in'] = false;
		add_action('wp_ajax_nopriv_zz_upload', 'strlen');
		$found->reportAjax(400);
		$GLOBALS['wp']['hooked'] = [];
		$found->reportAjax(200);
		$found->reportAjax(403);
		foreach(['', '0', ['x']] as $action)
		{
			$_REQUEST = ['action' => $action];
			$found->reportAjax(400);
		}
		$_REQUEST = ['action' => 'zz_upload'];
		$GLOBALS['pagenow'] = 'admin.php';
		$found->reportAjax(400);
		$GLOBALS['pagenow'] = 'admin-ajax.php';
		$GLOBALS['wp']['doing_ajax'] = false;
		$found->reportAjax(400);
		// what do_action('shutdown') hands a callback hooked with one argument: the response's own status decides (none on the CLI)
		$GLOBALS['wp']['doing_ajax'] = true;
		$found->reportAjax('');
		$rows = $sender->queued();
		
		return count($rows) === 2
			&& $rows[0]['kind'] === 'not_found'
			&& $rows[0]['message'] === '404 Not Found: /wp-admin/admin-ajax.php?action=zz_upload'
			&& $rows[0]['extra'] === ['miss' => 'ajax', 'action' => 'zz_upload', 'handler' => 'none']
			&& $rows[1]['extra']['handler'] === 'signed_in';
	}
	
	/**
	 * RULE: the ajax row's message keeps the one parameter that names what
	 * was asked for — the action, encoded, cut to 64 characters — and none
	 * of the request's other fields; its extra carries the action cut to
	 * 200. Every other caller's path still loses its query. Falsify: ignore
	 * $keepQuery — the ajax path loses its action, or every path keeps its
	 * query.
	 */
	public function theMessageKeepsOnlyTheActionOfTheQuery(): bool
	{
		$sender = $this->sender();
		$found = new PluginNotFound(new Config, $sender);
		$GLOBALS['pagenow'] = 'admin-ajax.php';
		$GLOBALS['wp']['doing_ajax'] = true;
		$_REQUEST = ['action' => str_repeat('a', 300), '_wpnonce' => 'n', 'data' => 'x'];
		$found->reportAjax(400);
		$_REQUEST = ['action' => 'a b&data=x'];
		$found->reportAjax(400);
		$sender->capture404('/p?x=1&y=2');
		$sender->capture404('/p?action=q', [], true);
		$rows = $sender->queued();
		
		return count($rows) === 4
			&& $rows[0]['message'] === '404 Not Found: /wp-admin/admin-ajax.php?action=' . str_repeat('a', 64)
			&& str_contains($rows[0]['message'], '_wpnonce') === false
			&& $rows[0]['extra']['action'] === str_repeat('a', 200)
			&& $rows[1]['message'] === '404 Not Found: /wp-admin/admin-ajax.php?action=a%20b%26data%3Dx'
			&& $rows[2]['message'] === '404 Not Found: /p'
			&& $rows[3]['message'] === '404 Not Found: /p?action=q';
	}
	
	/**
	 * RULE: pages, REST routes and ajax actions share one budget of thirty a
	 * minute — past it none of the three queues — and a new window opens it
	 * again. Falsify: let the REST or the ajax path skip throttled() — it
	 * queues past the budget.
	 */
	public function theBudgetIsOneForPagesRestAndAjax(): bool
	{
		$sender = $this->sender();
		$found = new PluginNotFound(new Config, $sender);
		$GLOBALS['pagenow'] = 'admin-ajax.php';
		$GLOBALS['wp']['doing_ajax'] = true;
		$GLOBALS['wp']['is_404'] = true;
		$_REQUEST = ['action' => 'zz_upload'];
		for($i = 0; $i < PluginNotFound::MAX_PER_MINUTE / 3; $i++)
		{
			$found->reportPage();
			$this->restMiss($found, '/foo/v1/bar');
			$found->reportAjax(400);
		}
		$full = count($sender->queued());
		$found->reportPage();
		$this->restMiss($found, '/foo/v1/bar');
		$found->reportAjax(400);
		$past = count($sender->queued());
		// the window closed
		$GLOBALS['wp']['transients']['ovos_codesafe_404_rate'] = 0;
		$found->reportAjax(400);
		$this->restMiss($found, '/foo/v1/bar');
		
		return PluginNotFound::MAX_PER_MINUTE === 30
			&& $full === 30
			&& $past === 30
			&& array_column($sender->queued(), 'message')[30] === '404 Not Found: /wp-admin/admin-ajax.php?action=zz_upload'
			&& count($sender->queued()) === 32;
	}
	
	/**
	 * RULE: with Report 404s off nothing is hooked and a miss queues nothing;
	 * with it on the three reporters are hooked — the REST one at priority 0,
	 * before a plugin that serves and exits in the same filter, taking the
	 * filter's four arguments; the shutdown one taking none, since
	 * do_action('shutdown') would hand it an empty string. Falsify: hook the
	 * REST filter at 10, or with one argument; hook shutdown with the default
	 * one; hook anything while the switch is off.
	 */
	public function nothingHooksWithoutTheSwitch(): bool
	{
		$GLOBALS['wp']['options'][Config::OPTION] = ['report_404' => false];
		$sender = $this->sender();
		$off = new PluginNotFound(new Config, $sender);
		$off->register();
		$hookedOff = $GLOBALS['wp']['hooked'];
		$this->restMiss($off, '/foo/v1/bar');
		$queuedOff = $sender->queued();
		$GLOBALS['wp']['options'][Config::OPTION] = ['report_404' => true];
		$on = new PluginNotFound(new Config, $this->sender());
		$on->register();
		
		return $hookedOff === []
			&& $queuedOff === []
			&& $GLOBALS['wp']['hooked'] === [
				['template_redirect', [$on, 'reportPage'], 10, 1],
				['rest_pre_serve_request', [$on, 'reportRest'], 0, 4],
				['shutdown', [$on, 'reportAjax'], 10, 0],
			];
	}
	
	/** a Sender whose queue the test reads */
	protected function sender(): Sender
	{
		return new class(new Config) extends Sender
		{
			public function queued(): array
			{
				return $this->queue;
			}
		};
	}
	
	/** rest_pre_serve_request with the REST server's answer for a route it has no handler for */
	protected function restMiss(
		PluginNotFound $found,
		string $route,
	): void
	{
		$found->reportRest(false, new WP_REST_Response(self::NO_ROUTE, 404), new WP_REST_Request('GET', $route), rest_get_server());
	}
}
