<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Consent;
use Ovos\Codesafe\Shield\Facts;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_replace;
use function count;
use function hash;
use function implode;
use function intdiv;
use function ksort;
use function is_dir;
use function mkdir;
use function rmdir;
use function scandir;
use function str_split;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
// the kernel file holds Facts, Store and Ruleset beside Kernel: the adapter's require brings it
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Adapter.php';

/**
 * The Shield and the REST API: who a REST request is at plugins_loaded, as
 * WordPress will authenticate it later — an application password in Basic
 * credentials is its user, a login cookie without a wp_rest nonce is no one,
 * what cannot be told is held — and the REST prefix the early layers tell a
 * REST request by. Judged against two blocking virtual patches on one route:
 * rule 21 for anonymous callers, rule 22 for callers lacking manage_options.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class ShieldRest extends Test
{
	protected const string PASSWORD = 'abcd1234EFGH5678ijkl9012';
	
	protected const string ROUTE = '/wp-json/fx/v1/save';
	
	protected const string NONCE = 'a1b2c3d4e5';
	
	protected string $dir;
	
	protected Kernel $kernel;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		$GLOBALS['wp']['users'] = [
			'integration' => [7, 'integration@example.com', ['manage_options', 'edit_posts']],
			'editor' => [8, 'editor@example.com', ['edit_posts']],
		];
		$GLOBALS['wp']['app_passwords'] = [
			7 => [['uuid' => 'u7', 'password' => hash('sha256', self::PASSWORD)]],
			8 => [['uuid' => 'u8', 'password' => hash('sha256', self::PASSWORD)]],
		];
		$this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-rest-' . uniqid();
		mkdir($this->dir, 0700, true);
		
		$route = [['target' => 'path', 'test' => 'prefix', 'value' => '/wp-json/fx/v1/']];
		$store = new Store($this->dir . DIRECTORY_SEPARATOR . 'shield-efefefefefefefefefefefef.json', '');
		$store->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => [
				['id' => 21, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'block', 'expires_at' => null,
					'who' => 'anonymous', 'conditions' => $route],
				['id' => 22, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'block', 'expires_at' => null,
					'who' => 'lacks:manage_options', 'conditions' => $route],
			],
		], time())->toRecord());
		$this->kernel = new Kernel('', '', $store,
			static fn(): array => ['status' => 0, 'headers' => [], 'body' => ''],
			static function(): void
			{
			});
	}
	
	#[Internal]
	public function finalize(): void
	{
		wp_shim_reset();
		$this->remove($this->dir);
	}
	
	/**
	 * RULE: Basic credentials holding a user's application password make a
	 * REST request that user's at plugins_loaded — signed in, counted by
	 * their id, their capabilities answered for them — by login or by e-mail,
	 * the password's grouping spaces ignored; the nonce answer is left open,
	 * WordPress checks one for that user, not the current one. Falsify: read
	 * is_user_logged_in() alone — WordPress checks the password only later,
	 * the integration looks anonymous and rule 21 refuses it.
	 */
	public function anApplicationPasswordIsItsUserOnARestRequest(): bool
	{
		$caller = Adapter::caller($this->basic('integration', implode(' ', str_split(self::PASSWORD, 4))), [], [], false, true);
		$facts = $this->facts($caller);
		$byEmail = Adapter::caller($this->basic('integration@example.com', self::PASSWORD), [], [], false, true);
		$editor = Adapter::caller($this->basic('editor', self::PASSWORD), [], [], false, true);
		// outside the REST API WordPress does not check them: anonymous, as ever
		$page = Adapter::caller($this->basic('integration', self::PASSWORD), [], [], false, false);
		
		return $caller['authed'] === true && $caller['user'] === 'user:7'
			&& $facts->can('manage_options') === true && $facts->can('delete_users') === false
			&& $facts->nonceValid('wp_rest', self::NONCE) === null
			&& $this->judged($caller)->isPass()
			&& $byEmail['user'] === 'user:7' && $this->judged($byEmail)->isPass()
			&& $editor['user'] === 'user:8' && ($this->judged($editor)->rule['id'] ?? 0) === 22
			&& $page['authed'] === false && ($this->judged($page)->rule['id'] ?? 0) === 21;
	}
	
	/**
	 * RULE: Basic credentials WordPress would refuse leave the request
	 * anonymous: a wrong password, an unknown user, half the credentials,
	 * application passwords refused to the user, never used on the network or
	 * switched off. Falsify: take the login for the user — anyone naming an
	 * administrator in a Basic header walks past rule 21.
	 */
	public function aWrongOrUnusableApplicationPasswordIsAnonymous(): bool
	{
		$anonymous = fn(array $server): bool => Adapter::caller($server, [], [], false, true)['authed'] === false;
		$wrong = Adapter::caller($this->basic('integration', 'x' . self::PASSWORD), [], [], false, true);
		$unknown = $anonymous($this->basic('nobody', self::PASSWORD));
		$half = $anonymous(['PHP_AUTH_USER' => 'integration'] + $this->server());
		$GLOBALS['wp']['app_passwords_refused'] = [7];
		$refused = $anonymous($this->basic('integration', self::PASSWORD));
		$GLOBALS['wp']['app_passwords_refused'] = [];
		$GLOBALS['wp']['app_passwords_in_use'] = false;
		$unused = $anonymous($this->basic('integration', self::PASSWORD));
		$GLOBALS['wp']['app_passwords_in_use'] = true;
		$GLOBALS['wp']['app_passwords_available'] = false;
		$off = $anonymous($this->basic('integration', self::PASSWORD));
		
		return $wrong['authed'] === false && ($this->judged($wrong)->rule['id'] ?? 0) === 21
			&& $unknown && $half && $refused && $unused && $off;
	}
	
	/**
	 * RULE: a REST request the login cookie signed in counts as signed in only
	 * with a valid wp_rest nonce — without one WordPress runs it as user 0,
	 * with a wrong one it refuses it — while a page request keeps the cookie's
	 * user, and a user signed in by other means needs no nonce. Falsify: take
	 * is_user_logged_in() for a REST request — a subscriber's cookie carries
	 * a request WordPress runs anonymous past rule 21.
	 */
	public function aRestCookieWithoutTheNonceIsNoOne(): bool
	{
		$GLOBALS['wp']['nonces'] = ['wp_rest' => self::NONCE];
		$GLOBALS['wp_rest_auth_cookie'] = true;
		$bare = Adapter::caller($this->server(), [], [], true, true);
		$wrong = Adapter::caller(['HTTP_X_WP_NONCE' => 'ffffffffff'] + $this->server(), [], [], true, true);
		// the form's _wpnonce over the query's, as WordPress merges $_REQUEST
		$overridden = Adapter::caller($this->server(), ['_wpnonce' => self::NONCE], ['_wpnonce' => 'ffffffffff'], true, true);
		$page = Adapter::caller($this->server(), [], [], true, false);
		unset($GLOBALS['wp_rest_auth_cookie']);
		$otherMeans = Adapter::caller($this->server(), [], [], true, true);
		
		return $bare['authed'] === false && ($this->judged($bare)->rule['id'] ?? 0) === 21
			&& $this->facts($bare)->can('manage_options') === false
			&& $this->facts($bare)->nonceValid('fx_save', self::NONCE) === null
			&& $wrong['authed'] === false
			&& $overridden['authed'] === false
			&& $page['authed'] === true
			&& $otherMeans['authed'] === true;
	}
	
	/**
	 * RULE: the login cookie with a valid wp_rest nonce — the X-WP-Nonce header
	 * or _wpnonce in the request — is the cookie's user, their capabilities
	 * answered. Falsify: drop every cookie-signed REST request to anonymous —
	 * the block editor's own saves meet rule 21.
	 */
	public function aRestCookieWithAValidNonceIsSignedIn(): bool
	{
		$GLOBALS['wp']['nonces'] = ['wp_rest' => self::NONCE];
		$GLOBALS['wp']['current_caps'] = ['manage_options'];
		$GLOBALS['wp_rest_auth_cookie'] = true;
		$header = Adapter::caller(['HTTP_X_WP_NONCE' => self::NONCE] + $this->server(), [], [], true, true);
		$query = Adapter::caller($this->server(), ['_wpnonce' => self::NONCE], [], true, true);
		$form = Adapter::caller($this->server(), [], ['_wpnonce' => self::NONCE], true, true);
		
		return $header['authed'] === true && $this->judged($header)->isPass()
			&& $this->facts($header)->can('manage_options') === true
			&& $query['authed'] === true
			&& $form['authed'] === true;
	}
	
	/**
	 * RULE: where the caller cannot be told — here the application passwords
	 * cannot be read — the caller is unknown, with no answers: rule 21 (for
	 * anonymous callers) and rule 22 (for those lacking manage_options) both
	 * wait, the first held as unanswered, observing. Falsify: count it
	 * anonymous — a hiccup in the user store refuses every integration.
	 */
	public function whatCannotBeToldIsHeldNotRefused(): bool
	{
		$GLOBALS['wp']['app_passwords_throw'] = true;
		$caller = Adapter::caller($this->basic('integration', self::PASSWORD), [], [], false, true);
		$facts = $this->facts($caller);
		$verdict = $this->judged($caller);
		
		return $caller['known'] === false && $caller['can'] === null
			&& $facts->callerKnown === false
			&& $facts->can('manage_options') === null
			&& $facts->nonceValid('wp_rest', self::NONCE) === null
			&& $verdict->outcome === Verdict::OBSERVE
			&& $verdict->reason === Verdict::REASON_UNANSWERED
			&& ($verdict->rule['id'] ?? 0) === 21;
	}
	
	/**
	 * RULE: a caller WordPress tells only later is unknown at plugins_loaded —
	 * a REST request with a token another plugin reads (Bearer), every
	 * XML-RPC call — while a REST request with no credentials is the
	 * anonymous caller it is, and Basic credentials an application password
	 * signs in are known. Falsify: read a Bearer request as anonymous — rule
	 * 21 refuses every JWT integration before its plugin has signed it in.
	 */
	public function aTokenOrAnXmlRpcCallerIsUnknown(): bool
	{
		$bearer = Adapter::caller(['HTTP_AUTHORIZATION' => 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.x'] + $this->server(), [], [], false, true);
		$xmlrpc = Adapter::caller(['REQUEST_URI' => '/xmlrpc.php'] + $this->server(), [], [], false, false, true);
		$plain = Adapter::caller($this->server(), [], [], false, true);
		$password = Adapter::caller($this->basic('integration', self::PASSWORD), [], [], false, true);
		
		return $bearer['known'] === false && $xmlrpc['known'] === false
			&& $plain['known'] === true && $plain['authed'] === false
			&& $password['known'] === true && $password['authed'] === true
			&& $this->judged($bearer)->reason === Verdict::REASON_UNANSWERED
			&& $this->judged($plain)->isBlock();
	}
	
	/**
	 * RULE: a held request waits on the hook where WordPress has settled its
	 * caller — rest_pre_dispatch for REST, xmlrpc_call for an XML-RPC call —
	 * and on WordPress's shutdown action, both before any plugin's default
	 * priority; a request the kernel decides at once waits on nothing.
	 * Falsify: wait on init — a token is still unread there, and the second
	 * judgement guesses again.
	 */
	public function aHeldRequestWaitsOnTheHookWordPressSettlesItsCallerOn(): bool
	{
		$reports = [];
		$rest = $this->adapter($reports);
		$token = [['HTTP_AUTHORIZATION' => 'Bearer forged'] + $this->server(), [], [], [], []];
		$rest->judgeRequest($token, Adapter::caller($token[0], [], [], false, true), '203.0.113.9', 'wp-json');
		$restHooks = $GLOBALS['wp']['hooked'];
		$GLOBALS['wp']['hooked'] = [];
		$xmlrpc = $this->adapter($reports);
		$call = [$this->server(), [], [], [], []];
		$xmlrpc->judgeRequest($call, Adapter::caller($call[0], [], [], false, false, true), '203.0.113.9', 'wp-json', true);
		$xmlrpcHooks = $GLOBALS['wp']['hooked'];
		$GLOBALS['wp']['hooked'] = [];
		$this->adapter($reports)->judgeRequest($call, Adapter::caller($call[0], [], [], false, true), '203.0.113.9', 'wp-json');
		
		return $restHooks === [['rest_pre_dispatch', [$rest, 'judgeAgain'], Adapter::HOOK_PRIORITY, 1], ['shutdown', [$rest, 'settleHeld'], Adapter::HOOK_PRIORITY, 1]]
			&& $xmlrpcHooks === [['xmlrpc_call', [$xmlrpc, 'judgeAgain'], Adapter::HOOK_PRIORITY, 1], ['shutdown', [$xmlrpc, 'settleHeld'], Adapter::HOOK_PRIORITY, 1]]
			&& $GLOBALS['wp']['hooked'] === [];
	}
	
	/**
	 * RULE: an unknown caller's request is held, not settled: nothing is
	 * counted or reported until WordPress has settled the user. Judged again
	 * then (rest_pre_dispatch, xmlrpc_call), it is refused for an anonymous
	 * caller and served for one holding manage_options, once; never judged
	 * again, WordPress's shutdown reports the observe it was, once. Falsify:
	 * report the held verdict at once — every JWT call is reported twice; or
	 * judge it again with the unknown caller — a forged Bearer header turns
	 * every block into an observe.
	 */
	public function anUnknownCallerIsJudgedAgainOnceWordPressHasTheUser(): bool
	{
		$reports = [];
		$adapter = $this->adapter($reports);
		$request = [['HTTP_AUTHORIZATION' => 'Bearer forged'] + $this->server(), [], [], [], []];
		$unknown = Adapter::caller($request[0], [], [], false, true);
		$anonymous = ['authed' => false, 'user' => '', 'can' => static fn(string $capability): bool => false, 'nonce' => null, 'known' => true];
		$admin = ['authed' => true, 'user' => 'user:7', 'can' => static fn(string $capability): bool => true, 'nonce' => null, 'known' => true];
		
		$held = $adapter->judgeRequest($request, $unknown, '203.0.113.9', 'wp-json');
		$heldReports = count($reports);
		$adapter->judgeAgain(null, $anonymous);
		$refused = $reports;
		// judged once: a second rest_pre_dispatch (a batch's sub-request) finds nothing held
		$adapter->judgeAgain(null, $anonymous);
		$once = count($reports);
		
		$reports = [];
		$adapter->judgeRequest($request, $unknown, '203.0.113.9', 'wp-json');
		$served = $adapter->judgeAgain('kept', $admin);
		$adminReports = count($reports);
		
		$reports = [];
		$adapter->judgeRequest($request, $unknown, '203.0.113.9', 'wp-json');
		$adapter->settleHeld();
		$adapter->settleHeld();
		$settled = $reports;
		
		return $held === null && $heldReports === 0
			&& count($refused) === 1 && $refused[0][0] === Verdict::KIND_BLOCK && $refused[0][2]['rule'] === 21 && $once === 1
			&& $served === 'kept' && $adminReports === 0
			&& count($settled) === 1 && $settled[0][0] === Verdict::KIND_OBSERVE && $settled[0][2]['rule'] === 21;
	}
	
	/**
	 * RULE: every request the adapter settles tallies its evidence once, as
	 * Kernel::handle() does — the counting's heartbeat (rule 0's entry) and
	 * each vpatch's entry, match and authed — a held one only when it is
	 * settled, for the caller WordPress settled; a request an earlier layer
	 * judged is tallied too, judged nothing and reported nothing. Falsify:
	 * count and report by hand without tally() — no WordPress site sends a
	 * vpatch's evidence or the heartbeat, and nothing it carries is ever
	 * counted; or tally a held request at once — it counts twice.
	 */
	public function everySettledRequestTalliesItsEvidenceOnce(): bool
	{
		$reports = [];
		$prefix = 'shield-rest-tally-' . uniqid();
		$store = new Store($this->dir . DIRECTORY_SEPARATOR . 'shield-tally.json', $prefix);
		$store->write($this->kernel->store()->read());
		$adapter = $this->adapter($reports, $store);
		$request = [$this->server(), [], [], [], []];
		$admin = ['authed' => true, 'user' => 'user:7', 'can' => static fn(string $capability): bool => true, 'nonce' => null, 'known' => true];
		$anonymous = ['authed' => false, 'user' => '', 'can' => static fn(string $capability): bool => false, 'nonce' => null, 'known' => true];
		$unknown = Adapter::caller(['HTTP_AUTHORIZATION' => 'Bearer forged'] + $this->server(), [], [], false, true);
		$taken = static function() use ($store): array
		{
			// the minute the tally ran in, and the one either side should the clock turn
			$minute = intdiv(time(), 60);
			$hits = [];
			foreach([$minute - 1, $minute, $minute + 1] as $at)
			{
				foreach($store->takeHits($at) as $id => $counts)
				{
					foreach($counts as $outcome => $count)
					{
						$hits[$id][$outcome] = ($hits[$id][$outcome] ?? 0) + $count;
					}
				}
			}
			ksort($hits);
			
			return $hits;
		};
		$taken();
		
		// served: the administrator holds manage_options and is signed in
		$adapter->judgeRequest($request, $admin, '203.0.113.9', 'wp-json');
		$served = $taken();
		// held, then judged again for an anonymous caller: tallied once, then
		$adapter->judgeRequest($request, $unknown, '203.0.113.9', 'wp-json');
		$whileHeld = $taken();
		$adapter->judgeAgain(null, $anonymous);
		$adapter->judgeAgain(null, $anonymous);
		$settled = $taken();
		// an earlier layer judged it: only the evidence
		$reports = [];
		$adapter->tallyRequest($request, $admin, '203.0.113.9', 'wp-json');
		$early = $taken();
		
		$zero = ['observe' => 0, 'block' => 0, 'entry' => 0, 'match' => 0, 'authed' => 0];
		$entered = array_replace($zero, ['entry' => 1]);
		
		return $served === [0 => $entered, 21 => $entered, 22 => $entered]
			&& $whileHeld === []
			&& $settled[0] === $entered && $settled[21] === array_replace($zero, ['block' => 1, 'entry' => 1, 'match' => 1])
			&& $settled[22] === array_replace($zero, ['entry' => 1, 'match' => 1])
			&& $early === [0 => $entered, 21 => $entered, 22 => $entered] && $reports === [];
	}
	
	/**
	 * RULE: a REST request is told by the prefix as a path segment anywhere in
	 * the path, decoded once or twice, or by a rest_route WordPress's empty()
	 * takes — and the adapter takes it for one only where WordPress routes it,
	 * the front end's index.php. Falsify: answer admin-ajax.php's rest_route
	 * field — an administrator's cookie without a REST nonce turns anonymous.
	 */
	public function aRestRequestIsToldByItsAddressAndWhereWordPressRoutesIt(): bool
	{
		$rest = static fn(string $uri, string $prefix = 'wp-json', array $get = [], array $post = []): bool => Prepend::isRest(['REQUEST_URI' => $uri], $get, $post, $prefix);
		$front = Adapter::servesRest(['REQUEST_URI' => self::ROUTE], [], [], 'wp-json');
		$GLOBALS['pagenow'] = 'admin-ajax.php';
		$ajax = Adapter::servesRest(['REQUEST_URI' => '/wp-admin/admin-ajax.php'], [], ['rest_route' => '/fx/v1/save'], 'wp-json');
		
		return $rest('/wp-json/wp/v2/posts') && $rest('/wp-json') && $rest('/wp-json/?context=edit')
			&& $rest('/blog/wp-json/wp/v2/posts') && $rest('/index.php/wp-json/wp/v2/posts')
			&& $rest('/wp%2Djson/wp/v2/posts') && $rest('/wp%252Djson/wp/v2/posts')
			&& $rest('/?rest_route=/wp/v2/posts', get: ['rest_route' => '/wp/v2/posts']) && $rest('/', post: ['rest_route' => '/'])
			&& $rest('/api/v1/x', '/api/') && $rest('/wp-json/x', 'api') === false
			&& $rest('/wp-jsonx/y') === false && $rest('/shop/') === false
			&& $rest('/', get: ['rest_route' => '']) === false && $rest('/', get: ['rest_route' => '0']) === false
			&& $front && $ajax === false;
	}
	
	/**
	 * RULE: init, last, writes the site's REST prefix — rest_get_url_prefix()
	 * with every filter in place — into the consent the early layers read,
	 * only when it changed, and the plugin's own write before plugins_loaded
	 * keeps it. Falsify: write it on every request — a file write per page
	 * view; leave it to the early write — a custom prefix is lost every
	 * request and the site's integrations are judged as anonymous.
	 */
	public function theInitHookWritesThePrefixOnlyWhenItChanged(): bool
	{
		$consent = ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => ''];
		$none = Adapter::syncRestPrefix($this->dir);
		Prepend::writeConsent($this->dir, $consent);
		$default = Adapter::syncRestPrefix($this->dir);
		$GLOBALS['wp']['filters']['rest_url_prefix'] = [static fn(string $prefix): string => 'api'];
		$changed = Adapter::syncRestPrefix($this->dir);
		$again = Adapter::syncRestPrefix($this->dir);
		$kept = Prepend::writeConsent($this->dir, $consent);
		
		return $none === false && $default === false
			&& $changed === true && $again === false
			&& $kept === false
			&& Prepend::consent($this->dir)['rest_prefix'] === 'api';
	}
	
	// ---- helpers --------------------------------------------------------------
	
	/** the REST request rules 21 and 22 watch */
	protected function server(): array
	{
		return [
			'REQUEST_METHOD' => 'POST',
			'REQUEST_URI' => self::ROUTE,
			'HTTP_USER_AGENT' => 'fx-integration/2.1',
			'REMOTE_ADDR' => '203.0.113.9',
		];
	}
	
	/** an adapter judging with this test's rules, blocking on, its kernel's reports recorded into $reports */
	protected function adapter(
		array &$reports,
		?Store $store = null,
	): Adapter
	{
		$kernel = new Kernel('', '', $store ?? $this->kernel->store(),
			static fn(): array => ['status' => 0, 'headers' => [], 'body' => ''],
			static function(string $kind, string $message, array $extra) use (&$reports): void
			{
				$reports[] = [$kind, $message, $extra];
			});
		$config = new class extends Config
		{
			public function __construct()
			{
			}
			
			public function enabled(): bool
			{
				return true;
			}
			
			public function shieldDetect(): bool
			{
				return true;
			}
			
			public function shieldEnforce(): bool
			{
				return true;
			}
			
			public function shieldKill(): bool
			{
				return false;
			}
		};
		
		return new Adapter($config, new Sender(new Config), $kernel);
	}
	
	/** the request with Basic credentials as WordPress leaves them by plugins_loaded */
	protected function basic(
		string $login,
		string $password,
	): array
	{
		return ['PHP_AUTH_USER' => $login, 'PHP_AUTH_PW' => $password] + $this->server();
	}
	
	protected function facts(
		array $caller,
	): Facts
	{
		return Adapter::facts($this->server(), [], [], [], [], $caller, '203.0.113.9');
	}
	
	/** the kernel's verdict on the route for this caller, with blocking on */
	protected function judged(
		array $caller,
	): Verdict
	{
		return $this->kernel->judge($this->facts($caller), new Consent(true, true, false));
	}
	
	/** a temp directory and everything under it */
	protected function remove(
		string $dir,
	): void
	{
		if(is_dir($dir) === false)
		{
			return;
		}
		foreach(scandir($dir) ?: [] as $name)
		{
			if($name === '.' || $name === '..')
			{
				continue;
			}
			$path = $dir . DIRECTORY_SEPARATOR . $name;
			is_dir($path) ? $this->remove($path) : unlink($path);
		}
		rmdir($dir);
	}
}
