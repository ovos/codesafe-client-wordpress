<?php
declare(strict_types=1);

namespace Tests;

use Closure;
use Ovos\Codesafe\Redactor;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Prepend as BasePrepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;
use Ovos\Test;
use Ovos\Test\Exception\SkipException;
use Ovos\Test\Internal;
use ReflectionClass;

use function apcu_enabled;
use function array_diff_key;
use function array_keys;
use function array_map;
use function array_slice;
use function base64_encode;
use function basename;
use function count;
use function dirname;
use function escapeshellarg;
use function exec;
use function explode;
use function fclose;
use function file_get_contents;
use function file_put_contents;
use function filemtime;
use function function_exists;
use function getenv;
use function glob;
use function implode;
use function in_array;
use function is_array;
use function is_dir;
use function is_file;
use function is_int;
use function is_resource;
use function json_decode;
use function json_encode;
use function mkdir;
use function preg_match;
use function proc_close;
use function proc_open;
use function range;
use function realpath;
use function rmdir;
use function scandir;
use function sleep;
use function sprintf;
use function str_contains;
use function str_ends_with;
use function str_repeat;
use function str_replace;
use function str_starts_with;
use function stream_get_contents;
use function strlen;
use function strtoupper;
use function substr;
use function symlink;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;
use function var_export;

use const DIRECTORY_SEPARATOR;
use const PHP_BINARY;
use const PHP_OS_FAMILY;

// the kernel file holds Store, Ruleset and Verdict beside Kernel, so no
// class-per-file autoloader finds them: the layer's own require brings it
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Adapter.php';

/**
 * The auto_prepend_file layer, without WordPress: a temp store directory holds
 * a ruleset (a proven UA rule, an observe URI rule) and a consent file; the
 * layer is driven through Prepend::judge() with fabricated request arrays.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Prepend extends Test
{
	protected const string BOT = 'zz-prepend-bot/1.0';
	
	protected const string PROBE = '/wp-admin/admin-ajax.php?action=x&include=../../etc/passwd';
	
	/** a staged core copy as WP_Upgrader::unpack_package() leaves it, below the site root */
	protected const string STAGED = 'wp-content/upgrade/wordpress-7.1.3-a1b2c3/wordpress/wp-admin/setup-config.php';
	
	/** the ruleset's name the consent carries — drawn by writeConsent() when none is given */
	protected const string RULES_NAME = 'shield-abababababababababababab.json';
	
	/** the API key the ruleset is sealed under */
	protected const string KEY = 'harness-key';
	
	/** Kernel::sealKey(self::KEY): what the adapter writes into the consent, never the key itself */
	protected const string SEAL = '7c7a00e4abca682d0f5c8a4e2f46c29f036b9f508e73f10e47198eeb605b1099';
	
	protected const array ENFORCE = ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => '', 'root' => '', 'content' => '', 'plugins' => '',
		'uploads' => [], 'uploads_guard' => true, 'entries' => false,
		'rules' => self::RULES_NAME, 'proxy_header' => '', 'proxies' => [], 'rest_prefix' => 'wp-json', 'seal' => self::SEAL, 'login_cookie' => ''];
	
	protected string $dir;
	
	#[Internal]
	public function prepare(): void
	{
		$this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-prepend-' . uniqid();
		mkdir($this->dir, 0700, true);
		
		$rules = [
			['id' => 7, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'ua', 'op' => 'contains', 'value' => 'zz-prepend-bot', 'ci' => true, 'mode' => 'proven', 'expires_at' => null],
			['id' => 8, 'origin' => 'finding', 'finding' => 'f', 'cve' => 'CVE-2099-0001', 'field' => 'uri', 'op' => 'regex', 'value' => '[?&]include=[^&]*\.\./', 'ci' => true, 'mode' => 'observe', 'expires_at' => null],
		];
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		
		unset($GLOBALS[BasePrepend::STASH]);
	}
	
	#[Internal]
	public function finalize(): void
	{
		unset($GLOBALS[BasePrepend::STASH]);
		
		$this->remove($this->dir);
	}
	
	public function withoutConsentFileTheLayerSaysNothing(): bool
	{
		return BasePrepend::judge($this->dir, $this->server(self::BOT)) === null;
	}
	
	public function consentIsWrittenOnceAndNotAgainWhileUnchanged(): bool
	{
		$written = BasePrepend::writeConsent($this->dir, self::ENFORCE);
		$again = BasePrepend::writeConsent($this->dir, self::ENFORCE);
		
		return $written === true
			&& $again === false
			&& BasePrepend::consent($this->dir) === self::ENFORCE;
	}
	
	public function provenRuleUnderEnforceBlocksWithTheKernelsReport(): bool
	{
		$blocked = $this->blocked();
		
		return $blocked !== null
			&& $blocked['verdict']->outcome === Verdict::BLOCK
			&& (int)$blocked['verdict']->rule['id'] === 7
			&& ($blocked['report'][0] ?? '') === Verdict::KIND_BLOCK
			&& ($blocked['report'][2]['rule'] ?? 0) === 7
			&& str_contains((string)$blocked['report'][1], 'refused GET /wp-content/plugins/some-plugin/file.php');
	}
	
	public function observeRuleObservesAndReportsShieldObserve(): bool
	{
		$observed = $this->observed();
		
		return $observed !== null
			&& $observed['verdict']->outcome === Verdict::OBSERVE
			&& ($observed['report'][0] ?? '') === Verdict::KIND_OBSERVE;
	}
	
	public function plainRequestIsNothing(): bool
	{
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		
		return BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/')) === null;
	}
	
	/**
	 * RULE: a proven vpatch whose nonce this layer cannot check is left to the
	 * plugins_loaded adapter where WordPress loads — not judged here, so the
	 * adapter judges it with wp_verify_nonce — and observed here where no
	 * adapter will ever run (a direct hit on a plugin file); a request without
	 * the nonce is refused here, there is nothing to check. Falsify: settle
	 * the unanswered verdict as an observe — a junk nonce walks past the
	 * block on every page WordPress serves.
	 */
	public function anUnansweredVpatchIsLeftToTheAdapterWhereWordPressLoads(): bool
	{
		$rules = [['id' => 12, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'proven', 'expires_at' => null,
			'who' => 'anyone', 'conditions' => [['target' => 'query:action', 'test' => 'equals', 'value' => 'fx_save'],
			['target' => 'query:_wpnonce', 'test' => 'nonce_invalid', 'value' => 'fx_save_settings']]]];
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$root = $this->site();
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$request = fn(string $uri, string $script, array $get): array => [$this->server(self::BOT, $uri, $script), $get];
		[$page, $pageGet] = $request('/?action=fx_save&_wpnonce=abc123', $root . '/index.php', ['action' => 'fx_save', '_wpnonce' => 'abc123']);
		[$file, $fileGet] = $request('/wp-content/plugins/some-plugin/file.php?action=fx_save&_wpnonce=abc123', $root . '/wp-content/plugins/some-plugin/file.php',
			['action' => 'fx_save', '_wpnonce' => 'abc123']);
		[$bare, $bareGet] = $request('/?action=fx_save', $root . '/index.php', ['action' => 'fx_save']);
		$ran = null;
		$left = BasePrepend::judge($this->dir, $page, [], [], null, null, $ran, $pageGet);
		$leftRan = $ran;
		$observed = BasePrepend::judge($this->dir, $file, [], [], null, null, $ran, $fileGet);
		$refused = BasePrepend::judge($this->dir, $bare, [], [], null, null, $ran, $bareGet);
		
		return $left === null && $leftRan === false
			&& ($observed['verdict'] ?? null)?->outcome === Verdict::OBSERVE && $observed['verdict']->reason === Verdict::REASON_UNANSWERED
			&& ($refused['verdict'] ?? null)?->outcome === Verdict::BLOCK;
	}
	
	/**
	 * RULE: this layer finds a REST route after the site's own prefix, the one
	 * the consent carries — not after wp-json on a site that moved it.
	 * Falsify: build the facts without the prefix — a `rest` vpatch on a
	 * site with another prefix never holds before WordPress.
	 */
	public function aRestRouteIsFoundAfterTheSitesOwnPrefix(): bool
	{
		$rules = [['id' => 14, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'proven', 'expires_at' => null,
			'who' => 'anyone', 'conditions' => [['target' => 'rest', 'test' => 'prefix', 'value' => '/fx/v1/settings']]]];
		// kept as the site's pull keeps it, with WordPress's module
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$root = $this->site();
		BasePrepend::writeConsent($this->dir, ['root' => $root, 'rest_prefix' => 'api'] + self::ENFORCE);
		$moved = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/api/fx/v1/settings', $root . '/index.php'));
		$default = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/wp-json/fx/v1/settings', $root . '/index.php'));
		
		return ($moved['verdict'] ?? null)?->outcome === Verdict::BLOCK && (int)$moved['verdict']->rule['id'] === 14
			&& $default === null;
	}
	
	/**
	 * RULE: where WordPress loads, a caller it tells only later — a REST
	 * request with a token (Bearer), an XML-RPC call — is unknown here: a
	 * rule for anonymous callers waits for the adapter, unjudged, while a rule
	 * for anyone still blocks before WordPress. Falsify: judge the token
	 * request as anonymous — a JWT integration is refused before its plugin
	 * signs it in.
	 */
	public function aTokenOrAnXmlRpcCallerIsLeftToTheAdapter(): bool
	{
		$rule = static fn(int $id, string $who, array $condition): array => ['id' => $id, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '',
			'mode' => 'proven', 'expires_at' => null, 'who' => $who, 'conditions' => [$condition]];
		$write = function(array ...$rules): void
		{
			// kept as the site's pull keeps them, with WordPress's module
			(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
				'contract' => 1,
				'dialect' => 're2-2026',
				'project' => 'harness',
				'rules' => $rules,
			], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		};
		$root = $this->site();
		file_put_contents($root . '/xmlrpc.php', "<?php\n");
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$token = ['HTTP_AUTHORIZATION' => 'Bearer eyJhbGciOiJIUzI1NiJ9.e30.x'] + $this->server('Mozilla/5.0', '/wp-json/fx/v1/save', $root . '/index.php');
		$xmlrpc = $this->server('Mozilla/5.0', '/xmlrpc.php', $root . '/xmlrpc.php');
		
		$write($rule(31, 'anonymous', ['target' => 'rest', 'test' => 'equals', 'value' => '/fx/v1/save']),
			$rule(32, 'anonymous', ['target' => 'path', 'test' => 'suffix', 'value' => '/xmlrpc.php']));
		$ran = null;
		$leftToken = BasePrepend::judge($this->dir, $token, [], [], null, null, $ran);
		$tokenRan = $ran;
		$leftXmlrpc = BasePrepend::judge($this->dir, $xmlrpc, [], [], null, null, $ran);
		$xmlrpcRan = $ran;
		// the same request with no token is the anonymous caller it is
		$anonymous = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/wp-json/fx/v1/save', $root . '/index.php'));
		$write($rule(33, 'anyone', ['target' => 'rest', 'test' => 'equals', 'value' => '/fx/v1/save']));
		$anyone = BasePrepend::judge($this->dir, $token);
		
		return $leftToken === null && $tokenRan === false && $leftXmlrpc === null && $xmlrpcRan === false
			&& ($anonymous['verdict'] ?? null)?->isBlock() === true
			&& ($anyone['verdict'] ?? null)?->isBlock() === true && (int)$anyone['verdict']->rule['id'] === 33;
	}
	
	/**
	 * RULE: the mu-plugin stage runs inside WordPress, so what a signed-in
	 * request's verdict waits on is the adapter's there whatever the script —
	 * a file outside the stored root, as on a WordPress-in-a-subdirectory
	 * install or a wp-load.php include — while the prepend layer, before
	 * WordPress, judges such a script itself. Falsify: tell it by the script
	 * in the mu-plugin stage too — a signed-in editor on a subdirectory
	 * install is judged anonymous.
	 */
	public function theMuPluginStageIsInsideWordPress(): bool
	{
		$root = $this->site();
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$cookie = ['wordpress_logged_in_abc123' => 'x'];
		// rule 8 observes it: nothing this layer refuses whoever asks
		$outside = $this->server('Mozilla/5.0', '/x.php?include=../../etc/passwd', $this->dir . '/outside.php');
		
		return BasePrepend::judge($this->dir, $outside, [], $cookie) !== null
			&& BasePrepend::judge($this->dir, $outside, [], $cookie, null, null, $ran, null, [], true) === null;
	}
	
	/**
	 * What a signed-in request to a file WordPress runs through observes is
	 * the plugins_loaded judge's, not this layer's, which reports it with the
	 * user — WordPress's test cookie is not a login
	 */
	public function loginCookieDefersToPluginsLoadedWhereWordPressRuns(): bool
	{
		$root = $this->site();
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$cookie = ['wordpress_logged_in_abc123' => 'x'];
		$probe = '?include=../../etc/passwd';
		
		return BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/' . $probe, $root . '/index.php'), [], $cookie) === null
			&& BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/wp-admin/admin-ajax.php' . $probe, $root . '/wp-admin/admin-ajax.php'), [], $cookie) === null
			&& BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/wp-admin/network/sites.php' . $probe, $root . '/wp-admin/network/sites.php'), [], $cookie) === null
			&& BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/' . $probe, $root . '/index.php'), [], ['wordpress_test_cookie' => 'WP Cookie check']) !== null;
	}
	
	/**
	 * RULE: a login cookie, or Basic credentials on a REST request, is a NAME
	 * anyone can send, and WordPress's mu-plugins, drop-ins and plugin files
	 * run before plugins_loaded: this layer still refuses what holds
	 * whoever asks — a match rule, a vpatch for anyone — judging the caller
	 * as one it cannot tell, and leaves to the adapter what waits on who (a
	 * vpatch for anonymous callers) unjudged, a rate rule uncounted. Falsify:
	 * step aside for the cookie — `Cookie: wordpress_logged_in_x=1` walks a
	 * blocked exploit past this layer to code that runs before the adapter.
	 */
	public function aLoginCookieOrBasicCredentialsSkipNoBlockForAnyone(): bool
	{
		$rules = [
			['id' => 7, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'ua', 'op' => 'contains', 'value' => 'zz-prepend-bot', 'ci' => true, 'mode' => 'proven', 'expires_at' => null],
			['id' => 41, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'proven', 'expires_at' => null,
				'who' => 'anonymous', 'conditions' => [['target' => 'query:action', 'test' => 'equals', 'value' => 'fx_save']]],
			['id' => 42, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'uri', 'op' => 'prefix', 'value' => '/shop/', 'ci' => true,
				'mode' => 'proven', 'expires_at' => null, 'kind' => 'rate', 'rate' => ['key' => 'ip', 'limit' => 1, 'window' => 60]],
		];
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$root = $this->site();
		$apcu = function_exists('apcu_enabled') && apcu_enabled();
		BasePrepend::writeConsent($this->dir, ['root' => $root, 'prefix' => 'tests:prepend-deferred:' . uniqid()] + self::ENFORCE);
		$cookie = ['wordpress_logged_in_x' => '1'];
		$basic = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('x:y')];
		$ran = null;
		$bot = BasePrepend::judge($this->dir, $this->server(self::BOT, '/', $root . '/index.php'), [], $cookie, null, null, $ran);
		$botRan = $ran;
		$rest = BasePrepend::judge($this->dir, $basic + $this->server(self::BOT, '/wp-json/fx/v1/save', $root . '/index.php'));
		$anonymous = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/?action=fx_save', $root . '/index.php'), [], $cookie, null, null, $ran);
		$anonymousRan = $ran;
		// the same request without the cookie is the anonymous caller it is
		$plain = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/?action=fx_save', $root . '/index.php'));
		// two requests the adapter judges again count nothing here: the first one judged here is the rule's first
		$shop = fn(array $cookies): ?array => BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/shop/', $root . '/index.php'), [], $cookies);
		$deferred = [$shop($cookie), $shop($cookie)];
		$counted = [$shop([]), $shop([])];
		
		return ($bot['verdict'] ?? null)?->isBlock() === true && (int)$bot['verdict']->rule['id'] === 7 && $botRan === true
			&& ($rest['verdict'] ?? null)?->isBlock() === true
			&& $anonymous === null && $anonymousRan === false
			&& ($plain['verdict'] ?? null)?->isBlock() === true && (int)$plain['verdict']->rule['id'] === 41
			&& $deferred === [null, null]
			&& ($apcu === false || ($counted[0] === null && ($counted[1]['verdict'] ?? null)?->status() === 429));
	}
	
	/**
	 * RULE: past the ceiling this layer still refuses what a blocking rule
	 * matches, and lets pass what a rule that only observes matched — a site
	 * cut off from codesafe keeps its virtual patches before WordPress too —
	 * and the report says the ruleset is stale. Falsify: pass past the
	 * ceiling — a day without codesafe walks every exploit past the earliest
	 * layer.
	 */
	public function pastTheCeilingABlockingRuleStillRefuses(): bool
	{
		$rules = [
			['id' => 7, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'ua', 'op' => 'contains', 'value' => 'zz-prepend-bot', 'ci' => true, 'mode' => 'proven', 'expires_at' => null],
			['id' => 8, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'uri', 'op' => 'contains', 'value' => 'zz-observed', 'ci' => true, 'mode' => 'observe', 'expires_at' => null],
		];
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time() - Kernel::CEILING - 60, platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$root = $this->site();
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$bot = BasePrepend::judge($this->dir, $this->server(self::BOT, '/', $root . '/index.php'));
		$observed = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/zz-observed', $root . '/index.php'));
		
		return ($bot['verdict'] ?? null)?->isBlock() === true && (int)$bot['verdict']->rule['id'] === 7
			&& ($bot['report'][2]['tags'] ?? null) === ['stale'] && $observed === null;
	}
	
	/**
	 * M12: a login cookie's NAME is anyone's to send, and on a file WordPress
	 * never loads for no adapter will judge — so this layer does: a plugin's
	 * own PHP file, wp-admin's load-styles.php (no plugins), a file outside
	 * the site root, and any file while the root is unknown
	 */
	public function loginCookieDoesNotSkipAFileWordPressNeverLoadsFor(): bool
	{
		$root = $this->site();
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$cookie = ['wordpress_logged_in_abc123' => 'x'];
		$plugin = BasePrepend::judge($this->dir, $this->server(self::BOT, '/wp-content/plugins/some-plugin/file.php',
			$root . '/wp-content/plugins/some-plugin/file.php'), [], $cookie);
		$styles = BasePrepend::judge($this->dir, $this->server(self::BOT, '/wp-admin/load-styles.php', $root . '/wp-admin/load-styles.php'), [], $cookie);
		$outside = BasePrepend::judge($this->dir, $this->server(self::BOT, '/x.php', $this->dir . '/outside.php'), [], $cookie);
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		$unknownRoot = BasePrepend::judge($this->dir, $this->server(self::BOT, '/', $root . '/index.php'), [], $cookie);
		
		return $plugin !== null && $plugin['verdict']->isBlock()
			&& $styles !== null
			&& $outside !== null
			&& $unknownRoot !== null;
	}
	
	public function sameRuleWithoutBlockingBoxObserves(): bool
	{
		BasePrepend::writeConsent($this->dir, ['enforce' => false] + self::ENFORCE);
		$softened = BasePrepend::judge($this->dir, $this->server(self::BOT));
		
		return $softened !== null
			&& $softened['verdict']->outcome === Verdict::OBSERVE;
	}
	
	public function detectionOffIsNothing(): bool
	{
		BasePrepend::writeConsent($this->dir, ['detect' => false] + self::ENFORCE);
		
		return BasePrepend::judge($this->dir, $this->server(self::BOT)) === null;
	}
	
	public function killIsNothing(): bool
	{
		BasePrepend::writeConsent($this->dir, ['kill' => true] + self::ENFORCE);
		
		return BasePrepend::judge($this->dir, $this->server(self::BOT)) === null;
	}
	
	public function drainHandsQueuedBlocksOnWithTheLayerNamedThenIsEmpty(): bool
	{
		$handed = $this->queueTwoBlocksAndDrain($drained);
		
		return $drained === 2
			&& count($handed) === 2
			&& $handed[0][0] === Verdict::KIND_BLOCK
			&& ($handed[0][2]['layer'] ?? '') === 'prepend'
			&& ($handed[0][2]['rule'] ?? 0) === 7
			&& BasePrepend::drain($this->dir, static fn(): null => null) === 0;
	}
	
	/**
	 * Its uri, address, user agent, the 403 and the time
	 */
	public function queuedBlockCarriesTheRefusedRequestsOwnFacts(): bool
	{
		$context = $this->queueTwoBlocksAndDrain($drained)[0][3] ?? [];
		
		return ($context['uri'] ?? '') === '/wp-content/plugins/some-plugin/file.php'
			&& ($context['ip'] ?? '') === '203.0.113.9'
			&& ($context['ua'] ?? '') === self::BOT
			&& ($context['method'] ?? '') === 'GET'
			&& ($context['status'] ?? 0) === 403
			&& is_int($context['at'] ?? null)
			&& $context['at'] > time() - 60;
	}
	
	public function contextOfLeavesStatusOutWhenNoneDecided(): bool
	{
		return isset(BasePrepend::contextOf($this->server('x'), null)['status']) === false;
	}
	
	/**
	 * RULE: a refused request's facts are capped before the queue and the
	 * seen list hold them — the uri at CONTEXT_URI_MAX bytes, the user agent,
	 * the referer and the host at CONTEXT_FIELD_MAX — never inside a UTF-8
	 * character, so the file stays JSON. Falsify: keep them whole — 8 KB of
	 * each per hit grows the rewritten queue to megabytes, a cost the sender
	 * pays on every request it sends.
	 */
	public function contextOfCapsEveryField(): bool
	{
		$long = str_repeat('a', 9000);
		$server = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/' . $long, 'HTTP_USER_AGENT' => $long, 'HTTP_REFERER' => 'https://x.test/' . $long,
			'HTTP_HOST' => $long, 'REMOTE_ADDR' => '203.0.113.9'];
		$context = BasePrepend::contextOf($server, 403);
		// an umlaut across the cut: the whole character goes
		$umlaut = BasePrepend::contextOf(['HTTP_USER_AGENT' => str_repeat('a', BasePrepend::CONTEXT_FIELD_MAX - 1) . "\u{e4}x"], null);
		
		return strlen($context['uri']) === BasePrepend::CONTEXT_URI_MAX
			&& strlen($context['ua']) === BasePrepend::CONTEXT_FIELD_MAX
			&& strlen($context['referer']) === BasePrepend::CONTEXT_FIELD_MAX
			&& strlen($context['host']) === BasePrepend::CONTEXT_FIELD_MAX
			&& $umlaut['ua'] === str_repeat('a', BasePrepend::CONTEXT_FIELD_MAX - 1)
			&& json_encode($umlaut) !== false;
	}
	
	public function queueIsCappedAtQueueMaxOldestGoingFirst(): bool
	{
		for($i = 0; $i < BasePrepend::QUEUE_MAX + 5; $i++)
		{
			BasePrepend::queue($this->dir, [Verdict::KIND_BLOCK, 'shield rule 7 refused GET /' . $i, ['rule' => 7]]);
		}
		
		return BasePrepend::drain($this->dir, static fn(): null => null) === BasePrepend::QUEUE_MAX;
	}
	
	/**
	 * RULE: past QUEUE_MAX the oldest report that is no block goes, a block
	 * only when the queue holds nothing else: two blocks, then a cap's worth
	 * of observes — the blocks stay, the two oldest observes go; a queue full
	 * of blocks drops an observe met there, and a block met there takes the
	 * oldest block's place. Falsify: give up the oldest whatever its kind —
	 * a request queues up to four observes, and a few dozen observed
	 * requests between two drains push out the blocks Shield\Alarm reads.
	 */
	public function aFullQueueGivesUpObservesBeforeBlocks(): bool
	{
		$block = static fn(string $path): array => [Verdict::KIND_BLOCK, 'shield rule 7 refused GET /' . $path, ['rule' => 7]];
		$observe = static fn(string $path): array => [Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /' . $path, ['rule' => 8]];
		BasePrepend::queue($this->dir, $block('a'));
		BasePrepend::queue($this->dir, $block('b'));
		for($i = 0; $i < BasePrepend::QUEUE_MAX; $i++)
		{
			BasePrepend::queue($this->dir, $observe((string)$i));
		}
		$mixed = $this->drained();
		$late = [];
		foreach([$observe, $block] as $report)
		{
			for($i = 0; $i < BasePrepend::QUEUE_MAX; $i++)
			{
				BasePrepend::queue($this->dir, $block((string)$i));
			}
			BasePrepend::queue($this->dir, $report('late'));
			$late[] = $this->drained();
		}
		$messages = static fn(Closure $report, array $paths): array => array_map(static fn(int|string $path): string => $report((string)$path)[1], $paths);
		
		return $mixed === [...$messages($block, ['a', 'b']), ...$messages($observe, range(2, BasePrepend::QUEUE_MAX - 1))]
			&& $late[0] === $messages($block, range(0, BasePrepend::QUEUE_MAX - 1))
			&& $late[1] === [...$messages($block, range(1, BasePrepend::QUEUE_MAX - 1)), ...$messages($block, ['late'])];
	}
	
	public function claimHandsTheStashOnceAndSettleThenQueuesNothing(): bool
	{
		$observed = $this->observed();
		$GLOBALS[BasePrepend::STASH] = ['verdict' => $observed['verdict'], 'reports' => $observed['reports'], 'claimed' => false];
		$claimed = BasePrepend::claimAll();
		
		return $claimed === [$observed['report']]
			&& BasePrepend::claimAll() === [] && BasePrepend::claim() === null
			&& BasePrepend::settle($this->dir) === false
			&& BasePrepend::drain($this->dir, static fn(): null => null) === 0;
	}
	
	/**
	 * A request WordPress never loaded for leaves the stash to shutdown, which
	 * queues it with the status the request ended with
	 */
	public function settleQueuesTheUnclaimedObserveReportWithFactsAndStatus(): bool
	{
		$observed = $this->observed();
		$GLOBALS[BasePrepend::STASH] = ['verdict' => $observed['verdict'], 'reports' => $observed['reports'], 'claimed' => false];
		$settled = BasePrepend::settle($this->dir, $this->server('Mozilla/5.0', self::PROBE), 200);
		$handed = [];
		BasePrepend::drain($this->dir, static function(
			string $kind,
			string $message,
			array $extra,
			array $context,
		) use (&$handed): void
		{
			$handed[] = [$kind, $message, $extra, $context];
		});
		
		return $settled === true
			&& count($handed) === 1
			&& $handed[0][0] === Verdict::KIND_OBSERVE
			&& ($handed[0][2]['layer'] ?? '') === 'prepend'
			&& ($handed[0][2]['rule'] ?? 0) === 8
			&& ($handed[0][3]['uri'] ?? '') === self::PROBE
			&& ($handed[0][3]['status'] ?? 0) === 200;
	}
	
	public function withoutStashClaimAndSettleAreNothing(): bool
	{
		return BasePrepend::claim() === null && BasePrepend::claimAll() === []
			&& BasePrepend::settle($this->dir) === false;
	}
	
	/**
	 * RULE: an adapter older than this file claims one report (claim()): it
	 * gets the first stashed, in the one-report shape it reads, and the
	 * others stay for shutdown, which queues them for the site's next request;
	 * a stash of one is claimed whole. Falsify: claim the whole stash for the
	 * first report — while an upgrade has copied Prepend.php and not yet
	 * Adapter.php, every other rule's report of the request is lost.
	 */
	public function anOlderAdaptersClaimTakesTheFirstReportAndShutdownQueuesTheRest(): bool
	{
		$first = [Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /x.php', ['rule' => 8]];
		$second = [Verdict::KIND_OBSERVE, 'shield rule 9 observed GET /x.php', ['rule' => 9]];
		$GLOBALS[BasePrepend::STASH] = ['verdict' => new Verdict(Verdict::OBSERVE), 'reports' => [$first, $second], 'claimed' => false];
		$claimed = BasePrepend::claim();
		$settled = BasePrepend::settle($this->dir, $this->server('Mozilla/5.0', self::PROBE), 200);
		$handed = $this->drained();
		$GLOBALS[BasePrepend::STASH] = ['verdict' => new Verdict(Verdict::OBSERVE), 'reports' => [$first], 'claimed' => false];
		$alone = BasePrepend::claim();
		
		return $claimed === $first && $settled === true && $handed === ['shield rule 9 observed GET /x.php']
			&& $alone === $first && BasePrepend::settle($this->dir) === false;
	}
	
	/**
	 * RULE: a request two observing rules match before WordPress — which then
	 * never loads for it — leaves both reports: the layer's judgement keeps
	 * every report the kernel makes, the stash holds them, and settle() at
	 * shutdown queues each for the site's next request to drain. Falsify: let
	 * the layer's reporter keep one slot — the second rule's report is lost.
	 */
	public function twoObservingRulesQueueBothReports(): bool
	{
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => [
				['id' => 8, 'origin' => 'finding', 'finding' => 'f', 'cve' => 'CVE-2099-0001', 'field' => 'uri', 'op' => 'regex', 'value' => '[?&]include=[^&]*\.\./', 'ci' => true,
					'mode' => 'observe', 'expires_at' => null],
				['id' => 9, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'uri', 'op' => 'contains', 'value' => 'admin-ajax.php', 'ci' => true,
					'mode' => 'observe', 'expires_at' => null],
			],
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$observed = $this->observed();
		$GLOBALS[BasePrepend::STASH] = ['verdict' => $observed['verdict'], 'reports' => $observed['reports'], 'claimed' => false];
		$settled = BasePrepend::settle($this->dir, $this->server('Mozilla/5.0', self::PROBE), 200);
		$handed = [];
		BasePrepend::drain($this->dir, static function(
			string $kind,
			string $message,
			array $extra,
			array $context,
		) use (&$handed): void
		{
			$handed[] = [$kind, $extra['rule'] ?? 0, $context['status'] ?? 0];
		});
		
		return ($observed['report'][2]['rule'] ?? 0) === 8
			&& $settled === true
			&& $handed === [[Verdict::KIND_OBSERVE, 8, 200], [Verdict::KIND_OBSERVE, 9, 200]];
	}
	
	/**
	 * The stub names this plugin's Prepend.php, the interpreter accepts it, and
	 * a current one is left alone
	 */
	public function ensureStubWritesAnAcceptedStubAndLeavesCurrentOneAlone(): bool
	{
		$stub = BasePrepend::ensureStub($this->dir);
		$content = (string)file_get_contents($stub);
		$mtime = filemtime($stub);
		sleep(1);
		$again = BasePrepend::ensureStub($this->dir);
		exec(PHP_BINARY . ' -l ' . escapeshellarg($stub) . ' 2>&1', $output, $lint);
		
		return $stub === $this->dir . DIRECTORY_SEPARATOR . BasePrepend::STUB
			&& $lint === 0
			&& str_contains($content, str_replace('\\', '/', realpath(__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php')))
			&& str_contains($content, 'shield prepend v' . BasePrepend::STUB_VERSION)
			&& str_contains($content, 'Prepend::run(__DIR__)')
			&& $again === $stub
			&& filemtime($stub) === $mtime;
	}
	
	/** the stub guards its call with class_exists(): a name that is not this class leaves the layer silently off */
	public function stubChecksForTheClassItCalls(): bool
	{
		$content = (string)file_get_contents(BasePrepend::ensureStub($this->dir));
		
		return str_contains($content, "class_exists('" . str_replace('\\', '\\\\', BasePrepend::class) . "', false)")
			&& str_contains($content, '\\' . BasePrepend::class . '::run(__DIR__)');
	}
	
	/**
	 * The stub ovos-console left, which a site's PHP configuration may still
	 * name: written where it is, judging against the new store directory
	 */
	public function legacyStubRunsThisPluginAgainstTheNewStore(): bool
	{
		mkdir($this->dir . DIRECTORY_SEPARATOR . 'ovos-console');
		$legacy = $this->dir . DIRECTORY_SEPARATOR . 'ovos-console' . DIRECTORY_SEPARATOR . 'prepend.php';
		$stub = BasePrepend::ensureStub($this->dir, $legacy);
		$content = (string)file_get_contents($stub);
		$mtime = filemtime($stub);
		sleep(1);
		$again = BasePrepend::ensureStub($this->dir, $legacy);
		exec(PHP_BINARY . ' -l ' . escapeshellarg($stub) . ' 2>&1', $output, $lint);
		
		return $stub === $legacy
			&& $lint === 0
			&& str_contains($content, '::run(' . var_export($this->dir, true) . ')')
			&& $again === $legacy
			&& filemtime($stub) === $mtime
			&& BasePrepend::status($this->dir, $legacy, $legacy)['state'] === 'legacy'
			&& BasePrepend::status($this->dir, $legacy)['state'] === 'other';
	}
	
	/**
	 * RULE: a new setup gets codesafe-shield.php — named for the product and
	 * its job — and the two lines the settings page prints name it; no
	 * prepend.php appears. Falsify: keep the bare prepend.php as the name —
	 * the directive an operator pastes reads as malware persistence.
	 */
	public function aNewSetupWritesTheNamedStub(): bool
	{
		$stub = BasePrepend::ensureStub($this->dir);
		$lines = BasePrepend::lines($this->dir);
		
		return basename($stub) === 'codesafe-shield.php' && is_file($stub)
			&& is_file($this->dir . DIRECTORY_SEPARATOR . 'prepend.php') === false
			&& str_ends_with($lines['ini'], DIRECTORY_SEPARATOR . 'codesafe-shield.php"')
			&& str_ends_with($lines['htaccess'], DIRECTORY_SEPARATOR . 'codesafe-shield.php"');
	}
	
	/**
	 * RULE: a configuration still naming the store's prepend.php is `legacy`
	 * — live, the file it names reported — and the plugin keeps that file
	 * current, rewritten when it is out of date and judging against the data
	 * beside it (`__DIR__`, as the scan expects). Falsify: leave the store's
	 * own old name out of status() — the site reads `other` and the hello
	 * says no layer.
	 */
	public function aConfigurationNamingTheOldStubKeepsItCurrent(): bool
	{
		$old = $this->dir . DIRECTORY_SEPARATOR . 'prepend.php';
		file_put_contents($old, "<?php\n// ovos codesafe shield prepend v0 — an older plugin's\n");
		$status = BasePrepend::status($this->dir, $old);
		$rewritten = BasePrepend::tendOldStub($this->dir, $this->dir, $status);
		$content = (string)file_get_contents($old);
		
		return $status['state'] === 'legacy' && $status['named'] === $old
			&& BasePrepend::status($this->dir, str_replace('/', '\\', $old))['state'] === 'legacy'
			&& $rewritten === 'kept'
			&& str_contains($content, 'shield prepend v' . BasePrepend::STUB_VERSION)
			&& str_contains($content, 'Prepend::run(__DIR__)');
	}
	
	/**
	 * RULE: the store's prepend.php is kept current while it is there, whatever
	 * this request's configuration names — the new stub, nothing, another
	 * file — and never deleted: another directory's php.ini or .user.ini may
	 * still name it, and PHP fails every request there once it is gone. A
	 * file by that name the plugin did not write is left as it is. Falsify:
	 * tend the old stub only while this request's configuration names it —
	 * a site that moved the root's line runs wp-admin through a stale stub;
	 * delete it once the new stub is named — wp-admin fails on a missing
	 * prepend file; drop the marker check — a host's own file is overwritten.
	 */
	public function anOldStubNoLongerNamedIsKeptCurrentNeverDeleted(): bool
	{
		$stub = BasePrepend::ensureStub($this->dir);
		$old = $this->dir . DIRECTORY_SEPARATOR . 'prepend.php';
		$seen = [];
		foreach([$stub, '', '/srv/wordfence-waf.php'] as $ini)
		{
			file_put_contents($old, "<?php\n// ovos codesafe shield prepend v0 — an older plugin's\n");
			$seen[] = BasePrepend::tendOldStub($this->dir, $this->dir, BasePrepend::status($this->dir, $ini));
			$content = is_file($old) ? (string)file_get_contents($old) : '';
			$seen[] = str_contains($content, 'shield prepend v' . BasePrepend::STUB_VERSION) && str_contains($content, 'Prepend::run(__DIR__)');
		}
		file_put_contents($old, "<?php\n// a host's own file\n");
		$foreign = BasePrepend::tendOldStub($this->dir, $this->dir, BasePrepend::status($this->dir, $stub));
		
		return $seen === ['kept', true, 'kept', true, 'kept', true]
			&& $foreign === '' && file_get_contents($old) === "<?php\n// a host's own file\n"
			&& is_file($stub);
	}
	
	public function olderStubIsRewritten(): bool
	{
		$stub = BasePrepend::ensureStub($this->dir);
		file_put_contents($stub, "<?php\n// ovos codesafe shield prepend v0 — an older plugin's\n");
		BasePrepend::ensureStub($this->dir);
		
		return str_contains((string)file_get_contents($stub), 'shield prepend v' . BasePrepend::STUB_VERSION);
	}
	
	public function statusReadsInactiveActiveAndOther(): bool
	{
		$stub = BasePrepend::ensureStub($this->dir);
		
		return BasePrepend::status($this->dir, '')['state'] === 'inactive'
			&& BasePrepend::status($this->dir, 'none')['state'] === 'inactive'
			&& BasePrepend::status($this->dir, $stub)['state'] === 'active'
			&& BasePrepend::status($this->dir, str_replace('/', '\\', $stub))['state'] === 'active'
			&& BasePrepend::status($this->dir, '/srv/wordfence-waf.php')['state'] === 'other'
			&& BasePrepend::lines($this->dir)['htaccess'] === 'php_value auto_prepend_file "' . $stub . '"';
	}
	
	/**
	 * A rate rule on wp-login.php keyed by the login name: the spray against
	 * one account from many addresses trips it, another name does not, a
	 * request that is not a login POST is not counted, and a proven rule
	 * under enforce is a 429 with the seconds to the window's end. Counting
	 * needs APCu — the consent's prefix names it; without one the rule is
	 * skipped and the request passes.
	 */
	public function rateRuleOnTheLoginCountsTheNameTriedAndIsA429(): bool
	{
		if(function_exists('apcu_enabled') === false || apcu_enabled() === false)
		{
			throw new SkipException('APCu is not enabled for this SAPI (apc.enable_cli).');
		}
		$rules = [['id' => 9, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'uri', 'op' => 'prefix', 'value' => '/wp-login.php',
			'ci' => true, 'mode' => 'proven', 'expires_at' => null, 'kind' => 'rate', 'rate' => ['key' => 'user', 'limit' => 2, 'window' => 60]]];
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		BasePrepend::writeConsent($this->dir, ['prefix' => 'tests:prepend-rate:' . uniqid()] + self::ENFORCE);
		$login = fn(string $ip, string $name): ?array => BasePrepend::judge($this->dir,
			['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/wp-login.php', 'HTTP_USER_AGENT' => 'Mozilla/5.0', 'REMOTE_ADDR' => $ip],
			['log' => $name, 'pwd' => 'x']);
		
		$spray = [$login('198.51.100.1', 'admin'), $login('198.51.100.2', 'Admin '), $login('198.51.100.3', 'admin')];
		$other = $login('198.51.100.4', 'editor');
		$page = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/wp-login.php'));
		$limited = $spray[2]['verdict'] ?? null;
		
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		$withoutApcu = true;
		for($i = 0; $i < 4; $i++)
		{
			$withoutApcu = $withoutApcu && $login('198.51.100.5', 'admin') === null;
		}
		
		return $spray[0] === null && $spray[1] === null
			&& $limited !== null && $limited->isBlock() && $limited->status() === 429 && $limited->kind() === Verdict::KIND_RATE
			&& $limited->retryAfter >= 1 && $limited->retryAfter <= 60
			&& ($spray[2]['report'][0] ?? '') === Verdict::KIND_RATE
			&& $other === null && $page === null
			&& $withoutApcu
			&& BasePrepend::loginName(['REQUEST_URI' => '/wp-login.php?action=login'], ['log' => ' Anna ']) === 'login:anna'
			&& BasePrepend::loginName(['REQUEST_URI' => '/wp-admin/'], ['log' => 'anna']) === ''
			&& BasePrepend::loginName(['REQUEST_URI' => '/wp-login.php'], []) === '';
	}
	
	// ---- the store's files (M13) ---------------------------------------------
	
	/**
	 * Every file the layer and the plugin write opens with the PHP exit: run
	 * by a web server that ignores the .htaccess, it prints nothing — the
	 * consent, the queue, the known set and the seen list alike
	 */
	public function everyStoreFileIsGuardedAndPrintsNothingWhenRun(): bool
	{
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		BasePrepend::queue($this->dir, [Verdict::KIND_BLOCK, 'shield rule 7 refused GET /', ['rule' => 7]], ['ip' => '203.0.113.9']);
		BasePrepend::writeKnown($this->dir, '6.8', '1.0.3', ['wp-admin/index.php' => 'core']);
		BasePrepend::forget($this->dir, []);
		$printed = '';
		foreach([BasePrepend::CONSENT, BasePrepend::QUEUE, BasePrepend::ENTRIES, BasePrepend::SEEN] as $name)
		{
			$path = $this->dir . DIRECTORY_SEPARATOR . $name;
			if(str_starts_with((string)file_get_contents($path), BasePrepend::GUARD) === false || str_ends_with($name, '.php') === false)
			{
				return false;
			}
			$output = [];
			exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($path), $output);
			$printed .= implode('', $output);
		}
		
		return $printed === ''
			&& BasePrepend::consent($this->dir)['detect'] === true
			&& BasePrepend::known($this->dir)['known'] === ['wp-admin/index.php' => 'core']
			&& BasePrepend::drain($this->dir, static fn(): null => null) === 1;
	}
	
	/**
	 * The kernel writes its ruleset as plain JSON, so its NAME is what keeps
	 * it from the web: drawn at random the first time, kept on every rewrite,
	 * never the old fixed shield.json
	 */
	public function theRulesetsNameIsDrawnOnceAndKept(): bool
	{
		$consent = self::ENFORCE;
		unset($consent['rules']);
		BasePrepend::writeConsent($this->dir, $consent);
		$drawn = BasePrepend::consent($this->dir)['rules'];
		BasePrepend::writeConsent($this->dir, ['enforce' => false] + $consent);
		$kept = BasePrepend::consent($this->dir)['rules'];
		
		return preg_match(BasePrepend::RULES_PATTERN, $drawn) === 1
			&& $drawn !== BasePrepend::RULES
			&& $kept === $drawn
			&& BasePrepend::rules($this->dir) === $this->dir . DIRECTORY_SEPARATOR . $drawn;
	}
	
	/**
	 * 1.0.2's plain-JSON store, brought over: the queue and the seen list keep
	 * what was not sent yet, the ruleset is renamed to the drawn name, and no
	 * old file is left for a web server to serve
	 */
	public function migrateBringsThe102StoreBehindTheGuard(): bool
	{
		$old = $this->dir . DIRECTORY_SEPARATOR;
		$rules = (string)file_get_contents($old . self::RULES_NAME);
		unlink($old . self::RULES_NAME);
		file_put_contents($old . 'shield.json', $rules);
		file_put_contents($old . 'shield-consent.json', '{"detect":true}');
		file_put_contents($old . 'shield-reports.json', '[{"kind":"shield_block","message":"m","extra":{"rule":7},"context":{"ip":"203.0.113.9"}}]');
		file_put_contents($old . 'entries-seen.json', '{"paths":{"evil.php":{"n":1}},"dropped":0}');
		file_put_contents($old . 'entries.json', '{"core":"6.8","plugin":"1.0.2","known":{"wp-admin/index.php":"core"}}');
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		$moved = BasePrepend::migrate($this->dir);
		$left = glob($old . '*.json');
		
		return $moved === 5
			&& $left === [$old . self::RULES_NAME]
			&& file_get_contents($old . self::RULES_NAME) === $rules
			&& BasePrepend::judge($this->dir, $this->server(self::BOT)) !== null
			&& isset(BasePrepend::seen($this->dir)['paths']['evil.php'])
			&& BasePrepend::known($this->dir)['plugin'] === '1.0.2'
			&& BasePrepend::drain($this->dir, static fn(): null => null) === 1;
	}
	
	/** CODESAFE_STORE_DIR: the data carried to the new directory, the stub's directory emptied of it */
	public function migrateCarriesTheStoreToAnotherDirectory(): bool
	{
		$to = $this->dir . DIRECTORY_SEPARATOR . 'outside';
		mkdir($to);
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		BasePrepend::queue($this->dir, [Verdict::KIND_BLOCK, 'm', ['rule' => 7]], []);
		BasePrepend::writeConsent($to, self::ENFORCE);
		$moved = BasePrepend::migrate($this->dir, $to);
		
		return $moved === 3
			&& is_file($this->dir . DIRECTORY_SEPARATOR . BasePrepend::CONSENT) === false
			&& is_file($this->dir . DIRECTORY_SEPARATOR . BasePrepend::QUEUE) === false
			&& is_file($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME) === false
			&& is_file($to . DIRECTORY_SEPARATOR . self::RULES_NAME)
			&& BasePrepend::drain($to, static fn(): null => null) === 1;
	}
	
	/**
	 * The uri a queued report carries is scrubbed BEFORE the file holds it: a
	 * password-reset key never reaches the disk, encoded or carried inside a
	 * redirect. The login name and the e-mail stay as written since 1.0.6 —
	 * codesafe masks them on arrival and keeps the original for a reveal
	 */
	public function aQueuedUriIsScrubbedBeforeItIsWritten(): bool
	{
		$uri = '/wp-login.php?action=rp&key=Zx9SecretResetKey20&login=marcin&email=john.doe%40example.com&rp_key=Other1Secret'
			. '&%74oken%3DEncodedSecret9&redirect_to=https%3A%2F%2Fsite.test%2F%3Fpwd%3DNestedSecret8';
		$server = ['HTTP_REFERER' => 'https://site.test/?pass=hunter2&user=john.doe@example.com'] + $this->server(self::BOT, $uri);
		BasePrepend::queue($this->dir, [Verdict::KIND_BLOCK, 'm', ['rule' => 7]], BasePrepend::contextOf($server, 403));
		$raw = (string)file_get_contents($this->dir . DIRECTORY_SEPARATOR . BasePrepend::QUEUE);
		$context = BasePrepend::contextOf($server, 403);
		
		return str_contains($raw, 'Zx9SecretResetKey20') === false
			&& str_contains($raw, 'Other1Secret') === false
			&& str_contains($raw, 'hunter2') === false
			&& str_contains($raw, 'EncodedSecret9') === false
			&& str_contains($raw, 'NestedSecret8') === false
			&& $context['uri'] === '/wp-login.php?action=rp&key=[redacted]&login=marcin&email=john.doe%40example.com&rp_key=[redacted]'
				. '&token=[redacted]&redirect_to=https%3A%2F%2Fsite.test%2F%3Fpwd%3D[redacted]'
			&& $context['referer'] === 'https://site.test/?pass=[redacted]&user=john.doe@example.com';
	}
	
	/**
	 * The layer restates the Redactor's lists and its query scrub — it may
	 * load no other class — so the copies are held to the originals here: a
	 * name added to one and not the other, or a decoding rule, fails this, not
	 * a site. On a query the two answer alike; the path is the Redactor's
	 * alone (token-shaped segments, on the drain)
	 */
	public function theLayersCopiesOfTheRedactorsListsAreTheRedactors(): bool
	{
		$redactor = new ReflectionClass(Redactor::class);
		$corpus = [
			'/wp-login.php?action=rp&key=K9&login=marcin&email=john.doe%40example.com',
			'/?%74oken=abc&a=1',
			'/?token%3Dabc&b=2',
			'/?x=1&%2574oken%253Dabc',
			'/wp-login.php?redirect_to=https%3A%2F%2Fsite.test%2Fwp-admin%2F%3Fpwd%3Dhunter2%26user%3Dmarcin',
			'/?redirect_to=%2Fwp-admin%2F%3Faction%3Dx%26_wpnonce%3Dabc123',
			'/?opts[api_key]=x&opts[name]=y&card_number=4111',
			'/?q=a%3Db&empty=&&lone',
			'/?pass=x#frag',
			'/plain/path',
			'',
		];
		foreach($corpus as $uri)
		{
			if(BasePrepend::scrubUri($uri) !== Redactor::scrubUrl($uri, identities: false))
			{
				return false;
			}
		}
		
		return BasePrepend::SECRET_NAMES === $redactor->getConstant('SECRET_NAMES')
			&& BasePrepend::QUERY_NAMES === Redactor::QUERY_NAMES;
	}
	
	// ---- the visitor's address (M5) -----------------------------------------
	
	/**
	 * REMOTE_ADDR unless a header is named AND REMOTE_ADDR is a trusted proxy;
	 * a list is walked from the right past the trusted hops; anything that is
	 * not an address falls back
	 */
	public function clientIpTakesTheHeaderOnlyFromATrustedProxy(): bool
	{
		$cf = ['REMOTE_ADDR' => '173.245.48.7', 'HTTP_CF_CONNECTING_IP' => '198.51.100.23'];
		$spoof = ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_CF_CONNECTING_IP' => '198.51.100.23'];
		$chain = ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '192.0.2.66, 198.51.100.23, 10.0.0.7'];
		$ranges = ['173.245.48.0/20', '10.0.0.0/8'];
		
		return BasePrepend::clientIp($cf) === '173.245.48.7'
			&& BasePrepend::clientIp($cf, 'CF-Connecting-IP') === '173.245.48.7'
			&& BasePrepend::clientIp($cf, 'CF-Connecting-IP', $ranges) === '198.51.100.23'
			&& BasePrepend::clientIp($spoof, 'CF-Connecting-IP', $ranges) === '203.0.113.9'
			&& BasePrepend::clientIp($chain, 'X-Forwarded-For', $ranges) === '198.51.100.23'
			&& BasePrepend::clientIp(['HTTP_X_FORWARDED_FOR' => 'not-an-ip'] + $chain, 'X-Forwarded-For', $ranges) === '10.0.0.2'
			&& BasePrepend::clientIp(['HTTP_X_FORWARDED_FOR' => '[2001:db8::5]:443'] + $chain, 'X-Forwarded-For', $ranges) === '2001:db8::5'
			&& BasePrepend::clientIp(['HTTP_CF_CONNECTING_IP' => ''] + $cf, 'CF-Connecting-IP', $ranges) === '173.245.48.7';
	}
	
	/**
	 * The layer judges and queues with the address the consent's proxy names:
	 * an ip rule on the visitor matches behind the proxy, and the queued row
	 * carries the visitor, not the edge
	 */
	public function theLayerJudgesAndQueuesTheForwardedVisitor(): bool
	{
		$rules = [['id' => 11, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'ip', 'op' => 'cidr', 'value' => '198.51.100.0/24',
			'ci' => true, 'mode' => 'proven', 'expires_at' => null]];
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$server = ['REMOTE_ADDR' => '173.245.48.7', 'HTTP_CF_CONNECTING_IP' => '198.51.100.23'] + $this->server('Mozilla/5.0', '/');
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		$direct = BasePrepend::judge($this->dir, $server);
		BasePrepend::writeConsent($this->dir, ['proxy_header' => 'CF-Connecting-IP', 'proxies' => ['173.245.48.0/20']] + self::ENFORCE);
		$proxied = BasePrepend::judge($this->dir, $server);
		$consent = BasePrepend::consent($this->dir);
		$ip = BasePrepend::clientIp($server, $consent['proxy_header'], $consent['proxies']);
		
		return $direct === null
			&& $proxied !== null && $proxied['verdict']->isBlock()
			&& BasePrepend::contextOf($server, 403, $ip)['ip'] === '198.51.100.23'
			&& BasePrepend::contextOf($server, 403)['ip'] === '173.245.48.7';
	}
	
	/**
	 * RULE: the mu-plugin (ovos/codesafe docs/plans/shield-auto-deploy.md P7.g)
	 * is written once into a directory it makes, lints, names this layer's
	 * Prepend.php and store and a Plugin Name, is left alone while current
	 * and rewritten when not; a file by its name it did not write is never
	 * overwritten nor removed, its own is removed. Falsify: overwrite any file
	 * by that name — a site's own mu-plugin of that name is gone on the
	 * plugin's next request.
	 */
	public function theMuPluginIsKeptCurrentAndNeverOverAnotherFile(): bool
	{
		$mu = $this->dir . DIRECTORY_SEPARATOR . 'mu-plugins';
		$path = BasePrepend::ensureMuPlugin($this->dir, $mu);
		$first = is_file($path) ? (string)file_get_contents($path) : '';
		exec(PHP_BINARY . ' -l ' . escapeshellarg($path) . ' 2>&1', $output, $lint);
		$mtime = filemtime($path);
		sleep(1);
		$kept = BasePrepend::ensureMuPlugin($this->dir, $mu) === $path && filemtime($path) === $mtime;
		file_put_contents($path, str_replace(var_export($this->dir, true), var_export('/elsewhere', true), $first));
		$rewritten = BasePrepend::ensureMuPlugin($this->dir, $mu) === $path && (string)file_get_contents($path) === $first;
		
		$foreign = $this->dir . DIRECTORY_SEPARATOR . 'mu-foreign';
		mkdir($foreign, 0700, true);
		$theirs = $foreign . DIRECTORY_SEPARATOR . BasePrepend::MU_PLUGIN;
		file_put_contents($theirs, "<?php // a site's own\n");
		$untouched = BasePrepend::ensureMuPlugin($this->dir, $foreign) === ''
			&& BasePrepend::removeMuPlugin($foreign) === false
			&& (string)file_get_contents($theirs) === "<?php // a site's own\n";
		
		return $path === $mu . DIRECTORY_SEPARATOR . BasePrepend::MU_PLUGIN
			&& $lint === 0
			&& str_contains($first, 'Plugin Name:')
			&& str_contains($first, BasePrepend::MU_MARKER . ' v' . BasePrepend::MU_VERSION)
			&& str_contains($first, str_replace('\\', '/', realpath(__DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php')))
			&& str_contains($first, 'Prepend::run(' . var_export($this->dir, true) . ')')
			&& str_contains($first, 'PHP_VERSION_ID >= 80300')
			&& $kept && $rewritten && $untouched
			&& BasePrepend::removeMuPlugin($mu) && is_file($path) === false
			&& BasePrepend::removeMuPlugin($mu) === false;
	}
	
	/**
	 * RULE: judge() says whether the kernel judged the request — true for a
	 * request it judged, a passed one included; false where the layer left it
	 * alone (no consent, a login cookie where WordPress runs). run() reads it
	 * to tell the plugins_loaded adapter not to judge a passed request again.
	 * Falsify: answer true for a signed-in request — the adapter skips it and
	 * nothing judges it at all.
	 */
	public function theJudgeSaysWhetherItJudged(): bool
	{
		$root = $this->site();
		$without = null;
		BasePrepend::judge($this->dir, $this->server(self::BOT), [], [], null, null, $without);
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$passed = null;
		$plain = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/', $root . '/index.php'), [], [], null, null, $passed);
		$blocked = null;
		BasePrepend::judge($this->dir, $this->server(self::BOT), [], [], null, null, $blocked);
		$signedIn = null;
		BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/?include=../../etc/passwd', $root . '/index.php'), [], ['wordpress_logged_in_abc123' => 'x'],
			null, null, $signedIn);
		
		return $without === false && $plain === null && $passed === true && $blocked === true && $signedIn === false;
	}
	
	/**
	 * RULE: what a REST request carrying Basic credentials to a file
	 * WordPress runs through waits on — a rule for anonymous callers — is the
	 * plugins_loaded judge's, not this layer's: an application password makes
	 * it a user's only once WordPress checks it — whether the server parsed
	 * the credentials or the header still holds them, addressed by path or by
	 * rest_route, under the REST prefix the consent keeps; anything else is
	 * judged here as before. Falsify: judge it as anonymous — an
	 * integration's REST call is refused before WordPress could tell who it is.
	 */
	public function aRestRequestWithBasicCredentialsIsLeftToTheAdapter(): bool
	{
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => [['id' => 43, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'proven', 'expires_at' => null,
				'who' => 'anonymous', 'conditions' => [['target' => 'query:probe', 'test' => 'equals', 'value' => '1']]]],
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$root = $this->site();
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$basic = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('integration:abcd 1234')];
		$request = fn(string $uri, array $extra = [], string $script = '/index.php'): array => $extra + $this->server('Mozilla/5.0', $uri, $root . $script);
		$ran = null;
		$header = BasePrepend::judge($this->dir, $request('/wp-json/fx/v1/save?probe=1', $basic), [], [], null, null, $ran);
		$headerRan = $ran;
		$parsed = BasePrepend::judge($this->dir, $request('/wp-json/fx/v1/save?probe=1', ['PHP_AUTH_USER' => 'integration', 'PHP_AUTH_PW' => 'abcd']));
		$route = BasePrepend::judge($this->dir, $request('/?rest_route=/fx/v1/save&probe=1', $basic));
		$posted = BasePrepend::judge($this->dir, $request('/?probe=1', $basic), ['rest_route' => '/fx/v1/save']);
		$without = BasePrepend::judge($this->dir, $request('/wp-json/fx/v1/save?probe=1'));
		$page = BasePrepend::judge($this->dir, $request('/shop/?probe=1', $basic));
		$file = BasePrepend::judge($this->dir, $request('/wp-content/plugins/some-plugin/file.php/wp-json/x?probe=1', $basic,
			'/wp-content/plugins/some-plugin/file.php'));
		// the site's own prefix: /api/ is the REST API, /wp-json/ no longer is
		BasePrepend::writeConsent($this->dir, ['root' => $root, 'rest_prefix' => 'api'] + self::ENFORCE);
		$custom = BasePrepend::judge($this->dir, $request('/api/fx/v1/save?probe=1', $basic));
		$default = BasePrepend::judge($this->dir, $request('/wp-json/fx/v1/save?probe=1', $basic));
		
		return $header === null && $headerRan === false
			&& $parsed === null && $route === null && $posted === null
			&& ($without['verdict'] ?? null)?->isBlock() === true
			&& ($page['verdict'] ?? null)?->isBlock() === true
			&& ($file['verdict'] ?? null)?->isBlock() === true
			&& $custom === null
			&& ($default['verdict'] ?? null)?->isBlock() === true;
	}
	
	/**
	 * RULE: wp-admin's installer and upgrader and the network's activation
	 * page define WP_INSTALLING, under which WordPress loads no site plugin:
	 * no adapter will judge them, so this layer does, a login cookie or not;
	 * the rest of wp-admin and the root entries load WordPress whole.
	 * Falsify: count them as loading WordPress — a login cookie's NAME walks
	 * an exploit past both layers on install.php.
	 */
	public function theInstallerAndTheActivationPageLoadNoPlugins(): bool
	{
		$root = $this->site();
		foreach(['wp-admin/install.php', 'wp-admin/upgrade.php', 'wp-admin/setup-config.php', 'wp-activate.php'] as $file)
		{
			file_put_contents($root . '/' . $file, "<?php\n");
			if(BasePrepend::loadsWordPress(['SCRIPT_FILENAME' => $root . '/' . $file], $root))
			{
				return false;
			}
		}
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$observed = BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', '/wp-admin/install.php?include=../../etc/passwd', $root . '/wp-admin/install.php'), [],
			['wordpress_logged_in_x' => '1']);
		
		return BasePrepend::loadsWordPress(['SCRIPT_FILENAME' => $root . '/wp-admin/admin-ajax.php'], $root)
			&& BasePrepend::loadsWordPress(['SCRIPT_FILENAME' => $root . '/index.php'], $root)
			&& ($observed['verdict'] ?? null)?->outcome === Verdict::OBSERVE;
	}
	
	/**
	 * RULE: the layer hands the kernel the host's request bag ($_REQUEST)
	 * beside the query and the form, so a request: rule meets a value a
	 * cookie put there. Falsify: build the facts without it — a handler that
	 * reads $_REQUEST before WordPress rebuilds it gets the cookie's value
	 * past the rule.
	 */
	public function theRequestBagReachesTheKernel(): bool
	{
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => [['id' => 44, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'proven', 'expires_at' => null,
				'who' => 'anyone', 'conditions' => [['target' => 'path', 'test' => 'suffix', 'value' => '/file.php'],
				['target' => 'request:action', 'test' => 'equals', 'value' => 'fx_delete']]]],
		], time(), platforms: BasePrepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		$server = $this->server('Mozilla/5.0', '/wp-content/plugins/some-plugin/file.php?action=benign');
		$bag = BasePrepend::judge($this->dir, $server, [], ['action' => 'fx_delete'], null, null, $ran, ['action' => 'benign'], [], null, ['action' => 'fx_delete']);
		$none = BasePrepend::judge($this->dir, $server, [], ['action' => 'fx_delete'], null, null, $ran, ['action' => 'benign']);
		
		return ($bag['verdict'] ?? null)?->isBlock() === true && $none === null;
	}
	
	/**
	 * RULE: the consent carries the site's REST prefix — read back without its
	 * slashes, wp-json from a consent that never had one — and a writer that
	 * does not know it (the plugin before plugins_loaded, the deactivation)
	 * keeps the one there. Falsify: default it on every write — the early
	 * layers lose a custom prefix on the next request.
	 */
	public function theConsentCarriesTheRestPrefixAndKeepsIt(): bool
	{
		$consent = self::ENFORCE;
		unset($consent['rest_prefix']);
		BasePrepend::write($this->dir . DIRECTORY_SEPARATOR . BasePrepend::CONSENT, $consent);
		$older = BasePrepend::consent($this->dir)['rest_prefix'];
		$unchanged = BasePrepend::writeConsent($this->dir, $consent);
		$written = BasePrepend::writeConsent($this->dir, ['rest_prefix' => '/api/v2/'] + $consent);
		$read = BasePrepend::consent($this->dir)['rest_prefix'];
		$kept = BasePrepend::writeConsent($this->dir, $consent);
		$changed = BasePrepend::writeConsent($this->dir, ['enforce' => false] + $consent);
		
		return $older === 'wp-json' && $unchanged === false
			&& $written === true && $read === 'api/v2'
			&& $kept === false
			&& $changed === true && BasePrepend::consent($this->dir)['rest_prefix'] === 'api/v2';
	}
	
	/**
	 * RULE: writeRestPrefix() rewrites the consent only when the prefix changed
	 * — a slash more or less is no change — keeps everything else in it, and
	 * writes nothing where there is no consent yet. Falsify: write on every
	 * call — the init hook writes a file on every request.
	 */
	public function theRestPrefixIsWrittenOnlyWhenItChanged(): bool
	{
		$none = BasePrepend::writeRestPrefix($this->dir, 'api');
		$noFile = is_file($this->dir . DIRECTORY_SEPARATOR . BasePrepend::CONSENT) === false;
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		$same = BasePrepend::writeRestPrefix($this->dir, 'wp-json');
		$slashed = BasePrepend::writeRestPrefix($this->dir, '/wp-json/');
		$changed = BasePrepend::writeRestPrefix($this->dir, 'api');
		$again = BasePrepend::writeRestPrefix($this->dir, 'api/');
		$expected = self::ENFORCE;
		$expected['rest_prefix'] = 'api';
		
		return $none === false && $noFile
			&& $same === false && $slashed === false
			&& $changed === true && $again === false
			&& BasePrepend::consent($this->dir) === $expected;
	}
	
	// ---- the guard: WordPress's update working directories -------------------
	
	/**
	 * RULE: a script under wp-content/upgrade/ or upgrade-temp-backup/ is
	 * refused before any rule, measured on its resolved path — a staged core
	 * copy, a parked plugin, one reached through `..`, the content directory
	 * spelled in another case — and reported as a shield_block with the
	 * guard's fixed message and its path below the content directory. A
	 * plugin's file, upgrade.php beside the directory, a directory merely
	 * starting with its name, a file outside the site, a missing file and an
	 * unknown content directory are left to the rules. Falsify: compare the
	 * top directory as a prefix — upgraded/ is refused; compare with case —
	 * the content directory spelled in upper case lets the staged copy run.
	 */
	public function theGuardRefusesAScriptInTheUpgradeWorkingDirectories(): bool
	{
		$root = $this->site();
		$content = $root . '/wp-content';
		$consent = ['content' => $content] + self::ENFORCE;
		$staged = $this->stage($root, self::STAGED);
		$parked = $this->stage($root, 'wp-content/upgrade-temp-backup/plugins/akismet/akismet.php');
		$beside = $this->stage($root, 'wp-content/upgrade.php');
		$prefixed = $this->stage($root, 'wp-content/upgraded/x.php');
		$guard = static fn(string $script, array $with = []): ?array => BasePrepend::guard(['SCRIPT_FILENAME' => $script], $with + $consent);
		$refused = $guard($staged);
		
		return $refused !== null && $refused['block'] === true
			&& $refused['report'] === [Verdict::KIND_BLOCK, BasePrepend::GUARD_REFUSED,
				['guard' => 'upgrade_dir', 'action' => 'upgrade_dir', 'matched' => 'upgrade/wordpress-7.1.3-a1b2c3/wordpress/wp-admin/setup-config.php']]
			&& ($guard($parked)['report'][2]['matched'] ?? '') === 'upgrade-temp-backup/plugins/akismet/akismet.php'
			&& ($guard($content . '/plugins/../upgrade/wordpress-7.1.3-a1b2c3/wordpress/wp-admin/setup-config.php')['block'] ?? false) === true
			&& ($guard($staged, ['content' => strtoupper($content)])['block'] ?? false) === true
			&& $guard($root . '/wp-content/plugins/some-plugin/file.php') === null
			&& $guard($beside) === null
			&& $guard($prefixed) === null
			&& $guard($this->dir . DIRECTORY_SEPARATOR . 'outside.php') === null
			&& $guard($content . '/upgrade/gone.php') === null
			&& $guard($staged, ['content' => '']) === null;
	}
	
	/**
	 * RULE: the guard meets the consent a rule set to block meets — refused
	 * with the blocking box ticked, observed (a shield_observe with the
	 * guard's other fixed message) with it unticked, nothing with detection
	 * off or the kill constant set. Falsify: refuse without the blocking box
	 * — a site that only observes turns requests away; or skip the kill
	 * check — the server's off switch leaves the guard on.
	 */
	public function theGuardFollowsTheLayersConsent(): bool
	{
		$root = $this->site();
		$server = ['SCRIPT_FILENAME' => $this->stage($root, self::STAGED)];
		$consent = ['content' => $root . '/wp-content'] + self::ENFORCE;
		$observed = BasePrepend::guard($server, ['enforce' => false] + $consent);
		
		return $observed !== null && $observed['block'] === false
			&& $observed['report'][0] === Verdict::KIND_OBSERVE
			&& $observed['report'][1] === BasePrepend::GUARD_OBSERVED
			&& BasePrepend::guard($server, ['detect' => false] + $consent) === null
			&& BasePrepend::guard($server, ['kill' => true] + $consent) === null
			&& BasePrepend::GUARD_KINDS === ['block' => Verdict::KIND_BLOCK, 'observe' => Verdict::KIND_OBSERVE];
	}
	
	/**
	 * RULE: the consent carries the content directory the guard measures
	 * against, and a change of it is written. Falsify: leave `content` out of
	 * writeConsent() — every guard reads '' and says nothing.
	 */
	public function theConsentCarriesTheContentDirectory(): bool
	{
		$written = BasePrepend::writeConsent($this->dir, ['content' => '/srv/site/wp-content'] + self::ENFORCE);
		$read = BasePrepend::consent($this->dir)['content'];
		$moved = BasePrepend::writeConsent($this->dir, ['content' => '/srv/other/wp-content'] + self::ENFORCE);
		
		return $written && $read === '/srv/site/wp-content'
			&& $moved && BasePrepend::consent($this->dir)['content'] === '/srv/other/wp-content';
	}
	
	/**
	 * RULE: the plugin hands the layer WP_CONTENT_DIR resolved — `..` and a
	 * link followed, forward slashes, no trailing one — the spelling the
	 * guard's realpath of the script is measured against; '' without the
	 * constant. In a process of its own: the constant would reach every other
	 * class. Falsify: hand WP_CONTENT_DIR over as written — a content
	 * directory named through `..` never matches and the guard says nothing.
	 */
	public function thePluginHandsTheLayerTheContentDirectoryResolved(): bool
	{
		$root = $this->site();
		$script = $this->dir . DIRECTORY_SEPARATOR . 'content-root.php';
		$adapter = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Adapter.php';
		file_put_contents($script, "<?php\nrequire " . var_export($adapter, true) . ";\n"
			. "echo '[', Ovos\\Codesafe\\Shield\\Adapter::contentRoot(), ']';\n"
			. "define('WP_CONTENT_DIR', " . var_export($root . '/wp-content/plugins/../', true) . ");\n"
			. "echo '[', Ovos\\Codesafe\\Shield\\Adapter::contentRoot(), ']';\n");
		$output = [];
		exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' 2>&1', $output);
		
		return implode('', $output) === '[][' . $root . '/wp-content]';
	}
	
	/**
	 * RULE: the stub, as PHP's auto_prepend_file runs it, refuses a staged
	 * script with 403 and X-Shield-Guard before a byte of it runs, and queues
	 * the shield_block with the refused request's own facts; with the
	 * blocking box unticked the script runs and the shield_observe is queued
	 * with the status the request ended with; under the kill constant the
	 * script runs and nothing is queued; a plugin's file meets no guard.
	 * Through php-cgi (the CLI never judges). Falsify: drop the guard from
	 * run() — the staged script prints; drop the refusal — it prints after
	 * the report; drop the observe's shutdown queue — nothing is reported.
	 */
	public function theStubRefusesAStagedScriptAndQueuesTheGuardsReport(): bool
	{
		$cgi = $this->cgiBinary();
		$root = $this->site();
		$staged = $this->stage($root, self::STAGED, "<?php\necho 'staged ran';\n");
		$plugin = $this->stage($root, 'wp-content/plugins/some-plugin/run.php', "<?php\necho 'plugin ran';\n");
		$stub = BasePrepend::ensureStub($this->dir);
		$uri = '/' . self::STAGED;
		$consent = ['content' => $root . '/wp-content'] + self::ENFORCE;
		$run = function(array $with, string $script, string $uri) use ($cgi, $stub, $consent): array
		{
			BasePrepend::writeConsent($this->dir, $with + $consent);
			$output = $this->runCgi($cgi, $stub, $script, $uri);
			$queued = [];
			BasePrepend::drain($this->dir, static function(string $kind, string $message, array $extra, array $context) use (&$queued): void
			{
				$queued[] = [$kind, $message, $extra, $context];
			});
			
			return [$output, $queued];
		};
		[$refused, $blocks] = $run([], $staged, $uri);
		[$observed, $observes] = $run(['enforce' => false], $staged, $uri);
		[$killed, $none] = $run(['kill' => true], $staged, $uri);
		[$plain, $nothing] = $run([], $plugin, '/wp-content/plugins/some-plugin/run.php');
		
		return str_contains($refused, 'Status: 403') && str_contains($refused, 'X-Shield-Guard: upgrade_dir')
			&& str_contains($refused, 'X-Shield-Layer: prepend') && str_contains($refused, 'staged ran') === false
			&& count($blocks) === 1 && $blocks[0][0] === Verdict::KIND_BLOCK && $blocks[0][1] === BasePrepend::GUARD_REFUSED
			&& ($blocks[0][2]['guard'] ?? '') === 'upgrade_dir' && ($blocks[0][2]['layer'] ?? '') === 'prepend'
			&& ($blocks[0][3]['uri'] ?? '') === $uri && ($blocks[0][3]['ip'] ?? '') === '203.0.113.9' && ($blocks[0][3]['status'] ?? 0) === 403
			&& str_contains($observed, 'staged ran') && str_contains($observed, 'Status: 403') === false
			&& count($observes) === 1 && $observes[0][0] === Verdict::KIND_OBSERVE && $observes[0][1] === BasePrepend::GUARD_OBSERVED
			&& ($observes[0][3]['status'] ?? 0) === 200
			&& str_contains($killed, 'staged ran') && $none === []
			&& str_contains($plain, 'plugin ran') && $nothing === [];
	}
	
	// ---- the guard: uploads -----------------------------------------------------
	
	/**
	 * RULE: any script run from under uploads is refused before any rule,
	 * whatever its name (`.php`, `.phtml`, a `.jpg` a handler runs as PHP):
	 * the prepend runs only once PHP is running the file. Matched on the
	 * spelling the server gave as well as the resolved path, so a path-info
	 * spelling and a missing file are refused too, and reported as a
	 * shield_block with the guard's fixed message and the path below the
	 * uploads directory. The site's index.php, a plugin's file, a sibling
	 * merely starting with the name and the directory itself are left to the
	 * rules. Falsify: match the resolved path alone — the path-info spelling
	 * runs; compare the directory as a bare prefix — uploadsx/ is refused.
	 */
	public function theUploadsGuardRefusesAnyScriptUnderUploads(): bool
	{
		$root = $this->site();
		$content = $root . '/wp-content';
		$consent = ['root' => $root, 'content' => $content, 'plugins' => $content . '/plugins'] + self::ENFORCE;
		$php = $this->stage($root, 'wp-content/uploads/2026/08/x.php');
		$phtml = $this->stage($root, 'wp-content/uploads/2026/08/x.phtml');
		$jpg = $this->stage($root, 'wp-content/uploads/2026/08/cat.jpg');
		$sibling = $this->stage($root, 'wp-content/uploadsx/y.php');
		$guard = static fn(string $script, array $with = []): ?array => BasePrepend::guard(['SCRIPT_FILENAME' => $script], $with + $consent);
		$refused = $guard($php);
		
		return $refused !== null && $refused['block'] === true && $refused['guard'] === BasePrepend::GUARD_UPLOADS
			&& $refused['report'] === [Verdict::KIND_BLOCK, BasePrepend::GUARD_UPLOADS_REFUSED,
				['guard' => 'uploads', 'action' => 'uploads', 'matched' => 'uploads/2026/08/x.php']]
			&& ($guard($phtml)['report'][2]['matched'] ?? '') === 'uploads/2026/08/x.phtml'
			&& ($guard($jpg)['report'][2]['matched'] ?? '') === 'uploads/2026/08/cat.jpg'
			&& ($guard($jpg . '/shell.php')['report'][2]['matched'] ?? '') === 'uploads/2026/08/cat.jpg/shell.php'
			&& ($guard($content . '/uploads/gone.php')['guard'] ?? '') === 'uploads'
			&& ($guard($content . '/plugins/../uploads/2026/08/x.php')['guard'] ?? '') === 'uploads'
			&& $guard($root . '/index.php') === null
			&& $guard($content . '/plugins/some-plugin/file.php') === null
			&& $guard($sibling) === null
			&& $guard($content . '/uploads') === null;
	}
	
	/**
	 * RULE: a script spelled to slip past the comparison is still under
	 * uploads — the Windows stream suffix (`uploads::$INDEX_ALLOCATION`), a
	 * trailing dot or space on a segment, a doubled slash, `..`, backslashes,
	 * another case; pure, on paths that do not exist, so every OS runs it.
	 * Falsify: drop the colon cut, the trailing-dot trim or the `..`
	 * collapse from lexicalPath() — each spelling runs.
	 */
	public function aScriptSpelledToSlipPastIsStillUnderUploads(): bool
	{
		$consent = ['root' => '/srv/site', 'content' => '/srv/site/wp-content', 'plugins' => '/srv/site/wp-content/plugins'] + self::ENFORCE;
		$under = static fn(string $script): bool => (BasePrepend::guard(['SCRIPT_FILENAME' => $script], $consent)['guard'] ?? '') === 'uploads';
		
		return BasePrepend::lexicalPath('C:\\site\\wp-content\\uploads::$INDEX_ALLOCATION\\x.php::$DATA') === 'C:/site/wp-content/uploads/x.php'
			&& BasePrepend::lexicalPath('/srv/site//wp-content/./uploads.../2026/../x.php. ') === '/srv/site/wp-content/uploads/x.php'
			&& BasePrepend::lexicalPath('C:/../x') === 'C:/x'
			&& BasePrepend::lexicalPath('//host/share/uploads/') === '//host/share/uploads'
			&& $under('/srv/site/wp-content/uploads::$INDEX_ALLOCATION/x.php')
			&& $under('/srv/site/wp-content/uploads./x.php')
			&& $under('/srv/site/wp-content/uploads . /x.php')
			&& $under('/srv/site/wp-content//uploads/x.php')
			&& $under('/srv/site/wp-content/plugins/../uploads/x.php')
			&& $under('\\srv\\site\\wp-content\\uploads\\x.php')
			&& $under('/srv/site/wp-content/UPLOADS/x.php')
			&& $under('/srv/site/wp-content/uploadsx/x.php') === false
			&& $under('/srv/site/wp-content/uploads/../index.php') === false
			&& $under('/srv/site/index.php') === false;
	}
	
	/**
	 * RULE: an uploads directory that is empty, relative, the site root, the
	 * content or plugins directory, wp-admin, wp-includes or any directory
	 * above them never refuses the site: not index.php, not wp-admin, not a
	 * plugin's file — read straight from a consent no writer filtered, as
	 * the mu-plugin stage reads it too. A good directory beside them still
	 * guards, and without the site root or the content directory the guard
	 * says nothing at all. Falsify: drop safeBase() from the match — every
	 * request to the site is refused and WordPress never boots to heal the
	 * consent; drop wp-admin or the plugins directory from what it keeps —
	 * the dashboard or a plugin's endpoint is refused.
	 */
	public function aBadUploadsDirectoryNeverRefusesTheSite(): bool
	{
		$root = $this->site();
		$content = $root . '/wp-content';
		$plugins = $content . '/plugins';
		$shell = $this->stage($root, 'wp-content/uploads/2026/08/x.php');
		$this->stage($root, 'wp-includes/ms-files.php');
		$site = [$root . '/index.php', $root . '/wp-admin/admin-ajax.php', $root . '/wp-admin/network/sites.php', $root . '/wp-includes/ms-files.php',
			$plugins . '/some-plugin/file.php', $root . '/wp-login.php'];
		$drive = preg_match('~^[A-Za-z]:~', $root) === 1 ? substr($root, 0, 2) . '/' : '/';
		$bad = ['', 'wp-content/uploads', $root, $root . '/', $content, $plugins, dirname($root), dirname($root, 2), '/', $drive,
			$root . '/wp-admin', $root . '/wp-includes', $root . '/./wp-content/', $plugins . '/..', strtoupper($root), $root . '::$INDEX_ALLOCATION'];
		// read back from a file the writer never touched, every bad directory and one good one
		file_put_contents($this->dir . DIRECTORY_SEPARATOR . BasePrepend::CONSENT, BasePrepend::GUARD . json_encode(['detect' => true, 'enforce' => true,
			'root' => $root, 'content' => $content, 'plugins' => $plugins, 'uploads' => [...$bad, $content . '/uploads']]));
		$read = (array)BasePrepend::consent($this->dir);
		$consent = ['root' => $root, 'content' => $content, 'plugins' => $plugins] + self::ENFORCE;
		$refusesTheSite = false;
		foreach([...array_map(static fn(string $base): array => ['uploads' => [$base]] + $consent, $bad), $read] as $with)
		{
			foreach($site as $script)
			{
				$refusesTheSite = $refusesTheSite || BasePrepend::guard(['SCRIPT_FILENAME' => $script], $with) !== null;
			}
		}
		
		return $refusesTheSite === false
			&& (BasePrepend::guard(['SCRIPT_FILENAME' => $shell], $read)['guard'] ?? '') === 'uploads'
			&& BasePrepend::guard(['SCRIPT_FILENAME' => $shell], ['root' => ''] + $read) === null
			&& BasePrepend::guard(['SCRIPT_FILENAME' => $shell], ['content' => ''] + $read) === null
			&& BasePrepend::guard(['SCRIPT_FILENAME' => $plugins . '/some-plugin/file.php'], ['content' => '', 'plugins' => '', 'uploads' => [$content]] + $consent) === null
			&& BasePrepend::guard(['SCRIPT_FILENAME' => $shell], ['root' => 'relative/site'] + $read) === null
			&& BasePrepend::safeBase($content . '/uploads', $root, $content, $plugins)
			&& BasePrepend::safeBase('', $root, $content, $plugins) === false
			&& BasePrepend::safeBase($content . '/uploads', '', $content, $plugins) === false;
	}
	
	/**
	 * RULE: the plugin hands the layer only an uploads directory that is
	 * safe, as written and as resolved: the site's upload base; on a network
	 * the base without `/sites/N`, and the old network's blogs.dir where
	 * given; nothing for an empty base (a broken upload_dir filter), an
	 * `upload_path` of `wp-content`, the root, a directory above it, the
	 * plugins directory or wp-admin, and nothing without the site root.
	 * Falsify: drop safeBase() from the writer — the consent carries the
	 * root; keep `/sites/N` — on a network only the main site's files are
	 * guarded.
	 */
	public function theWriterHandsTheLayerOnlyASafeUploadsDirectory(): bool
	{
		$root = $this->site();
		$content = $root . '/wp-content';
		$plugins = $content . '/plugins';
		$this->stage($root, 'wp-content/uploads/index.php');
		$bases = static fn(string $basedir, bool $network = false, string $blogs = '', ?string $at = null): array
			=> Adapter::uploadBases($basedir, $network, $blogs, $at ?? $root, $content, $plugins);
		$expected = [$content . '/blogs.dir', $content . '/uploads'];
		
		return $bases($content . '/uploads') === [$content . '/uploads']
			&& $bases($content . '/uploads/') === [$content . '/uploads']
			&& $bases('') === []
			&& $bases('wp-content/uploads') === []
			&& $bases($content) === []
			&& $bases($root) === []
			&& $bases(dirname($root)) === []
			&& $bases($plugins) === []
			&& $bases($root . '/wp-admin') === []
			&& $bases($content . '/uploads/sites/3', true) === [$content . '/uploads']
			&& $bases($content . '/uploads/sites/3') === [$content . '/uploads/sites/3']
			&& $bases($content . '/uploads', true, $content . '/blogs.dir') === $expected
			&& $bases('', true, $content . '/blogs.dir') === [$content . '/blogs.dir']
			&& $bases($content . '/uploads', false, '', '') === []
			&& Adapter::uploadBases($content, false, '', $root, '', '') === [];
	}
	
	/**
	 * RULE: at init the plugin writes the site's upload base into the
	 * consent — on a network the base without `/sites/N`, with blogs.dir
	 * where ms_files_rewriting is on, ABSPATH . UPLOADBLOGSDIR where the old
	 * network defines it — and only the main network's main site writes: a
	 * subsite, or a second network's main site, leaves the file as it is,
	 * so two sites never rewrite it in turn. A broken upload_dir filter or
	 * an `upload_path` of `wp-content` writes nothing. In processes of their
	 * own: ABSPATH and WP_CONTENT_DIR would reach every other test. Falsify:
	 * drop the main-network check — a second network rewrites the file with
	 * its own directory; ignore UPLOADBLOGSDIR — an old network that moved
	 * its sites' files keeps them unguarded.
	 */
	public function atInitOnlyTheMainNetworksMainSiteWritesTheUploads(): bool
	{
		$root = $this->site();
		$content = $root . '/wp-content';
		$plugins = $content . '/plugins';
		$this->stage($root, 'wp-content/uploads/index.php');
		$sync = function(array $wp, ?string $blogs = null) use ($root): mixed
		{
			BasePrepend::writeConsent($this->dir, self::ENFORCE);
			
			return json_decode($this->fixture(PHP_BINARY, ['dir' => $this->dir, 'root' => $root, 'wp' => $wp, 'call' => 'uploads']
				+ ($blogs === null ? [] : ['blogsdir' => $blogs])), true);
		};
		$network = ['multisite' => true, 'upload_basedir' => $content . '/uploads/sites/2'];
		
		return $sync(['upload_basedir' => $content . '/uploads']) === [true, [$content . '/uploads'], $plugins]
			&& $sync($network) === [true, [$content . '/uploads'], $plugins]
			&& $sync(['site_options' => ['ms_files_rewriting' => 1]] + $network) === [true, [$content . '/blogs.dir', $content . '/uploads'], $plugins]
			&& $sync(['site_options' => ['ms_files_rewriting' => 1]] + $network, 'wp-content/old-blogs') === [true, [$content . '/old-blogs', $content . '/uploads'], $plugins]
			&& $sync(['main_site' => false] + $network) === [false, [], $plugins]
			&& $sync(['main_network' => false] + $network) === [false, [], $plugins]
			&& $sync(['upload_basedir' => '']) === [false, [], $plugins]
			&& $sync(['upload_basedir' => $content]) === [false, [], $plugins];
	}
	
	/**
	 * RULE: syncPrepend() hooks the uploads writer at the end of init, beside
	 * the REST prefix's and the login cookie's. Through php-cgi, since it
	 * does nothing on the CLI. Falsify: never hook it — the consent keeps
	 * <content>/uploads whatever the site's upload base.
	 */
	public function theUploadsWriterIsHookedAtInit(): bool
	{
		$hooked = json_decode($this->fixture($this->cgiBinary(), ['dir' => '', 'root' => $this->site(), 'call' => 'prepend',
			'wp' => ['options' => ['ovos_codesafe' => ['enabled' => true, 'url' => 'https://codesafe.invalid', 'api_key' => 'k']]]]), true);
		
		return is_array($hooked) && in_array('syncUploads', $hooked, true) && in_array('syncRestPrefix', $hooked, true);
	}
	
	/**
	 * RULE: the consent keeps the uploads directories sorted and without
	 * duplicates, as written and as read, so the writer's comparison holds
	 * still whatever order WordPress hands them in; the plugin-load writer,
	 * which cannot know them, keeps them; writeUploads() writes only a
	 * change, and nothing without a consent. Falsify: drop the sort — two
	 * orders rewrite the file on every request; drop the keep-unless-given —
	 * every request writes [] at plugin load and the list again at init.
	 */
	public function theUploadsListHoldsStillInTheConsent(): bool
	{
		BasePrepend::writeConsent($this->dir, ['uploads' => ['/srv/b/uploads', '/srv/a/uploads', '/srv/b/uploads/', 'relative/x', '']] + self::ENFORCE);
		$read = BasePrepend::consent($this->dir)['uploads'] ?? null;
		$same = BasePrepend::writeUploads($this->dir, ['/srv/a/uploads', '/srv/b/uploads']);
		$reordered = BasePrepend::writeUploads($this->dir, ['/srv/b/uploads', '/srv/a/uploads', '/srv/a/uploads']);
		$atLoad = BasePrepend::writeConsent($this->dir, array_diff_key(self::ENFORCE, ['uploads' => true]));
		$kept = BasePrepend::consent($this->dir)['uploads'] ?? null;
		$changed = BasePrepend::writeUploads($this->dir, ['/srv/c/uploads']);
		$nowhere = $this->dir . DIRECTORY_SEPARATOR . 'nowhere';
		mkdir($nowhere);
		
		return $read === ['/srv/a/uploads', '/srv/b/uploads']
			&& $same === false && $reordered === false
			&& $atLoad === false && $kept === $read
			&& $changed === true && (BasePrepend::consent($this->dir)['uploads'] ?? null) === ['/srv/c/uploads']
			&& BasePrepend::writeUploads($nowhere, ['/srv/c/uploads']) === false;
	}
	
	/**
	 * RULE: the init writer keeps a directory the consent already names
	 * while it exists and is still safe to guard, beside the ones it is
	 * given, so an upload_dir filter that runs on some requests only cannot
	 * swap the list back and forth; one gone from the disk, or one that is
	 * the content directory, goes. Past UPLOADS_MAX the given ones stay and
	 * the kept ones fill the room, and uploadsOf() keeps the first
	 * UPLOADS_MAX in sort order. Falsify: replace the list — the filter's two
	 * answers rewrite the file in turn; skip is_dir() or safeBase() — a gone
	 * or unsafe directory stays; sort before the cut — a given directory that
	 * sorts last is lost; drop the cut in uploadsOf() — twenty ride along.
	 */
	public function theUploadsWriterKeepsADirectoryStillThere(): bool
	{
		$root = $this->site();
		$content = $root . '/wp-content';
		$site = ['root' => $root, 'content' => $content, 'plugins' => $content . '/plugins'] + self::ENFORCE;
		$this->stage($root, 'wp-content/uploads/index.php');
		$this->stage($root, 'media/index.php');
		BasePrepend::writeConsent($this->dir, ['uploads' => [$content . '/uploads', $root . '/gone', $content]] + $site);
		$first = BasePrepend::writeUploads($this->dir, [$root . '/media']);
		$both = BasePrepend::consent($this->dir)['uploads'] ?? null;
		$back = BasePrepend::writeUploads($this->dir, [$content . '/uploads']);
		$again = BasePrepend::writeUploads($this->dir, [$root . '/media']);
		// a full list of kept directories, every one sorting ahead of the given one
		$kept = array_map(fn(int $at): string => dirname($this->stage($root, sprintf('old/a%02d/index.php', $at))), range(1, BasePrepend::UPLOADS_MAX));
		BasePrepend::writeConsent($this->dir, ['uploads' => $kept] + $site);
		$crowded = BasePrepend::writeUploads($this->dir, [$root . '/zz-media']);
		$many = array_map(static fn(int $at): string => sprintf('/srv/u%02d', $at), range(20, 1, -1));
		
		return $first === true && $both === [$root . '/media', $content . '/uploads']
			&& $back === false && $again === false
			&& $crowded === true
			&& (BasePrepend::consent($this->dir)['uploads'] ?? null) === [...array_slice($kept, 0, BasePrepend::UPLOADS_MAX - 1), $root . '/zz-media']
			&& BasePrepend::uploadsOf($many) === array_map(static fn(int $at): string => sprintf('/srv/u%02d', $at), range(1, BasePrepend::UPLOADS_MAX));
	}
	
	/**
	 * RULE: an uploads directory is resolved as it is written and spelled
	 * for the comparison after: lexicalPath() first would collapse `link/..`
	 * before realpath() follows the link (and on Linux rename a directory
	 * whose name ends in a dot or holds a colon), so the writer would miss
	 * the directory it resolves to, and safeBase() would pass a spelling
	 * that resolves to wp-content. A junction stands in for the link where
	 * Windows grants no symlink. Falsify: resolve lexicalPath()'s spelling
	 * in uploadBases() — the real uploads directory is not written; in
	 * safeBase() — a base resolving to wp-content passes.
	 */
	public function anUploadsDirectoryIsResolvedAsWritten(): bool
	{
		$root = $this->site();
		$content = $root . '/wp-content';
		$plugins = $content . '/plugins';
		$this->stage($root, 'wp-content/uploads/2026/index.php');
		$outside = str_replace('\\', '/', sys_get_temp_dir()) . '/ovos-shield-outside-' . uniqid();
		mkdir($outside);
		$links = [$outside . '/into-uploads' => $content . '/uploads/2026', $outside . '/into-plugins' => $plugins];
		try
		{
			foreach($links as $link => $target)
			{
				if($this->makeLink($target, $link) === false)
				{
					throw new SkipException('Neither a symlink nor a junction can be made here.');
				}
			}
			
			return in_array($content . '/uploads', Adapter::uploadBases($outside . '/into-uploads/..', false, '', $root, $content, $plugins), true)
				&& BasePrepend::safeBase($outside . '/into-plugins/..', $root, $content, $plugins) === false
				&& BasePrepend::safeBase($outside . '/into-uploads/..', $root, $content, $plugins);
		}
		finally
		{
			// a link is taken away as a link, never walked: remove() would follow it
			foreach(array_keys($links) as $link)
			{
				$this->dropLink($link);
			}
			$this->remove($outside);
		}
	}
	
	/**
	 * RULE: a consent an older plugin wrote, with no uploads directories and
	 * no switch, guards <content>/uploads: the old consent never leaves the
	 * guard dead. Falsify: drop the fallback — an updated plugin's first
	 * requests, or a site whose init never ran, guard nothing; default the
	 * switch to off — every older consent turns the guard off.
	 */
	public function anOlderConsentStillGuardsUploads(): bool
	{
		$root = $this->site();
		$shell = $this->stage($root, 'wp-content/uploads/2026/08/x.php');
		file_put_contents($this->dir . DIRECTORY_SEPARATOR . BasePrepend::CONSENT, BasePrepend::GUARD . json_encode(['detect' => true, 'enforce' => true,
			'kill' => false, 'prefix' => '', 'root' => $root, 'content' => $root . '/wp-content', 'entries' => false, 'rules' => self::RULES_NAME]));
		$consent = (array)BasePrepend::consent($this->dir);
		
		return ($consent['uploads'] ?? null) === [] && ($consent['uploads_guard'] ?? null) === true && ($consent['plugins'] ?? null) === ''
			&& (BasePrepend::guard(['SCRIPT_FILENAME' => $shell], $consent)['report'][2]['matched'] ?? '') === 'uploads/2026/08/x.php';
	}
	
	/**
	 * RULE: a site whose uploads live elsewhere is guarded there and only
	 * there: <content>/uploads is no longer uploads once the consent names
	 * another directory. Falsify: always add <content>/uploads — a site
	 * that keeps a script-serving directory by that name loses it.
	 */
	public function aCustomUploadsDirectoryIsTheOneGuarded(): bool
	{
		$root = $this->site();
		$media = $this->stage($root, 'media/2026/x.php');
		$default = $this->stage($root, 'wp-content/uploads/x.php');
		$consent = ['root' => $root, 'content' => $root . '/wp-content', 'uploads' => [$root . '/media']] + self::ENFORCE;
		
		return (BasePrepend::guard(['SCRIPT_FILENAME' => $media], $consent)['report'][2]['matched'] ?? '') === 'media/2026/x.php'
			&& BasePrepend::guard(['SCRIPT_FILENAME' => $default], $consent) === null;
	}
	
	/**
	 * RULE: the uploads guard meets the consent a rule set to block meets —
	 * refused with the blocking box, observed (shield_observe, its own fixed
	 * message) without it, nothing with detection off or the kill constant
	 * set — and its own switch turns it off while the upgrade guard stays.
	 * Falsify: skip the switch — CODESAFE_UPLOADS_GUARD false still refuses;
	 * read the switch for the upgrade guard too — a staged copy runs.
	 */
	public function theUploadsGuardFollowsTheConsentAndItsOwnSwitch(): bool
	{
		$root = $this->site();
		$shell = ['SCRIPT_FILENAME' => $this->stage($root, 'wp-content/uploads/x.php')];
		$staged = ['SCRIPT_FILENAME' => $this->stage($root, self::STAGED)];
		$consent = ['root' => $root, 'content' => $root . '/wp-content'] + self::ENFORCE;
		$observed = BasePrepend::guard($shell, ['enforce' => false] + $consent);
		BasePrepend::writeConsent($this->dir, ['uploads_guard' => false] + $consent);
		$off = (array)BasePrepend::consent($this->dir);
		
		return $observed !== null && $observed['block'] === false && $observed['guard'] === 'uploads'
			&& $observed['report'][0] === Verdict::KIND_OBSERVE && $observed['report'][1] === BasePrepend::GUARD_UPLOADS_OBSERVED
			&& BasePrepend::guard($shell, ['detect' => false] + $consent) === null
			&& BasePrepend::guard($shell, ['kill' => true] + $consent) === null
			&& ($off['uploads_guard'] ?? null) === false
			&& BasePrepend::guard($shell, $off) === null
			&& (BasePrepend::guard($staged, $off)['guard'] ?? '') === 'upgrade_dir';
	}
	
	/**
	 * RULE: CODESAFE_UPLOADS_GUARD false turns the guard off through the
	 * consent the plugin writes, read as a boolean: the string 'false', 'off'
	 * or 0 turns it off too; unset, true, or a value that is no boolean
	 * ('maybe', an array) keeps it on. In a process of its own: the constant
	 * would reach every other class. Falsify: read the switch nowhere in
	 * consentOf() — the constant changes nothing; cast it with (bool) — the
	 * string 'false' keeps the guard on.
	 */
	public function theUploadsGuardConstantReachesTheConsent(): bool
	{
		$run = function(string $define): string
		{
			$script = $this->dir . DIRECTORY_SEPARATOR . 'uploads-guard-' . uniqid() . '.php';
			$src = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR;
			file_put_contents($script, "<?php\nspl_autoload_register(static function(string \$class): void\n{\n"
				. "\t\$file = " . var_export($src, true) . " . str_replace('\\\\', '/', substr(\$class, 14)) . '.php';\n"
				. "\tif(str_starts_with(\$class, 'Ovos\\\\Codesafe\\\\') && is_file(\$file))\n\t{\n\t\trequire \$file;\n\t}\n});\n"
				. "require " . var_export(__DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php', true) . ";\n"
				. $define
				. "\$config = new Ovos\\Codesafe\\Config();\n"
				. "echo json_encode([\$config->uploadsGuard(), Ovos\\Codesafe\\Shield\\Adapter::consentOf(\$config)['uploads_guard']]);\n");
			$output = [];
			exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' 2>&1', $output);
			
			return implode('', $output);
		};
		
		return $run('') === '[true,true]'
			&& $run("define('CODESAFE_UPLOADS_GUARD', false);\n") === '[false,false]'
			&& $run("define('CODESAFE_UPLOADS_GUARD', 'false');\n") === '[false,false]'
			&& $run("define('CODESAFE_UPLOADS_GUARD', 'off');\n") === '[false,false]'
			&& $run("define('CODESAFE_UPLOADS_GUARD', 0);\n") === '[false,false]'
			&& $run("define('CODESAFE_UPLOADS_GUARD', true);\n") === '[true,true]'
			&& $run("define('CODESAFE_UPLOADS_GUARD', 'maybe');\n") === '[true,true]'
			&& $run("define('CODESAFE_UPLOADS_GUARD', ['x']);\n") === '[true,true]';
	}
	
	/**
	 * RULE: the stub, as PHP's auto_prepend_file runs it, refuses a script
	 * under uploads — a .php, a .jpg PHP runs — with 403, X-Shield-Guard:
	 * uploads and X-Shield-Layer: prepend before a byte of it runs, queues
	 * the shield_block, and the executed-file watch records the hit as
	 * refused; with the blocking box off the script runs, a shield_observe
	 * is queued and the hit counts as a run. A consent of bad directories
	 * leaves index.php running. Through php-cgi. Falsify: name the upgrade
	 * guard in the refusal — the header says upgrade_dir; record every hit
	 * as a run — the watch says the shell ran.
	 */
	public function theStubRefusesAScriptUnderUploadsAndTheWatchCountsTheRefusal(): bool
	{
		$cgi = $this->cgiBinary();
		$root = $this->site();
		$index = $this->stage($root, 'index.php', "<?php\necho 'site ran';\n");
		$shell = $this->stage($root, 'wp-content/uploads/2026/08/x.php', "<?php\necho 'shell ran';\n");
		$jpg = $this->stage($root, 'wp-content/uploads/2026/08/cat.jpg', "<?php\necho 'jpg ran';\n");
		$stub = BasePrepend::ensureStub($this->dir);
		BasePrepend::writeKnown($this->dir, '7.1.2', '1.0.3', ['wp-admin/admin-ajax.php' => 'core']);
		$consent = ['root' => $root, 'content' => $root . '/wp-content', 'plugins' => $root . '/wp-content/plugins', 'entries' => true] + self::ENFORCE;
		$relative = 'wp-content/uploads/2026/08/x.php';
		$run = function(array $with, string $script) use ($cgi, $stub, $consent, $root): array
		{
			BasePrepend::writeConsent($this->dir, $with + $consent);
			$output = $this->runCgi($cgi, $stub, $script, '/' . substr($script, strlen($root) + 1));
			$queued = [];
			BasePrepend::drain($this->dir, static function(string $kind, string $message, array $extra, array $context) use (&$queued): void
			{
				$queued[] = [$kind, $message, $extra, $context];
			});
			
			return [$output, $queued];
		};
		[$refused, $blocks] = $run([], $shell);
		$afterBlock = BasePrepend::seen($this->dir)['paths'][$relative] ?? [];
		[$image] = $run([], $jpg);
		[$observed, $observes] = $run(['enforce' => false], $shell);
		$afterObserve = BasePrepend::seen($this->dir)['paths'][$relative] ?? [];
		[$switchedOff, $none] = $run(['uploads_guard' => false], $shell);
		[$site, $nothing] = $run(['uploads' => [$root, $root . '/wp-content', dirname($root)]], $index);
		
		return str_contains($refused, 'Status: 403') && str_contains($refused, 'X-Shield-Guard: uploads')
			&& str_contains($refused, 'X-Shield-Layer: prepend') && str_contains($refused, 'shell ran') === false
			&& count($blocks) === 1 && $blocks[0][0] === Verdict::KIND_BLOCK && $blocks[0][1] === BasePrepend::GUARD_UPLOADS_REFUSED
			&& ($blocks[0][2]['guard'] ?? '') === 'uploads' && ($blocks[0][2]['matched'] ?? '') === 'uploads/2026/08/x.php'
			&& ($blocks[0][3]['status'] ?? 0) === 403
			&& ($afterBlock['n'] ?? 0) === 1 && ($afterBlock['refused'] ?? -1) === 1
			&& str_contains($image, 'Status: 403') && str_contains($image, 'jpg ran') === false
			&& str_contains($observed, 'shell ran') && count($observes) === 1 && $observes[0][1] === BasePrepend::GUARD_UPLOADS_OBSERVED
			&& ($afterObserve['n'] ?? 0) === 2 && ($afterObserve['refused'] ?? -1) === 1
			&& str_contains($switchedOff, 'shell ran') && $none === []
			&& str_contains($site, 'site ran') && str_contains($site, 'Status: 403') === false && $nothing === [];
	}
	
	/**
	 * RULE: a link from elsewhere into uploads is refused by its resolved
	 * path, a link under uploads pointing out by its spelling; on a
	 * `current → releases/N` deploy the plugin hands both spellings of the
	 * upload base, so a script reached through `current` is refused, while a
	 * base whose resolved path is the site root — written through `current`
	 * — never refuses index.php. A directory junction stands in for the
	 * link where Windows grants no symlink. Falsify: drop the resolved arm
	 * — the link into uploads runs; drop the resolved spelling from the
	 * writer or from safeBase() — the deploy's spelling, or a root named
	 * through it, slips by.
	 */
	public function linksIntoAndOutOfUploadsAreBothCaught(): bool
	{
		$root = $this->site();
		$content = $root . '/wp-content';
		$plugins = $content . '/plugins';
		$this->stage($root, 'wp-content/uploads/2026/08/x.php');
		$outside = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-outside-' . uniqid();
		mkdir($outside);
		file_put_contents($outside . DIRECTORY_SEPARATOR . 'out.php', "<?php\n");
		$links = [$root . '/elsewhere' => $content . '/uploads/2026/08', $content . '/uploads/out' => $outside, $this->dir . '/current' => $root];
		try
		{
			foreach($links as $link => $target)
			{
				if($this->makeLink($target, $link) === false)
				{
					throw new SkipException('Neither a symlink nor a junction can be made here.');
				}
			}
			$current = $this->dir . '/current';
			$consent = ['root' => $root, 'content' => $content, 'plugins' => $plugins] + self::ENFORCE;
			$written = Adapter::uploadBases($current . '/wp-content/uploads', false, '', $root, $content, $plugins);
			$deploy = ['uploads' => $written] + $consent;
			$guard = static fn(string $script, array $with): ?array => BasePrepend::guard(['SCRIPT_FILENAME' => $script], $with);
			
			return ($guard($root . '/elsewhere/x.php', $consent)['report'][2]['matched'] ?? '') === 'uploads/2026/08/x.php'
				&& ($guard($content . '/uploads/out/out.php', $consent)['guard'] ?? '') === 'uploads'
				&& $written === BasePrepend::uploadsOf([$current . '/wp-content/uploads', $content . '/uploads'])
				&& ($guard($current . '/wp-content/uploads/2026/08/x.php', $deploy)['guard'] ?? '') === 'uploads'
				&& ($guard($content . '/uploads/2026/08/x.php', $deploy)['guard'] ?? '') === 'uploads'
				&& $guard($current . '/index.php', $deploy) === null
				&& $guard($current . '/index.php', ['uploads' => [$current]] + $consent) === null
				&& $guard($current . '/wp-content/plugins/some-plugin/file.php', ['uploads' => [$current . '/wp-content']] + $consent) === null
				&& Adapter::uploadBases($current, false, '', $root, $content, $plugins) === [];
		}
		finally
		{
			// a link is taken away as a link, never walked: remove() would follow it
			foreach(array_keys($links) as $link)
			{
				$this->dropLink($link);
			}
			$this->remove($outside);
		}
	}
	
	// ---- helpers --------------------------------------------------------------
	
	protected function server(
		string $ua,
		string $uri = '/wp-content/plugins/some-plugin/file.php',
		?string $script = null,
	): array
	{
		return [
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => $uri,
			'HTTP_USER_AGENT' => $ua,
			'REMOTE_ADDR' => '203.0.113.9',
		] + ($script === null ? [] : ['SCRIPT_FILENAME' => $script]);
	}
	
	/**
	 * A site root under the store's temp directory, with the files a request
	 * may run: WordPress's index.php, wp-admin's ajax, network and
	 * load-styles entries, and a plugin's own PHP file
	 */
	protected function site(): string
	{
		$root = $this->dir . DIRECTORY_SEPARATOR . 'site';
		foreach(['index.php', 'wp-admin/admin-ajax.php', 'wp-admin/load-styles.php', 'wp-admin/network/sites.php',
			'wp-content/plugins/some-plugin/file.php'] as $file)
		{
			$path = $root . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $file);
			if(is_dir(dirname($path)) === false)
			{
				mkdir(dirname($path), 0700, true);
			}
			file_put_contents($path, "<?php\n");
		}
		file_put_contents($this->dir . DIRECTORY_SEPARATOR . 'outside.php', "<?php\n");
		
		return str_replace('\\', '/', (string)realpath($root));
	}
	
	/** one file below the site root, made with its directories; its path */
	protected function stage(
		string $root,
		string $relative,
		string $body = "<?php\n",
	): string
	{
		$path = $root . '/' . $relative;
		if(is_dir(dirname($path)) === false)
		{
			mkdir(dirname($path), 0700, true);
		}
		file_put_contents($path, $body);
		
		return $path;
	}
	
	/**
	 * A link at $link to the directory $target: a symlink, or on Windows
	 * without the right to make one, a directory junction, which PHP's
	 * realpath() resolves the same way. False when neither can be made
	 */
	protected function makeLink(
		string $target,
		string $link,
	): bool
	{
		if(@symlink($target, $link))
		{
			return true;
		}
		if(PHP_OS_FAMILY !== 'Windows')
		{
			return false;
		}
		$output = [];
		exec('cmd /c mklink /J ' . escapeshellarg(str_replace('/', '\\', $link)) . ' ' . escapeshellarg(str_replace('/', '\\', $target)) . ' 2>&1', $output, $status);
		
		return $status === 0 && is_dir($link);
	}
	
	/**
	 * tests/files/uploads-sync.file.php run by $binary — the CLI, or php-cgi,
	 * which takes the file as its script — with $given in its environment:
	 * what it printed, the CGI headers left out
	 *
	 * @param array{dir: string, root: string, wp: array<string, mixed>, call: string} $given
	 */
	protected function fixture(
		string $binary,
		array $given,
	): string
	{
		$file = __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'uploads-sync.file.php';
		$cgi = str_contains(basename($binary), 'cgi');
		$environment = ['OVOS_UPLOADS_SYNC' => (string)json_encode($given)]
			+ ($cgi ? ['GATEWAY_INTERFACE' => 'CGI/1.1', 'SCRIPT_FILENAME' => $file, 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/'] : []);
		// Windows' own libraries need it in any process
		if(getenv('SYSTEMROOT') !== false)
		{
			$environment['SYSTEMROOT'] = (string)getenv('SYSTEMROOT');
		}
		$command = $cgi ? [$binary, '-n', '-d', 'cgi.force_redirect=0'] : [$binary, $file];
		$process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->dir, $environment);
		if(is_resource($process) === false)
		{
			return '';
		}
		$output = (string)stream_get_contents($pipes[1]) . (string)stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		proc_close($process);
		
		return $cgi ? (explode("\r\n\r\n", $output, 2)[1] ?? '') : $output;
	}
	
	/** a link made by makeLink() taken away, never what it points at: a junction goes with rmdir(), a symlink with unlink() */
	protected function dropLink(
		string $link,
	): void
	{
		if(@rmdir($link) === false)
		{
			@unlink($link);
		}
	}
	
	/** php-cgi beside this PHP — the SAPI a site's prepend runs in; the test is skipped without one */
	protected function cgiBinary(): string
	{
		$dir = dirname(PHP_BINARY);
		// Windows ships php-cgi.exe beside php.exe; Debian's packages name it php-cgi8.x beside php8.x
		foreach([$dir . DIRECTORY_SEPARATOR . 'php-cgi.exe', $dir . DIRECTORY_SEPARATOR . str_replace('php', 'php-cgi', basename(PHP_BINARY)),
			$dir . DIRECTORY_SEPARATOR . 'php-cgi'] as $candidate)
		{
			if(is_file($candidate))
			{
				return $candidate;
			}
		}
		
		throw new SkipException('No php-cgi beside ' . PHP_BINARY . '.');
	}
	
	/**
	 * One request through php-cgi with the stub as auto_prepend_file and no
	 * php.ini: what it printed, headers and body
	 */
	protected function runCgi(
		string $cgi,
		string $stub,
		string $script,
		string $uri,
	): string
	{
		$environment = ['GATEWAY_INTERFACE' => 'CGI/1.1', 'SCRIPT_FILENAME' => $script, 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $uri,
			'REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Mozilla/5.0'];
		// Windows' own libraries need it in any process
		if(getenv('SYSTEMROOT') !== false)
		{
			$environment['SYSTEMROOT'] = (string)getenv('SYSTEMROOT');
		}
		$process = proc_open([$cgi, '-n', '-d', 'cgi.force_redirect=0', '-d', 'auto_prepend_file=' . $stub], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
			$pipes, $this->dir, $environment);
		if(is_resource($process) === false)
		{
			return '';
		}
		$output = (string)stream_get_contents($pipes[1]) . (string)stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		proc_close($process);
		
		return $output;
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
	
	protected function blocked(): ?array
	{
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		
		return BasePrepend::judge($this->dir, $this->server(self::BOT));
	}
	
	protected function observed(): ?array
	{
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		
		return BasePrepend::judge($this->dir, $this->server('Mozilla/5.0', self::PROBE));
	}
	
	/** the queued reports' messages, oldest first, the queue drained */
	protected function drained(): array
	{
		$messages = [];
		BasePrepend::drain($this->dir, static function(
			string $kind,
			string $message,
		) use (&$messages): void
		{
			$messages[] = $message;
		});
		
		return $messages;
	}
	
	protected function queueTwoBlocksAndDrain(
		?int &$drained,
	): array
	{
		$blocked = $this->blocked();
		BasePrepend::queue($this->dir, $blocked['report'], BasePrepend::contextOf($this->server(self::BOT), 403));
		BasePrepend::queue($this->dir, $blocked['report'], BasePrepend::contextOf($this->server(self::BOT), 403));
		
		$handed = [];
		$drained = BasePrepend::drain($this->dir, static function(
			string $kind,
			string $message,
			array $extra,
			array $context,
		) use (&$handed): void
		{
			$handed[] = [$kind, $message, $extra, $context];
		});
		
		return $handed;
	}
}
