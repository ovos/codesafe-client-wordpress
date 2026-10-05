<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Redactor;
use Ovos\Codesafe\Shield\Prepend as BasePrepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;
use Ovos\Test;
use Ovos\Test\Exception\SkipException;
use Ovos\Test\Internal;
use ReflectionClass;

use function apcu_enabled;
use function count;
use function dirname;
use function escapeshellarg;
use function exec;
use function file_get_contents;
use function file_put_contents;
use function filemtime;
use function function_exists;
use function glob;
use function implode;
use function is_dir;
use function is_file;
use function is_int;
use function mkdir;
use function preg_match;
use function realpath;
use function rmdir;
use function scandir;
use function sleep;
use function str_contains;
use function str_ends_with;
use function str_repeat;
use function str_replace;
use function str_starts_with;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;
use function var_export;

use const DIRECTORY_SEPARATOR;
use const PHP_BINARY;

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
	
	/** the ruleset's name the consent carries — drawn by writeConsent() when none is given */
	protected const string RULES_NAME = 'shield-abababababababababababab.json';
	
	protected const array ENFORCE = ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => '', 'root' => '', 'entries' => false,
		'rules' => self::RULES_NAME, 'proxy_header' => '', 'proxies' => []];
	
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
		], time())->toRecord());
		
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
	 * A signed-in request to a file WordPress runs through is the plugins_loaded
	 * judge's, not this layer's — WordPress's test cookie is not a login
	 */
	public function loginCookieDefersToPluginsLoadedWhereWordPressRuns(): bool
	{
		$root = $this->site();
		BasePrepend::writeConsent($this->dir, ['root' => $root] + self::ENFORCE);
		$cookie = ['wordpress_logged_in_abc123' => 'x'];
		
		return BasePrepend::judge($this->dir, $this->server(self::BOT, '/', $root . '/index.php'), [], $cookie) === null
			&& BasePrepend::judge($this->dir, $this->server(self::BOT, '/wp-admin/admin-ajax.php', $root . '/wp-admin/admin-ajax.php'), [], $cookie) === null
			&& BasePrepend::judge($this->dir, $this->server(self::BOT, '/wp-admin/network/sites.php', $root . '/wp-admin/network/sites.php'), [], $cookie) === null
			&& BasePrepend::judge($this->dir, $this->server(self::BOT, '/', $root . '/index.php'), [], ['wordpress_test_cookie' => 'WP Cookie check']) !== null;
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
	
	public function queueIsCappedAtQueueMaxOldestGoingFirst(): bool
	{
		for($i = 0; $i < BasePrepend::QUEUE_MAX + 5; $i++)
		{
			BasePrepend::queue($this->dir, [Verdict::KIND_BLOCK, 'shield rule 7 refused GET /' . $i, ['rule' => 7]]);
		}
		
		return BasePrepend::drain($this->dir, static fn(): null => null) === BasePrepend::QUEUE_MAX;
	}
	
	public function claimHandsTheStashOnceAndSettleThenQueuesNothing(): bool
	{
		$observed = $this->observed();
		$GLOBALS[BasePrepend::STASH] = ['verdict' => $observed['verdict'], 'report' => $observed['report'], 'claimed' => false];
		$claimed = BasePrepend::claim();
		
		return $claimed === $observed['report']
			&& BasePrepend::claim() === null
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
		$GLOBALS[BasePrepend::STASH] = ['verdict' => $observed['verdict'], 'report' => $observed['report'], 'claimed' => false];
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
		return BasePrepend::claim() === null
			&& BasePrepend::settle($this->dir) === false;
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
		$legacy = $this->dir . DIRECTORY_SEPARATOR . 'old-prepend.php';
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
		], time())->toRecord());
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
		], time())->toRecord());
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
