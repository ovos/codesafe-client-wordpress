<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Shield\Prepend as BasePrepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;
use Ovos\Test;
use Ovos\Test\Exception\SkipException;
use Ovos\Test\Internal;

use function apcu_enabled;
use function count;
use function escapeshellarg;
use function exec;
use function file_get_contents;
use function file_put_contents;
use function filemtime;
use function function_exists;
use function glob;
use function is_dir;
use function is_int;
use function mkdir;
use function realpath;
use function rmdir;
use function sleep;
use function str_contains;
use function str_replace;
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
	
	protected const array ENFORCE = ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => '', 'root' => '', 'entries' => false];
	
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
		(new Store($this->dir . DIRECTORY_SEPARATOR . 'shield.json', ''))->write(Ruleset::fromPayload([
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
		
		if(is_dir($this->dir))
		{
			foreach(glob($this->dir . DIRECTORY_SEPARATOR . '*') as $file)
			{
				unlink($file);
			}
			rmdir($this->dir);
		}
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
	 * A signed-in request is the plugins_loaded judge's, not this layer's —
	 * WordPress's test cookie is not a login
	 */
	public function loginCookieDefersToPluginsLoaded(): bool
	{
		BasePrepend::writeConsent($this->dir, self::ENFORCE);
		
		return BasePrepend::judge($this->dir, $this->server(self::BOT), [], ['wordpress_logged_in_abc123' => 'x']) === null
			&& BasePrepend::judge($this->dir, $this->server(self::BOT), [], ['wordpress_test_cookie' => 'WP Cookie check']) !== null;
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
		(new Store($this->dir . DIRECTORY_SEPARATOR . 'shield.json', ''))->write(Ruleset::fromPayload([
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
	
	// ---- helpers --------------------------------------------------------------
	
	protected function server(
		string $ua,
		string $uri = '/wp-content/plugins/some-plugin/file.php',
	): array
	{
		return [
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => $uri,
			'HTTP_USER_AGENT' => $ua,
			'REMOTE_ADDR' => '203.0.113.9',
		];
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
