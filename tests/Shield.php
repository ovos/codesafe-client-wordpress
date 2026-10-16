<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Rollup;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Consent;
use Ovos\Codesafe\Shield\Facts;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;
use Ovos\Test;
use Ovos\Test\Internal;
use Ovos\Test\Exception\SkipException;
use ReflectionClass;

use function class_exists;
use function function_exists;
use function getenv;
use function is_dir;
use function is_file;
use function realpath;
use function rtrim;
use function sha1_file;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;

use const BASE_DIR;
use const DIRECTORY_SEPARATOR;

if(class_exists(Kernel::class, false) === false)
{
	require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Kernel.php';
}
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The Shield kernel the plugin vendors: that it is the console's kernel byte
 * for byte, that it is the copy under test, and a smoke judge over a fake
 * ruleset in a temp-dir store.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Shield extends Test
{
	protected const string KERNEL = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Kernel.php';
	
	protected string $path;
	
	protected Kernel $kernel;
	
	protected array $reports;
	
	protected int $pulls;
	
	#[Internal]
	public function prepare(): void
	{
		$this->path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-harness-' . uniqid() . '.json';
		$store = new Store($this->path, '');
		$rules = [
			['id' => 2, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'ua', 'op' => 'prefix', 'value' => 'python-requests', 'ci' => true, 'mode' => 'proven', 'expires_at' => null],
			['id' => 1, 'origin' => 'finding', 'finding' => 'f', 'cve' => 'CVE-2099-0001', 'field' => 'uri', 'op' => 'regex', 'value' => '[?&]include=[^&]*\.\./', 'ci' => true, 'mode' => 'observe', 'expires_at' => null],
		];
		$store->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time())->toRecord());
		
		$this->reports = [];
		$this->pulls = 0;
		$this->kernel = new Kernel('https://console.invalid', 'harness-key', $store,
			function(): array
			{
				$this->pulls++;
				
				return ['status' => 304, 'headers' => [], 'body' => ''];
			},
			function(
				string $kind,
				string $message,
				array $extra,
			): void
			{
				$this->reports[] = [$kind, $message, $extra];
			});
	}
	
	#[Internal]
	public function finalize(): void
	{
		if(is_file($this->path))
		{
			unlink($this->path);
		}
	}
	
	/**
	 * php-library carries the same names — if its copy were the one loaded,
	 * every claim below would test the wrong file
	 */
	public function kernelUnderTestIsThePluginsCopy(): bool
	{
		return realpath((new ReflectionClass(Kernel::class))->getFileName()) === realpath(self::KERNEL);
	}
	
	/**
	 * Both copies are synced from the console's client-php/Shield.php; the
	 * console's own suite holds php-library's copy to the source, so equal
	 * here is equal to the source
	 */
	public function kernelIsPhpLibrarysCopyByteForByte(): bool
	{
		$library = BASE_DIR . 'vendor/ovos/php-library/src/Codesafe/Shield/Kernel.php';
		if(is_file($library) === false)
		{
			throw new SkipException('no php-library checkout at ' . $library);
		}
		
		return sha1_file($library) === sha1_file(self::KERNEL);
	}
	
	/**
	 * Against the source itself, when a console checkout is at hand
	 * (OVOS_CONSOLE_PATH, or ../codesafe or ../console beside this repository)
	 */
	public function kernelIsConsolesClientPhpShieldByteForByte(): bool
	{
		$source = $this->consolePath() . '/client-php/Shield.php';
		if(is_file($source) === false)
		{
			throw new SkipException('no console checkout at ' . $source);
		}
		
		return sha1_file($source) === sha1_file(self::KERNEL);
	}
	
	public function provenRuleUnderEnforceBlocksAndReportsShieldBlock(): bool
	{
		return $this->kernel->handle($this->bot(), new Consent(true, true, false))->outcome === Verdict::BLOCK
			&& ($this->reports[0][0] ?? '') === Verdict::KIND_BLOCK;
	}
	
	public function sameRuleWithoutEnforceObserves(): bool
	{
		return $this->kernel->handle($this->bot(), new Consent(true, false, false))->outcome === Verdict::OBSERVE
			&& ($this->reports[0][0] ?? '') === Verdict::KIND_OBSERVE;
	}
	
	/**
	 * Greedy [^&]* runs to the LAST ../ before the class stops — the fragment
	 * is what a person would want to see
	 */
	public function observeRuleMatchesTheDecodedQueryAndReportsTheFragment(): bool
	{
		$probe = Facts::fromServer([
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => '/wp-admin/admin-ajax.php?action=x&include=%2e%2e/%2e%2e/etc/passwd',
			'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'REMOTE_ADDR' => '203.0.113.9',
		]);
		
		return $this->kernel->handle($probe, new Consent(true, true, false))->outcome === Verdict::OBSERVE
			&& ($this->reports[0][2]['matched'] ?? '') === '&include=../../';
	}
	
	/**
	 * RULE: the adapter hands the kernel the parsed bags a virtual patch reads
	 * — the query, the form, the cookies, the uploads' names, the REST prefix — and WordPress's
	 * two answers only where WordPress gives them: outside it can() and
	 * nonceValid() say nothing, and the rule only observes. Falsify: build
	 * the facts without the bags — every vpatch condition on a parameter
	 * reads nothing and no vpatch ever holds on a WordPress site.
	 */
	public function theAdapterHandsTheKernelTheBagsAndWordPressAnswers(): bool
	{
		$server = ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/wp-admin/admin-ajax.php?page=1',
			'CONTENT_TYPE' => 'application/x-www-form-urlencoded', 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
		$caller = Adapter::caller($server, ['page' => '1'], ['action' => 'fx_settings'], false, false);
		$facts = Adapter::facts($server, ['page' => '1'], ['action' => 'fx_settings'], ['fx_session' => 'abc'],
			['fx_upload' => ['name' => 'notes.txt', 'tmp_name' => '/tmp/x']], $caller, '203.0.113.9', 'api');
		
		return $facts->query === ['page' => '1'] && $facts->form === ['action' => 'fx_settings'] && $facts->cookies === ['fx_session' => 'abc']
			&& $facts->files === ['fx_upload' => 'notes.txt'] && $facts->headers['x-requested-with'] === 'XMLHttpRequest'
			&& $facts->restPrefix === 'api'
			&& (function_exists('current_user_can') || $facts->can('manage_options') === null)
			&& (function_exists('wp_verify_nonce') || $facts->nonceValid('fx_save', 'abc123') === null);
	}
	
	public function plainRequestPasses(): bool
	{
		$plain = Facts::fromServer([
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => '/',
			'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'REMOTE_ADDR' => '203.0.113.9',
		]);
		
		return $this->kernel->handle($plain, new Consent(true, true, false))->isPass();
	}
	
	public function killPassesEverythingAndPullsNothing(): bool
	{
		$kill = new Consent(true, true, true);
		
		return $this->kernel->handle($this->bot(), $kill)->reason === 'kill'
			&& $this->kernel->pull($kill) === Kernel::PULL_OFF
			&& $this->pulls === 0;
	}
	
	public function duePullIsConditionalGetAnsweredWith304(): bool
	{
		return $this->kernel->pull(new Consent(true, false, false), time() + Kernel::INTERVAL) === Kernel::PULL_UNCHANGED
			&& $this->pulls === 1;
	}
	
	public function rollupCarriesTheShieldHitsAndEvidenceAsTheirSections(): bool
	{
		$assembled = Rollup::assemble(29833333, Rollup::withExtra(['requests' => 3], static fn(int $minute): array => ['so:203' => 4, 'sb:203' => 1,
			'se:203' => 9, 'sm:203' => 5, 'sa:203' => 2], 29833333));
			
		return ($assembled['shield_observe'] ?? null) === ['203' => 4]
			&& ($assembled['shield_block'] ?? null) === ['203' => 1]
			&& ($assembled['shield_entry'] ?? null) === ['203' => 9] && ($assembled['shield_match'] ?? null) === ['203' => 5]
			&& ($assembled['shield_authed'] ?? null) === ['203' => 2];
	}
	
	/**
	 * RULE: the adapter answers unsafe_html with WordPress's post filter,
	 * reading only markup the filter takes out as unsafe — a script is, a
	 * bare `&`, a stray bracket and text written with entities are not —
	 * and the facts carry that answer. Falsify: compare wp_kses_post() with
	 * the value as it is — every `Tom & Jerry` in a field is refused.
	 */
	public function theAdapterAnswersUnsafeHtmlWithThePostFilter(): bool
	{
		$server = ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/wp-admin/admin-ajax.php', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'];
		$caller = Adapter::caller($server, [], ['action' => 'fx_save'], false, false);
		$facts = Adapter::facts($server, [], ['action' => 'fx_save'], [], [], $caller, '203.0.113.9');
		
		return Adapter::htmlUnsafe('<script>alert(1)</script>') && Adapter::htmlUnsafe('Tom & Jerry') === false && Adapter::htmlUnsafe('5 > 3') === false
			&& Adapter::htmlUnsafe('x < y') === false && Adapter::htmlUnsafe('&lt;script&gt;') === false && Adapter::htmlUnsafe('<b>bold</b>') === false
			&& $facts->htmlUnsafe('<script>x</script>') === true && $facts->htmlUnsafe('a & b') === false;
	}
	
	public function fragmentWithoutHitsCarriesNoShieldSections(): bool
	{
		return isset(Rollup::assemble(29833333, ['requests' => 3])['shield_observe']) === false;
	}
	
	// ---- helpers --------------------------------------------------------------
	
	protected function bot(): Facts
	{
		return Facts::fromServer([
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => '/',
			'HTTP_USER_AGENT' => 'python-requests/2.31',
			'REMOTE_ADDR' => '203.0.113.9',
		]);
	}
	
	protected function consolePath(): string
	{
		$path = getenv('OVOS_CONSOLE_PATH');
		if($path !== false && $path !== '')
		{
			return rtrim($path, '/\\');
		}
		
		// the checkout beside this one, under its name since the rename or before it
		$beside = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR;
		
		return is_dir($beside . 'codesafe') ? $beside . 'codesafe' : $beside . 'console';
	}
}
