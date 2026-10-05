<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Rollup;
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
	
	public function rollupCarriesTheShieldHitsAsTheTwoSections(): bool
	{
		$assembled = Rollup::assemble(29833333, Rollup::withExtra(['requests' => 3], static fn(int $minute): array => ['so:203' => 4, 'sb:203' => 1], 29833333));
		
		return ($assembled['shield_observe'] ?? null) === ['203' => 4]
			&& ($assembled['shield_block'] ?? null) === ['203' => 1];
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
