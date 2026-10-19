<?php
declare(strict_types=1);

namespace Tests;

use APCUIterator;
use Ovos\Codesafe\Config;
use Ovos\Codesafe\Rollup as CodesafeRollup;
use Ovos\Test;
use Ovos\Test\Exception\SkipException;

use function apcu_delete;
use function apcu_fetch;
use function apcu_store;
use function array_fill;
use function count;
use function get_option;
use function intdiv;
use function preg_quote;
use function time;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The duration histogram the rollup ships: the coarse bucket every sender
 * shares, and bucket 0's split (codesafe's D5) — nearly every request lands
 * in bucket 0 (≤ 25 ms), where codesafe's percentiles read 12.5 / 23.8 ms
 * whatever the site does, so a duration there also counts into ≤ 5, ≤ 10 or
 * ≤ 25 ms and ships as durations_fine. codesafe drops a split that does not
 * add up to its key's bucket 0, never the fragment.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Rollup extends Test
{
	/**
	 * RULE: the bounds are the wire contract, and a duration in bucket 0 also
	 * counts into its part of the split — pinned AT the bounds — in the
	 * __total headline and in the route's own split, beside the coarse
	 * bucket; past bucket 0 there is no split.
	 */
	public function bucketZeroSplitsIntoThreeParts(): bool
	{
		return CodesafeRollup::DURATION_BOUNDS === [25, 50, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 30000]
			&& CodesafeRollup::DURATION_SPLIT === [5, 10]
			&& CodesafeRollup::DURATION_FINE_PARTS === 3
			&& CodesafeRollup::bucketFor(25.0) === 0
			&& CodesafeRollup::bucketFor(25.1) === 1
			&& CodesafeRollup::splitFor(0.0) === 0
			&& CodesafeRollup::splitFor(5.0) === 0
			&& CodesafeRollup::splitFor(5.1) === 1
			&& CodesafeRollup::splitFor(10.0) === 1
			&& CodesafeRollup::splitFor(10.1) === 2
			&& CodesafeRollup::splitFor(25.0) === 2
			&& CodesafeRollup::splitFor(25.1) === null
			&& CodesafeRollup::durationFields('/admin/ajax', 7.0) === ['dt:0', 'd:/admin/ajax:0', 'dtf:1', 'df:/admin/ajax:1']
			&& CodesafeRollup::durationFields('/feed', 30.0) === ['dt:1', 'd:/feed:1'];
	}
	
	/**
	 * RULE: dtf:/df: counters assemble into three-int splits under
	 * durations_fine — the route split on the LAST colon — and only beside
	 * the vector they split: no __total headline, no durations and no
	 * split; a route whose vector was evicted ships no split of its own.
	 * Falsify: drop the intersection — `/gone` ships a split of a vector the
	 * fragment does not carry.
	 */
	public function theSplitAssemblesBesideTheVectorItSplits(): bool
	{
		$payload = CodesafeRollup::assemble(29248320, [
			'requests' => 4,
			'dt:0' => 3,
			'dt:2' => 1,
			'd:/rest:0' => 2,
			'd:/search:0' => 1,
			'd:/search:2' => 1,
			'dtf:0' => 2,
			'dtf:2' => 1,
			'df:/rest:0' => 1,
			'df:/rest:2' => 1,
			'df:/search:0' => 1,
			'df:/gone:1' => 1,
		]);
		
		$evicted = CodesafeRollup::assemble(29248320, [
			'requests' => 1,
			'd:/search:0' => 1,
			'dtf:0' => 1,
			'df:/search:0' => 1,
		]);
		
		return ($payload['durations_fine'] ?? null) === [
				'/rest' => [1, 0, 1],
				'/search' => [1, 0, 0],
				'__total' => [2, 0, 1],
			]
			&& ($payload['durations']['__total'] ?? null) === [3, 0, 1, ...array_fill(0, CodesafeRollup::DURATION_BUCKETS - 3, 0)]
			&& isset($evicted['durations']) === false
			&& isset($evicted['durations_fine']) === false;
	}
	
	/**
	 * RULE: codesafe's own 403 — its JSON failure — is the project's rollups
	 * switch off: the site goes quiet for the hour, and the option keeps
	 * since when, written once per spell so the settings page names the
	 * first refusal; an accepted fragment ends the spell; a firewall's HTML
	 * 403 and any other answer change nothing; a changed URL or key ends the
	 * spell at once. Falsify: write the option on every 403 — the time moves
	 * with each hourly ask; drop the JSON check — a WAF page silences the site.
	 */
	public function aRefusalQuietsTheSiteAndAnAcceptedFragmentEndsIt(): bool
	{
		$this->needsApcu();
		$rollup = $this->rollup();
		$now = 1_790_000_000;
		$refusal = '{"success":false,"error":"rollups disabled for this project"}';
		
		$before = $rollup->refused();
		$unanswered = $rollup->heard(500, '', $now) === false
			&& $rollup->heard(403, '<html><body>Forbidden by the firewall</body></html>', $now) === false
			&& $rollup->refused() === false
			&& get_option(CodesafeRollup::OPTION_REFUSED, false) === false;
		$refused = $rollup->heard(403, $refusal, $now)
			&& $rollup->refused()
			&& get_option(CodesafeRollup::OPTION_REFUSED, false) === $now;
		$rollup->heard(403, $refusal, $now + 3600);
		$kept = get_option(CodesafeRollup::OPTION_REFUSED, false) === $now;
		$rollup->heard(202, '{"success":true}', $now + 7200);
		$ended = get_option(CodesafeRollup::OPTION_REFUSED, false) === false;
		$rollup->heard(403, $refusal, $now + 9000);
		$rollup->forgetRefusal();
		$forgotten = $rollup->refused() === false && get_option(CodesafeRollup::OPTION_REFUSED, false) === false;
		
		return $before === false && $unanswered && $refused && $kept && $ended && $forgotten;
	}
	
	/**
	 * RULE: a refused site counts nothing — not even this request — and one
	 * not refused counts it. Falsify: drop the refused() check in observe()
	 * — the refused site keeps counting into APCu every request.
	 */
	public function aRefusedSiteCountsNothing(): bool
	{
		$this->needsApcu();
		$rollup = $this->rollup();
		$minute = intdiv(time(), 60);
		
		$rollup->heard(403, '{"success":false}');
		$rollup->observe();
		$quiet = $rollup->counted($minute) === 0;
		$rollup->forgetRefusal();
		$rollup->observe();
		$counted = $rollup->counted($minute) === 1;
		$rollup->clear();
		
		return $quiet && $counted;
	}
	
	/**
	 * RULE: the flush stops at the first refusal — one POST, not one per
	 * waiting minute. Falsify: drop the break — both minutes are posted to a
	 * project that said no.
	 */
	public function theFlushStopsAtTheFirstRefusal(): bool
	{
		$this->needsApcu();
		$rollup = $this->rollup(refuse: true);
		$minute = intdiv(time(), 60);
		$rollup->seed($minute - 3);
		$rollup->seed($minute - 2);
		
		$rollup->flushNow($minute);
		$sent = $rollup->sent;
		$rollup->clear();
		
		return count($sent) === 1 && $sent[0]['minute'] === $minute - 3;
	}
	
	/** APCu holds the counters and the refusal; without it these rules are moot */
	protected function needsApcu(): void
	{
		if(CodesafeRollup::hasApcu() === false)
		{
			throw new SkipException('APCu is not enabled for this SAPI (apc.enable_cli).');
		}
	}
	
	/**
	 * A connected Rollup on a site of its own (its APCu prefix), driven as a
	 * web request, whose send() records the fragment instead of posting it
	 * and answers a refusal when asked to
	 */
	protected function rollup(
		bool $refuse = false,
	): CodesafeRollup
	{
		wp_shim_reset();
		$GLOBALS['wp']['options']['home'] = 'https://zz-rollup-test.example';
		$GLOBALS['wp']['options'][Config::OPTION] = ['enabled' => true, 'url' => 'https://codesafe.example', 'api_key' => 'k'];
		$rollup = new class(new Config, $refuse) extends CodesafeRollup
		{
			/** @var list<array<string, mixed>> */
			public array $sent = [];
			
			public function __construct(
				Config $config,
				protected bool $refuse,
			)
			{
				parent::__construct($config);
			}
			
			/** the requests counted in a minute */
			public function counted(
				int $minute,
			): int
			{
				return (int)apcu_fetch($this->prefix() . $minute . ':requests');
			}
			
			/** a complete minute waiting to be shipped */
			public function seed(
				int $minute,
			): void
			{
				apcu_store($this->prefix() . $minute . ':requests', 1, 3600);
			}
			
			public function flushNow(
				int $minute,
			): void
			{
				$this->flush($minute);
			}
			
			/** every key under this site's prefix gone */
			public function clear(): void
			{
				foreach(new APCUIterator('~^' . preg_quote($this->prefix(), '~') . '~') as $entry)
				{
					apcu_delete((string)$entry['key']);
				}
			}
			
			protected function isCli(): bool
			{
				return false;
			}
			
			protected function send(
				array $payload,
			): bool
			{
				$this->sent[] = $payload;
				
				return $this->refuse;
			}
		};
		$rollup->clear();
		
		return $rollup;
	}
}
