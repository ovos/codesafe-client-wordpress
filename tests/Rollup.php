<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Rollup as CodesafeRollup;
use Ovos\Test;

use function array_fill;

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
}
