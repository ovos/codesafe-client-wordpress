<?php
declare(strict_types=1);

/**
 * An older Prepend, without claimAll(), for
 * tests/files/adapter-stage.file.php: the stash holds one report, and
 * claim() answers it once, or null. Only what the adapter's claim and its
 * constants read.
 *
 * Under tests/files/, so the runner never takes it for a test.
 */

namespace Ovos\Codesafe\Shield;

use function is_array;
use function is_string;

final class Prepend
{
	/** read by the adapter's own constants */
	public const RULES = 'shield.json';
	
	public const STASH = 'ovos_codesafe_shield_prepend';
	
	public const MARK = 'CODESAFE_SHIELD_PREPENDED';
	
	/** @return ?array{0: string, 1: string, 2: array} */
	public static function claim(): ?array
	{
		$stash = $GLOBALS[self::STASH] ?? null;
		if(is_array($stash) === false || ($stash['claimed'] ?? false) === true)
		{
			return null;
		}
		$GLOBALS[self::STASH]['claimed'] = true;
		$report = $stash['report'] ?? null;
		
		return is_array($report) && is_string($report[0] ?? null) && is_string($report[1] ?? null)
			? [$report[0], $report[1], is_array($report[2] ?? null) ? $report[2] : []]
			: null;
	}
}
