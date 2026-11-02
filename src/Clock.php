<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

/**
 * The one rule for a time the plugin stored and reads back to decide
 * whether to wait: the code writes the time it acted, or a retry a known
 * span after it. A stored time further ahead was not written by this code
 * but planted in the options table, where it would hold a guard shut for
 * good, since its age is negative and below every limit; it is stale.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
final class Clock
{
	/**
	 * Seconds a stored time may run ahead of this server's clock: servers
	 * sharing one options table keep clocks a little apart. A plant within it
	 * holds a guard no longer than the guard's own span and these seconds
	 */
	public const SKEW = 5;
	
	/**
	 * Whether $at lies ahead of $now by more than $by, the furthest this code
	 * writes it ahead, and the skew
	 */
	public static function ahead(
		int $at,
		int $now,
		int $by = 0,
	): bool
	{
		return $at > $now + $by + self::SKEW;
	}
}
