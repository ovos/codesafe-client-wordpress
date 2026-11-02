<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Checksums as PluginChecksums;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_key_last;
use function count;
use function md5;
use function str_ends_with;
use function strtoupper;
use function time;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The wordpress.org checksum lists without the network: the shim's
 * wp_remote_get answers with the list the test sets.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Checksums extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: a plugin list keeps a file wordpress.org names with several md5s
	 * (a version built more than once: a tag edited after it was cut, trunk
	 * shipped under the same number), and a file matches any of them in any
	 * case; a single md5 still matches as before, a malformed one is dropped,
	 * and the list is cached under the shape's own key. Falsify: keep only
	 * string md5s — the file vanishes from the list and the scan calls it
	 * foreign, as it did for duplicate-post 4.7 on www.ovos.at.
	 */
	public function aListWithSeveralHashesAcceptsAnyOfThem(): bool
	{
		$first = md5('first cut');
		$second = md5('second cut');
		$single = md5('only cut');
		$GLOBALS['wp']['api'] = ['files' => [
			'demo.php' => ['md5' => [$first, strtoupper($second)], 'sha256' => ['x', 'y']],
			'inc/one.php' => ['md5' => $single],
			'bad.php' => ['md5' => 'not-a-hash'],
		]];
		
		$list = (new PluginChecksums)->plugin('demo', '1.0');
		$key = array_key_last($GLOBALS['wp']['transients']);
		
		return $list !== null
			&& $list['demo.php'] === [$first, $second]
			&& isset($list['bad.php']) === false
			&& PluginChecksums::matches($list, 'demo.php', strtoupper($second))
			&& PluginChecksums::matches($list, 'demo.php', $first)
			&& PluginChecksums::matches($list, 'demo.php', $single) === false
			&& PluginChecksums::matches($list, 'inc/one.php', $single)
			&& PluginChecksums::matches($list, 'missing.php', $single) === false
			&& str_ends_with((string)$key, 'plugin_demo_1.0_v2');
	}
	
	/**
	 * RULE: a cached list carries the time it was fetched and holds no longer
	 * than its kind may, since WordPress keeps a transient for as long as its
	 * stored timeout says and one written with no timeout for good: a list a
	 * month, an unavailable answer a week. One without a time, as a plant
	 * writes it, or dated ahead of the clock, is fetched again; one within its
	 * time is answered without asking wordpress.org.
	 * Falsify: trust the transient — a planted "unavailable" with no timeout
	 * blinds the core checksums, and the executed-file watch with them, for
	 * good.
	 */
	public function aCachedListHoldsItsKindsTimeAtMost(): bool
	{
		$GLOBALS['wp']['api'] = ['checksums' => ['wp-load.php' => md5('core')]];
		$read = static function(array $cached): array
		{
			$GLOBALS['wp']['transients']['ovos_codesafe_sums_core_7.0_en_us'] = $cached;
			$before = count($GLOBALS['wp']['got']);
			$list = (new PluginChecksums)->core('7.0', 'en_US');
			
			return [count($GLOBALS['wp']['got']) - $before, $list];
		};
		$cached = ['wp-load.php' => md5('cached')];
		
		[$planted, $fromPlant] = $read(['list' => null]);
		[$future] = $read(['list' => null, 'at' => time() + 315_360_000]);
		[$missFresh, $miss] = $read(['list' => null, 'at' => time() - 60]);
		[$missOld] = $read(['list' => null, 'at' => time() - 8 * 86400]);
		[$listFresh, $list] = $read(['list' => $cached, 'at' => time() - 29 * 86400]);
		[$listOld] = $read(['list' => $cached, 'at' => time() - 31 * 86400]);
		// the scan asks whether a list is at hand before it spends a fetch on it: a plant is not
		$GLOBALS['wp']['transients']['ovos_codesafe_sums_core_7.0_en_us'] = ['list' => null, 'at' => time() + 315_360_000];
		$plantedAtHand = (new PluginChecksums)->coreCached('7.0', 'en_US');
		$GLOBALS['wp']['transients']['ovos_codesafe_sums_core_7.0_en_us'] = ['list' => null, 'at' => time() - 60];
		$atHand = (new PluginChecksums)->coreCached('7.0', 'en_US');
		
		return $planted === 1 && $fromPlant !== null
			&& $plantedAtHand === false && $atHand
			&& $future === 1
			&& $missFresh === 0 && $miss === null
			&& $missOld === 1
			&& $listFresh === 0 && $list === $cached
			&& $listOld === 1;
	}
}
