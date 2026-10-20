<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Checksums as PluginChecksums;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_key_last;
use function md5;
use function str_ends_with;
use function strtoupper;

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
}
