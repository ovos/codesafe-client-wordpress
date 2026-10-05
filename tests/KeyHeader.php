<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Test;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

use function file_get_contents;
use function preg_match_all;
use function str_ends_with;

use const DIRECTORY_SEPARATOR;

/**
 * Every request the plugin sends to codesafe names its key twice: as
 * X-Codesafe-Key, which every instance since the rename (2026-09-24) reads,
 * and as X-Console-Key, which an instance from before it reads alone. A
 * site cannot know which one it reports to, so no sender may drop either
 * name until every instance has been upgraded.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class KeyHeader extends Test
{
	protected const string SOURCE = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src';
	
	/**
	 * RULE: every X-Console-Key under src/ comes right after an
	 * X-Codesafe-Key in the same form, on its line or the one above.
	 * Falsify: delete one X-Codesafe-Key line from src/Sender.php.
	 */
	public function everyKeyHeaderIsSentUnderBothNames(): bool
	{
		$sites = 0;
		$files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::SOURCE, RecursiveDirectoryIterator::SKIP_DOTS));
		foreach($files as $file)
		{
			if(str_ends_with($file->getFilename(), '.php') === false)
			{
				continue;
			}
			$code = (string)file_get_contents($file->getPathname());
			$old = preg_match_all("/'X-Console-Key(?:' =>|: ')/", $code);
			$paired = preg_match_all("/'X-Codesafe-Key(' =>|: ')[^\\n]*\\n?\\s*'X-Console-Key\\1/", $code);
			if($old !== $paired)
			{
				return false;
			}
			$sites += $old;
		}
		
		// Sender (four), Rollup, Inventory, ScanRunner and the Shield kernel
		return $sites === 8;
	}
}
