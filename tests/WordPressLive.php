<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Test;
use RuntimeException;

use function escapeshellarg;
use function exec;
use function getenv;
use function implode;
use function is_file;
use function rtrim;

use const DIRECTORY_SEPARATOR;
use const PHP_BINARY;

/**
 * The signed-update path on a REAL WordPress (tests/files/wp-live.file.php): its
 * own download_url(), HTTP API, transients, a real GitHub API answer, a real
 * .sig fetch. In a subprocess — a bootstrapped WordPress cannot share a
 * process with the other classes' shims.
 *
 * Skipped unless OVOS_WP_PATH names a WordPress install with this plugin
 * ACTIVE; needs network access to github.com.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class WordPressLive extends Test
{
	protected string $root = '';
	
	public function __construct()
	{
		$root = getenv('OVOS_WP_PATH');
		$this->root = rtrim($root === false ? '' : $root, '/\\');
		
		if($this->root === '' || is_file($this->root . DIRECTORY_SEPARATOR . 'wp-load.php') === false)
		{
			$this->setDisabled(true,
				'OVOS_WP_PATH does not name a WordPress install.'
			);
		}
	}
	
	public function signedUpdatePathHoldsOnRealWordPress(): bool
	{
		exec(PHP_BINARY . ' ' . escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wp-live.file.php') . ' ' . escapeshellarg($this->root) . ' 2>&1', $output, $status);
		
		if($status !== 0)
		{
			// the script's own ok / FAIL lines are the reason
			throw new RuntimeException(implode("\n", $output));
		}
		
		return true;
	}
}
