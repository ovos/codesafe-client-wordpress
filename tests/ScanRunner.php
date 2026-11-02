<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Scan;
use Ovos\Codesafe\ScanRunner as PluginScanRunner;
use Ovos\Test;
use Ovos\Test\Internal;

use function time;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The scan runner's two stored times, the lock and the last pass: written
 * by the runner as the time it acted, so one ahead of the clock was planted
 * in the options table and is stale, never a reason to wait.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class ScanRunner extends Test
{
	/** ten years: a plant meant to hold for good */
	protected const int AHEAD = 315_360_000;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: a lock dated ahead of the clock is taken over like a dead
	 * request's; a lock taken just now, or a few seconds ahead by another
	 * server's clock, holds; one past its TTL is taken over.
	 * Falsify: drop the check — a planted future lock starves the scan for
	 * good, since its age is negative and below the TTL forever.
	 */
	public function aLockFromTheFutureIsTakenOver(): bool
	{
		$runner = $this->runner();
		$GLOBALS['wp']['options'][PluginScanRunner::LOCK] = time() + self::AHEAD;
		$planted = $runner->take();
		$taken = (int)($GLOBALS['wp']['options'][PluginScanRunner::LOCK] ?? 0);
		$GLOBALS['wp']['options'][PluginScanRunner::LOCK] = time();
		$held = $runner->take();
		$GLOBALS['wp']['options'][PluginScanRunner::LOCK] = time() + 3;
		$skewed = $runner->take();
		$GLOBALS['wp']['options'][PluginScanRunner::LOCK] = time() - 91;
		$dead = $runner->take();
		
		return $planted
			&& $taken <= time()
			&& $held === false
			&& $skewed === false
			&& $dead;
	}
	
	/**
	 * RULE: a last pass finished ahead of the clock never finished: the next
	 * pass is due now; an ordinary one is due an interval after it finished.
	 * Falsify: read `finished` as it is — a pass dated ten years out puts the
	 * background scan off for ten years.
	 */
	public function aPassFinishedInTheFutureIsDueNow(): bool
	{
		$runner = $this->runner();
		$GLOBALS['wp']['options'][PluginScanRunner::OPTION] = ['state' => null,
			'last' => ['finished' => time() + self::AHEAD, 'sent' => 202, 'report' => []]];
		$planted = $runner->dueAt();
		$GLOBALS['wp']['options'][PluginScanRunner::OPTION]['last']['finished'] = time() - 60;
		$ordinary = $runner->dueAt();
		
		return $planted !== null && $planted <= time()
			&& $ordinary !== null && $ordinary > time();
	}
	
	/**
	 * A runner whose lock the test takes directly
	 *
	 * @return PluginScanRunner&object{take: callable}
	 */
	protected function runner(): PluginScanRunner
	{
		$config = new Config();
		
		return new class($config, new Scan($config)) extends PluginScanRunner
		{
			public function take(): bool
			{
				return $this->lock();
			}
		};
	}
}
