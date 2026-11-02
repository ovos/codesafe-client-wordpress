<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Scan;
use Ovos\Codesafe\ScanRunner as PluginScanRunner;
use Ovos\Test;
use Ovos\Test\Internal;
use RuntimeException;

use function array_key_exists;
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
	 * RULE: the runner hands the scan a checkpoint that keeps the file it is
	 * about to judge in an option of its own and drops it once cleared,
	 * writing nothing of the pass; the next chunk hands that name to the pass
	 * it resumes or begins, and drops the option. A finished pass's resume
	 * points become the next pass's start. Falsify: keep the name in the
	 * pass's own option (the whole pass is written on every large file);
	 * leave the option behind (the name is handed on twice); drop
	 * resume_next with the pass (every pass starts at the top).
	 */
	public function aDyingChunkLeavesItsCheckpointAndResumePointsCarryOver(): bool
	{
		$config = new Config();
		$scan = new class($config) extends Scan
		{
			/** @var list<array<string, mixed>> the resume points each new pass was started with */
			public array $started = [];
			
			public bool $dies = true;
			
			/** @var list<mixed> the name each chunk was handed */
			public array $handed = [];
			
			public bool $clears = false;
			
			public function start(
				string $mode,
				array $resume = [],
			): array
			{
				$this->started[] = $resume;
				
				return ['mode' => $mode, 'done' => false];
			}
			
			public function advance(
				array $state,
				int $budgetMs,
			): array
			{
				$this->handed[] = $state['judging'] ?? null;
				
				if($this->dies || $this->clears)
				{
					($this->checkpoint)(['area' => 'themes', 'path' => '/site/boom.php', 'size' => 300000]);
				}
				
				if($this->dies)
				{
					throw new RuntimeException('died judging');
				}
				
				if($this->clears)
				{
					($this->checkpoint)(null);
				}
				
				return ['done' => true, 'resume_next' => ['cache' => 'pages/p08']] + $state;
			}
			
			public function report(
				array $state,
				string $client,
			): array
			{
				return ['v' => 1];
			}
		};
		$runner = new class($config, $scan) extends PluginScanRunner
		{
			public function once(): string
			{
				return $this->run('manual', 1000);
			}
		};
		
		try
		{
			$runner->once();
		}
		catch(RuntimeException)
		{
			// the chunk died after its checkpoint
		}
		
		$left = $GLOBALS['wp']['options'][PluginScanRunner::JUDGING] ?? null;
		$pass = $GLOBALS['wp']['options'][PluginScanRunner::OPTION]['state'] ?? null;
		$scan->dies = false;
		$finished = $runner->once();
		$taken = array_key_exists(PluginScanRunner::JUDGING, $GLOBALS['wp']['options']) === false;
		$scan->clears = true;
		$runner->once();
		$cleared = array_key_exists(PluginScanRunner::JUDGING, $GLOBALS['wp']['options']) === false;
		
		return $left === ['area' => 'themes', 'path' => '/site/boom.php', 'size' => 300000]
			&& $pass === null
			&& $finished === 'done'
			&& $taken
			&& $cleared
			&& $scan->handed === [null, $left, null]
			&& $scan->started === [[], [], ['cache' => 'pages/p08']];
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
