<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_filter;
use function array_values;
use function count;
use function gmdate;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * M17 of the 2026-10-03 security audit: one 60-a-minute budget served every
 * security kind, so sixty bad logins silenced the privilege grant and the
 * Shield block that followed. Each kind now counts in its own window;
 * privileged_action has no cap; what goes over a cap is counted and sent as
 * ONE summary event of its kind when its window closes.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class SecurityBudget extends Test
{
	protected const int NOW = 1_790_000_000;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/** a flood of failed logins leaves the privilege grant and the Shield block that follow it untouched */
	public function aLoginFloodSilencesNeitherAPrivilegeGrantNorAShieldBlock(): bool
	{
		$sender = $this->sender();
		for($i = 0; $i < 70; $i++)
		{
			$sender->reportRefusal('auth_failure', 'login failed');
		}
		$sender->reportRefusal('privileged_action', 'role granted: administrator');
		$sender->reportRefusal('shield_block', 'shield rule 7 refused GET /x');
		
		return count($this->of($sender, 'auth_failure')) === 30
			&& count($this->of($sender, 'privileged_action')) === 1
			&& count($this->of($sender, 'shield_block')) === 1;
	}
	
	/** privileged_action has no budget at all — eighty in a minute, eighty sent */
	public function privilegedActionIsNeverHeldBack(): bool
	{
		$sender = $this->sender();
		for($i = 0; $i < 80; $i++)
		{
			$sender->reportRefusal('privileged_action', 'option changed: siteurl');
		}
		
		return count($this->of($sender, 'privileged_action')) === 80;
	}
	
	/**
	 * What went over a budget is not forgotten: the next security event after
	 * the window closed carries ONE summary of the kind, with the count
	 */
	public function aFloodIsSummarisedWhenItsWindowCloses(): bool
	{
		$sender = $this->sender();
		for($i = 0; $i < 35; $i++)
		{
			$sender->reportRefusal('auth_failure', 'login failed');
		}
		$during = count($this->of($sender, 'auth_failure'));
		$sender->clock = self::NOW + 61;
		$sender->reportRefusal('csrf_reject', 'nonce refused');
		$summary = array_values(array_filter($this->of($sender, 'auth_failure'),
			static fn(array $payload): bool => ($payload['extra']['summary'] ?? false) === true));
		$sender->reportRefusal('csrf_reject', 'nonce refused again');
		$again = array_filter($this->of($sender, 'auth_failure'),
			static fn(array $payload): bool => ($payload['extra']['summary'] ?? false) === true);
		
		return $during === 30
			&& count($summary) === 1
			&& $summary[0]['extra']['suppressed'] === 5
			&& $summary[0]['extra']['sent'] === 30
			&& $summary[0]['timestamp'] === gmdate('c', self::NOW + 60)
			&& count($this->of($sender, 'csrf_reject')) === 2
			&& count($again) === 1;
	}
	
	/** the shield's block has the widest budget, and its excess is summarised too */
	public function shieldBlocksGetTheWidestBudget(): bool
	{
		$sender = $this->sender();
		for($i = 0; $i < 95; $i++)
		{
			$sender->reportRefusal('shield_block', 'shield rule 7 refused GET /x');
			$sender->drop();
		}
		$sender->reportRefusal('shield_block', 'one more');
		
		return count($this->of($sender, 'shield_block')) === 1;
	}
	
	/** the count 1.0.2 kept in the same transient is read as no window at all */
	public function the102CounterIsReadAsAFreshStart(): bool
	{
		$GLOBALS['wp']['transients']['ovos_codesafe_security_rate'] = 60;
		$sender = $this->sender();
		$sender->reportRefusal('auth_failure', 'login failed');
		
		return count($this->of($sender, 'auth_failure')) === 1;
	}
	
	/** a sender with every gate open whose queue and clock the test holds */
	protected function sender(): object
	{
		$config = new class extends Config
		{
			public function securityEvents(): bool
			{
				return true;
			}
			
			public function shieldDetect(): bool
			{
				return true;
			}
		};
		
		$sender = new class($config) extends Sender
		{
			public int $clock = 0;
			
			public function queued(): array
			{
				return $this->queue;
			}
			
			/** what a flush does to the queue, without the post */
			public function drop(): void
			{
				$this->queue = [];
			}
			
			protected function now(): int
			{
				return $this->clock;
			}
		};
		$sender->clock = self::NOW;
		
		return $sender;
	}
	
	/** the queued events of one kind */
	protected function of(
		object $sender,
		string $kind,
	): array
	{
		return array_values(array_filter($sender->queued(),
			static fn(array $payload): bool => ($payload['events'][0]['className'] ?? '') === $kind));
	}
}
