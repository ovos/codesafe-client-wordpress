<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * Sender::reportRefusal and the site's word on how much one matters (codesafe
 * docs/plans/sender-security-priority.md): codesafe stores a security event at
 * its kind's default unless the sender names a MORE severe priority, so the
 * plugin sends the one it is given, clamped to 0-7, and INFO without one —
 * below every kind's default, so codesafe applies the default.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class SenderRefusal extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/** a sender with security events on whose queue the test can read */
	protected function sender(): object
	{
		$config = new class extends Config
		{
			public function securityEvents(): bool
			{
				return true;
			}
		};
		
		return new class($config) extends Sender
		{
			public function queued(): array
			{
				return $this->queue;
			}
		};
	}
	
	public function aRefusalCarriesThePriorityTheSiteNamesAndInfoWithoutOne(): bool
	{
		$sender = $this->sender();
		$sender->reportRefusal('auth_failure', 'administrator login failed', [], [], 3);
		$sender->reportRefusal('auth_failure', 'out of range', [], [], 12);
		$sender->reportRefusal('csrf_reject');
		[$raised, $clamped, $plain] = $sender->queued();
		
		return $raised['priority'] === 3
			&& $raised['kind'] === 'security'
			&& $raised['events'][0]['className'] === 'auth_failure'
			&& $clamped['priority'] === 7
			&& $plain['priority'] === 6
			&& $plain['message'] === 'csrf_reject';
	}
}
