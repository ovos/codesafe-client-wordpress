<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Security;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;

use function count;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * Security::reportLoginFailed and the account it names (codesafe
 * docs/plans/sender-security-priority.md): a failed login on an existing
 * account carries the account as context.userId, so codesafe groups each
 * account's failures as one issue and can count many accounts refused at
 * once; an administrator's is raised to WARNING; a name no account carries
 * stays nameless at the kind's default.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class SecurityLoginFailure extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		$GLOBALS['wp']['users'] = [
			'editor' => [7, 'editor@example.com', ['edit_posts']],
			'owner' => [1, 'owner@example.com', ['edit_posts', 'manage_options']],
			'network' => [2, 'network@example.com', ['edit_posts']],
		];
		$GLOBALS['wp']['super_admins'] = [2];
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
	
	public function anAdministratorsFailureIsWarningAndNamesTheAccount(): bool
	{
		$sender = $this->sender();
		$security = new Security($sender);
		$security->reportLoginFailed('owner');
		// a multisite super admin runs the site too, whatever the site's roles say
		$security->reportLoginFailed('network');
		// wp-login takes an e-mail in the name field as well
		$security->reportLoginFailed('owner@example.com');
		[$owner, $network, $byEmail] = $sender->queued();
		
		return $owner['priority'] === 4
			&& ($owner['context']['userId'] ?? '') === '1'
			&& $owner['events'][0]['className'] === 'auth_failure'
			&& $network['priority'] === 4
			&& ($network['context']['userId'] ?? '') === '2'
			&& $byEmail['priority'] === 4
			&& ($byEmail['context']['userId'] ?? '') === '1';
	}
	
	public function anOrdinaryAccountIsNamedAtTheDefault(): bool
	{
		$sender = $this->sender();
		(new Security($sender))->reportLoginFailed('editor');
		[$editor] = $sender->queued();
		
		return $editor['priority'] === 6
			&& ($editor['context']['userId'] ?? '') === '7';
	}
	
	public function aNameNoAccountCarriesStaysNameless(): bool
	{
		$sender = $this->sender();
		$security = new Security($sender);
		$security->reportLoginFailed('admin');
		$security->reportLoginFailed('nobody@example.com');
		$security->reportLoginFailed('');
		$queued = $sender->queued();
		
		foreach($queued as $payload)
		{
			if($payload['priority'] !== 6 || isset($payload['context']['userId']))
			{
				return false;
			}
		}
		
		return count($queued) === 3;
	}
}
