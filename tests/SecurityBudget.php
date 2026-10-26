<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Security;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_column;
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
	
	/**
	 * RULE: a file-editor save is a privileged_action only for an account
	 * that may edit that kind of file (core's edit_plugins / edit_themes, the
	 * check core runs before it saves); anyone else's attempt, which core
	 * refuses, is a permission_denied under that kind's budget.
	 * Falsify: report every attempt as privileged_action — any subscriber
	 * posting to admin-ajax.php in a loop sends an uncapped incident line.
	 */
	public function aFileEditorSaveIsPrivilegedOnlyForWhoMayEditFiles(): bool
	{
		$post = $_POST;
		$sender = $this->sender();
		$security = new Security($sender);
		$_POST = ['action' => 'edit-theme-plugin-file', 'file' => 'akismet/akismet.php', 'plugin' => 'akismet/akismet.php'];
		for($i = 0; $i < 40; $i++)
		{
			$security->reportFileEditorSave();
		}
		$refused = $this->of($sender, 'permission_denied');
		$GLOBALS['wp']['current_caps'] = ['edit_plugins'];
		$security->reportFileEditorSave();
		// a theme's file needs edit_themes, which this account lacks
		$_POST = ['action' => 'edit-theme-plugin-file', 'file' => 'header.php', 'theme' => 'twentytwenty'];
		$security->reportFileEditorSave();
		$GLOBALS['wp']['current_caps'] = ['edit_themes'];
		$_POST['file'] = 'functions.php';
		$security->reportFileEditorSave();
		$_POST = $post;
		$saved = $this->of($sender, 'privileged_action');
		
		return count($refused) === 30
			&& $refused[0]['events'][0]['message'] === 'file editor save refused: plugin akismet/akismet.php'
			&& count($this->of($sender, 'permission_denied')) === 30
			&& count($saved) === 2
			&& $saved[0]['events'][0]['message'] === 'file editor save: plugin akismet/akismet.php'
			&& $saved[1]['events'][0]['message'] === 'file editor save: theme functions.php'
			&& ($saved[1]['extra']['action'] ?? '') === 'file_edit';
	}
	
	/**
	 * RULE: a sign-up — an account made by no one who may create accounts,
	 * with no capability the site's default role lacks — is routine, as a
	 * clean login is, and reports nothing: an open registration or a shop's
	 * checkout cannot flood the uncapped privileged_action. An account above
	 * the default role, any account an administrator creates, every role
	 * change, and a sign-up into a default role that can write posts (open
	 * signup into administrator, the post-compromise trap) are reported.
	 * Falsify: drop the sign-up check — fifty sign-ups are fifty incident
	 * lines; drop any one of its guards — one of the four lines goes silent.
	 */
	public function anOrdinarySignUpIsNoPrivilegedAction(): bool
	{
		$GLOBALS['wp']['roles'] = [
			'subscriber' => ['read' => true, 'level_0' => true],
			'customer' => ['read' => true],
			'editor' => ['read' => true, 'edit_posts' => true, 'unfiltered_html' => true],
			'administrator' => ['read' => true, 'edit_posts' => true, 'manage_options' => true, 'create_users' => true],
		];
		$GLOBALS['wp']['options']['default_role'] = 'subscriber';
		$sender = $this->sender();
		$security = new Security($sender);
		for($i = 0; $i < 50; $i++)
		{
			$security->reportRoleChange(100 + $i, $i % 2 === 0 ? 'subscriber' : 'customer', []);
		}
		$quiet = count($this->of($sender, 'privileged_action'));
		$security->reportRoleChange(200, 'editor', []);
		// the site's default role flipped to administrator: an open signup makes admins
		$GLOBALS['wp']['options']['default_role'] = 'administrator';
		$security->reportRoleChange(201, 'administrator', []);
		$GLOBALS['wp']['options']['default_role'] = 'subscriber';
		$GLOBALS['wp']['current_caps'] = ['create_users'];
		$security->reportRoleChange(202, 'subscriber', []);
		$GLOBALS['wp']['current_caps'] = [];
		$security->reportRoleChange(203, 'subscriber', ['editor']);
		$lines = array_column(array_column($this->of($sender, 'privileged_action'), 'events'), 0);
		
		return $quiet === 0
			&& array_column($lines, 'message') === [
				'user created: #200 as editor',
				'user created: #201 as administrator',
				'user created: #202 as subscriber',
				'user role changed: #203 editor -> subscriber',
			];
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
