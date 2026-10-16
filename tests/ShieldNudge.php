<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Test;
use Ovos\Test\Internal;
use RuntimeException;

use function str_repeat;
use function time;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * Fast pickup (ovos/codesafe docs/plans/shield-auto-deploy.md P7.d): codesafe's
 * ingest answers say the project's Shield ruleset version, the Sender and the
 * Rollup hand a 2xx answer to the adapter, and the adapter's kernel pulls on
 * its next tick when the version differs from the one it stored.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class ShieldNudge extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: shieldVersion() reads the `shield` an ingest answer carries and
	 * nothing else — '' for an answer without one, a version that is not a
	 * string, a body that is not JSON
	 */
	public function shieldVersionIsReadOffAnAnswerAndNothingElse(): bool
	{
		$version = str_repeat('a', 64);
		
		return Sender::shieldVersion('{"success":true,"accepted":1,"shield":"' . $version . '"}') === $version
			&& Sender::shieldVersion('{"success":true,"accepted":1}') === ''
			&& Sender::shieldVersion('{"shield":7}') === ''
			&& Sender::shieldVersion('<html>') === ''
			&& Sender::shieldVersion('') === '';
	}
	
	/**
	 * RULE: a batch's answer reaches the onAnswer() hook on a 2xx only, and a
	 * hook that throws never fails the batch. Falsify: hand it every answer —
	 * a 503's error page is parsed for a version on every retry.
	 */
	public function aBatchAnswerReachesTheHookOnlyOnA2xx(): bool
	{
		$sender = new class(new Config) extends Sender
		{
			public function hear(
				int $status,
				string $body,
			): void
			{
				$this->heard($status, $body);
			}
		};
		$heard = [];
		$sender->hear(202, 'before any hook');
		$sender->onAnswer(static function(string $body) use (&$heard): void
		{
			$heard[] = $body;
		});
		$sender->hear(202, 'taken');
		$sender->hear(503, 'later');
		$sender->hear(401, 'refused');
		$sender->onAnswer(static function(): void
		{
			throw new RuntimeException('a listener that breaks');
		});
		$sender->hear(202, 'still silent');
		
		return $heard === ['taken'];
	}
	
	/**
	 * RULE: the adapter's nudge() forces the kernel's next pull when the
	 * version differs from the stored one, and does nothing while detection
	 * is off. Falsify: nudge a switched-off shield — a site whose owner set
	 * the kill constant pulls on every answer.
	 */
	public function aNudgeForcesThePullOnlyWhileTheShieldIsOn(): bool
	{
		$one = str_repeat('a', 64);
		$two = str_repeat('b', 64);
		$on = new Adapter($this->config(true), new Sender(new Config));
		$store = $on->kernel()->store();
		$store->write(Ruleset::fromPayload(['contract' => Ruleset::CONTRACT, 'dialect' => Ruleset::DIALECT, 'project' => 'p', 'rules' => []],
			time(), '', $one)->toRecord());
		$off = new Adapter($this->config(false), new Sender(new Config));
		
		try
		{
			return $on->nudge($one) === false && $store->pullForced() === false
				&& $on->nudge($two) && $store->pullForced()
				&& $off->nudge($two) === false;
		}
		finally
		{
			$store->forcePull(false);
		}
	}
	
	protected function config(
		bool $detect,
	): Config
	{
		return new class($detect) extends Config
		{
			public function __construct(
				protected bool $detectOn,
			)
			{
			}
			
			public function enabled(): bool
			{
				return true;
			}
			
			public function url(): string
			{
				return 'https://console.invalid';
			}
			
			public function apiKey(): string
			{
				return 'nudge-key';
			}
			
			public function shieldDetect(): bool
			{
				return $this->detectOn;
			}
			
			public function shieldKill(): bool
			{
				return false;
			}
		};
	}
}
