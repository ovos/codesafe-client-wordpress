<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Inventory;
use Ovos\Codesafe\Plugin;
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
	
	/**
	 * RULE: softwareVersion() reads the `software` an ingest answer carries
	 * and nothing else
	 */
	public function softwareVersionIsReadOffAnAnswerAndNothingElse(): bool
	{
		return Sender::softwareVersion('{"success":true,"accepted":1,"shield":"s","software":"v1"}') === 'v1'
			&& Sender::softwareVersion('{"success":true,"shield":"s"}') === ''
			&& Sender::softwareVersion('{"software":7}') === ''
			&& Sender::softwareVersion('<html>') === ''
			&& Sender::softwareVersion('') === '';
	}
	
	/**
	 * RULE: the hook every answer reaches (Plugin::answerHook) hands the
	 * software version to the inventory on a 2xx only, and there is no hook
	 * when neither the Shield nor the inventory listens. Falsify: build the
	 * hook from the Shield alone — an operator's pick waits for the daily send.
	 */
	public function anAnswerNudgesTheInventoryOnA2xxOnly(): bool
	{
		$GLOBALS['wp']['options'][Config::OPTION] = ['enabled' => true, 'url' => 'https://console.invalid', 'api_key' => str_repeat('a', 64)];
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
		$hook = Plugin::answerHook(null, new Inventory(new Config));
		if($hook === null)
		{
			return false;
		}
		$sender->onAnswer($hook);
		
		$sender->hear(503, '{"software":"v8"}');
		$refused = isset($GLOBALS['wp']['options']['ovos_codesafe_inventory_dirty']) === false;
		$sender->hear(202, '{"accepted":1,"software":"v9"}');
		
		return Plugin::answerHook(null, null) === null
			&& $refused
			&& ($GLOBALS['wp']['options']['ovos_codesafe_inventory_dirty'] ?? null) === 'v9';
	}
	
	/**
	 * RULE: the Shield's pull hands X-Codesafe-Software on, from the 200 and
	 * the 304 alike, whatever its case, and from nothing else — while the
	 * kernel still gets every header. Falsify: read it on a 200 only — a site
	 * whose ruleset never changes never hears a pick.
	 */
	public function theShieldPullHandsTheSoftwareVersionOn(): bool
	{
		$adapter = new Adapter($this->config(true), new Sender(new Config));
		$heard = [];
		$adapter->onSoftware(static function(string $version) use (&$heard): void
		{
			$heard[] = $version;
		});
		
		$GLOBALS['wp']['get_status'] = 304;
		$GLOBALS['wp']['get_headers'] = ['X-Codesafe-Software' => 'v1', 'X-Shield-Version' => 'r'];
		$notModified = $adapter->transport('https://console.invalid/api/v1/shield', [], 1000);
		$GLOBALS['wp']['get_status'] = 200;
		$GLOBALS['wp']['get_headers'] = ['x-codesafe-software' => ['v2']];
		$adapter->transport('https://console.invalid/api/v1/shield', [], 1000);
		$GLOBALS['wp']['get_status'] = 503;
		$GLOBALS['wp']['get_headers'] = ['X-Codesafe-Software' => 'v3'];
		$adapter->transport('https://console.invalid/api/v1/shield', [], 1000);
		$GLOBALS['wp']['get_status'] = 200;
		$GLOBALS['wp']['get_headers'] = [];
		$adapter->transport('https://console.invalid/api/v1/shield', [], 1000);
		
		return $heard === ['v1', 'v2']
			&& $notModified['status'] === 304
			&& ($notModified['headers']['x-codesafe-software'] ?? null) === 'v1'
			&& ($notModified['headers']['x-shield-version'] ?? null) === 'r';
	}
	
	/**
	 * RULE: a version from an answer or from the pull's header is taken only
	 * in the shape codesafe sends — letters, digits, dot, dash, underscore, at
	 * most 64 — anything else reads as none, so no answer and no proxy in front
	 * of codesafe parks a large or strange value in the site's options.
	 * Falsify: drop the shape — a 65-character or a markup-carrying version is
	 * stored.
	 */
	public function aVersionOffItsShapeReadsAsNone(): bool
	{
		$long = str_repeat('a', 65);
		$adapter = new Adapter($this->config(true), new Sender(new Config));
		$heard = [];
		$adapter->onSoftware(static function(string $version) use (&$heard): void
		{
			$heard[] = $version;
		});
		$GLOBALS['wp']['get_status'] = 200;
		$GLOBALS['wp']['get_headers'] = ['X-Codesafe-Software' => $long];
		$adapter->transport('https://console.invalid/api/v1/shield', [], 1000);
		$GLOBALS['wp']['get_headers'] = ['X-Codesafe-Software' => 'v1<script>'];
		$adapter->transport('https://console.invalid/api/v1/shield', [], 1000);
		
		return Sender::token(str_repeat('a', 64)) === str_repeat('a', 64)
			&& Sender::token('0f3a.b_c-1') === '0f3a.b_c-1'
			&& Sender::token($long) === ''
			&& Sender::token('v 1') === ''
			&& Sender::token('') === ''
			&& Sender::softwareVersion('{"software":"' . $long . '"}') === ''
			&& Sender::softwareVersion('{"software":"v1\\"><b>"}') === ''
			&& Sender::shieldVersion('{"shield":"' . $long . '"}') === ''
			&& Sender::shieldVersion('{"shield":"a;b"}') === ''
			&& $heard === [];
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
