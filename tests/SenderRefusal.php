<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_flip;
use function array_intersect_key;
use function gmdate;

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
			
			/** one payload as the flush sends it, over a base the test names */
			public function decorated(
				array $payload,
				array $base,
			): array
			{
				return $this->decorate($payload, ['type' => 'http', 'entry' => 'web', 'context' => $base]);
			}
		};
	}
	
	/**
	 * A report another request queued — its context carries `at` — wears
	 * that request's facts and nothing of the request sending it: no status,
	 * session, account, trace or referrer of the sender; the site's host and
	 * directory stay. A report the request makes itself still takes the base
	 */
	public function aReportFromAnotherRequestTakesNothingOfTheSendingOne(): bool
	{
		$sender = $this->sender();
		$sender->reportRefusal('csrf_reject', 'queued elsewhere', [], ['uri' => '/wp-content/x.php', 'ip' => '203.0.113.9', 'at' => 1789390120]);
		$sender->reportRefusal('auth_success', 'signed in', [], ['userId' => '7']);
		[$queued, $own] = $sender->queued();
		$base = [
			'dir' => '/srv/site',
			'traceId' => 'abc123',
			'host' => 'site.test',
			'uri' => '/de/',
			'method' => 'GET',
			'referer' => 'https://site.test/',
			'ip' => '198.51.100.7',
			'ua' => 'Mozilla/5.0',
			'status' => 301,
			'sessionId' => 's1',
			'userId' => '1',
			'request' => ['get' => ['lang' => 'de']],
		];
		$foreign = $sender->decorated($queued, $base)['context'];
		$mine = $sender->decorated($own, $base)['context'];
		
		return $foreign['uri'] === '/wp-content/x.php'
			&& $foreign['ip'] === '203.0.113.9'
			&& $foreign['host'] === 'site.test'
			&& $foreign['dir'] === '/srv/site'
			&& array_intersect_key($foreign, array_flip(['method', 'referer', 'ua', 'status', 'sessionId', 'userId', 'traceId', 'request'])) === []
			&& $queued['timestamp'] === gmdate('c', 1789390120)
			&& $mine['userId'] === '7'
			&& $mine['status'] === 301
			&& $mine['sessionId'] === 's1'
			&& $mine['uri'] === '/de/';
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
