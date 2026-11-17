<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Test;
use Ovos\Test\Internal;
use Tests\Files\WireSender;

use function addslashes;
use function array_slice;
use function count;
use function json_decode;
use function str_repeat;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'WireSender.file.php';

/**
 * The browser's Fetch Metadata on its way out of the site — `Sec-Fetch-Site`,
 * `-Mode`, `-Dest`, `-User` — which codesafe reads to tell a request a page
 * on another site made a visitor's browser send (an image, a script) from
 * one the visitor or a scanner sent: the Sender sends it with every request
 * it reports, the layer before WordPress keeps it with a refused request's
 * facts, and a drained report carries the refused request's, never the
 * draining one's. Each value goes as a token: lowercase, nothing but
 * `[a-z0-9?-]`, 32 characters.
 */
class FetchMetadata extends Test
{
	/** a cross-site image's four, as a browser sends them */
	protected const array IMAGE = ['HTTP_SEC_FETCH_SITE' => 'cross-site', 'HTTP_SEC_FETCH_MODE' => 'no-cors', 'HTTP_SEC_FETCH_DEST' => 'image',
		'HTTP_SEC_FETCH_USER' => '?1'];
	
	/** …as they are kept */
	protected const array KEPT = ['sec-fetch-site' => 'cross-site', 'sec-fetch-mode' => 'no-cors', 'sec-fetch-dest' => 'image', 'sec-fetch-user' => '?1'];
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: the Sender sends the four first and as tokens — a value
	 * WordPress slashed, one with a line break, one past 32 characters — so a
	 * request with thirty `x-…` headers still carries them, and the cap
	 * still holds over all of them. Falsify: take them in the loop as any
	 * other header (off the list, dropped), or send the value as it came.
	 */
	public function theSenderSendsThemFirstAsTokens(): bool
	{
		$saved = [$_SERVER, $_POST, $_GET];
		$_SERVER = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/.env', 'HTTP_HOST' => 'site.test'];
		for($n = 10; $n < 40; $n++)
		{
			$_SERVER['HTTP_X_H_' . $n] = 'v';
		}
		// WordPress hands $_SERVER over magic-quoted (wp_magic_quotes)
		$_SERVER['HTTP_SEC_FETCH_SITE'] = addslashes("Cross-Site'");
		$_SERVER['HTTP_SEC_FETCH_MODE'] = "no-cors\r\n";
		$_SERVER['HTTP_SEC_FETCH_DEST'] = str_repeat('image', 10);
		$_SERVER['HTTP_SEC_FETCH_USER'] = '?1';
		$_POST = [];
		$_GET = [];
		try
		{
			$wire = (new WireSender(new Config(), ''))->wire();
		}
		finally
		{
			[$_SERVER, $_POST, $_GET] = $saved;
		}
		$headers = json_decode($wire, true)[0]['context']['request']['headers'] ?? [];
		
		return count($headers) === 24
			&& array_slice($headers, 0, 4, true) === ['sec-fetch-site' => 'cross-site', 'sec-fetch-mode' => 'no-cors',
				'sec-fetch-dest' => str_repeat('image', 6) . 'im', 'sec-fetch-user' => '?1']
			&& isset($headers['x-h-29']) && isset($headers['x-h-30']) === false;
	}
	
	/**
	 * RULE: a refused request's facts keep its four under `headers`, as
	 * tokens; a request without them keeps none, and a value with no token
	 * is left out. Falsify: leave them out — a report the layer refused
	 * before WordPress counts as a scanner's.
	 */
	public function theRefusedRequestsFactsKeepThem(): bool
	{
		$server = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/.env', 'REMOTE_ADDR' => '203.0.113.9'];
		$odd = Prepend::contextOf($server + ['HTTP_SEC_FETCH_SITE' => 'Cross-Site', 'HTTP_SEC_FETCH_DEST' => '<>', 'HTTP_SEC_FETCH_MODE' => ['cors']], 403);
		
		return (Prepend::contextOf($server + self::IMAGE, 403)['headers'] ?? null) === self::KEPT
			&& ($odd['headers'] ?? null) === ['sec-fetch-site' => 'cross-site']
			&& isset(Prepend::contextOf($server, 403)['headers']) === false;
	}
	
	/**
	 * RULE: a drained report's request carries the four of its facts, read
	 * again through the token rule, beside the query; nothing else the file
	 * holds under `headers`, and nothing where it holds none or no list.
	 * Falsify: pass the file's `headers` through — a value written there is
	 * sent as it is; or drop them — the report counts as a scanner's.
	 */
	public function aDrainedReportReadsTheFourAlone(): bool
	{
		$drained = Adapter::drained(['uri' => '/.env?a=1', 'headers' => ['sec-fetch-site' => 'Cross-Site', 'sec-fetch-dest' => '<>',
			'sec-fetch-mode' => ['cors'], 'cookie' => 'a=b', 'sec-fetch-user' => '?1']]);
		
		return ($drained['request'] ?? null) === ['get' => ['a' => '1'], 'headers' => ['sec-fetch-site' => 'cross-site', 'sec-fetch-user' => '?1']]
			&& (Adapter::drained(['uri' => '/.env', 'headers' => 'cross-site'])['request'] ?? null) === []
			&& (Adapter::drained(['uri' => '/.env'])['request'] ?? null) === [];
	}
	
	/**
	 * RULE: a report the layer queued reaches codesafe with the refused
	 * request's four, never the draining request's: the Sender's own request
	 * (a same-origin page view) does not reach it. Falsify: leave the
	 * request out of the drained facts — the Sender fills it with the
	 * draining request's.
	 */
	public function aQueuedReportCarriesTheRefusedRequestsFour(): bool
	{
		$refused = Prepend::contextOf(['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/.env?a=1', 'REMOTE_ADDR' => '203.0.113.9'] + self::IMAGE, 403);
		$sender = $this->sender();
		$sender->reportRefusal('shield_block', 'shield rule 7 refused GET /.env', ['rule' => 7], Adapter::drained($refused));
		$context = $sender->decorated($sender->queued()[0], ['host' => 'site.test',
			'request' => ['headers' => ['sec-fetch-site' => 'same-origin', 'sec-fetch-mode' => 'navigate', 'accept' => 'text/html']]])['context'];
		
		return ($context['request'] ?? null) === ['get' => ['a' => '1'], 'headers' => self::KEPT];
	}
	
	/**
	 * RULE: the layer before WordPress restates the Sender's names, cap and
	 * token rule (it references no other plugin class): both read a request
	 * alike. Falsify: change one copy.
	 */
	public function theTwoCopiesAgree(): bool
	{
		$servers = [
			self::IMAGE,
			['HTTP_SEC_FETCH_SITE' => " Same-Site\t", 'HTTP_SEC_FETCH_MODE' => str_repeat('navigate', 6), 'HTTP_SEC_FETCH_DEST' => 7],
			['HTTP_SEC_FETCH_SITE' => '<>', 'HTTP_SEC_FETCH_USER' => true],
			[],
		];
		foreach($servers as $server)
		{
			if(Sender::fetchHeaders($server) !== Prepend::fetchHeaders($server))
			{
				return false;
			}
		}
		
		return Sender::FETCH_HEADERS === Prepend::FETCH_HEADERS && Sender::FETCH_VALUE_MAX === Prepend::FETCH_VALUE_MAX;
	}
	
	/** a sender with security events and the Shield's reports on, whose queue the test reads */
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
}
