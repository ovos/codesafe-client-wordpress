<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Spool as CodesafeSpool;
use Ovos\Test;
use Ovos\Test\Internal;

use function apcu_enabled;
use function apcu_exists;
use function apcu_fetch;
use function array_shift;
use function dirname;
use function file_get_contents;
use function function_exists;
use function is_int;
use function str_contains;
use function str_repeat;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The batches codesafe did not take are posted again after the response,
 * then kept for a later request — ovos/php-library's rules (codesafe
 * docs/SENDER.md §5 rule 3): Sender::send() posted each batch once and read
 * no answer. Only what codesafe certainly did not take (retryable()), once
 * more after fastcgi_finish_request() released the visitor, then in APCu
 * under a fixture prefix here — at most 10 batches of at most 64 KB, never
 * into the last quarter of APCu's memory — with a 30 s backoff. The
 * transport is scripted through transmit(); nothing is posted.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Spool extends Test
{
	protected const PREFIX = 'zz-spool-test:';
	
	#[Internal]
	public function isDisabled(): bool
	{
		if(function_exists('apcu_enabled') === false || apcu_enabled() === false)
		{
			$this->reason = 'APCu unavailable';
			
			return true;
		}
		
		return false;
	}
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		(new CodesafeSpool(self::PREFIX))->clear();
	}
	
	#[Internal]
	public function deconstruct(): void
	{
		(new CodesafeSpool(self::PREFIX))->clear();
	}
	
	/**
	 * RULE: kept is only what codesafe certainly did not take — never sent
	 * whole, or 429/502/503/504; a 2xx is done, a 4xx final, and an answer
	 * lost after sending may have been stored
	 */
	public function onlyWhatWasNotTakenIsKept(): bool
	{
		return Sender::retryable(0, false) === true
			&& Sender::retryable(503, true) === true
			&& Sender::retryable(429, true) === true
			&& Sender::retryable(502, true) === true
			&& Sender::retryable(504, true) === true
			&& Sender::retryable(202, true) === false
			&& Sender::retryable(400, true) === false
			&& Sender::retryable(500, true) === false
			&& Sender::retryable(0, true) === false;
	}
	
	/**
	 * RULE: curl says codesafe may have the batch when an answer came or the
	 * whole body went out; WordPress's HTTP API cannot say, so its failure
	 * is never retried — read off the source, it posts
	 */
	public function theTransportSaysWhetherCodesafeMayHaveIt(): bool
	{
		$source = (string)file_get_contents(dirname(__DIR__) . '/src/Sender.php');
		
		return str_contains($source, "\$status > 0 || (int)curl_getinfo(\$handle, CURLINFO_SIZE_UPLOAD_T) >= strlen(\$json),")
			&& str_contains($source, "? [0, true]\n\t\t\t: [(int)wp_remote_retrieve_response_code(\$response), true];")
			&& str_contains($source, "&& @fastcgi_finish_request() === true;");
	}
	
	/** RULE: first kept, first taken; an empty take moves nothing */
	public function theSpoolIsFirstInFirstOut(): bool
	{
		$spool = new CodesafeSpool(self::PREFIX);
		$spool->clear();
		$spool->keep('a');
		$spool->keep('b');
		$order = [$spool->take(), $spool->take(), $spool->take(), $spool->size()];
		$spool->keep('c');
		
		return $order === ['a', 'b', null, 0]
			&& $spool->take() === 'c';
	}
	
	/**
	 * RULE: the spool never crowds the site's cache out: the batches passed
	 * over are deleted at once, a big batch is never kept, nothing is kept
	 * while APCu has less than a quarter free
	 */
	public function theSpoolNeverCrowdsTheCache(): bool
	{
		$spool = new class(self::PREFIX) extends CodesafeSpool
		{
			public bool $room = true;
			
			/** the slots that exist in APCu, passed over or not */
			public function slots(): int
			{
				$count = 0;
				$tail = apcu_fetch($this->key('tail'));
				for($slot = 1; is_int($tail) && $slot <= $tail; $slot++)
				{
					$count+= apcu_exists($this->key('slot:' . $slot)) ? 1 : 0;
				}
				
				return $count;
			}
			
			protected function roomy(): bool
			{
				return $this->room;
			}
		};
		$spool->clear();
		for($i = 1; $i <= 3 * CodesafeSpool::MAX_BATCHES; $i++)
		{
			$spool->keep('batch ' . $i);
		}
		$bounded = [$spool->slots(), $spool->size()];
		$oldest = $spool->take();
		$big = $spool->keep(str_repeat('x', CodesafeSpool::MAX_BATCH_BYTES + 1));
		$spool->room = false;
		$crowded = $spool->keep('small');
		
		return $bounded === [CodesafeSpool::MAX_BATCHES, CodesafeSpool::MAX_BATCHES]
			&& $oldest === 'batch ' . (2 * CodesafeSpool::MAX_BATCHES + 1)
			&& $big === false
			&& $crowded === false;
	}
	
	/**
	 * RULE: after the release a batch codesafe did not take is posted once
	 * more; refused again it is kept and the posts back off; while backing
	 * off a batch is kept without a post; a 2xx takes one kept batch along;
	 * before the release there is no retry; a final answer is never retried
	 * and takes nothing along
	 */
	public function aBatchCodesafeDidNotTakeIsPostedAgainThenLater(): bool
	{
		$spool = new CodesafeSpool(self::PREFIX);
		
		$spool->clear();
		$blip = $this->sender([[0, false], [202, true]], true);
		$blip->sendOne('a');
		$passed = [$blip->posted, $blip->paused, $spool->size(), $spool->backingOff()];
		
		$spool->clear();
		$outage = $this->sender([[503, true], [503, true]], true);
		$outage->sendOne('b');
		$kept = [$outage->posted, $spool->size(), $spool->backingOff()];
		
		$waiting = $this->sender([], true);
		$waiting->sendOne('c');
		$heldBack = [$waiting->posted, $spool->size()];
		
		$spool->clear();
		$spool->keep('old');
		$back = $this->sender([[202, true], [202, true]], true);
		$back->sendOne('d');
		$drained = [$back->posted, $spool->size()];
		
		$spool->clear();
		$spool->keep('old');
		$unreleased = $this->sender([[0, false]], false);
		$unreleased->sendOne('e');
		$noRetry = [$unreleased->posted, $unreleased->paused, $spool->size()];
		
		$spool->clear();
		$spool->keep('old');
		$final = $this->sender([[400, true]], true);
		$final->sendOne('f');
		
		return $passed === [['a', 'a'], 1, 0, false]
			&& $kept === [['b', 'b'], 1, true]
			&& $heldBack === [[], 2]
			&& $drained === [['d', 'old'], 0]
			&& $noRetry === [['e'], 0, 2]
			&& $final->posted === ['f'] && $final->paused === 0 && $spool->size() === 1;
	}
	
	/**
	 * A sender whose transport answers $answers in turn ([status, sent]),
	 * released or not, its spool under the fixture prefix
	 *
	 * @param list<array{int, bool}> $answers
	 */
	protected function sender(
		array $answers,
		bool $released,
	): object
	{
		return new class(new Config, $answers, $released) extends Sender
		{
			public array $posted = [];
			
			public int $paused = 0;
			
			public function __construct(
				Config $config,
				protected array $answers,
				protected bool $released,
			)
			{
				parent::__construct($config);
			}
			
			public function sendOne(
				string $json,
			): void
			{
				$this->send($json);
			}
			
			protected function release(): bool
			{
				return $this->released;
			}
			
			protected function pause(): void
			{
				$this->paused++;
			}
			
			protected function spool(): ?CodesafeSpool
			{
				return new CodesafeSpool('zz-spool-test:');
			}
			
			protected function transmit(
				string $json,
			): array
			{
				$this->posted[] = $json;
				
				return array_shift($this->answers) ?? [0, false];
			}
		};
	}
}
