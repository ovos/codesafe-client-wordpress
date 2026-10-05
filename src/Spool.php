<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function apcu_delete;
use function apcu_exists;
use function apcu_fetch;
use function apcu_inc;
use function apcu_sma_info;
use function apcu_store;
use function function_exists;
use function get_option;
use function is_int;
use function is_string;
use function max;
use function md5;
use function min;
use function strlen;
use function substr;

/**
 * The batches codesafe did not take, kept for a later request — the same
 * rules as ovos/php-library's Spool (codesafe docs/SENDER.md §5 rule 3):
 * Sender::send() posted each batch once and read no answer, so a codesafe
 * deploy, an outage or a 503 lost every error of those seconds, and every
 * request kept paying the connect timeout meanwhile.
 *
 * Only a batch codesafe CERTAINLY did not take is kept (Sender::retryable()).
 * A FIFO of numbered slots in APCu, scoped to this site as the rollups are
 * (shared hosting runs several WordPress sites in one pool): the tail and
 * the head are counters (apcu_inc is atomic), so two workers keeping or
 * taking at once never rewrite one array over the other. At most
 * MAX_BATCHES — past it the oldest are deleted — each at most
 * MAX_BATCH_BYTES, for TTL seconds, and none while APCu has less than
 * MIN_FREE_SHARE of its memory free: the site's own object cache comes
 * first. After a retryable failure a backoff key holds the next posts back
 * for BACKOFF seconds, so a dead codesafe costs a request an APCu write, not
 * a connect timeout. NO APCu, NO SPOOL — one post, as before.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Spool
{
	/** batches kept at most — a long outage keeps the newest */
	public const MAX_BATCHES = 10;
	
	/** a batch bigger than this is never kept — with MAX_BATCHES, 640 KB of APCu at most */
	public const MAX_BATCH_BYTES = 65536;
	
	/** the share of APCu's memory that must stay free for a batch to be kept */
	public const MIN_FREE_SHARE = 0.25;
	
	/** how long a kept batch waits at most, seconds */
	public const TTL = 3600;
	
	/** how long the posts wait after a retryable failure, seconds (codesafe's own Retry-After is 30) */
	public const BACKOFF = 30;
	
	public function __construct(
		protected string $keyPrefix,
	)
	{
	}
	
	/** this site's spool, or null where APCu is not there to hold one */
	public static function forSite(): ?self
	{
		if(Rollup::hasApcu() === false)
		{
			return null;
		}
		$site = function_exists('get_option') ? (string)get_option('home') : '';
		
		return new self('ovos:codesafe:spool:' . substr(md5($site), 0, 8) . ':');
	}
	
	/**
	 * One batch kept at the tail, the oldest deleted past MAX_BATCHES. Never
	 * a batch over MAX_BATCH_BYTES, never into the last MIN_FREE_SHARE of
	 * APCu's memory. False when it was not kept
	 */
	public function keep(
		string $json,
	): bool
	{
		if(strlen($json) > self::MAX_BATCH_BYTES || $this->roomy() === false)
		{
			return false;
		}
		
		$tail = apcu_inc($this->key('tail'));
		if(is_int($tail) === false)
		{
			return false;
		}
		apcu_store($this->key('slot:' . $tail), $json, self::TTL);
		
		// past the bound the head moves over the oldest, and their slots go
		// at once — left to the TTL, an outage's every batch would sit in
		// APCu for the hour
		$head = $this->head();
		$over = $tail - $head - self::MAX_BATCHES;
		if($over > 0)
		{
			apcu_inc($this->key('head'), $over);
			for($slot = $head + 1; $slot <= $head + $over; $slot++)
			{
				apcu_delete($this->key('slot:' . $slot));
			}
		}
		
		return true;
	}
	
	/** the oldest kept batch, taken — null when none is left */
	public function take(): ?string
	{
		// a few slots at most: one that expired or was passed over is skipped
		for($tries = 0; $tries < self::MAX_BATCHES; $tries++)
		{
			$tail = apcu_fetch($this->key('tail'));
			if(is_int($tail) === false || $this->head() >= $tail)
			{
				return null;
			}
			// the claim is the increment: two takers never get one slot
			$slot = apcu_inc($this->key('head'));
			if(is_int($slot) === false)
			{
				return null;
			}
			$json = apcu_fetch($this->key('slot:' . $slot));
			apcu_delete($this->key('slot:' . $slot));
			if(is_string($json))
			{
				return $json;
			}
		}
		
		return null;
	}
	
	/** how many batches wait — the tail past the head */
	public function size(): int
	{
		$tail = apcu_fetch($this->key('tail'));
		
		return is_int($tail) ? max(0, min(self::MAX_BATCHES, $tail - $this->head())) : 0;
	}
	
	/** hold the posts back for BACKOFF seconds */
	public function backOff(): void
	{
		apcu_store($this->key('backoff'), 1, self::BACKOFF);
	}
	
	/** whether the posts are held back */
	public function backingOff(): bool
	{
		return apcu_exists($this->key('backoff'));
	}
	
	/** everything forgotten — the tests' clean slate */
	public function clear(): void
	{
		$tail = apcu_fetch($this->key('tail'));
		for($slot = $this->head() + 1; is_int($tail) && $slot <= $tail; $slot++)
		{
			apcu_delete($this->key('slot:' . $slot));
		}
		apcu_delete([$this->key('tail'), $this->key('head'), $this->key('backoff')]);
	}
	
	/** whether APCu has MIN_FREE_SHARE of its memory free */
	protected function roomy(): bool
	{
		$info = apcu_sma_info(true);
		$total = (int)($info['num_seg'] ?? 0) * (int)($info['seg_size'] ?? 0);
		
		return $total > 0 && (int)($info['avail_mem'] ?? 0) >= $total * self::MIN_FREE_SHARE;
	}
	
	protected function head(): int
	{
		$head = apcu_fetch($this->key('head'));
		
		return is_int($head) ? $head : 0;
	}
	
	protected function key(
		string $suffix,
	): string
	{
		return $this->keyPrefix . $suffix;
	}
}
