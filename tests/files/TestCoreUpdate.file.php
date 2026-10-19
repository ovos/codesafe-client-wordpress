<?php
declare(strict_types=1);

namespace Tests\Files;

use Ovos\Codesafe\CoreUpdate;

/**
 * CoreUpdate with WP_AUTO_UPDATE_CORE and the request's kind set by the
 * test — a process defines a constant once, and the suite runs in one
 */
final class TestCoreUpdate extends CoreUpdate
{
	/** WP_AUTO_UPDATE_CORE as the test defines it, null for undefined */
	public mixed $constantValue = null;
	
	/** whether this request is one WordPress asks in (its cron run, wp-admin) */
	public bool $here = false;
	
	protected function constant(): mixed
	{
		return $this->constantValue;
	}
	
	protected function askedHere(): bool
	{
		return $this->here;
	}
}
