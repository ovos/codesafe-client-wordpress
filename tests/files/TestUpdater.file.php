<?php
declare(strict_types=1);

namespace Tests\Files;

use Ovos\Codesafe\Updater;

/**
 * The plugin's Updater with the test pair's public key in place of the shipped one
 */
final class TestUpdater extends Updater
{
	public static string $key = '';
	
	protected static function publicKey(): string
	{
		return self::$key;
	}
}
