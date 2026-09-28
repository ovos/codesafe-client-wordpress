<?php
declare(strict_types=1);

namespace Tests;

use Console\Error\Body;
use Console\Error\Personal;
use Console\Error\Scrubber;
use Ovos\Test;
use Tests\Files\Checkout;
use UnexpectedValueException;

use function getenv;
use function is_array;
use function is_file;
use function json_encode;
use function mb_strlen;
use function parse_str;
use function rawurldecode;
use function rawurlencode;
use function rtrim;
use function sprintf;
use function str_contains;
use function urlencode;
use function var_export;

use const DIRECTORY_SEPARATOR;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'WireSender.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'Checkout.file.php';

/**
 * G3, the console's half — the console never stores a raw personal field. The
 * plugin's wire JSON through the console's own Scrubber::scrubRequest() in
 * `structure` mode (what Row::make runs) and Personal::apply() (what the
 * Writer runs): the eleven outcomes proven by hand on 2026-09-22, in both
 * bags, and a whole-bag check that no raw personal value or credential
 * survives anywhere.
 *
 * ovos/console is private: skipped unless a checkout is at hand
 * (OVOS_CONSOLE_PATH, or ../console beside this repository).
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class SanitizerStored extends Test
{
	protected const array EXPECTED = [
		'account_password' => '[redacted]',
		'pwd' => '[redacted]',
		'billing_first_name' => 'A***',
		'billing_last_name' => 'B***e*',
		'billing_phone' => '+99 999 9999999',
		'sepa_iban' => 'DE99 9999 9999 9999 9999 99',
		'billing_email' => 'a***.***g**@example.com',
		'quantity' => '0',
		'sku' => 'SKU-9912',
		'order_id' => '4711',
	];
	
	protected array $stored = [];
	
	protected array $storedBody = [];
	
	protected string $blob = '';
	
	public function __construct()
	{
		$path = getenv('OVOS_CONSOLE_PATH');
		$console = rtrim($path === false || $path === '' ? __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'console' : $path, '/\\');
		$library = $console . '/project/libraries/Console/Error';
		
		if(is_file($library . '/Personal.php') === false)
		{
			$this->setDisabled(true,
				'no console checkout at ' . $console . ' (OVOS_CONSOLE_PATH)'
			);
			
			return;
		}
		
		foreach(['Scrubber', 'Body', 'Personal'] as $class)
		{
			require_once $library . '/' . $class . '.php';
		}
		
		$sent = Checkout::send();
		$this->stored = Personal::apply(Scrubber::scrubRequest(
			$sent['request'],
			Body::MODE_STRUCTURE,
			(string)($sent['wire']['context']['uri'] ?? ''),
		));
		$this->blob = (string)json_encode($this->stored, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
		parse_str((string)($this->stored['body'] ?? ''), $this->storedBody);
	}
	
	public function storedRowKeepsPostBagAndFormBody(): bool
	{
		return is_array($this->stored['post'] ?? null)
			&& $this->storedBody !== [];
	}
	
	/**
	 * Passwords destroyed, names / phone / IBAN / e-mail pseudonymised with
	 * their shape kept, quantity / sku / order id kept — in both bags
	 */
	public function eachFieldIsStoredAsTheConsoleDecided(): bool
	{
		$expected = self::EXPECTED + [
			'order_comments' => sprintf('[text:%d]', mb_strlen(Checkout::NOTE)),
		];
		
		foreach(['post' => $this->stored['post'] ?? [], 'body' => $this->storedBody] as $bag => $fields)
		{
			foreach($expected as $field => $value)
			{
				if(($fields[$field] ?? null) !== $value)
				{
					// the reason column names the one that moved
					throw new UnexpectedValueException(sprintf('%s: %s should be %s, got %s',
						$bag,
						$field,
						$value,
						var_export($fields[$field] ?? null, true),
					));
				}
			}
		}
		
		return true;
	}
	
	public function noRawPersonalValueOrCredentialIsStored(): bool
	{
		$raws = Checkout::PERSONAL + [
			'postcode' => Checkout::FIELDS['billing_postcode'],
			'order note (whole)' => Checkout::NOTE,
			'account_password' => Checkout::FIELDS['account_password'],
			'pwd' => Checkout::FIELDS['pwd'],
			'billing_email' => Checkout::FIELDS['billing_email'],
			'cookie' => Checkout::COOKIE,
			'cookie (decoded)' => rawurldecode(Checkout::COOKIE),
		];
		
		foreach($raws as $raw)
		{
			if(str_contains($this->blob, $raw)
				|| str_contains($this->blob, urlencode($raw))
				|| str_contains($this->blob, rawurlencode($raw))
			)
			{
				return false;
			}
		}
		
		return true;
	}
	
	public function checkoutNonceIsNotStored(): bool
	{
		return str_contains($this->blob, Checkout::FIELDS['woocommerce-process-checkout-nonce']) === false;
	}
}
