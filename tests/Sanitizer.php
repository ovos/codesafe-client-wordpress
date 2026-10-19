<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Test;
use Tests\Files\Checkout;

use function is_string;
use function json_encode;
use function rawurldecode;
use function rawurlencode;
use function str_contains;
use function trim;
use function urlencode;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'WireSender.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'Checkout.file.php';

/**
 * G3, the plugin's half — the plugin never ships a credential. One
 * WooCommerce checkout through the plugin's real request path; what leaves
 * the site: both password fields [redacted] in post and body, the cookie
 * header not sent, quantity / sku / order id byte-identical, the e-mail AS
 * SENT — and no password or cookie value anywhere in the JSON.
 *
 * Personal data travels to the console on purpose (console
 * docs/plans/reveal-everything.md, 2026-09-24): the console masks it before
 * anything is stored and keeps the original encrypted for an audited reveal
 * and a replay, and a mask made here is one it could never undo. What must
 * never cross is a secret. The stored half is Tests\SanitizerStored.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Sanitizer extends Test
{
	protected array $sent;
	
	public function __construct()
	{
		$this->sent = Checkout::send();
	}
	
	public function requestCarriesPostBagAndFormBody(): bool
	{
		return $this->sent['post'] !== []
			&& $this->sent['body'] !== [];
	}
	
	public function passwordsAreRedactedInPostAndBody(): bool
	{
		foreach($this->bags() as $fields)
		{
			if(($fields['account_password'] ?? null) !== '[redacted]'
				|| ($fields['pwd'] ?? null) !== '[redacted]'
			)
			{
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * For the console to mask and keep
	 */
	public function emailTravelsAsSentInPostAndBody(): bool
	{
		foreach($this->bags() as $fields)
		{
			if(($fields['billing_email'] ?? null) !== Checkout::FIELDS['billing_email'])
			{
				return false;
			}
		}
		
		return true;
	}
	
	public function quantitySkuAndOrderIdAreByteIdenticalInPostAndBody(): bool
	{
		foreach($this->bags() as $fields)
		{
			if(($fields['quantity'] ?? null) !== '0'
				|| ($fields['sku'] ?? null) !== 'SKU-9912'
				|| ($fields['order_id'] ?? null) !== '4711'
			)
			{
				return false;
			}
		}
		
		return true;
	}
	
	public function cookieHeaderIsNotSent(): bool
	{
		return isset($this->sent['request']['headers']['cookie']) === false;
	}
	
	public function allowlistedHeadersStillGo(): bool
	{
		return ($this->sent['request']['headers']['x-requested-with'] ?? null) === 'XMLHttpRequest';
	}
	
	/**
	 * In any spelling: raw, JSON-escaped, rawurlencoded, urlencoded
	 */
	public function noRawPasswordOrCookieAnywhereInTheWireJson(): bool
	{
		$secrets = [
			Checkout::FIELDS['account_password'],
			Checkout::FIELDS['pwd'],
			Checkout::COOKIE,
			rawurldecode(Checkout::COOKIE),
		];
		
		foreach($secrets as $raw)
		{
			foreach([$raw, json_encode($raw), rawurlencode($raw), urlencode($raw)] as $spelling)
			{
				if(is_string($spelling) && str_contains($this->sent['json'], trim($spelling, '"')))
				{
					return false;
				}
			}
		}
		
		return true;
	}
	
	public function checkoutNonceDoesNotCrossTheWire(): bool
	{
		return str_contains($this->sent['json'], Checkout::FIELDS['woocommerce-process-checkout-nonce']) === false;
	}
	
	/**
	 * @return array<string, array>
	 */
	protected function bags(): array
	{
		return [
			'post' => $this->sent['post'],
			'body' => $this->sent['body'],
		];
	}
}
