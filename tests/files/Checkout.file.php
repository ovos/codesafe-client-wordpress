<?php
declare(strict_types=1);

namespace Tests\Files;

use Ovos\Codesafe\Config;

use function array_map;
use function http_build_query;
use function json_decode;
use function parse_str;
use function rawurldecode;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * One WooCommerce checkout POST — form-encoded, so it arrives in $_POST AND as
 * the raw body — driven through the plugin's REAL request path (WireSender),
 * with the superglobals put back as they were
 */
final class Checkout
{
	public const string NOTE = 'Bitte vor 17 Uhr liefern, der Hintereingang im Hof ist offen und der Hund bellt nur, er beißt aber nicht.';
	
	public const string COOKIE = 'admin%7C1790000000%7CsEcReTsEsSiOnToKeN0123456789abcdef';
	
	public const array FIELDS = [
		'billing_first_name' => 'Anna',
		'billing_last_name' => 'Berger',
		'billing_company' => '',
		'billing_country' => 'AT',
		'billing_address_1' => 'Hauptstraße 12',
		'billing_postcode' => '1030',
		'billing_city' => 'Wien',
		'billing_phone' => '+43 660 1234567',
		'billing_email' => 'anna.berger@example.com',
		'sepa_iban' => 'DE89 3704 0044 0532 0130 00',
		'account_password' => 'Sommer 2026 Hund!',
		'pwd' => 'hunter2-wp-login',
		'order_comments' => self::NOTE,
		'quantity' => '0',
		'sku' => 'SKU-9912',
		'order_id' => '4711',
		'payment_method' => 'sepa',
		'terms' => 'on',
		'woocommerce-process-checkout-nonce' => '7f3a9c2e41',
		'_wp_http_referer' => '/?wc-ajax=update_order_review',
	];
	
	/**
	 * The raw personal values a site's customer typed
	 */
	public const array PERSONAL = [
		'first name' => 'Anna',
		'last name' => 'Berger',
		'address' => 'Hauptstraße 12',
		'city' => 'Wien',
		'phone' => '+43 660 1234567',
		'IBAN' => 'DE89 3704 0044 0532 0130 00',
		'order note' => 'Hintereingang',
	];
	
	/**
	 * @return array{json: string, wire: array, request: array, post: array, body: array}
	 */
	public static function send(): array
	{
		$saved = [$_SERVER, $_POST, $_GET, $_COOKIE];
		
		wp_shim_reset();
		$GLOBALS['wp']['options']['ovos_codesafe'] = [
			'enabled' => true,
			'url' => 'https://console.invalid',
			'api_key' => 'harness-key',
			'request_body' => 'structure',
			'environment' => 'test',
		];
		
		$_SERVER = [
			'REQUEST_METHOD' => 'POST',
			'REQUEST_URI' => '/?wc-ajax=checkout',
			'HTTP_HOST' => 'shop.example.test',
			'HTTP_REFERER' => 'https://shop.example.test/checkout/',
			'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'HTTP_ACCEPT' => 'application/json, text/javascript, */*; q=0.01',
			'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
			'HTTP_COOKIE' => 'wordpress_logged_in_abc=' . self::COOKIE,
			'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=UTF-8',
			'REMOTE_ADDR' => '203.0.113.9',
		];
		// WordPress hands $_POST over magic-quoted (wp_magic_quotes); the Sender unslashes
		$_POST = array_map('addslashes', self::FIELDS);
		$_GET = ['wc-ajax' => 'checkout'];
		$_COOKIE = ['wordpress_logged_in_abc' => rawurldecode(self::COOKIE)];
		
		try
		{
			$json = (new WireSender(new Config(), http_build_query(self::FIELDS)))->wire();
		}
		finally
		{
			[$_SERVER, $_POST, $_GET, $_COOKIE] = $saved;
		}
		
		$wire = json_decode($json, true)[0] ?? [];
		$request = $wire['context']['request'] ?? [];
		parse_str((string)($request['body'] ?? ''), $body);
		
		return [
			'json' => $json,
			'wire' => $wire,
			'request' => $request,
			'post' => $request['post'] ?? [],
			'body' => $body,
		];
	}
}
