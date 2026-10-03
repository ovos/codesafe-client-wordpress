<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Redactor;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Test;
use Ovos\Test\Internal;
use Tests\Files\WireSender;

use function http_build_query;
use function json_decode;
use function str_contains;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'WireSender.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Adapter.php';

/**
 * H3 of the 2026-10-03 security audit: what the request bags carry. The reset
 * link's `key` was dropped from the uri and sent whole in request.get; card
 * fields and an IBAN had no rule at all; wp-login's `log` went out as typed.
 * Each claim is driven through the plugin's real request path (WireSender)
 * or the Redactor itself.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Redaction extends Test
{
	protected const string RESET_KEY = 'Zx9ResetKeyQq20chars';
	
	protected const string RP_KEY = 'Rp9PostedResetKeyWw';
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * In a request bag the query names drop by EXACT name — the reset link's
	 * key, an OAuth code, a signature, an OTP — while names that only contain
	 * them stay readable; an `extra` bag (no request flag) is as before
	 */
	public function requestBagsDropTheQueryNamesByExactName(): bool
	{
		$bag = ['action' => 'rp', 'key' => self::RESET_KEY, 'Code' => '4/0Ab', 'sig' => 's', 'otp' => '123456', 'pin' => '0000',
			'hash' => 'h', 'auth' => 'a', 'content_hash' => 'c0ffee', 'pinned' => '1', 'coupon_code' => 'SAVE10',
			'meta' => ['key' => 'colour']];
		$scrubbed = Redactor::scrub($bag, identities: false, request: true);
		$extra = Redactor::scrub($bag);
		
		foreach(['key', 'Code', 'sig', 'otp', 'pin', 'hash', 'auth'] as $name)
		{
			if($scrubbed[$name] !== '[redacted]')
			{
				return false;
			}
		}
		
		return $scrubbed['action'] === 'rp'
			&& $scrubbed['content_hash'] === 'c0ffee'
			&& $scrubbed['pinned'] === '1'
			&& $scrubbed['coupon_code'] === 'SAVE10'
			&& $scrubbed['meta']['key'] === '[redacted]'
			&& $extra['key'] === self::RESET_KEY;
	}
	
	/**
	 * The payment and reset fields in the spellings gateways post them in are
	 * secret everywhere — and the words that merely resemble them are not
	 */
	public function paymentAndResetFieldsAreSecretAndTheirLookalikesAreNot(): bool
	{
		$secret = ['rp_key', 'rp-key', 'card_number', 'cardnumber', 'wc-stripe-card-number', 'x_card_num', 'x_card_code', 'ccnum',
			'cc-number', 'cc_no', 'cvv', 'cvv2', 'CVC', 'card_cvc', 'paypal_pro-card-cvc', 'csc', 'ccv', 'card-expiry', 'card_exp',
			'security_code', 'account_number', 'bank_account_no', 'acctnum', 'iban', 'sepa_iban', 'IBAN'];
		$ordinary = ['caribbean', 'account_notes', 'account_type', 'card_title', 'cc_email', 'cscart_id', 'library', 'discard',
			'card_export', 'pinned', 'description', 'account'];
		
		foreach($secret as $name)
		{
			if(Redactor::isSecretName($name) === false
				|| Redactor::scrub([$name => '4111111111111111'])[$name] !== '[redacted]'
				|| str_contains(Redactor::scrubText('{"' . $name . '": "4111 1111 1111 1111"}'), '4111') === true)
			{
				return false;
			}
		}
		foreach($ordinary as $name)
		{
			if(Redactor::isSecretName($name) === true)
			{
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * The reset form, as wp-login.php receives it: the key in the query and
	 * rp_key in the post leave nowhere in the JSON. The login name in the
	 * bags travels as typed: codesafe masks it on arrival and keeps the
	 * original in its identity vault for an audited REVEAL (codesafe
	 * reveal-everything §2) — masked here, it could never be revealed.
	 * Without the key it is no takeover
	 */
	public function theResetRequestCarriesNoKeyAndTheLoginForTheVault(): bool
	{
		$wire = $this->wire('/wp-login.php?action=rp&key=' . self::RESET_KEY . '&login=marcin',
			['action' => 'rp', 'key' => self::RESET_KEY, 'login' => 'marcin'],
			['rp_key' => self::RP_KEY, 'pass1' => 'Sommer 2026', 'log' => 'mg', 'user_login' => 'marcin', 'wp-submit' => 'Save']);
		$request = json_decode($wire, true)[0]['context']['request'] ?? [];
		
		return str_contains($wire, self::RESET_KEY) === false
			&& str_contains($wire, self::RP_KEY) === false
			&& ($request['get']['key'] ?? '') === '[redacted]'
			&& ($request['get']['login'] ?? '') === 'marcin'
			&& ($request['post']['rp_key'] ?? '') === '[redacted]'
			&& ($request['post']['pass1'] ?? '') === '[redacted]'
			&& ($request['post']['log'] ?? '') === 'mg'
			&& ($request['post']['user_login'] ?? '') === 'marcin'
			&& ($request['post']['wp-submit'] ?? '') === 'Save';
	}
	
	/**
	 * Off a credential route the request keeps its people for codesafe to
	 * mask and keep (reveal-everything), exactly as on one
	 */
	public function offACredentialRouteTheNamesTravelForTheConsoleToMask(): bool
	{
		$wire = $this->wire('/?wc-ajax=checkout', ['wc-ajax' => 'checkout'], ['username' => 'marcin', 'billing_email' => 'anna@example.com']);
		$request = json_decode($wire, true)[0]['context']['request'] ?? [];
		
		return ($request['post']['username'] ?? '') === 'marcin'
			&& ($request['post']['billing_email'] ?? '') === 'anna@example.com';
	}
	
	/** a report the prepend layer queued gets the same request.get rule on its drain */
	public function aDrainedReportsRequestGetFollowsTheSameRule(): bool
	{
		$drained = Adapter::drained(['uri' => '/wp-login.php?action=rp&key=' . self::RESET_KEY . '&login=marcin&code=abc']);
		
		return ($drained['request']['get']['key'] ?? '') === '[redacted]'
			&& ($drained['request']['get']['code'] ?? '') === '[redacted]'
			&& ($drained['request']['get']['login'] ?? '') === 'm***i*'
			&& ($drained['request']['get']['action'] ?? '') === 'rp';
	}
	
	/**
	 * The error JSON the plugin would post for a request with this uri, query
	 * and form fields — the superglobals put back as they were
	 */
	protected function wire(
		string $uri,
		array $get,
		array $post,
	): string
	{
		$saved = [$_SERVER, $_POST, $_GET];
		$GLOBALS['wp']['options']['ovos_codesafe'] = [
			'enabled' => true,
			'url' => 'https://console.invalid',
			'api_key' => 'harness-key',
			'request_body' => 'structure',
		];
		$_SERVER = [
			'REQUEST_METHOD' => 'POST',
			'REQUEST_URI' => $uri,
			'HTTP_HOST' => 'site.test',
			'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
			'REMOTE_ADDR' => '203.0.113.9',
		];
		$_GET = $get;
		$_POST = $post;
		
		try
		{
			return (new WireSender(new Config(), http_build_query($post)))->wire();
		}
		finally
		{
			[$_SERVER, $_POST, $_GET] = $saved;
		}
	}
}
