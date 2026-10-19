<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Redactor;
use Ovos\Codesafe\Security;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Test;
use Ovos\Test\Internal;
use Tests\Files\WireSender;

use function json_decode;
use function str_contains;
use function str_repeat;
use function strlen;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'WireSender.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Adapter.php';

/**
 * The identity round (codesafe docs/plans/identity-round-2026-10.md, 1.0.6):
 * everything bound for codesafe carries e-mail addresses and usernames as
 * written — codesafe masks them on arrival and keeps the original encrypted
 * for an audited REVEAL — while every secret is still dropped here. The one
 * exception is a login name in PROSE, which codesafe could not recognise:
 * it stays masked, unless it is an e-mail address.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Identities extends Test
{
	protected const string TOKEN = 'Tk9SecretQueryTokenValue';
	
	protected const string API_KEY = 'sk_live_ExtraApiKey42';
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * The error's uri, referer and extra: the people in them as written, the
	 * token, the password and the api key gone
	 */
	public function theUrlsAndTheExtraCarryThePeopleAndNoSecret(): bool
	{
		$wire = $this->wire(
			'/account/anna@example.com?user=marcin&email=anna%40example.com&token=' . self::TOKEN,
			'https://site.test/wp-login.php?log=marcin&pwd=Sommer2026',
			['customer' => 'anna@example.com', 'username' => 'marcin', 'api_key' => self::API_KEY],
		);
		$payload = json_decode($wire, true)[0] ?? [];
		$context = $payload['context'] ?? [];
		
		return str_contains($wire, self::TOKEN) === false
			&& str_contains($wire, self::API_KEY) === false
			&& str_contains($wire, 'Sommer2026') === false
			&& ($context['uri'] ?? '') === '/account/anna@example.com?user=marcin&email=anna%40example.com&token=[redacted]'
			&& ($context['referer'] ?? '') === 'https://site.test/wp-login.php?log=marcin&pwd=[redacted]'
			&& ($context['extra']['customer'] ?? '') === 'anna@example.com'
			&& ($context['extra']['username'] ?? '') === 'marcin'
			&& ($context['extra']['api_key'] ?? '') === '[redacted]';
	}
	
	/**
	 * A WP-CLI run's argv: the address as typed, the password beside it
	 * dropped in both argument styles
	 */
	public function theArgvCarriesTheAddressAndNoSecret(): bool
	{
		$saved = $_SERVER['argv'] ?? null;
		$_SERVER['argv'] = ['wp', 'user', 'create', 'anna', 'anna@example.com', '--user_pass=Sommer2026', '--password', 'Winter2026'];
		
		try
		{
			$args = (new class(new Config()) extends Sender
			{
				public function args(): array
				{
					return $this->buildContext()['context']['args'] ?? [];
				}
			})->args();
		}
		finally
		{
			$_SERVER['argv'] = $saved;
		}
		
		return $args === ['wp', 'user', 'create', 'anna', 'anna@example.com', '--user_pass=[redacted]', '--password', '[redacted]'];
	}
	
	/**
	 * A security event's line keeps an address as written, a not-found
	 * line too — its path's token segment still goes
	 */
	public function theLinesCarryTheAddressAndNoSecret(): bool
	{
		$sender = $this->sender();
		$sender->reportRefusal('csrf_reject', 'nonce check failed for anna@example.com');
		$sender->capture404('/reset/token/' . self::TOKEN . '/anna@example.com?pwd=x');
		[$refusal, $missing] = $sender->queued();
		
		return $refusal['message'] === 'nonce check failed for anna@example.com'
			&& $refusal['events'][0]['message'] === 'nonce check failed for anna@example.com'
			&& $missing['message'] === '404 Not Found: /reset/token/[redacted]/anna@example.com';
	}
	
	/**
	 * The one exception: a login NAME in prose stays masked — codesafe has no
	 * key to recognise it by — while an e-mail typed as the name travels as
	 * written; the account itself is context.userId
	 */
	public function aLoginNameInProseStaysMaskedAndAnAddressDoesNot(): bool
	{
		$GLOBALS['wp']['users'] = ['marcin' => [7, 'marcin@example.com', ['edit_posts']]];
		$sender = $this->sender();
		$security = new Security($sender);
		$security->reportLoginFailed('marcin');
		$security->reportLoginFailed('marcin@example.com');
		$security->reportLoginFailed("anna@example.com' OR 1=1");
		[$byName, $byEmail, $shaped] = $sender->queued();
		
		return $byName['message'] === 'login failed for m***i*'
			&& ($byName['context']['userId'] ?? '') === '7'
			&& $byEmail['message'] === 'login failed for marcin@example.com'
			&& ($byEmail['context']['userId'] ?? '') === '7'
			&& str_contains($shaped['message'], 'anna@example.com') === false
			&& Redactor::proseName('') === '';
	}
	
	/**
	 * Percent-encoding hides nothing and loses nothing: an encoded address
	 * reaches codesafe as an address (sanitize_text_field() stripped the %40,
	 * leaving a name no rule recognises), and an encoded secret's name, an
	 * encoded `=` or a secret inside a redirect is still dropped
	 */
	public function anEncodedAddressArrivesWholeAndAnEncodedSecretDoesNot(): bool
	{
		$wire = $this->wire(
			'/?email=anna%40example.com&%74oken=' . self::TOKEN . '1&pwd%3D' . self::TOKEN . '2'
				. '&redirect_to=https%3A%2F%2Fsite.test%2F%3Ftoken%3D' . self::TOKEN . '3',
			'https://site.test/?e=bob%40example.com&api%5Fkey=' . self::API_KEY,
			[],
		);
		$context = json_decode($wire, true)[0]['context'] ?? [];
		$drained = Adapter::drained([
			'uri' => '/?email=anna%40example.com&%74oken=' . self::TOKEN,
			'referer' => 'https://site.test/?e=bob%40example.com&api%5Fkey=' . self::API_KEY,
		]);
		
		return str_contains($wire, self::TOKEN) === false
			&& str_contains($wire, self::API_KEY) === false
			&& ($context['uri'] ?? '') === '/?email=anna%40example.com&%74oken=[redacted]&pwd=[redacted]'
				. '&redirect_to=https%3A%2F%2Fsite.test%2F%3Ftoken%3D[redacted]'
			&& ($context['referer'] ?? '') === 'https://site.test/?e=bob%40example.com&api%5Fkey=[redacted]'
			&& ($drained['uri'] ?? '') === '/?email=anna%40example.com&%74oken=[redacted]'
			&& ($drained['referer'] ?? '') === 'https://site.test/?e=bob%40example.com&api%5Fkey=[redacted]'
			&& ($drained['request']['get']['email'] ?? '') === 'anna@example.com'
			// read raw, but never a control character, never unbounded
			&& Redactor::rawUrl(" /a\x01b?c=%40\r\n") === '/ab?c=%40'
			&& strlen(Redactor::rawUrl('/' . str_repeat('x', Redactor::URL_MAX))) === Redactor::URL_MAX;
	}
	
	/**
	 * A request FIELD holding a URL or a query is judged like the uri: the
	 * redirect_to of wp-login carried `?pwd=` whole in request.get (seen on
	 * the live bed, 2026-10-03), while prose with an `=` in it is left alone
	 */
	public function aRequestFieldHoldingAUrlLosesItsSecrets(): bool
	{
		$saved = [$_SERVER, $_POST, $_GET];
		$_SERVER = ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/wp-login.php', 'HTTP_HOST' => 'site.test'];
		$_GET = ['redirect_to' => 'http://site.test/?pwd=' . self::TOKEN . '&user=marcin'];
		$_POST = ['_wp_http_referer' => '/wp-admin/options.php?page=x&token=' . self::TOKEN, 'note' => 'a = b, c=d', 'email' => 'anna@example.com'];
		
		try
		{
			$wire = (new WireSender(new Config(), ''))->wire();
		}
		finally
		{
			[$_SERVER, $_POST, $_GET] = $saved;
		}
		$request = json_decode($wire, true)[0]['context']['request'] ?? [];
		
		return str_contains($wire, self::TOKEN) === false
			&& ($request['get']['redirect_to'] ?? '') === 'http://site.test/?pwd=[redacted]&user=marcin'
			&& ($request['post']['_wp_http_referer'] ?? '') === '/wp-admin/options.php?page=x&token=[redacted]'
			&& ($request['post']['note'] ?? '') === 'a = b, c=d'
			&& ($request['post']['email'] ?? '') === 'anna@example.com';
	}
	
	/** a drained report's urls follow the Sender's: the people in, the secrets out */
	public function aDrainedReportCarriesThePeopleAndNoSecret(): bool
	{
		$drained = Adapter::drained([
			'uri' => '/?login=marcin&email=anna%40example.com&pwd=' . self::TOKEN,
			'referer' => 'https://site.test/?user=marcin&token=' . self::TOKEN,
		]);
		
		return ($drained['uri'] ?? '') === '/?login=marcin&email=anna%40example.com&pwd=[redacted]'
			&& ($drained['referer'] ?? '') === 'https://site.test/?user=marcin&token=[redacted]'
			&& ($drained['request']['get']['login'] ?? '') === 'marcin'
			&& ($drained['request']['get']['email'] ?? '') === 'anna@example.com'
			&& ($drained['request']['get']['pwd'] ?? '') === '[redacted]';
	}
	
	/** the masks are still there for a caller that asks for them — the default */
	public function theMasksStayTheDefault(): bool
	{
		return Redactor::scrubUrl('/?user=marcin&email=anna%40example.com') === '/?user=m***i*&email=a***@example.com'
			&& Redactor::scrubArgs(['anna@example.com']) === ['anna***@example.com']
			&& Redactor::scrub(['username' => 'marcin'])['username'] === 'm***i*';
	}
	
	/** a sender with security events and not-found reports on, whose queue the test can read */
	protected function sender(): object
	{
		$config = new class extends Config
		{
			public function securityEvents(): bool
			{
				return true;
			}
			
			public function report404(): bool
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
		};
	}
	
	/**
	 * The error JSON the plugin would post for a GET with this uri, referer
	 * and extra — the superglobals put back as they were
	 */
	protected function wire(
		string $uri,
		string $referer,
		array $extra,
	): string
	{
		$saved = [$_SERVER, $_POST, $_GET];
		$GLOBALS['wp']['options']['ovos_codesafe'] = [
			'enabled' => true,
			'url' => 'https://console.invalid',
			'api_key' => 'harness-key',
		];
		$_SERVER = [
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => $uri,
			'HTTP_REFERER' => $referer,
			'HTTP_HOST' => 'site.test',
			'REMOTE_ADDR' => '203.0.113.9',
		];
		$_GET = [];
		$_POST = [];
		
		try
		{
			return (new WireSender(new Config(), ''))->wire($extra);
		}
		finally
		{
			[$_SERVER, $_POST, $_GET] = $saved;
		}
	}
}
