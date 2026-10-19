<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Connect as PluginConnect;
use Ovos\Codesafe\Rollup;
use Ovos\Codesafe\Scan;
use Ovos\Codesafe\ScanRunner;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Settings;
use Ovos\Test;
use Ovos\Test\Internal;
use ReflectionClass;

use function count;
use function json_decode;
use function json_encode;
use function parse_str;
use function str_repeat;
use function str_starts_with;
use function strlen;
use function strpos;
use function substr;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * CONNECT: the site sends the browser to codesafe's #/connect with a state
 * and a PKCE challenge, and trades the one-time code codesafe sends back —
 * with the verifier that never left the server — for the project's keys.
 * Only a return carrying this user's state is taken, the exchange goes to the
 * URL the admin typed, and only a well-formed answer is saved.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Connect extends Test
{
	protected const string URL = 'https://codesafe.example';
	
	protected const string API_KEY = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
	
	protected const string JS_KEY = '0123456789abcdef0123456789abcdef';
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/** RFC 7636 appendix B: the verifier's S256 challenge, base64url without padding */
	public function theChallengeIsRfc7636s(): bool
	{
		return PluginConnect::challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk') === 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
	}
	
	/** an http(s) URL with a host, its trailing slash dropped — nothing else is taken */
	public function onlyAnHttpUrlWithAHostIsTaken(): bool
	{
		return PluginConnect::url(' https://codesafe.example/ ') === self::URL
			&& PluginConnect::url('http://10.0.0.5:8080/codesafe') === 'http://10.0.0.5:8080/codesafe'
			&& PluginConnect::url('') === ''
			&& PluginConnect::url('codesafe.example') === ''
			&& PluginConnect::url('ftp://codesafe.example') === ''
			&& PluginConnect::url('javascript:alert(1)') === ''
			&& PluginConnect::url('https://user:pass@codesafe.example') === ''
			&& PluginConnect::url('https://codesafe.example/?next=evil') === ''
			&& PluginConnect::url('https://codesafe.example/#/projects') === '';
	}
	
	/**
	 * RULE: the browser goes to codesafe's #/connect, every parameter in the
	 * fragment — which no server logs — and comes back intact
	 */
	public function theBrowserGoesToTheConnectRouteWithEverythingInTheFragment(): bool
	{
		$location = PluginConnect::authorizeUrl(self::URL, 'https://shop.example/', 'Shop & Co',
			'https://shop.example/wp-admin/admin-post.php?action=ovos_codesafe_connect', 'st4te', 'ch4llenge');
		$prefix = self::URL . '/#/connect?';
		parse_str(substr($location, strlen($prefix)), $parameters);
		
		return str_starts_with($location, $prefix)
			&& strpos($location, '?') === strlen($prefix) - 1
			&& $parameters === [
				'site' => 'https://shop.example/',
				'name' => 'Shop & Co',
				'return' => 'https://shop.example/wp-admin/admin-post.php?action=ovos_codesafe_connect',
				'state' => 'st4te',
				'challenge' => 'ch4llenge',
			];
	}
	
	/**
	 * RULE: a return without a pending connect, or with another state, is
	 * refused before anything is sent; a cancelled one changes nothing.
	 * Falsify: skip the state comparison — a forged return posts its code.
	 */
	public function onlyThisUsersReturnIsTaken(): bool
	{
		$connect = $this->connect();
		$pending = ['url' => self::URL, 'state' => 'mine', 'verifier' => 'v'];
		
		$none = $connect->finish(null, ['state' => 'mine', 'code' => 'c', 'error' => '']);
		$other = $connect->finish($pending, ['state' => 'theirs', 'code' => 'c', 'error' => '']);
		$empty = $connect->finish($pending, ['state' => '', 'code' => 'c', 'error' => '']);
		$cancelled = $connect->finish($pending, ['state' => 'mine', 'code' => '', 'error' => 'access_denied']);
		
		return $none === ['outcome' => 'state']
			&& $other === ['outcome' => 'state']
			&& $empty === ['outcome' => 'state']
			&& $cancelled === ['outcome' => 'cancelled']
			&& $GLOBALS['wp']['posted'] === []
			&& $connect->saved === [];
	}
	
	/**
	 * RULE: the code and the verifier go to the URL the admin typed, kept on
	 * this server; the keys codesafe answers are saved, and a test error goes
	 * out with them
	 */
	public function theKeysArriveAndATestErrorFollows(): bool
	{
		$GLOBALS['wp']['options'][Config::OPTION] = ['enabled' => true];
		$GLOBALS['wp']['post_status'] = 200;
		$GLOBALS['wp']['post_body'] = (string)json_encode(['project' => ['id' => 7, 'name' => 'Shop'],
			'api_key' => self::API_KEY, 'js_key' => self::JS_KEY]);
		$connect = $this->connect();
		
		$outcome = $connect->finish(['url' => self::URL, 'state' => 'mine', 'verifier' => 'the-verifier'],
			['state' => 'mine', 'code' => 'the-code', 'error' => '']);
		$posted = $GLOBALS['wp']['posted'];
		
		return $outcome === ['outcome' => 'done', 'project' => 'Shop', 'enabled' => true, 'test' => 202]
			&& count($posted) === 1
			&& $posted[0][0] === self::URL . '/api/v1/connect/exchange'
			&& json_decode($posted[0][1]['body'], true) === ['code' => 'the-code', 'verifier' => 'the-verifier']
			&& $connect->saved === [[self::URL, self::API_KEY, self::JS_KEY]];
	}
	
	/**
	 * RULE: the real save puts in the new URL, keys and the master switch,
	 * keeps every box as the page shows it — a stored `false` stays off, a
	 * hand-patched `1` stays on — the Sender reads the new URL for the test
	 * error, and a rollup refusal heard from the old project is forgotten.
	 * Falsify: swap `$fresh + $input` — the old URL and key win; drop the
	 * refresh() — the test error goes to the old codesafe; drop the (bool)
	 * cast — the patched `1` is saved as off; drop the forget in sanitize()
	 * — the page keeps saying the new project refuses.
	 */
	public function theSaveReplacesTheConnectionAndKeepsEveryBox(): bool
	{
		[$connect, $sender] = $this->realConnect(['url' => 'https://old.example', 'api_key' => 'old-key', 'js_key' => 'old-js',
			'report_404' => false, 'rollups' => 1], self::JS_KEY);
		$GLOBALS['wp']['options'][Rollup::OPTION_REFUSED] = 1_790_000_000;
		
		$outcome = $connect->finish(['url' => self::URL, 'state' => 's', 'verifier' => 'v'], ['state' => 's', 'code' => 'c', 'error' => '']);
		$row = $GLOBALS['wp']['options'][Config::OPTION];
		
		return $outcome === ['outcome' => 'done', 'project' => 'Shop', 'enabled' => true, 'test' => 202]
			&& $row['url'] === self::URL
			&& $row['api_key'] === self::API_KEY
			&& $row['js_key'] === self::JS_KEY
			&& $row['enabled'] === true
			&& $row['report_404'] === false
			&& $row['rollups'] === true
			&& $row['scan'] === true
			&& $row['snapshot'] === true
			&& $sender->testedWith === self::URL
			&& isset($GLOBALS['wp']['options'][Rollup::OPTION_REFUSED]) === false;
	}
	
	/** a project codesafe answers without a JS key keeps the one pasted here */
	public function aProjectWithoutAJsKeyKeepsThePastedOne(): bool
	{
		[$connect] = $this->realConnect(['url' => 'https://old.example', 'api_key' => 'old-key', 'js_key' => 'pasted0123456789'], '');
		
		$connect->finish(['url' => self::URL, 'state' => 's', 'verifier' => 'v'], ['state' => 's', 'code' => 'c', 'error' => '']);
		$row = $GLOBALS['wp']['options'][Config::OPTION];
		
		return $row['api_key'] === self::API_KEY && $row['js_key'] === 'pasted0123456789';
	}
	
	/**
	 * RULE: anything but a 200 with a key-shaped API key saves nothing.
	 * Falsify: drop the key check — an error page's JSON becomes the API key.
	 */
	public function aBadAnswerSavesNothing(): bool
	{
		$outcomes = [];
		foreach([
			[404, ''],
			[0, ''],
			[200, 'not json'],
			[200, (string)json_encode(['api_key' => 'short', 'js_key' => self::JS_KEY])],
			[200, (string)json_encode(['api_key' => str_repeat('k', 32) . '<script>', 'js_key' => self::JS_KEY])],
			[200, (string)json_encode(['api_key' => self::API_KEY, 'js_key' => 'bad key'])],
		] as [$status, $body])
		{
			$GLOBALS['wp']['post_status'] = $status;
			$GLOBALS['wp']['post_body'] = $body;
			$connect = $this->connect();
			$outcomes[] = $connect->finish(['url' => self::URL, 'state' => 's', 'verifier' => 'v'], ['state' => 's', 'code' => 'c', 'error' => ''])
				=== ['outcome' => 'failed'] && $connect->saved === [];
		}
		
		$GLOBALS['wp']['post_status'] = 200;
		$GLOBALS['wp']['post_body'] = (string)json_encode(['api_key' => self::API_KEY, 'js_key' => '']);
		$withoutJs = $this->connect()->exchange(self::URL, 'c', 'v');
		
		return $outcomes === [true, true, true, true, true, true]
			&& $withoutJs === ['api_key' => self::API_KEY, 'js_key' => '', 'project' => ''];
	}
	
	/**
	 * A Connect with the real Settings and save(), over a stored row, whose
	 * exchange answers the project Shop with the test keys; the Sender shares
	 * its Config, as in the plugin, and records the URL the test error used
	 *
	 * @return array{0: PluginConnect, 1: Sender}
	 */
	protected function realConnect(
		array $row,
		string $jsKey,
	): array
	{
		$GLOBALS['wp']['options'][Config::OPTION] = $row;
		$GLOBALS['wp']['post_status'] = 200;
		$GLOBALS['wp']['post_body'] = (string)json_encode(['project' => ['id' => 7, 'name' => 'Shop'],
			'api_key' => self::API_KEY, 'js_key' => $jsKey]);
		$config = new Config;
		// a page request has read the row already: the save must refresh it
		$config->get('url');
		$sender = new class($config) extends Sender
		{
			public string $testedWith = '';
			
			public function isEnabled(): bool
			{
				return true;
			}
			
			public function sendTest(): int
			{
				$this->testedWith = $this->config->url();
				
				return 202;
			}
		};
		$settings = new Settings($config, $sender, 'ovos-codesafe.php', new ScanRunner($config, new Scan($config)));
		
		return [new PluginConnect($config, $sender, $settings), $sender];
	}
	
	/** a Connect that records what it would save, beside a Sender whose test error answers 202 */
	protected function connect(): PluginConnect
	{
		$sender = new class extends Sender
		{
			public function __construct()
			{
			}
			
			public function isEnabled(): bool
			{
				return true;
			}
			
			public function sendTest(): int
			{
				return 202;
			}
		};
		$settings = (new ReflectionClass(Settings::class))->newInstanceWithoutConstructor();
		
		return new class(new Config, $sender, $settings) extends PluginConnect
		{
			/** @var list<array{0: string, 1: string, 2: string}> */
			public array $saved = [];
			
			protected function save(
				string $url,
				string $apiKey,
				string $jsKey,
			): void
			{
				$this->saved[] = [$url, $apiKey, $jsKey];
			}
		};
	}
}
