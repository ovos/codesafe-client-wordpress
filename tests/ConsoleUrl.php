<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Inventory;
use Ovos\Codesafe\Rollup;
use Ovos\Codesafe\Scan;
use Ovos\Codesafe\ScanRunner;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Settings;
use Ovos\Test;
use Ovos\Test\Exception\SkipException;
use Ovos\Test\Internal;

use function fclose;
use function function_exists;
use function stream_select;
use function stream_socket_get_name;
use function stream_socket_server;
use function strrchr;
use function substr;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The console URL is the administrator's to type, and three transports hand
 * it to curl itself, which speaks far more than http: a gopher:// or dict://
 * URL would have every visitor's shutdown send raw bytes to whatever host and
 * port it names — a Redis or a mail server beside the site included. Only an
 * http(s) URL is saved, and only http(s) leaves through curl. A console on a
 * private or loopback address stays usable: codesafe on the LAN is a
 * deployment, not an attack.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class ConsoleUrl extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: the Sender's, the Rollup's and the Inventory's curl speak http(s)
	 * only — a gopher:// console URL (one stored before the form checked it,
	 * or a constant) opens no connection at all, to a port that would take
	 * one.
	 * Falsify: drop CURLOPT_PROTOCOLS from any one transport — curl connects
	 * to the listener and sends its request as gopher.
	 */
	public function aNonHttpConsoleUrlOpensNoConnection(): bool
	{
		if(function_exists('curl_init') === false)
		{
			throw new SkipException('Needs the curl extension.');
		}
		
		$transports = [
			'sender' => static fn(Config $config): mixed => (new class($config) extends Sender
			{
				public function post(): array
				{
					return $this->transmit('{}');
				}
			})->post(),
			'rollup' => static fn(Config $config): mixed => (new class($config) extends Rollup
			{
				public function post(): bool
				{
					return $this->send(['minute' => 0]);
				}
			})->post(),
			'inventory' => static fn(Config $config): mixed => (new class($config) extends Inventory
			{
				public function post(): array
				{
					return $this->send(['software' => []]);
				}
			})->post(),
		];
		
		foreach($transports as $send)
		{
			$server = stream_socket_server('tcp://127.0.0.1:0');
			$port = substr((string)strrchr((string)stream_socket_get_name($server, false), ':'), 1);
			$send($this->config('gopher://127.0.0.1:' . $port));
			$read = [$server];
			$write = null;
			$except = null;
			// a connection curl opened waits in the backlog: the socket reads ready
			$connected = stream_select($read, $write, $except, 0) === 1;
			fclose($server);
			if($connected)
			{
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * RULE: the settings form keeps an http(s) console URL — on a private
	 * address too — and saves any other scheme as no URL.
	 * Falsify: let esc_url_raw() take its default protocols — gopher://,
	 * dict:// and ftp:// are saved and reach the transports.
	 */
	public function theFormSavesOnlyAnHttpConsoleUrl(): bool
	{
		$kept = fn(string $url): string => $this->settings()->sanitize(['url' => $url, 'scan_interval' => '7'])['url'];
		
		return $kept('https://codesafe.example') === 'https://codesafe.example'
			&& $kept('http://10.0.0.5:8080/codesafe') === 'http://10.0.0.5:8080/codesafe'
			&& $kept('http://127.0.0.1:8081') === 'http://127.0.0.1:8081'
			&& $kept('gopher://10.0.0.5:6379/_FLUSHALL') === ''
			&& $kept('dict://127.0.0.1:11211/stats') === ''
			&& $kept('ftp://codesafe.example') === ''
			&& $kept('file:///etc/passwd') === '';
	}
	
	/** a config whose console is $url, whatever the constants or the stored option say */
	protected function config(
		string $url,
	): Config
	{
		return new class($url) extends Config
		{
			public function __construct(
				protected string $at,
			)
			{
			}
			
			public function url(): string
			{
				return $this->at;
			}
			
			public function apiKey(): string
			{
				return 'k';
			}
		};
	}
	
	protected function settings(): Settings
	{
		$config = new Config();
		
		return new Settings($config, new Sender($config), '/srv/wp/wp-content/plugins/ovos-codesafe/ovos-codesafe.php',
			new ScanRunner($config, new Scan($config)));
	}
}
