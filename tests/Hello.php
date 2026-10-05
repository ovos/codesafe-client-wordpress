<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Hello as PluginHello;
use Ovos\Codesafe\Plugin;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;

use function count;
use function json_decode;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The hello (codesafe docs/plans/project-features-live.md): the plugin tells
 * codesafe which of its own switches are on, in codesafe's words, once a day
 * and whenever one changes — so codesafe's project list stops showing a
 * feature as running that this site has switched off. A refused codesafe is
 * asked again an hour later, one without the endpoint a day later.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Hello extends Test
{
	protected const int NOW = 1_790_000_000;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * The switches in codesafe's words — and the Shield's two only where the
	 * adapter runs: enforce without detect, or under the kill constant, is inert
	 */
	public function theSwitchesAreToldInCodesafesWords(): bool
	{
		$features = (new PluginHello($this->config(['report_404' => true, 'inventory' => true, 'shield_detect' => true,
			'shield_enforce' => true]), $this->sender()))->features();
		$killed = (new PluginHello($this->config(['shield_detect' => true, 'shield_enforce' => true, 'shield_kill' => true]),
			$this->sender()))->features();
		$inert = (new PluginHello($this->config(['shield_enforce' => true]), $this->sender()))->features();
		
		return $features === [
				'errors' => true,
				'not_found' => true,
				'rollups' => false,
				'security' => false,
				'inventory' => true,
				'auto_update' => false,
				'files' => false,
				'entry_watch' => true,
				'shield_detect' => true,
				'shield_enforce' => true,
				'js' => true,
			]
			&& $killed['shield_detect'] === false && $killed['shield_enforce'] === false
			&& $inert['shield_enforce'] === false;
	}
	
	/** once a day, and at once when a switch changed — never on every request */
	public function aHelloGoesOutOnceADayAndWhenASwitchChanges(): bool
	{
		$sender = $this->sender();
		$hello = new PluginHello($this->config(['rollups' => true]), $sender);
		
		$first = $hello->maybeSend(self::NOW);
		$same = $hello->maybeSend(self::NOW + 60);
		$nextDay = $hello->maybeSend(self::NOW + PluginHello::DAY);
		$changed = (new PluginHello($this->config(['rollups' => false]), $sender))->maybeSend(self::NOW + PluginHello::DAY + 60);
		
		return $first && $same === false && $nextDay && $changed
			&& count($sender->said) === 3
			&& $sender->said[2]['rollups'] === false;
	}
	
	/** a refused codesafe is asked again an hour later; one without the endpoint (404) a day later */
	public function aRefusalWaitsAnHourAndA404ADay(): bool
	{
		$sender = $this->sender(503);
		$hello = new PluginHello($this->config(), $sender);
		
		$refused = $hello->maybeSend(self::NOW);
		$soon = $hello->maybeSend(self::NOW + 60);
		$sender->code = 404;
		$hourLater = $hello->maybeSend(self::NOW + PluginHello::RETRY + 1);
		$stillMissing = $hello->maybeSend(self::NOW + PluginHello::RETRY + 2 * PluginHello::RETRY);
		$sender->code = 202;
		$dayLater = $hello->maybeSend(self::NOW + PluginHello::RETRY + PluginHello::DAY + 2);
		
		return $refused === false && $soon === false && $hourLater === false && $stillMissing === false && $dayLater
			&& count($sender->said) === 3;
	}
	
	/** an unconnected plugin says nothing */
	public function anUnconnectedPluginSaysNothing(): bool
	{
		$sender = $this->sender(202, false);
		
		return (new PluginHello($this->config(), $sender))->maybeSend(self::NOW) === false
			&& $sender->said === [];
	}
	
	/** the post itself: the endpoint, the key, the client with this plugin's version and the switches */
	public function theSenderPostsTheHelloWithTheKey(): bool
	{
		$config = new class extends Config
		{
			public function enabled(): bool
			{
				return true;
			}
			
			public function url(): string
			{
				return 'https://codesafe.test';
			}
			
			public function apiKey(): string
			{
				return 'k3y';
			}
		};
		
		$code = (new Sender($config))->hello(['rollups' => true, 'inventory' => false]);
		[$url, $args] = $GLOBALS['wp']['posted'][0] ?? ['', []];
		$body = json_decode((string)($args['body'] ?? ''), true);
		
		return $code === 202
			&& $url === 'https://codesafe.test/api/v1/ingest/hello'
			&& ($args['headers']['X-Codesafe-Key'] ?? '') === 'k3y'
			&& $body === [
				'v' => 1,
				'client' => 'wordpress/' . Plugin::VERSION,
				'platform' => 'wordpress',
				'features' => ['rollups' => true, 'inventory' => false],
			];
	}
	
	/**
	 * The plugin's real Config over these settings — the option the settings
	 * page writes, the defaults filling the rest (entry_watch and js_enabled
	 * default on)
	 *
	 * @param array<string, bool> $settings option key => value
	 */
	protected function config(
		array $settings = [],
	): Config
	{
		$GLOBALS['wp']['options'][Config::OPTION] = $settings;
		
		return new Config;
	}
	
	/** a Sender that keeps what it was told and answers $code */
	protected function sender(
		int $code = 202,
		bool $enabled = true,
	): Sender
	{
		return new class($code, $enabled) extends Sender
		{
			/** @var list<array<string, bool>> */
			public array $said = [];
			
			public function __construct(
				public int $code,
				protected bool $on,
			)
			{
				parent::__construct(new Config);
			}
			
			public function isEnabled(): bool
			{
				return $this->on;
			}
			
			public function hello(
				array $features,
			): int
			{
				$this->said[] = $features;
				
				return $this->code;
			}
		};
	}
}
