<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Sensors;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_filter;
use function array_values;
use function count;
use function in_array;
use function json_decode;
use function json_encode;
use function str_contains;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The two sensor events: the goodbye the deactivation says and the change of
 * the plugin's own settings — codesafe's own words about the sensor, so they
 * pass whatever the Security events box says, name switches and never
 * values, and tell the console a site was pointed away from before the new
 * one hears anything.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class SensorEvents extends Test
{
	protected const int NOW = 1_790_000_000;
	
	protected const string OLD_URL = 'https://old.example.test';
	
	protected const string OLD_KEY = 'oldkey0000000000000000000000000000000000';
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/** both kinds are in the sender's closed list; the goodbye has no budget, the settings ten a minute */
	public function theSensorKindsPassWithTheSecurityBoxOff(): bool
	{
		$sender = $this->sender(securityEvents: false);
		$sender->reportRefusal('sensor_goodbye', 'plugin deactivated', ['action' => 'deactivated']);
		$sender->reportRefusal('privileged_action', 'option changed: siteurl', ['action' => 'option_change']);
		for($i = 0; $i < 12; $i++)
		{
			$sender->reportRefusal('sensor_settings', 'settings changed: rollups', ['action' => 'settings_changed']);
		}
		
		return in_array('sensor_goodbye', Sender::SECURITY_KINDS, true)
			&& in_array('sensor_settings', Sender::SECURITY_KINDS, true)
			&& count($this->of($sender, 'sensor_goodbye')) === 1
			&& count($this->of($sender, 'privileged_action')) === 0
			&& count($this->of($sender, 'sensor_settings')) === 10;
	}
	
	/**
	 * A saved settings page names the keys that changed, the switches that
	 * went off and on — and never a value: not the old or new URL, not a key,
	 * not an e-mail
	 */
	public function aSettingsChangeNamesSwitchesNeverValues(): bool
	{
		$sender = $this->sender();
		$old = ['enabled' => true, 'url' => self::OLD_URL, 'api_key' => self::OLD_KEY, 'security_events' => true,
			'rollups' => false, 'environment' => '', 'tags' => 'shop,eu'] + Config::DEFAULTS;
		$new = $old;
		$new['security_events'] = false;
		$new['rollups'] = true;
		$new['environment'] = 'local';
		$new['tags'] = 'shop';
		
		(new Sensors(new Config, $sender))->settingsChanged($old, $new);
		$events = $this->of($sender, 'sensor_settings');
		$event = $events[0] ?? [];
		$json = (string)json_encode($event);
		$extra = $event['extra'] ?? [];
		
		return count($events) === 1
			&& $event['events'][0]['message'] === 'settings changed: environment, rollups, security_events, tags'
			&& ($extra['action'] ?? '') === 'settings_changed'
			&& ($extra['changed'] ?? null) === ['environment', 'rollups', 'security_events', 'tags']
			&& ($extra['off'] ?? null) === ['security_events']
			&& ($extra['on'] ?? null) === ['rollups']
			&& str_contains($json, 'local') === false && str_contains($json, 'shop') === false
			&& str_contains($json, self::OLD_URL) === false && str_contains($json, self::OLD_KEY) === false
			&& $GLOBALS['wp']['posted'] === [];
	}
	
	/** nothing changed, nothing said; a non-array on either side is no change either */
	public function anUnchangedSaveSaysNothing(): bool
	{
		$sender = $this->sender();
		$same = Config::DEFAULTS + ['enabled' => true];
		(new Sensors(new Config, $sender))->settingsChanged($same, $same);
		(new Sensors(new Config, $sender))->settingsChanged('x', $same);
		
		return $this->of($sender, 'sensor_settings') === [];
	}
	
	/**
	 * A new URL or key points the site at another console: the old one is
	 * told now, synchronously, with the old key — the shutdown queue would
	 * post to the new one. The event names `url` / `api_key`, never either
	 * value; a site that had no console before tells nobody
	 */
	public function aRepointTellsTheOldConsoleFirst(): bool
	{
		$sender = $this->sender();
		$old = ['enabled' => true, 'url' => self::OLD_URL, 'api_key' => self::OLD_KEY] + Config::DEFAULTS;
		$new = $old;
		$new['url'] = 'https://new.example.test';
		$new['api_key'] = 'newkey0000000000000000000000000000000000';
		(new Sensors(new Config, $sender))->settingsChanged($old, $new);
		$posted = $GLOBALS['wp']['posted'];
		[$url, $args] = $posted[0] ?? ['', []];
		$body = json_decode((string)($args['body'] ?? ''), true);
		$event = $body[0] ?? ($body['events'][0] ?? []);
		$bodyJson = (string)($args['body'] ?? '');
		
		$fresh = $this->sender();
		$GLOBALS['wp']['posted'] = [];
		(new Sensors(new Config, $fresh))->settingsChanged(Config::DEFAULTS, $new);
		
		return count($posted) === 1
			&& $url === self::OLD_URL . '/api/v1/ingest'
			&& ($args['headers']['X-Codesafe-Key'] ?? '') === self::OLD_KEY
			&& str_contains($bodyJson, 'sensor_settings')
			&& str_contains($bodyJson, '"api_key"') && str_contains($bodyJson, '"url"')
			&& str_contains($bodyJson, 'new.example.test') === false && str_contains($bodyJson, 'newkey') === false
			&& str_contains($bodyJson, self::OLD_KEY) === false
			&& is_array($event)
			&& count($this->of($sender, 'sensor_settings')) === 1
			&& $GLOBALS['wp']['posted'] === []
			&& count($this->of($fresh, 'sensor_settings')) === 1;
	}
	
	/**
	 * RULE: the settings event carries no request context on either path —
	 * the saved form rides in $_POST with the key and the URL in it, and the
	 * request's URI, address and account are nobody's business on a word
	 * about switches. Falsify: decorate the event with the request as every
	 * other security event is — the new key leaves the site in the body.
	 */
	public function aSettingsChangeCarriesNoRequest(): bool
	{
		$_POST = ['ovos_codesafe' => ['api_key' => 'POSTSECRET0000000000000000000000', 'url' => 'https://posted.example.test', 'tags' => 'POSTTAG']];
		$old = ['enabled' => true, 'url' => self::OLD_URL, 'api_key' => self::OLD_KEY, 'tags' => 'a'] + Config::DEFAULTS;
		$new = $old;
		$new['api_key'] = 'POSTSECRET0000000000000000000000';
		// the tags setting rides every report as the site's tags by design: it stays off the forbidden list
		$new['tags'] = 'b';
		$GLOBALS['wp']['options'][Config::OPTION] = $new;
		$config = new Config;
		// a sender whose request context carries the form and the request, as a web request's does
		$sender = $this->flusher(config: $config);
		(new Sensors($config, $sender))->settingsChanged($old, $new);
		$told = (string)($GLOBALS['wp']['posted'][0][1]['body'] ?? '');
		$sender->flush();
		$queued = (string)($sender->sent[0] ?? '');
		$_POST = [];
		
		foreach(['POSTSECRET', 'posted.example.test', 'ovos-codesafe-leak', '203.0.113.77', 'leak-agent', '"userId":"9"'] as $value)
		{
			if(str_contains($queued, $value) || str_contains($told, $value))
			{
				return false;
			}
		}
		
		return str_contains($queued, 'sensor_settings') && str_contains($told, 'sensor_settings');
	}
	
	/**
	 * RULE: the sensor's own words flush while the plugin is switched off —
	 * a goodbye said by a disabled plugin still reaches the console it is
	 * pointed at; every other kind stays home, and nothing goes anywhere
	 * without a console and a key. Falsify: gate the flush on the enabled
	 * box — the goodbye of a plugin disabled first is never heard.
	 */
	public function aGoodbyeFlushesWhileThePluginIsSwitchedOff(): bool
	{
		$off = $this->flusher(enabled: false);
		$off->reportRefusal('sensor_goodbye', 'plugin deactivated', ['action' => 'deactivated']);
		$off->reportRefusal('auth_failure', 'login failed');
		$off->flush();
		$dark = $this->flusher(enabled: false, url: '');
		$dark->reportRefusal('sensor_goodbye', 'plugin deactivated', ['action' => 'deactivated']);
		$dark->flush();
		$on = $this->flusher(enabled: true);
		$on->reportRefusal('sensor_goodbye', 'plugin deactivated', ['action' => 'deactivated']);
		$on->reportRefusal('auth_failure', 'login failed');
		$on->flush();
		
		return count($off->sent) === 1 && str_contains($off->sent[0], 'sensor_goodbye') && str_contains($off->sent[0], 'auth_failure') === false
			&& $dark->sent === []
			&& count($on->sent) === 1 && str_contains($on->sent[0], 'sensor_goodbye') && str_contains($on->sent[0], 'auth_failure');
	}
	
	/**
	 * RULE: on a repoint the old console hears the word through tell(),
	 * with the old key, and the new one through the queue with the new key —
	 * the Config's cache is refreshed before the queue is written, since
	 * core fires the hook after the option changed. Falsify: skip the
	 * refresh — the queued copy posts to the old console too, and the new
	 * one never hears the site arrived.
	 */
	public function aRepointTellsTheOldConsoleAndQueuesForTheNew(): bool
	{
		$old = ['enabled' => true, 'url' => self::OLD_URL, 'api_key' => self::OLD_KEY] + Config::DEFAULTS;
		$new = $old;
		$new['url'] = 'https://new.example.test';
		$new['api_key'] = 'newkey0000000000000000000000000000000000';
		$GLOBALS['wp']['options'][Config::OPTION] = $old;
		$config = new Config;
		$sender = $this->flusher(config: $config);
		// the cache holds the old values, as a request that read them before the save does
		$before = $config->url();
		$GLOBALS['wp']['options'][Config::OPTION] = $new;
		(new Sensors($config, $sender))->settingsChanged($old, $new);
		$told = $GLOBALS['wp']['posted'];
		$sender->flush();
		
		return $before === self::OLD_URL
			&& count($told) === 1 && $told[0][0] === self::OLD_URL . '/api/v1/ingest' && ($told[0][1]['headers']['X-Codesafe-Key'] ?? '') === self::OLD_KEY
			&& $config->url() === 'https://new.example.test' && $config->apiKey() === $new['api_key']
			&& count($sender->sent) === 1 && str_contains($sender->sent[0], 'sensor_settings')
			&& $sender->sentTo === [['https://new.example.test', $new['api_key']]];
	}
	
	/** a Sender whose batches are recorded instead of posted — the console and the key they would go to beside the JSON */
	protected function flusher(
		bool $enabled = true,
		string $url = 'https://console.example.test',
		?Config $config = null,
	): object
	{
		if($config === null)
		{
			$GLOBALS['wp']['options'][Config::OPTION] = ['enabled' => $enabled, 'url' => $url, 'api_key' => $url === '' ? '' : 'key0000000000000000000000000000000000000',
				'security_events' => true] + Config::DEFAULTS;
			$config = new Config;
		}
		
		return new class($config) extends Sender
		{
			/** @var list<string> the batches, as JSON */
			public array $sent = [];
			
			/** @var list<array{0: string, 1: string}> the console and the key each batch was for */
			public array $sentTo = [];
			
			public function queued(): array
			{
				return $this->queue;
			}
			
			protected function send(
				string $json,
			): void
			{
				$this->sent[] = $json;
				$this->sentTo[] = [$this->config->url(), $this->config->apiKey()];
			}
			
			/** a web request's context, the saved form in it — what a settings event must not carry */
			protected function buildContext(): array
			{
				return ['type' => 'http', 'entry' => '/wp-admin/options.php', 'context' => [
					'uri' => '/wp-admin/options.php?page=ovos-codesafe-leak', 'ip' => '203.0.113.77', 'ua' => 'leak-agent/1.0',
					'userId' => '9', 'host' => 'shop.example.test', 'request' => ['post' => $_POST],
				]];
			}
		};
	}
	
	/** a Sender whose queue the test reads, the Security events box as given, the clock held */
	protected function sender(
		bool $securityEvents = true,
	): object
	{
		$config = new class($securityEvents) extends Config
		{
			public function __construct(
				protected bool $security,
			)
			{
			}
			
			public function securityEvents(): bool
			{
				return $this->security;
			}
			
			public function enabled(): bool
			{
				return true;
			}
			
			public function url(): string
			{
				return 'https://console.example.test';
			}
			
			public function apiKey(): string
			{
				return 'key0000000000000000000000000000000000000';
			}
		};
		
		$sender = new class($config) extends Sender
		{
			public int $clock = 0;
			
			public function queued(): array
			{
				return $this->queue;
			}
			
			protected function now(): int
			{
				return $this->clock;
			}
		};
		$sender->clock = self::NOW;
		
		return $sender;
	}
	
	/** the queued events of one kind */
	protected function of(
		object $sender,
		string $kind,
	): array
	{
		return array_values(array_filter($sender->queued(),
			static fn(array $payload): bool => ($payload['events'][0]['className'] ?? '') === $kind));
	}
}
