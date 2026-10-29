<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Hello as PluginHello;
use Ovos\Codesafe\Plugin;
use Ovos\Codesafe\Rollup;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;

use function count;
use function dirname;
use function escapeshellarg;
use function exec;
use function file_put_contents;
use function implode;
use function is_dir;
use function json_decode;
use function mkdir;
use function rmdir;
use function scandir;
use function str_replace;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;
use function var_export;

use const DIRECTORY_SEPARATOR;
use const PHP_BINARY;

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
	 * adapter runs: enforce without detect, or under the kill constant, is
	 * inert; the rollups only where APCu counts them. The defaults are on
	 */
	public function theSwitchesAreToldInCodesafesWords(): bool
	{
		$features = (new PluginHello($this->config(['enabled' => true, 'report_404' => true, 'inventory' => true, 'shield_detect' => true,
			'shield_enforce' => true]), $this->sender(), cli: false))->features();
		$off = (new PluginHello($this->config(['rollups' => false, 'security_events' => false, 'auto_update_vulnerable' => false,
			'scan' => false]), $this->sender(), cli: false))->features();
		$killed = (new PluginHello($this->config(['shield_detect' => true, 'shield_enforce' => true, 'shield_kill' => true]),
			$this->sender(), cli: false))->features();
		$inert = (new PluginHello($this->config(['shield_detect' => false, 'shield_enforce' => true]), $this->sender(), cli: false))->features();
		
		return $features === [
				'errors' => true,
				'not_found' => true,
				'rollups' => Rollup::hasApcu(),
				'security' => true,
				'inventory' => true,
				'auto_update' => true,
				'files' => true,
				'entry_watch' => true,
				'shield_detect' => true,
				'shield_enforce' => true,
				'shield_kill' => false,
				'shield_prepend' => false,
				'js' => true,
			]
			&& $off['rollups'] === false && $off['security'] === false && $off['auto_update'] === false && $off['files'] === false
			&& $killed['shield_detect'] === false && $killed['shield_enforce'] === false && $killed['shield_kill'] === true
			&& $inert['shield_enforce'] === false;
	}
	
	/**
	 * RULE: the rollups switch counts as on only where APCu can count —
	 * without it the hello says off, with it on. Falsify: drop the APCu
	 * condition — a host without APCu tells codesafe it sends rollups, and
	 * codesafe's PROJECTS offers a feature the site can never deliver.
	 */
	public function rollupsAreToldOnlyWhereApcuCountsThem(): bool
	{
		$without = (new PluginHello($this->config(['rollups' => true]), $this->sender(), false, cli: false))->features();
		$with = (new PluginHello($this->config(['rollups' => true]), $this->sender(), true, cli: false))->features();
		
		return $without['rollups'] === false && $with['rollups'] === true;
	}
	
	/**
	 * RULE: `shield_prepend` is true where PHP's auto_prepend_file runs the
	 * layer — the plugin's stub, or ovos-console's stub the plugin rewrote to
	 * run it — and false where it names nothing, something else, or the
	 * content directory is unknown. Falsify: count `active` alone — a site
	 * still pointing at ovos-console's stub reads as having no layer.
	 */
	public function thePrependLayerIsToldLiveWhereItRuns(): bool
	{
		$told = [];
		foreach(['active', 'legacy', 'inactive', 'other', 'unavailable'] as $state)
		{
			$told[$state] = (new PluginHello($this->config(), $this->sender(), null, $state, cli: false))->features()['shield_prepend'];
		}
		
		return $told === ['active' => true, 'legacy' => true, 'inactive' => false, 'other' => false, 'unavailable' => false];
	}
	
	/**
	 * RULE: read off PHP's own auto_prepend_file, a site whose configuration
	 * still names the store's prepend.php, or ovos-console's
	 * wp-content/ovos-console/prepend.php, is `legacy` — told live by the
	 * hello and by the settings row — and one naming codesafe-shield.php is
	 * `active`; the plugin names ovos-console's stub by its own name. In
	 * processes of their own: the directive is PHP's per process, and
	 * WP_CONTENT_DIR would reach every other class. Falsify: leave the
	 * store's old name out of Prepend::status() — ovos-wp, whose
	 * configuration names prepend.php, reads as having no layer; build
	 * ovos-console's path from the plugin's own stub name — a site still on
	 * ovos-console's stub reads `other`, never refreshed.
	 */
	public function theOldStubPhpStillNamesIsToldLive(): bool
	{
		$root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-hello-' . uniqid();
		$content = $root . DIRECTORY_SEPARATOR . 'wp-content';
		$src = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR;
		$script = $root . DIRECTORY_SEPARATOR . 'state.php';
		$console = $content . DIRECTORY_SEPARATOR . 'ovos-console' . DIRECTORY_SEPARATOR . 'prepend.php';
		mkdir(dirname($console), 0700, true);
		mkdir($content . DIRECTORY_SEPARATOR . 'ovos-codesafe', 0700, true);
		file_put_contents($script, "<?php\nrequire " . var_export($src . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php', true) . ";\n"
			. "require " . var_export($src . 'Shield' . DIRECTORY_SEPARATOR . 'Adapter.php', true) . ";\n"
			. "require " . var_export($src . 'Hello.php', true) . ";\n"
			. "define('WP_CONTENT_DIR', " . var_export($content, true) . ");\n"
			. "echo Ovos\\Codesafe\\Hello::prependState(), ' ', Ovos\\Codesafe\\Shield\\Adapter::prependStatus()['state'], ' ',\n"
			. "\tOvos\\Codesafe\\Shield\\Adapter::legacyStub() === " . var_export($console, true) . " ? 'named' : 'misnamed';\n");
		$states = [];
		foreach(['ovos-codesafe/prepend.php', 'ovos-console/prepend.php', 'ovos-codesafe/codesafe-shield.php'] as $relative)
		{
			// a stub that does nothing: PHP runs the prepend file before the script
			$stub = $content . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relative);
			file_put_contents($stub, "<?php\n");
			$output = [];
			exec(escapeshellarg(PHP_BINARY) . ' -d ' . escapeshellarg('auto_prepend_file=' . $stub) . ' '
				. escapeshellarg($script) . ' 2>&1', $output);
			$states[] = implode('', $output);
		}
		$this->remove($root);
		
		return $states === ['legacy legacy named', 'legacy legacy named', 'active active named'];
	}
	
	/** a temp directory and everything under it */
	protected function remove(
		string $path,
	): void
	{
		if(is_dir($path) === false)
		{
			@unlink($path);
			
			return;
		}
		foreach(scandir($path) ?: [] as $name)
		{
			if($name !== '.' && $name !== '..')
			{
				$this->remove($path . DIRECTORY_SEPARATOR . $name);
			}
		}
		rmdir($path);
	}
	
	/**
	 * RULE: the hello goes again at once when the prepend layer comes or goes,
	 * or the environment changes — codesafe keys the site's facts by it.
	 * Falsify: leave the environment out of the signature — a copy switched
	 * to staging is told a day late.
	 */
	public function aChangedPrependOrEnvironmentSendsTheHelloAgain(): bool
	{
		$sender = $this->sender();
		$first = (new PluginHello($this->config(), $sender, null, 'inactive', cli: false))->maybeSend(self::NOW);
		$same = (new PluginHello($this->config(), $sender, null, 'inactive', cli: false))->maybeSend(self::NOW + 60);
		$pasted = (new PluginHello($this->config(), $sender, null, 'active', cli: false))->maybeSend(self::NOW + 120);
		$staging = (new PluginHello($this->config(['environment' => 'staging']), $sender, null, 'active', cli: false))->maybeSend(self::NOW + 180);
		
		return $first && $same === false && $pasted && $staging
			&& count($sender->said) === 3
			&& $sender->said[1]['shield_prepend'] === true;
	}
	
	/** once a day, and at once when a switch changed — never on every request */
	public function aHelloGoesOutOnceADayAndWhenASwitchChanges(): bool
	{
		$sender = $this->sender();
		$hello = new PluginHello($this->config(['rollups' => true]), $sender, cli: false);
		
		$first = $hello->maybeSend(self::NOW);
		$same = $hello->maybeSend(self::NOW + 60);
		$nextDay = $hello->maybeSend(self::NOW + PluginHello::DAY);
		$changed = (new PluginHello($this->config(['rollups' => false]), $sender, cli: false))->maybeSend(self::NOW + PluginHello::DAY + 60);
		
		return $first && $same === false && $nextDay && $changed
			&& count($sender->said) === 3
			&& $sender->said[2]['rollups'] === false;
	}
	
	/** a refused codesafe is asked again an hour later; one without the endpoint (404) a day later */
	public function aRefusalWaitsAnHourAndA404ADay(): bool
	{
		$sender = $this->sender(503);
		$hello = new PluginHello($this->config(), $sender, cli: false);
		
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
		
		return (new PluginHello($this->config(), $sender, cli: false))->maybeSend(self::NOW) === false
			&& $sender->said === [];
	}
	
	/**
	 * The post itself: the endpoint, the key, the client with this plugin's
	 * version, the environment and the switches. Falsify: leave the
	 * environment out — codesafe files a developer's copy under production.
	 */
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
				'environment' => 'production',
				'features' => ['rollups' => true, 'inventory' => false],
			];
	}
	
	/**
	 * RULE: a plugin switched off but still pointed at a console with a key
	 * says hello all the same, with `errors` false — codesafe reads the
	 * switch-off off that word instead of a day of silence. Without a URL or
	 * a key nothing is said. Falsify: gate the hello on the enabled box — a
	 * disabled sender goes dark and codesafe can only guess why.
	 */
	public function aConnectedPluginSwitchedOffStillSaysHello(): bool
	{
		$off = $this->sender(202, false, true);
		$said = (new PluginHello($this->config(['enabled' => false, 'url' => 'https://c.example.test', 'api_key' => 'k']), $off, cli: false))
			->maybeSend(self::NOW);
		$dark = $this->sender(202, false, false);
		$silent = (new PluginHello($this->config(['enabled' => false]), $dark, cli: false))->maybeSend(self::NOW);
		$on = (new PluginHello($this->config(['enabled' => true, 'url' => 'https://c.example.test', 'api_key' => 'k']),
			$this->sender(), cli: false))->features();
		
		return $said === true && count($off->said) === 1 && $off->said[0]['errors'] === false
			&& $silent === false && $dark->said === []
			&& $on['errors'] === true;
	}
	
	/**
	 * RULE: the hello is never said from the command line — php-cli reads no
	 * .user.ini, so its prepend layer reads off, and a WP-CLI run would flip
	 * `shield_prepend` under the site. The seam says cli, and without a word
	 * the SAPI does (this test runs on php-cli). Falsify: drop the guard — a
	 * `wp cron event run` opens a sensor case on a healthy site.
	 */
	public function theHelloIsNotSaidFromTheCommandLine(): bool
	{
		$config = $this->config(['enabled' => true, 'url' => 'https://c.example.test', 'api_key' => 'k']);
		$cli = $this->sender();
		$said = (new PluginHello($config, $cli, cli: true))->maybeSend(self::NOW);
		$sapi = $this->sender();
		$bySapi = (new PluginHello($config, $sapi))->maybeSend(self::NOW);
		$web = $this->sender();
		$spoke = (new PluginHello($config, $web, cli: false))->maybeSend(self::NOW);
		
		return $said === false && $cli->said === []
			&& $bySapi === false && $sapi->said === []
			&& $spoke === true && count($web->said) === 1;
	}
	
	/**
	 * RULE: the hello names the site's host where the plugin knows it
	 * (home_url), so codesafe can tell two senders on one key apart — a
	 * staging copy, a second server; a plugin that cannot say leaves the
	 * word out. Falsify: leave it out always — codesafe keys the flips by
	 * the project alone and two hosts flap them.
	 */
	public function theHelloNamesTheSitesHost(): bool
	{
		$GLOBALS['wp']['options'][Config::OPTION] = ['enabled' => true, 'url' => 'https://c.example.test', 'api_key' => 'k'];
		$named = new class(new Config) extends Sender
		{
			protected function homeHost(): string
			{
				return 'shop.example.test';
			}
		};
		$named->hello(['errors' => true]);
		$nameless = new Sender(new Config);
		$nameless->hello(['errors' => true]);
		$bodies = array_map(static fn(array $post): array => (array)json_decode((string)($post[1]['body'] ?? ''), true), $GLOBALS['wp']['posted']);
		
		return count($bodies) === 2
			&& ($bodies[0]['host'] ?? '') === 'shop.example.test'
			&& array_key_exists('host', $bodies[1]) === false
			&& ($bodies[1]['client'] ?? '') === 'wordpress/' . Plugin::VERSION;
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
	
	/** a Sender that keeps what it was told and answers $code; connected as $enabled unless said otherwise */
	protected function sender(
		int $code = 202,
		bool $enabled = true,
		?bool $connected = null,
	): Sender
	{
		return new class($code, $enabled, $connected ?? $enabled) extends Sender
		{
			/** @var list<array<string, bool>> */
			public array $said = [];
			
			public function __construct(
				public int $code,
				protected bool $on,
				protected bool $reaches,
			)
			{
				parent::__construct(new Config);
			}
			
			public function isEnabled(): bool
			{
				return $this->on;
			}
			
			public function isConnected(): bool
			{
				return $this->reaches;
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
