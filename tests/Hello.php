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
		$features = (new PluginHello($this->config(['report_404' => true, 'inventory' => true, 'shield_detect' => true,
			'shield_enforce' => true]), $this->sender()))->features();
		$off = (new PluginHello($this->config(['rollups' => false, 'security_events' => false, 'auto_update_vulnerable' => false,
			'scan' => false]), $this->sender()))->features();
		$killed = (new PluginHello($this->config(['shield_detect' => true, 'shield_enforce' => true, 'shield_kill' => true]),
			$this->sender()))->features();
		$inert = (new PluginHello($this->config(['shield_detect' => false, 'shield_enforce' => true]), $this->sender()))->features();
		
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
		$without = (new PluginHello($this->config(['rollups' => true]), $this->sender(), false))->features();
		$with = (new PluginHello($this->config(['rollups' => true]), $this->sender(), true))->features();
		
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
			$told[$state] = (new PluginHello($this->config(), $this->sender(), null, $state))->features()['shield_prepend'];
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
		$first = (new PluginHello($this->config(), $sender, null, 'inactive'))->maybeSend(self::NOW);
		$same = (new PluginHello($this->config(), $sender, null, 'inactive'))->maybeSend(self::NOW + 60);
		$pasted = (new PluginHello($this->config(), $sender, null, 'active'))->maybeSend(self::NOW + 120);
		$staging = (new PluginHello($this->config(['environment' => 'staging']), $sender, null, 'active'))->maybeSend(self::NOW + 180);
		
		return $first && $same === false && $pasted && $staging
			&& count($sender->said) === 3
			&& $sender->said[1]['shield_prepend'] === true;
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
