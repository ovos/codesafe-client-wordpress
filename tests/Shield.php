<?php
declare(strict_types=1);

namespace Tests;

use APCUIterator;
use Ovos\Codesafe\Config;
use Ovos\Codesafe\Rollup;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Consent;
use Ovos\Codesafe\Shield\Facts;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;
use Ovos\Codesafe\Shield\Wordpress;
use Ovos\Test;
use Ovos\Test\Internal;
use Ovos\Test\Exception\SkipException;
use ReflectionClass;

use function apcu_delete;
use function array_diff;
use function basename;
use function chmod;
use function class_exists;
use function clearstatcache;
use function copy;
use function count;
use function dirname;
use function escapeshellarg;
use function exec;
use function explode;
use function fclose;
use function file_get_contents;
use function file_put_contents;
use function function_exists;
use function getenv;
use function implode;
use function is_dir;
use function is_file;
use function is_resource;
use function is_string;
use function is_writable;
use function json_decode;
use function json_encode;
use function mkdir;
use function preg_quote;
use function proc_close;
use function proc_open;
use function realpath;
use function rmdir;
use function rtrim;
use function scandir;
use function sha1_file;
use function str_contains;
use function str_replace;
use function stream_get_contents;
use function strpos;
use function substr;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;
use function wp_shim_reset;

use const BASE_DIR;
use const DIRECTORY_SEPARATOR;
use const PHP_BINARY;

if(class_exists(Kernel::class, false) === false)
{
	require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Kernel.php';
}
// right after the kernel and by path: autoloaded first, the module would not find the kernel's Platform
if(class_exists(Wordpress::class, false) === false)
{
	require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Wordpress.php';
}
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The Shield kernel the plugin vendors, its core and WordPress's module: that
 * each is the console's file byte for byte, that they are the copies under
 * test, that the adapter and the prepend layer both read the module, and a
 * smoke judge over a fake ruleset in a temp-dir store.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Shield extends Test
{
	protected const string KERNEL = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Kernel.php';
	
	protected const string MODULE = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Wordpress.php';
	
	protected const string PREPEND = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php';
	
	/** the harness kernel's API key: its store is sealed under Kernel::sealKey() of it */
	protected const string KEY = 'harness-key';
	
	protected string $path;
	
	protected Kernel $kernel;
	
	protected array $reports;
	
	protected int $pulls;
	
	#[Internal]
	public function prepare(): void
	{
		$this->path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-harness-' . uniqid() . '.json';
		$store = new Store($this->path, '');
		$rules = [
			['id' => 2, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'ua', 'op' => 'prefix', 'value' => 'python-requests', 'ci' => true, 'mode' => 'proven', 'expires_at' => null],
			['id' => 1, 'origin' => 'finding', 'finding' => 'f', 'cve' => 'CVE-2099-0001', 'field' => 'uri', 'op' => 'regex', 'value' => '[?&]include=[^&]*\.\./', 'ci' => true, 'mode' => 'observe', 'expires_at' => null],
		];
		$store->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => $rules,
		], time())->toRecord(Kernel::sealKey(self::KEY)));
		
		$this->reports = [];
		$this->pulls = 0;
		$this->kernel = new Kernel('https://console.invalid', self::KEY, $store,
			function(): array
			{
				$this->pulls++;
				
				return ['status' => 304, 'headers' => [], 'body' => ''];
			},
			function(
				string $kind,
				string $message,
				array $extra,
			): void
			{
				$this->reports[] = [$kind, $message, $extra];
			});
	}
	
	#[Internal]
	public function finalize(): void
	{
		if(is_file($this->path))
		{
			unlink($this->path);
		}
	}
	
	/**
	 * php-library carries the same names — if its copy were the one loaded,
	 * every claim below would test the wrong file
	 */
	public function kernelUnderTestIsThePluginsCopy(): bool
	{
		return realpath((new ReflectionClass(Kernel::class))->getFileName()) === realpath(self::KERNEL)
			&& realpath((new ReflectionClass(Wordpress::class))->getFileName()) === realpath(self::MODULE);
	}
	
	/**
	 * Both copies of each file are synced from the console's client-php/Shield.php
	 * and client-php/Shield/Wordpress.php; the console's own suite holds
	 * php-library's copies to the sources, so equal here is equal to the source
	 */
	public function kernelIsPhpLibrarysCopyByteForByte(): bool
	{
		$library = BASE_DIR . 'vendor/ovos/php-library/src/Codesafe/Shield/';
		if(is_file($library . 'Kernel.php') === false)
		{
			throw new SkipException('no php-library checkout at ' . $library);
		}
		
		return sha1_file($library . 'Kernel.php') === sha1_file(self::KERNEL) && sha1_file($library . 'Wordpress.php') === sha1_file(self::MODULE);
	}
	
	/**
	 * Against the source itself, when a console checkout is at hand
	 * (OVOS_CONSOLE_PATH, or ../codesafe or ../console beside this repository)
	 */
	public function kernelIsConsolesClientPhpShieldByteForByte(): bool
	{
		$source = $this->consolePath() . '/client-php/Shield.php';
		if(is_file($source) === false)
		{
			throw new SkipException('no console checkout at ' . $source);
		}
		
		return sha1_file($source) === sha1_file(self::KERNEL) && sha1_file($this->consolePath() . '/client-php/Shield/Wordpress.php') === sha1_file(self::MODULE);
	}
	
	public function provenRuleUnderEnforceBlocksAndReportsShieldBlock(): bool
	{
		return $this->kernel->handle($this->bot(), new Consent(true, true, false))->outcome === Verdict::BLOCK
			&& ($this->reports[0][0] ?? '') === Verdict::KIND_BLOCK;
	}
	
	public function sameRuleWithoutEnforceObserves(): bool
	{
		return $this->kernel->handle($this->bot(), new Consent(true, false, false))->outcome === Verdict::OBSERVE
			&& ($this->reports[0][0] ?? '') === Verdict::KIND_OBSERVE;
	}
	
	/**
	 * Greedy [^&]* runs to the LAST ../ before the class stops — the fragment
	 * is what a person would want to see
	 */
	public function observeRuleMatchesTheDecodedQueryAndReportsTheFragment(): bool
	{
		$probe = Facts::fromServer([
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => '/wp-admin/admin-ajax.php?action=x&include=%2e%2e/%2e%2e/etc/passwd',
			'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'REMOTE_ADDR' => '203.0.113.9',
		]);
		
		return $this->kernel->handle($probe, new Consent(true, true, false))->outcome === Verdict::OBSERVE
			&& ($this->reports[0][2]['matched'] ?? '') === '&include=../../';
	}
	
	/**
	 * RULE: the adapter hands the kernel the parsed bags a virtual patch reads
	 * — the query, the form, the cookies, the uploads' names, WordPress's module with the REST prefix — and WordPress's
	 * two answers only where WordPress gives them: outside it can() and
	 * nonceValid() say nothing, and the rule only observes. Falsify: build
	 * the facts without the bags — every vpatch condition on a parameter
	 * reads nothing and no vpatch ever holds on a WordPress site.
	 */
	public function theAdapterHandsTheKernelTheBagsAndWordPressAnswers(): bool
	{
		$server = ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/wp-admin/admin-ajax.php?page=1',
			'CONTENT_TYPE' => 'application/x-www-form-urlencoded', 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
		$caller = Adapter::caller($server, ['page' => '1'], ['action' => 'fx_settings'], false, false);
		$facts = Adapter::facts($server, ['page' => '1'], ['action' => 'fx_settings'], ['fx_session' => 'abc'],
			['fx_upload' => ['name' => 'notes.txt', 'tmp_name' => '/tmp/x']], $caller, '203.0.113.9', 'api');
		
		return $facts->query === ['page' => '1'] && $facts->form === ['action' => 'fx_settings'] && $facts->cookies === ['fx_session' => 'abc']
			&& $facts->files === ['fx_upload' => 'notes.txt'] && $facts->headers['x-requested-with'] === 'XMLHttpRequest'
			&& count($facts->platforms) === 1 && $facts->platforms[0] instanceof Wordpress && Wordpress::restPrefix($facts) === 'api'
			&& (function_exists('current_user_can') || $facts->can('manage_options') === null)
			&& (function_exists('wp_verify_nonce') || $facts->nonceValid('fx_save', 'abc123') === null);
	}
	
	/**
	 * RULE: the kernel the adapter builds for itself — the one that pulls —
	 * reads WordPress's module: its pull names the module to the door, with
	 * the word for the XML-RPC targets the module reads beyond its first
	 * release (`wordpress-xmlrpc`), and keeps a `rest` rule and a
	 * `shortcode:` rule, and the adapter refuses
	 * the exploit of each, the route under the site's own REST prefix.
	 * Falsify: build kernel() without Prepend::platforms() — the core leaves
	 * both rules out at the pull, and both exploits pass every WordPress site.
	 */
	public function theAdaptersOwnKernelReadsWordPresssModule(): bool
	{
		wp_shim_reset();
		// a home of its own: the kernel's APCu keys are this test's alone
		$GLOBALS['wp']['options']['home'] = 'https://shield-module-' . uniqid() . '.test';
		// the door's answer to the pull, through the adapter's own transport
		$GLOBALS['wp']['api'] = ['contract' => 1, 'dialect' => 're2-2026', 'project' => 'harness', 'rules' => $this->moduleRules()];
		$config = new class extends Config
		{
			public function __construct()
			{
			}
			
			public function enabled(): bool
			{
				return true;
			}
			
			public function url(): string
			{
				return 'https://codesafe.invalid';
			}
			
			public function apiKey(): string
			{
				return 'harness-key';
			}
			
			public function shieldDetect(): bool
			{
				return true;
			}
			
			public function shieldEnforce(): bool
			{
				return true;
			}
			
			public function shieldKill(): bool
			{
				return false;
			}
		};
		// no kernel handed in: kernel() builds the site's own
		$adapter = new Adapter($config, new Sender(new Config));
		try
		{
			$pulled = $adapter->kernel()->pull($adapter->consent(), force: true);
			$named = $GLOBALS['wp']['got'][0][1]['headers'][Kernel::HEADER_PLATFORMS] ?? '';
			$kept = count($adapter->kernel()->ruleset()->rules ?? []);
			$anonymous = ['authed' => false, 'user' => '', 'can' => null, 'nonce' => null, 'known' => true];
			[$route, $shortcode] = $this->moduleExploits('api');
			$routed = $adapter->judgeRequest([$route[0], [], $route[1], [], []], $anonymous, '203.0.113.9', 'api');
			$coded = $adapter->judgeRequest([$shortcode[0], [], $shortcode[1], [], []], $anonymous, '203.0.113.9', 'api');
		}
		finally
		{
			apcu_delete(new APCUIterator('~^' . preg_quote($adapter->prefix(), '~') . '~'));
			wp_shim_reset();
		}
		
		return $pulled === Kernel::PULL_FRESH && $named === 'core,wordpress,wordpress-xmlrpc' && $kept === 2
			&& $routed?->isBlock() === true && $routed->rule['id'] === 31
			&& $coded?->isBlock() === true && $coded->rule['id'] === 32;
	}
	
	/**
	 * RULE: the adapter's kernel keeps its ruleset on disk wherever it runs —
	 * in the store directory under the consent's name, else (no consent yet,
	 * no directory it can write) in the system temp dir under a name of the
	 * install and the key — never in APCu alone, which an idle eviction
	 * empties (apc.ttl): past the ceiling a site cut off from codesafe holds
	 * its blocking rules only while there is a record to hold them. Falsify:
	 * answer '' without a consent — the record lives in APCu alone, and an
	 * eviction leaves the site without a rule.
	 */
	public function theAdaptersRulesetIsOnDiskWithoutAConsent(): bool
	{
		wp_shim_reset();
		$GLOBALS['wp']['options']['home'] = 'https://shield-file-' . uniqid() . '.test';
		$GLOBALS['wp']['api'] = ['contract' => 1, 'dialect' => 're2-2026', 'project' => 'harness', 'rules' => $this->moduleRules()];
		$config = $this->pullingConfig();
		$adapter = new Adapter($config, new Sender(new Config));
		$file = $adapter->file();
		try
		{
			$pulled = $adapter->kernel()->pull($adapter->consent(), force: true);
			// APCu emptied, as an idle eviction empties it: the next request's adapter reads the record off the disk
			apcu_delete(new APCUIterator('~^' . preg_quote($adapter->prefix(), '~') . '~'));
			$kept = count((new Adapter($config, new Sender(new Config)))->kernel()->ruleset()->rules ?? []);
		}
		finally
		{
			apcu_delete(new APCUIterator('~^' . preg_quote($adapter->prefix(), '~') . '~'));
			if($file !== '' && is_file($file))
			{
				unlink($file);
			}
			wp_shim_reset();
		}
		
		return $file !== '' && $pulled === Kernel::PULL_FRESH && $kept === 2;
	}
	
	/**
	 * RULE: the temp dir's folder holds the record where it can (TEMP_DIR,
	 * made 0700), and where it cannot — a file in its place, one another user
	 * of a shared temp dir made — the temp dir itself does, never nowhere.
	 * Falsify: keep the folder's path whatever mkdir answered — the Store
	 * writes into a folder that is not there, and the record lives in APCu
	 * alone.
	 */
	public function theTempFolderFallsBackToTheTempDirWhenItIsNoFolder(): bool
	{
		$root = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'shield-temp-' . uniqid();
		mkdir($root, 0700);
		$folder = $root . DIRECTORY_SEPARATOR . Adapter::TEMP_DIR;
		try
		{
			$made = dirname(Adapter::tempFile('harness', 'key', $root)) === $folder && is_dir($folder);
			rmdir($folder);
			// a file where the folder belongs: mkdir cannot make it
			file_put_contents($folder, '');
			$planted = dirname(Adapter::tempFile('harness', 'key', $root)) === $root;
		}
		finally
		{
			if(is_file($folder))
			{
				unlink($folder);
			}
			if(is_dir($folder))
			{
				rmdir($folder);
			}
			rmdir($root);
		}
		
		return $made && $planted;
	}
	
	/**
	 * RULE: a temp folder the site cannot write — another user of a shared
	 * temp dir made it, 0700 — falls back to the temp dir itself. Falsify:
	 * take the folder because it exists — the Store's writes fail there, and
	 * the record lives in APCu alone. Skipped where a folder stays writable
	 * after chmod 0500 (Windows, root).
	 */
	public function aTempFolderTheSiteCannotWriteFallsBackToTheTempDir(): bool
	{
		$root = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'shield-temp-' . uniqid();
		mkdir($root, 0700);
		$folder = $root . DIRECTORY_SEPARATOR . Adapter::TEMP_DIR;
		mkdir($folder, 0700);
		chmod($folder, 0500);
		clearstatcache();
		try
		{
			if(is_writable($folder))
			{
				throw new SkipException('a folder chmod 0500 stays writable here');
			}
			
			return dirname(Adapter::tempFile('harness', 'key', $root)) === $root;
		}
		finally
		{
			chmod($folder, 0700);
			rmdir($folder);
			rmdir($root);
		}
	}
	
	/** a Config that pulls from a harness door, with the Shield on and enforcing */
	protected function pullingConfig(): Config
	{
		return new class extends Config
		{
			public function __construct()
			{
			}
			
			public function enabled(): bool
			{
				return true;
			}
			
			public function url(): string
			{
				return 'https://codesafe.invalid';
			}
			
			public function apiKey(): string
			{
				return 'harness-key';
			}
			
			public function shieldDetect(): bool
			{
				return true;
			}
			
			public function shieldEnforce(): bool
			{
				return true;
			}
			
			public function shieldKill(): bool
			{
				return false;
			}
		};
	}
	
	/**
	 * RULE: the prepend layer — before WordPress and at the mu-plugin stage
	 * inside it — reads WordPress's module too: it refuses a `rest` rule's
	 * exploit under the REST prefix the consent carries and a `shortcode:`
	 * rule's, and does so in a process that loads Prepend.php as the stubs
	 * do, by path and with no autoloader. Falsify: build its kernel or Facts
	 * without Prepend::platforms() — the core reads neither the route nor the
	 * shortcode, and the earliest layer lets both exploits through to
	 * WordPress; or drop Prepend.php's require of the module — every request
	 * the stubs judge dies on a class not found.
	 */
	public function thePrependLayerReadsWordPresssModule(): bool
	{
		$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-module-' . uniqid();
		mkdir($dir, 0700, true);
		$consent = ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => '', 'root' => '', 'entries' => false,
			'rules' => 'shield-cdcdcdcdcdcdcdcdcdcdcdcd.json', 'proxy_header' => '', 'proxies' => [], 'rest_prefix' => 'api', 'seal' => Kernel::sealKey(self::KEY)];
		$rules = $dir . DIRECTORY_SEPARATOR . $consent['rules'];
		$input = $dir . DIRECTORY_SEPARATOR . 'alone.json';
		$script = $dir . DIRECTORY_SEPARATOR . 'alone.php';
		(new Store($rules, ''))->write(Ruleset::fromPayload(['contract' => 1, 'dialect' => 're2-2026', 'project' => 'harness', 'rules' => $this->moduleRules()],
			time(), platforms: Prepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$refused = [];
		$alone = [];
		try
		{
			foreach($this->moduleExploits('api') as [$server, $post])
			{
				// before WordPress (a direct hit), then at the mu-plugin stage
				foreach([false, true] as $wordpress)
				{
					$judged = Prepend::judge($dir, $server, $post, [], null, $consent, wordpress: $wordpress);
					$refused[] = $judged !== null && $judged['verdict']->isBlock() ? $judged['verdict']->rule['id'] : 0;
				}
			}
			// the request handed over in a file: escapeshellarg() on Windows blanks the quotes of JSON
			file_put_contents($input, json_encode([$dir, ...$this->moduleExploits('api')[0], $consent]));
			file_put_contents($script, "<?php\n// Prepend.php as the stubs include it: by path, no autoloader\nrequire \$argv[1];\n"
				. "[\$dir, \$server, \$post, \$consent] = json_decode((string)file_get_contents(\$argv[2]), true);\n"
				. "\$judged = Ovos\\Codesafe\\Shield\\Prepend::judge(\$dir, \$server, \$post, [], null, \$consent, wordpress: false);\n"
				. "echo \$judged === null ? 0 : \$judged['verdict']->rule['id'];\n");
			exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg(self::PREPEND) . ' ' . escapeshellarg($input) . ' 2>&1', $alone);
		}
		finally
		{
			foreach([$rules, $input, $script] as $path)
			{
				if(is_file($path))
				{
					unlink($path);
				}
			}
			rmdir($dir);
		}
		
		return $refused === [31, 31, 32, 32] && $alone === ['31'];
	}
	
	/**
	 * RULE: an upgrade copies the plugin file by file, so a request can find
	 * Prepend.php and Adapter.php new while a kernel file is missing or half
	 * written. Loaded by path with no autoloader, in either order, they never
	 * die: the layer is not ready, judges nothing and trusts no proxy header
	 * it cannot check; with both files whole it refuses the exploit.
	 * Falsify: require either file without its is_file() guard, drop either
	 * catch, judge without ready(), or check a proxy range without the
	 * kernel — the process dies on a fatal.
	 */
	public function aKernelFileAnUpgradeHasNotCopiedYetLeavesTheRequestUnjudged(): bool
	{
		$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-upgrade-' . uniqid();
		$copy = $dir . DIRECTORY_SEPARATOR . 'Shield';
		mkdir($copy, 0700, true);
		$consent = ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => '', 'root' => '', 'entries' => false,
			'rules' => 'shield-efefefefefefefefefefefef.json', 'proxy_header' => '', 'proxies' => [], 'rest_prefix' => 'api', 'seal' => Kernel::sealKey(self::KEY)];
		$rules = $dir . DIRECTORY_SEPARATOR . $consent['rules'];
		$input = $dir . DIRECTORY_SEPARATOR . 'upgrade.json';
		$script = $dir . DIRECTORY_SEPARATOR . 'upgrade.php';
		(new Store($rules, ''))->write(Ruleset::fromPayload(['contract' => 1, 'dialect' => 're2-2026', 'project' => 'harness', 'rules' => $this->moduleRules()],
			time(), platforms: Prepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		$module = (string)file_get_contents(self::MODULE);
		// what the upgrade has copied of each kernel file: true whole, false nothing yet, a string the part written so far
		$states = [
			['Kernel.php' => true, 'Wordpress.php' => true],
			['Kernel.php' => true, 'Wordpress.php' => false],
			['Kernel.php' => false, 'Wordpress.php' => true],
			['Kernel.php' => true, 'Wordpress.php' => substr($module, 0, (int)strpos($module, "'wordpress';"))],
		];
		$files = ['Prepend.php', 'Adapter.php', 'Kernel.php', 'Wordpress.php'];
		$seen = [];
		try
		{
			// the request handed over in a file: escapeshellarg() on Windows blanks the quotes of JSON
			file_put_contents($input, json_encode([$dir, ...$this->moduleExploits('api')[0], $consent]));
			file_put_contents($script, "<?php\n// the Shield directory as an upgrade may leave it, loaded by path with no autoloader\n"
				. "foreach(explode(',', \$argv[3]) as \$file)\n{\n\trequire \$argv[1] . '/' . \$file;\n}\n"
				. "[\$dir, \$server, \$post, \$consent] = json_decode((string)file_get_contents(\$argv[2]), true);\n"
				. "\$judged = Ovos\\Codesafe\\Shield\\Prepend::judge(\$dir, \$server, \$post, [], null, \$consent, wordpress: false);\n"
				. "\$ip = Ovos\\Codesafe\\Shield\\Prepend::clientIp(['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9'], 'X-Forwarded-For', ['10.0.0.0/8']);\n"
				. "echo Ovos\\Codesafe\\Shield\\Prepend::ready() ? 'ready' : 'not ready', ' ', \$judged === null ? 0 : \$judged['verdict']->rule['id'], ' ', \$ip;\n");
			foreach($states as $state)
			{
				foreach(['Prepend.php' => true, 'Adapter.php' => true] + $state as $name => $content)
				{
					$path = $copy . DIRECTORY_SEPARATOR . $name;
					if(is_file($path))
					{
						unlink($path);
					}
					if($content === true)
					{
						copy(dirname(self::PREPEND) . DIRECTORY_SEPARATOR . $name, $path);
					}
					elseif(is_string($content))
					{
						file_put_contents($path, $content);
					}
				}
				// the stubs load Prepend.php first, WordPress's autoloader may load Adapter.php first
				foreach(['Prepend.php,Adapter.php', 'Adapter.php,Prepend.php'] as $order)
				{
					$output = [];
					exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($copy) . ' ' . escapeshellarg($input) . ' '
						. escapeshellarg($order) . ' 2>&1', $output);
					$seen[] = implode("\n", $output);
				}
			}
		}
		finally
		{
			foreach($files as $name)
			{
				if(is_file($copy . DIRECTORY_SEPARATOR . $name))
				{
					unlink($copy . DIRECTORY_SEPARATOR . $name);
				}
			}
			rmdir($copy);
			foreach([$rules, $input, $script] as $path)
			{
				if(is_file($path))
				{
					unlink($path);
				}
			}
			rmdir($dir);
		}
		
		return $seen === ['ready 31 203.0.113.9', 'ready 31 203.0.113.9', 'not ready 0 203.0.113.9', 'not ready 0 203.0.113.9',
			'not ready 0 10.0.0.1', 'not ready 0 10.0.0.1', 'not ready 0 203.0.113.9', 'not ready 0 203.0.113.9'];
	}
	
	/**
	 * RULE: the adapter hands the Sender every report the prepend layer
	 * stashed for the request, each marked as the layer's, and claims the
	 * stash, so the layer's shutdown queues none of them again. Falsify: send
	 * the first claimed report alone — a second rule's observe before
	 * WordPress never reaches codesafe.
	 */
	public function theAdapterSendsEveryReportThePrependClaimed(): bool
	{
		$sender = new class extends Sender
		{
			/** @var list<array{0: string, 1: string, 2: array}> */
			public array $said = [];
			
			public function __construct()
			{
			}
			
			public function reportRefusal(
				string $kind,
				string $message = '',
				array $extra = [],
				array $context = [],
				?int $priority = null,
			): void
			{
				$this->said[] = [$kind, $message, $extra];
			}
		};
		$adapter = new Adapter(new Config, $sender, $this->kernel);
		$GLOBALS[Prepend::STASH] = ['verdict' => new Verdict(Verdict::OBSERVE), 'reports' => [
			[Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /x.php', ['rule' => 8]],
			[Verdict::KIND_OBSERVE, 'shield rule 9 observed GET /x.php', ['rule' => 9]],
		], 'claimed' => false];
		try
		{
			$sent = $adapter->sendClaimed();
			$again = $adapter->sendClaimed();
		}
		finally
		{
			unset($GLOBALS[Prepend::STASH]);
		}
		
		return $sent === 2 && $again === 0
			&& $sender->said === [
				[Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /x.php', ['rule' => 8, 'layer' => 'prepend']],
				[Verdict::KIND_OBSERVE, 'shield rule 9 observed GET /x.php', ['rule' => 9, 'layer' => 'prepend']],
			];
	}
	
	/**
	 * RULE: through php-cgi, as a site runs it: a request the prepend layer
	 * judged (Prepend::MARK) is not judged again at plugins_loaded, and every
	 * report the layer stashed for it reaches the Sender there, marked as the
	 * layer's, the stash claimed. Falsify: leave the claim out of judge() —
	 * the layer's shutdown queues the reports for a later request, which
	 * sends them without this request's user.
	 */
	public function aMarkedRequestsReportsReachTheSenderAtPluginsLoaded(): bool
	{
		$answer = json_decode($this->stage('marked', $this->cgiBinary()), true);
		
		return $answer === ['said' => [[Verdict::KIND_OBSERVE, ['rule' => 8, 'layer' => 'prepend']], [Verdict::KIND_OBSERVE, ['rule' => 9, 'layer' => 'prepend']]],
			'claimed' => true];
	}
	
	/**
	 * RULE: a kernel older than the adapter — php-library's, loaded first by
	 * another plugin, or this plugin's own mid-upgrade — has no rejudge(); a
	 * held request is then judged again with that kernel's judge(): refused
	 * once WordPress names an anonymous caller, observed when
	 * settled at shutdown. Falsify: call rejudge() whatever kernel is loaded
	 * — the Error is caught, and every held token-carrying REST or XML-RPC
	 * request goes uncounted, unreported and unrefused.
	 */
	public function aHeldRequestIsSettledByAnOlderKernelToo(): bool
	{
		$answer = json_decode($this->stage('older-kernel', PHP_BINARY), true);
		
		return $answer === ['rejudge' => false, 'held' => true, 'refused' => [[Verdict::KIND_BLOCK, 21]], 'settled' => [[Verdict::KIND_OBSERVE, 21]]];
	}
	
	/**
	 * RULE: a Prepend.php older than the adapter, met while an upgrade copies
	 * the plugin file by file, has claim() alone, answering its one report:
	 * the adapter sends it, once. Falsify: call claimAll() whatever Prepend
	 * is loaded — the Error is caught at plugins_loaded, and the layer's
	 * report and the request's tally are lost.
	 */
	public function anOlderPrependsOneReportReachesTheSender(): bool
	{
		$answer = json_decode($this->stage('older-prepend', PHP_BINARY), true);
		
		return $answer === ['claimAll' => false, 'sent' => [1, 0], 'said' => [[Verdict::KIND_OBSERVE, ['rule' => 8, 'layer' => 'prepend']]]];
	}
	
	/**
	 * RULE: the adapter reads either shape of the layer's claim — the list
	 * claimAll() answers, or the one report or null an older claim()
	 * answers — and leaves out what is no report. Falsify: read a single
	 * report as a list — its kind and message are taken for reports, and
	 * nothing is sent.
	 */
	public function theClaimIsReadInEitherShape(): bool
	{
		$first = [Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /x.php', ['rule' => 8]];
		$second = [Verdict::KIND_OBSERVE, 'shield rule 9 observed GET /x.php', ['rule' => 9]];
		
		return Adapter::claimed(null) === [] && Adapter::claimed([]) === []
			&& Adapter::claimed($first) === [$first]
			&& Adapter::claimed([$first, $second]) === [$first, $second]
			&& Adapter::claimed([Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /x.php']) === [[Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /x.php', []]]
			&& Adapter::claimed([$first, 'junk', [7, 'x', []]]) === [$first];
	}
	
	public function plainRequestPasses(): bool
	{
		$plain = Facts::fromServer([
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => '/',
			'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'REMOTE_ADDR' => '203.0.113.9',
		]);
		
		return $this->kernel->handle($plain, new Consent(true, true, false))->isPass();
	}
	
	public function killPassesEverythingAndPullsNothing(): bool
	{
		$kill = new Consent(true, true, true);
		
		return $this->kernel->handle($this->bot(), $kill)->reason === 'kill'
			&& $this->kernel->pull($kill) === Kernel::PULL_OFF
			&& $this->pulls === 0;
	}
	
	public function duePullIsConditionalGetAnsweredWith304(): bool
	{
		return $this->kernel->pull(new Consent(true, false, false), time() + Kernel::INTERVAL) === Kernel::PULL_UNCHANGED
			&& $this->pulls === 1;
	}
	
	public function rollupCarriesTheShieldHitsAndEvidenceAsTheirSections(): bool
	{
		$assembled = Rollup::assemble(29833333, Rollup::withExtra(['requests' => 3], static fn(int $minute): array => ['so:203' => 4, 'sb:203' => 1,
			'se:203' => 9, 'sm:203' => 5, 'sa:203' => 2], 29833333));
			
		return ($assembled['shield_observe'] ?? null) === ['203' => 4]
			&& ($assembled['shield_block'] ?? null) === ['203' => 1]
			&& ($assembled['shield_entry'] ?? null) === ['203' => 9] && ($assembled['shield_match'] ?? null) === ['203' => 5]
			&& ($assembled['shield_authed'] ?? null) === ['203' => 2];
	}
	
	/**
	 * RULE: the adapter answers unsafe_html with WordPress's post filter,
	 * reading only markup the filter takes out as unsafe — a script is, a
	 * bare `&`, a stray bracket and text written with entities are not —
	 * and the facts carry that answer. Falsify: compare wp_kses_post() with
	 * the value as it is — every `Tom & Jerry` in a field is refused.
	 */
	public function theAdapterAnswersUnsafeHtmlWithThePostFilter(): bool
	{
		$server = ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/wp-admin/admin-ajax.php', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'];
		$caller = Adapter::caller($server, [], ['action' => 'fx_save'], false, false);
		$facts = Adapter::facts($server, [], ['action' => 'fx_save'], [], [], $caller, '203.0.113.9');
		
		return Adapter::htmlUnsafe('<script>alert(1)</script>') && Adapter::htmlUnsafe('Tom & Jerry') === false && Adapter::htmlUnsafe('5 > 3') === false
			&& Adapter::htmlUnsafe('x < y') === false && Adapter::htmlUnsafe('&lt;script&gt;') === false && Adapter::htmlUnsafe('<b>bold</b>') === false
			&& $facts->htmlUnsafe('<script>x</script>') === true && $facts->htmlUnsafe('a & b') === false;
	}
	
	/**
	 * RULE: the adapter hands the kernel PHP's $_REQUEST beside the query and
	 * the form — taken at plugins_loaded, before WordPress rebuilds it from
	 * the two — so a request: rule meets a value a cookie put there, on the
	 * facts it builds and on the request it judges. Falsify: judge without
	 * the bag — a handler that reads $_REQUEST at plugins_loaded gets the
	 * cookie's value past the rule.
	 */
	public function theAdapterHandsTheKernelTheRequestBag(): bool
	{
		wp_shim_reset();
		$server = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/?action=benign'];
		$get = ['action' => 'benign'];
		$cookies = ['action' => 'fx_delete'];
		$anonymous = ['authed' => false, 'user' => '', 'can' => null, 'nonce' => null, 'known' => true];
		$facts = Adapter::facts($server, $get, [], $cookies, [], $anonymous, '203.0.113.9', 'wp-json', $cookies);
		$path = sys_get_temp_dir() . '/shield-adapter-bag-' . uniqid() . '.json';
		$store = new Store($path, '', false);
		$store->write(Ruleset::fromPayload(['contract' => 1, 'dialect' => 're2-2026', 'project' => 'harness', 'rules' => [['id' => 51, 'kind' => 'vpatch',
			'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'proven', 'expires_at' => null, 'who' => 'anyone',
			'conditions' => [['target' => 'request:action', 'test' => 'equals', 'value' => 'fx_delete']]]]], time(), platforms: Prepend::platforms())->toRecord(Kernel::sealKey('k')));
		$config = new class extends Config
		{
			public function __construct()
			{
			}
			
			public function shieldDetect(): bool
			{
				return true;
			}
			
			public function shieldEnforce(): bool
			{
				return true;
			}
			
			public function shieldKill(): bool
			{
				return false;
			}
		};
		$adapter = new Adapter($config, new Sender(new Config),
			new Kernel('https://codesafe.invalid', 'k', $store, static fn(): array => ['status' => 0, 'headers' => [], 'body' => ''], platforms: Prepend::platforms()));
		try
		{
			$bag = $adapter->judgeRequest([$server, $get, [], $cookies, [], $cookies], $anonymous, '203.0.113.9', 'wp-json');
			$none = $adapter->judgeRequest([$server, $get, [], $cookies, []], $anonymous, '203.0.113.9', 'wp-json');
		}
		finally
		{
			unlink($path);
			wp_shim_reset();
		}
		
		return Kernel::values('request:action', $facts) === ['benign', 'fx_delete']
			&& $bag?->isBlock() === true && $none?->isPass() === true;
	}
	
	public function fragmentWithoutHitsCarriesNoShieldSections(): bool
	{
		return isset(Rollup::assemble(29833333, ['requests' => 3])['shield_observe']) === false;
	}
	
	// ---- helpers --------------------------------------------------------------
	
	protected function bot(): Facts
	{
		return Facts::fromServer([
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => '/',
			'HTTP_USER_AGENT' => 'python-requests/2.31',
			'REMOTE_ADDR' => '203.0.113.9',
		]);
	}
	
	/** two blocking vpatches in WordPress's module's words: 31 on a REST route, 32 on a shortcode's attribute */
	protected function moduleRules(): array
	{
		$vpatch = ['kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'block', 'expires_at' => null, 'who' => 'anyone'];
		
		return [
			['id' => 31, 'conditions' => [['target' => 'rest', 'test' => 'prefix', 'value' => '/fx/v1/'], ['target' => 'body:a', 'test' => 'equals', 'value' => 'evil']]]
				+ $vpatch,
			['id' => 32, 'conditions' => [['target' => 'body:content', 'decode' => ['shortcode:fx_box.title'], 'test' => 'contains', 'value' => '<script']]] + $vpatch,
		];
	}
	
	/**
	 * The exploit of each module rule as [server, form]: a POST to the REST
	 * route under this REST prefix, and a post whose shortcode carries a script
	 *
	 * @return list<array{array<string, string>, array<string, string>}>
	 */
	protected function moduleExploits(
		string $prefix,
	): array
	{
		$server = static fn(string $uri): array => ['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => $uri, 'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
			'HTTP_USER_AGENT' => 'Mozilla/5.0', 'REMOTE_ADDR' => '203.0.113.9'];
		
		return [
			[$server('/' . $prefix . '/fx/v1/save'), ['a' => 'evil']],
			[$server('/wp-admin/admin-ajax.php'), ['action' => 'fx_save', 'content' => '[fx_box title="<script>alert(1)</script>"]']],
		];
	}
	
	protected function consolePath(): string
	{
		$path = getenv('OVOS_CONSOLE_PATH');
		if($path !== false && $path !== '')
		{
			return rtrim($path, '/\\');
		}
		
		// the checkout beside this one, under its name since the rename or before it
		$beside = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR;
		
		return is_dir($beside . 'codesafe') ? $beside . 'codesafe' : $beside . 'console';
	}
	
	/** tests/files/adapter-stage.file.php in its $mode, run by $binary — the CLI, or php-cgi with no ini; what it printed, the CGI headers left out */
	protected function stage(
		string $mode,
		string $binary,
	): string
	{
		$file = __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'adapter-stage.file.php';
		$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-adapter-stage-' . uniqid();
		mkdir($dir, 0700, true);
		$cgi = str_contains(basename($binary), 'cgi');
		$environment = ['OVOS_ADAPTER_STAGE' => (string)json_encode(['mode' => $mode, 'dir' => $dir])]
			+ ($cgi ? ['GATEWAY_INTERFACE' => 'CGI/1.1', 'SCRIPT_FILENAME' => $file, 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/x.php'] : []);
		// Windows' own libraries need it in any process
		if(getenv('SYSTEMROOT') !== false)
		{
			$environment['SYSTEMROOT'] = (string)getenv('SYSTEMROOT');
		}
		$command = $cgi ? [$binary, '-n', '-d', 'cgi.force_redirect=0'] : [$binary, '-d', 'opcache.enable_cli=0', $file];
		$output = '';
		$process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $dir, $environment);
		if(is_resource($process))
		{
			$output = (string)stream_get_contents($pipes[1]) . (string)stream_get_contents($pipes[2]);
			fclose($pipes[1]);
			fclose($pipes[2]);
			proc_close($process);
		}
		// the store directory's guard files among them
		foreach(array_diff((array)scandir($dir), ['.', '..']) as $left)
		{
			unlink($dir . DIRECTORY_SEPARATOR . $left);
		}
		rmdir($dir);
		
		return $cgi ? (explode("\r\n\r\n", $output, 2)[1] ?? '') : $output;
	}
	
	/** php-cgi beside this PHP — the SAPI a site's plugins_loaded runs in; the test is skipped without one */
	protected function cgiBinary(): string
	{
		$dir = dirname(PHP_BINARY);
		// Windows ships php-cgi.exe beside php.exe; Debian's packages name it php-cgi8.x beside php8.x
		foreach([$dir . DIRECTORY_SEPARATOR . 'php-cgi.exe', $dir . DIRECTORY_SEPARATOR . str_replace('php', 'php-cgi', basename(PHP_BINARY)),
			$dir . DIRECTORY_SEPARATOR . 'php-cgi'] as $candidate)
		{
			if(is_file($candidate))
			{
				return $candidate;
			}
		}
		
		throw new SkipException('No php-cgi beside ' . PHP_BINARY . '.');
	}
}
