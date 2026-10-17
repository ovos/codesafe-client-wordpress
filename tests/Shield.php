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
use function class_exists;
use function count;
use function escapeshellarg;
use function exec;
use function file_put_contents;
use function function_exists;
use function getenv;
use function is_dir;
use function is_file;
use function json_encode;
use function mkdir;
use function preg_quote;
use function realpath;
use function rmdir;
use function rtrim;
use function sha1_file;
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
		], time())->toRecord());
		
		$this->reports = [];
		$this->pulls = 0;
		$this->kernel = new Kernel('https://console.invalid', 'harness-key', $store,
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
	 * reads WordPress's module: its pull names the module to the door and
	 * keeps a `rest` rule and a `shortcode:` rule, and the adapter refuses
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
		
		return $pulled === Kernel::PULL_FRESH && $named === 'core,wordpress' && $kept === 2
			&& $routed?->isBlock() === true && $routed->rule['id'] === 31
			&& $coded?->isBlock() === true && $coded->rule['id'] === 32;
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
			'rules' => 'shield-cdcdcdcdcdcdcdcdcdcdcdcd.json', 'proxy_header' => '', 'proxies' => [], 'rest_prefix' => 'api'];
		$rules = $dir . DIRECTORY_SEPARATOR . $consent['rules'];
		$input = $dir . DIRECTORY_SEPARATOR . 'alone.json';
		$script = $dir . DIRECTORY_SEPARATOR . 'alone.php';
		(new Store($rules, ''))->write(Ruleset::fromPayload(['contract' => 1, 'dialect' => 're2-2026', 'project' => 'harness', 'rules' => $this->moduleRules()],
			time(), platforms: Prepend::platforms())->toRecord());
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
}
