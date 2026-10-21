<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Database;
use Ovos\Codesafe\Scan as PluginScan;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_filter;
use function array_values;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function in_array;
use function is_dir;
use function md5;
use function mkdir;
use function realpath;
use function rmdir;
use function scandir;
use function str_replace;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;

use const DIRECTORY_SEPARATOR;
use const FILE_APPEND;

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
	 */
	protected function scanner(
		array $store,
		array $versions = [],
	): PluginScan
	{
		return new class(new Config, $this->roots, $store, $versions) extends PluginScan
		{
			public function __construct(
				Config $config,
				protected array $tree,
				protected array $own,
				protected array $versions,
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
		};
	}
	
	/**
	 * The phases of $areas from a fresh manual pass over the temp tree, with
	 * no core list, so nothing is fetched
	 *
	 * @param array{store: string, stub: string, legacy: string} $store
	 * @param list<string> $areas
	 * @param array<string, string> $versions plugin directory => version, for the checksum lists
	 */
	protected function walk(
		array $store,
		array $areas = ['content'],
		array $versions = [],
	): array
	{
		$scan = $this->scanner($store, $versions);
		$state = $scan->start('manual');
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
	 * stub beside the data, the legacy directory's stub, a stub naming a
	 * moved data directory, the data files and the mu-plugin are silent and
	 * counted verified. One byte appended to the stub or the mu-plugin is
	 * URGENT (both run on every request), a data file without its guard is
	 * HIGH, a stranger in the store stays content_php HIGH. Falsify: judge the
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
		Prepend::ensureStub($own['store'], $own['legacy'] . '/prepend.php');
		Prepend::writeConsent($own['store'], $consent);
		Prepend::writeKnown($own['store'], '7.1.3', '1.0.1', ['wp-admin/admin-ajax.php' => 'core']);
		Prepend::ensureMuPlugin($own['store'], $this->roots['mu']);
		$this->write($own['store'] . '/index.php', "<?php\n// silence is golden\n");
		
		$clean = $this->walk($own);
		
		// the data moved by CODESAFE_STORE_DIR: the stub stays and names the new directory
		$moved = ['store' => $content . '/private/store', 'stub' => $own['stub'], 'legacy' => $own['legacy']];
		mkdir($moved['store'], 0700, true);
		Prepend::ensureStub($moved['store'], $own['stub'] . '/prepend.php');
		Prepend::writeConsent($moved['store'], $consent);
		unlink($own['store'] . '/' . Prepend::CONSENT);
		unlink($own['store'] . '/' . Prepend::ENTRIES);
		unlink($this->roots['mu'] . '/' . Prepend::MU_PLUGIN);
		Prepend::ensureMuPlugin($moved['store'], $this->roots['mu']);
		
		$relocated = $this->walk($moved);
		
		file_put_contents($own['stub'] . '/prepend.php', "\nsystem(\$_GET['c']);\n", FILE_APPEND);
		file_put_contents($this->roots['mu'] . '/' . Prepend::MU_PLUGIN, "\n// x\n", FILE_APPEND);
		$this->write($moved['store'] . '/' . Prepend::CONSENT, (string)file_get_contents($moved['store'] . '/' . Prepend::CONSENT, offset: 15));
		$this->write($moved['store'] . '/x.php', "<?php system(\$_GET['c']);");
		
		$tampered = $this->walk($moved);
		
		return $this->verdict($clean, 'ovos-codesafe/prepend.php') === ''
			&& $this->verdict($clean, 'ovos-console/prepend.php') === ''
			&& $this->verdict($clean, 'ovos-codesafe/' . Prepend::CONSENT) === ''
			&& $this->verdict($clean, 'ovos-codesafe/' . Prepend::ENTRIES) === ''
			&& $this->verdict($clean, 'ovos-codesafe/index.php') === ''
			&& $this->verdict($clean, 'mu-plugins/' . Prepend::MU_PLUGIN) === ''
			&& $clean['areas']['content']['verified'] === 5
			&& $this->verdict($relocated, 'ovos-codesafe/prepend.php') === ''
			&& $this->verdict($relocated, 'private/store/' . Prepend::CONSENT) === ''
			&& $this->verdict($relocated, 'mu-plugins/' . Prepend::MU_PLUGIN) === ''
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
}
