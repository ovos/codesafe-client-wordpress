<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Scan as PluginScan;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_filter;
use function array_values;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function is_dir;
use function mkdir;
use function realpath;
use function rmdir;
use function scandir;
use function str_replace;
use function sys_get_temp_dir;
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
	 * The two wp-content phases of a fresh pass over the temp tree, nothing
	 * that fetches a checksum list, with the store where $store says
	 *
	 * @param array{store: string, stub: string, legacy: string} $store
	 */
	protected function walk(
		array $store,
	): array
	{
		$scan = new class(new Config, $this->roots, $store) extends PluginScan
		{
			public function __construct(
				Config $config,
				protected array $tree,
				protected array $own,
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
			
			protected function storePaths(): array
			{
				return $this->own;
			}
		};
		
		$state = $scan->start('manual');
		$state['phases'] = array_values(array_filter($state['phases'], static fn(array $phase): bool => $phase[0] === 'content'));
		
		return $scan->advance($state, 10_000);
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
}
