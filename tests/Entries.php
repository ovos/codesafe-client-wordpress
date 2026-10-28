<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Checksums;
use Ovos\Codesafe\Config;
use Ovos\Codesafe\Entries as BaseEntries;
use Ovos\Codesafe\Scan;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_diff;
use function array_key_exists;
use function array_keys;
use function array_replace;
use function array_unique;
use function count;
use function dirname;
use function escapeshellarg;
use function exec;
use function file_get_contents;
use function file_put_contents;
use function is_dir;
use function md5;
use function mkdir;
use function preg_match_all;
use function realpath;
use function rmdir;
use function scandir;
use function str_contains;
use function str_replace;
use function substr;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;
use const PHP_BINARY;

// the layer's file brings the kernel classes the way the stub does
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The executed-file watch without WordPress (ovos/codesafe docs/plans/
 * prepend-entry-watch.md): a temp WordPress-shaped tree with a store
 * directory, the layer's recorder driven through Prepend::entry() with
 * fabricated request arrays, and the plugin's judge driven through
 * Entries::judge() with the tree's roots and fixture checksum lists.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Entries extends Test
{
	protected const string IP = '203.0.113.9';
	
	/** core's listing guard, byte for byte: wp-content/index.php, plugins/index.php, themes/index.php */
	protected const string GOLDEN = "<?php\n// Silence is golden.\n";
	
	/** what a shell looked like as it ran, before a stub took its place */
	protected const string SHELL = '<?php system($_GET[1]);';
	
	/** W3 Total Cache's config: an exit, then the data */
	protected const string W3TC = "<?php exit; ?>{\"pgcache.enabled\":false}";
	
	/** AIOS's firewall settings: halted, then the data */
	protected const string HALTED = "<?php __halt_compiler();{\"rules\":[]}";
	
	protected string $root;
	
	protected string $dir;
	
	/** @var array<string, string> */
	protected array $roots;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		
		$base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-entries-' . uniqid();
		mkdir($base, 0700, true);
		$this->root = str_replace('\\', '/', (string)realpath($base));
		$this->dir = $this->root . '/wp-content/ovos-codesafe';
		$this->roots = [
			'root' => $this->root,
			'content' => $this->root . '/wp-content',
			'plugins' => $this->root . '/wp-content/plugins',
			'mu' => $this->root . '/wp-content/mu-plugins',
			'themes' => $this->root . '/wp-content/themes',
			'uploads' => $this->root . '/wp-content/uploads',
		];
		
		foreach([
			'index.php' => '<?php // the site',
			'about.php' => '<?php // a stranger in the root',
			'tools/app.php' => '<?php // a second application',
			'wp-admin/admin-ajax.php' => '<?php // core entry',
			'wp-admin/evil.php' => '<?php // not in the core list',
			'wp-includes/version.php' => 'v',
			// code, every one: a file of an opener and a comment is a stub, and runs nothing
			'wp-content/x.php' => '<?php echo 1; // loose in wp-content',
			'wp-content/.hidden/s.php' => '<?php // hidden',
			'wp-content/uploads/2026/09/x.php' => 'x',
			'wp-content/uploads/2026/index.php' => self::GOLDEN,
			'wp-content/index.php' => self::GOLDEN,
			'wp-content/themes/index.php' => self::GOLDEN,
			'wp-content/plugins/index.php' => "<?php\n/**\n * Silence is golden.\n */\n?>\n",
			'wp-content/plugins/akismet/akismet.php' => 'a',
			'wp-content/plugins/akismet/inc.php' => '<?php echo 1; // not in akismet\'s list',
			'wp-content/plugins/premium/api.php' => '<?php echo 1; // no list on wp.org',
			'wp-content/plugins/hello.php' => '<?php echo 1; // single-file plugin',
			'wp-content/mu-plugins/m.php' => '<?php echo 1; // must-use',
			'wp-content/themes/t/f.php' => '<?php echo 1; // a theme file',
			'wp-content/themes/twentytwentyfive/functions.php' => '<?php echo 1; // a default theme',
			'wp-content/themes/twentytwentyfive/patterns.php' => '<?php echo 2; // updated since the release',
			'wp-content/ovos-codesafe/index.php' => "<?php\n// silence is golden\n",
			'wp-content/w3tc-config/master.php' => self::W3TC,
			// W3 Total Cache installed: its data directory has an owner
			'wp-content/plugins/w3-total-cache/w3-total-cache.php' => '<?php // installed owner',
			// data directories whose plugins are not installed: code, and a data file
			'wp-content/wp-rocket-config/site.php' => '<?php echo 1; // left by wp-rocket',
			'wp-content/nfwlog/cache.php' => self::W3TC,
			// a plugins/ directory get_plugins() does not list, and one whose header names no version
			'wp-content/plugins/leftover/inc.php' => '<?php echo 1;',
			'wp-content/plugins/leftover/data.php' => self::W3TC,
			'wp-content/plugins/noversion/x.php' => '<?php echo 1;',
			// a theme registered one directory deep (search_theme_directories(): stylesheet `vendor/t`)
			'wp-content/themes/vendor/t/f.php' => '<?php echo 1; // a theme in a subdirectory',
			'wp-content/uploads/aios/settings.php' => self::HALTED,
			// the exit runs system() first: no guard
			'wp-content/guarded.php' => "<?php exit(system('id')); ?>",
		] as $path => $content)
		{
			$file = $this->root . '/' . $path;
			if(is_dir(dirname($file)) === false)
			{
				mkdir(dirname($file), 0700, true);
			}
			file_put_contents($file, $content);
		}
		
		Prepend::writeKnown($this->dir, '7.1.2', '1.0.1', ['wp-admin/admin-ajax.php' => 'core']);
		Prepend::writeConsent($this->dir, $this->consent());
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
	 * @return array{detect: bool, enforce: bool, kill: bool, prefix: string, root: string, entries: bool}
	 */
	protected function consent(
		bool $entries = true,
	): array
	{
		return ['detect' => false, 'enforce' => false, 'kill' => false, 'prefix' => '', 'root' => $this->root, 'entries' => $entries];
	}
	
	/**
	 * @return array<string, mixed>
	 */
	protected function server(
		string $relative,
		string $query = '',
	): array
	{
		return [
			'SCRIPT_FILENAME' => $this->root . '/' . $relative,
			'REQUEST_URI' => '/' . $relative . ($query === '' ? '' : '?' . $query),
			'REQUEST_METHOD' => 'GET',
			'REMOTE_ADDR' => self::IP,
			'HTTP_USER_AGENT' => 'zz-entry/1.0',
			'HTTP_HOST' => 'site.test',
		];
	}
	
	/**
	 * @return array<string, mixed>
	 */
	protected function record(
		string $md5 = '',
		int $n = 3,
	): array
	{
		return [
			'n' => $n,
			'first' => 1789390000,
			'last' => 1789390120,
			'size' => 13,
			'mtime' => 1789389000,
			'md5' => $md5,
			'context' => ['ip' => self::IP, 'method' => 'GET', 'uri' => '/x.php?cmd=id', 'ua' => 'zz-entry/1.0', 'at' => 1789390120],
		];
	}
	
	/**
	 * The plugin's judge with fixture lists: core vouches for admin-ajax.php,
	 * version.php ('v') and two default-theme files (functions.php as it is
	 * on disk, patterns.php as the release shipped it, not as it is now),
	 * akismet 5.7 for akismet.php ('a'); premium has no list. `$cached` false
	 * makes every list cost a fetch, so the budget of one shows. The scan's
	 * roots are the temp tree; every fixture plugin and theme runs until a
	 * test sets `running`
	 *
	 * @return BaseEntries&object{learnNow: callable, running: ?array}
	 */
	protected function entries(
		bool $cached = true,
		?Sender $sender = null,
	): BaseEntries
	{
		$config = new Config;
		$lists = new class($cached) extends Checksums
		{
			public int $fetched = 0;
			
			public function __construct(
				protected bool $isCached,
			)
			{
				parent::__construct(1);
			}
			
			public function core(
				string $version,
				string $locale,
			): ?array
			{
				$this->fetched++;
				
				return ['wp-admin/admin-ajax.php' => md5('<?php // core entry'), 'wp-includes/version.php' => md5('v'),
					'wp-content/themes/twentytwentyfive/functions.php' => md5('<?php echo 1; // a default theme'),
					'wp-content/themes/twentytwentyfive/patterns.php' => md5('<?php echo 1; // as the release shipped it')];
			}
			
			public function coreCached(
				string $version,
				string $locale,
			): bool
			{
				return $this->isCached;
			}
			
			public function plugin(
				string $slug,
				string $version,
			): ?array
			{
				$this->fetched++;
				
				return $slug === 'akismet' && $version === '5.7' ? ['akismet.php' => md5('a')] : null;
			}
			
			public function pluginCached(
				string $slug,
				string $version,
			): bool
			{
				return $this->isCached;
			}
		};
		
		$scan = new class($config, $this->roots) extends Scan
		{
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
		};
		
		return new class($config, $sender ?? new Sender($config), $scan, $lists) extends BaseEntries
		{
			/** what activeAnywhere() answers; null is "cannot know" */
			public ?array $running = ['plugins' => ['akismet', 'premium', 'hello', 'w3-total-cache'], 'themes' => ['t', 'twentytwentyfive']];
			
			protected function coreVersion(): string
			{
				return '7.1.2';
			}
			
			protected function activeAnywhere(): ?array
			{
				return $this->running;
			}
			
			/**
			 * @param list<string> $paths
			 */
			public function learnNow(
				string $dir,
				array $paths,
			): void
			{
				$this->learn($dir, $paths);
			}
		};
	}
	
	/**
	 * @return array{finding: ?array, learn: bool, wait: bool}
	 */
	protected function judge(
		string $relative,
		array $record,
		?BaseEntries $entries = null,
	): array
	{
		$versions = ['akismet' => '5.7', 'premium' => '1.0', 'noversion' => ''];
		
		return ($entries ?? $this->entries())->judge($relative, $record, $this->roots, $versions);
	}
	
	/** the queue as the tests find it, emptied — whichever order they ran in */
	protected function clearQueue(): void
	{
		Prepend::forget($this->dir, array_keys(Prepend::seen($this->dir)['paths']));
	}
	
	public function theSiteAndAKnownAdminEntryAreNeverRecorded(): bool
	{
		$this->clearQueue();
		$consent = $this->consent();
		
		return Prepend::entry($this->dir, $this->server('index.php'), $consent) === null
			&& Prepend::entry($this->dir, $this->server('wp-login.php'), $consent) === null
			&& Prepend::entry($this->dir, $this->server('wp-admin/admin-ajax.php', 'action=x'), $consent) === null
			&& Prepend::seen($this->dir)['paths'] === [];
	}
	
	/**
	 * A stranger is measured as it ran — size, md5 — and a later hit counts
	 * one more with that request's own facts
	 */
	public function aStrangerIsRecordedAsItRanAndLaterHitsCount(): bool
	{
		$this->clearQueue();
		$consent = $this->consent();
		$first = Prepend::entry($this->dir, $this->server('wp-content/uploads/2026/09/x.php', 'cmd=id'), $consent, 1789390000);
		$one = Prepend::seen($this->dir)['paths']['wp-content/uploads/2026/09/x.php'] ?? null;
		$again = Prepend::entry($this->dir, ['REMOTE_ADDR' => '198.51.100.7'] + $this->server('wp-content/uploads/2026/09/x.php', 'cmd=ls'), $consent, 1789390060);
		$two = Prepend::seen($this->dir)['paths']['wp-content/uploads/2026/09/x.php'] ?? null;
		
		return $first === 'wp-content/uploads/2026/09/x.php'
			&& $again === $first
			&& $one !== null
			&& $one['n'] === 1
			&& $one['first'] === 1789390000
			&& $one['size'] === 1
			&& $one['md5'] === md5('x')
			&& $one['context']['ip'] === self::IP
			&& $one['context']['uri'] === '/wp-content/uploads/2026/09/x.php?cmd=id'
			&& $two !== null
			&& $two['n'] === 2
			&& $two['first'] === 1789390000
			&& $two['last'] === 1789390060
			&& $two['md5'] === md5('x')
			&& $two['context']['ip'] === '198.51.100.7'
			&& count(Prepend::seen($this->dir)['paths']) === 1;
	}
	
	/**
	 * The status is the request's own, onto its record: an HTTP status only,
	 * and never onto a later hit's facts. The record holds exactly what
	 * contextOf() built, which is what the layer hands its shutdown function
	 */
	public function theStatusIsTheRequestsOwn(): bool
	{
		$this->clearQueue();
		$consent = $this->consent();
		$relative = 'wp-content/x.php';
		Prepend::entry($this->dir, $this->server($relative, 'a=1'), $consent);
		$first = Prepend::seen($this->dir)['paths'][$relative]['context'];
		$built = array_replace(Prepend::contextOf($this->server($relative, 'a=1'), null, self::IP), ['at' => $first['at']]);
		Prepend::recordStatus($this->dir, $relative, $first, false);
		Prepend::recordStatus($this->dir, $relative, $first, 1000);
		$none = Prepend::seen($this->dir)['paths'][$relative]['context'];
		Prepend::recordStatus($this->dir, $relative, $first, 200);
		$own = Prepend::seen($this->dir)['paths'][$relative]['context'];
		Prepend::entry($this->dir, ['REMOTE_ADDR' => '198.51.100.7'] + $this->server($relative, 'a=2'), $consent);
		Prepend::recordStatus($this->dir, $relative, $first, 404);
		$later = Prepend::seen($this->dir)['paths'][$relative]['context'];
		
		return $first === $built
			&& array_key_exists('status', $none) === false
			&& $own['status'] === 200
			&& $own['uri'] === '/wp-content/x.php?a=1'
			&& $later['ip'] === '198.51.100.7'
			&& array_key_exists('status', $later) === false;
	}
	
	/**
	 * The status is written when the request ends, by the shutdown function
	 * the layer registers — a PHP of its own records a stranger and answers 404
	 */
	public function theStatusIsWrittenWhenTheRequestEnds(): bool
	{
		$this->clearQueue();
		$relative = 'wp-content/x.php';
		$output = [];
		exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'entry-status.file.php')
			. ' ' . escapeshellarg($this->dir) . ' ' . escapeshellarg($this->root) . ' ' . escapeshellarg($relative) . ' 404 2>&1', $output, $exit);
		$record = Prepend::seen($this->dir)['paths'][$relative] ?? null;
		
		return $exit === 0
			&& $output === []
			&& $record !== null
			&& $record['n'] === 1
			&& ($record['context']['status'] ?? null) === 404;
	}
	
	public function withoutTheSwitchOrTheKnownSetNothingIsRecorded(): bool
	{
		$off = Prepend::entry($this->dir, $this->server('about.php'), $this->consent(false));
		$noRoot = Prepend::entry($this->dir, $this->server('about.php'), ['root' => '', 'entries' => true]);
		unlink($this->dir . '/' . Prepend::ENTRIES);
		$noKnown = Prepend::entry($this->dir, $this->server('about.php'), $this->consent());
		Prepend::writeKnown($this->dir, '7.1.2', '1.0.1', ['wp-admin/admin-ajax.php' => 'core']);
		$back = Prepend::entry($this->dir, $this->server('about.php'), $this->consent());
		
		return $off === null
			&& $noRoot === null
			&& $noKnown === null
			&& $back === 'about.php';
	}
	
	/** a file outside the site — a shared library, another vhost — is cannot-know, and a missing one is nothing */
	public function outsideTheSiteIsNothing(): bool
	{
		$outside = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-entries-outside-' . uniqid() . '.php';
		file_put_contents($outside, '<?php');
		$recorded = Prepend::entry($this->dir, ['SCRIPT_FILENAME' => $outside], $this->consent());
		unlink($outside);
		
		return $recorded === null
			&& Prepend::entry($this->dir, ['SCRIPT_FILENAME' => $this->root . '/nothing-here.php'], $this->consent()) === null
			&& Prepend::entry($this->dir, [], $this->consent()) === null;
	}
	
	public function theQueueIsCappedAtSeenMaxAndCountsTheRest(): bool
	{
		$this->clearQueue();
		$consent = $this->consent();
		for($i = 0; $i < Prepend::SEEN_MAX + 3; $i++)
		{
			$path = 'wp-content/uploads/many/' . $i . '.php';
			if(is_dir(dirname($this->root . '/' . $path)) === false)
			{
				mkdir(dirname($this->root . '/' . $path), 0700, true);
			}
			file_put_contents($this->root . '/' . $path, '<?php');
			Prepend::entry($this->dir, $this->server($path), $consent);
		}
		$seen = Prepend::seen($this->dir);
		
		return count($seen['paths']) === Prepend::SEEN_MAX
			&& $seen['dropped'] === 3;
	}
	
	public function forgetDropsTheJudgedAndKeepsWhatArrivedMeanwhile(): bool
	{
		$this->clearQueue();
		$consent = $this->consent();
		Prepend::entry($this->dir, $this->server('about.php'), $consent);
		Prepend::entry($this->dir, $this->server('wp-content/x.php'), $consent);
		Prepend::forget($this->dir, ['about.php']);
		$kept = Prepend::seen($this->dir);
		Prepend::forget($this->dir, ['wp-content/x.php']);
		$empty = Prepend::seen($this->dir);
		
		return array_keys($kept['paths']) === ['wp-content/x.php']
			&& $empty['paths'] === []
			&& $empty['dropped'] === 0;
	}
	
	/** an executed file under uploads is the headline — unless it is the stub plugins write there */
	public function judgeUploadsAndTheSilenceStub(): bool
	{
		$shell = $this->judge('wp-content/uploads/2026/09/x.php', $this->record(md5('x')));
		$stub = $this->judge('wp-content/uploads/2026/index.php', $this->record('', 1) + ['size' => 26]);
		
		return ($shell['finding']['detector'] ?? '') === 'executed_uploads'
			&& $shell['finding']['tier'] === 'urgent'
			&& $shell['finding']['area'] === 'uploads'
			&& $shell['finding']['path'] === '2026/09/x.php'
			&& $shell['finding']['size'] === 13
			&& $shell['finding']['mtime'] === 1789389000
			&& $shell['learn'] === false
			&& $stub['finding'] === null
			&& $stub['learn'] === true;
	}
	
	/**
	 * The silence stub runs no code wherever core or a plugin left it —
	 * core's guards in wp-content/, plugins/ and themes/ — and is judged on
	 * the bytes that ran: a stub on disk that the layer saw run as other
	 * bytes is the shell swapped out after use, and keeps its area's finding
	 */
	public function judgeTheSilenceStubWhereverItRan(): bool
	{
		$content = $this->judge('wp-content/index.php', $this->record(md5(self::GOLDEN)));
		$themes = $this->judge('wp-content/themes/index.php', $this->record());
		$plugins = $this->judge('wp-content/plugins/index.php', $this->record());
		$swapped = $this->judge('wp-content/index.php', $this->record(md5(self::SHELL)));
		$swappedUploads = $this->judge('wp-content/uploads/2026/index.php', $this->record(md5(self::SHELL)));
		
		return $content['finding'] === null && $content['learn'] === true
			&& $themes['finding'] === null && $themes['learn'] === true
			&& $plugins['finding'] === null && $plugins['learn'] === true
			&& ($swapped['finding']['detector'] ?? '') === 'executed_content'
			&& $swapped['finding']['tier'] === 'urgent'
			&& ($swappedUploads['finding']['detector'] ?? '') === 'executed_uploads'
			&& $swappedUploads['finding']['tier'] === 'urgent';
	}
	
	/**
	 * Core's list vouches for what the release ships under wp-content — a
	 * default theme's file, byte for byte as it ran; a file it names with
	 * other bytes (the theme updated since) is its area's to judge, and a
	 * list not cached yet vouches for nothing and keeps nothing waiting
	 */
	public function judgeWhatCoreShipsUnderWpContent(): bool
	{
		$shipped = $this->judge('wp-content/themes/twentytwentyfive/functions.php', $this->record());
		$updated = $this->judge('wp-content/themes/twentytwentyfive/patterns.php', $this->record());
		$uncached = $this->judge('wp-content/themes/twentytwentyfive/functions.php', $this->record(), $this->entries(false));
		
		return $shipped['finding'] === null && $shipped['learn'] === true
			&& ($updated['finding']['detector'] ?? '') === 'executed_unverified'
			&& $updated['finding']['area'] === 'themes'
			&& ($uncached['finding']['detector'] ?? '') === 'executed_unverified'
			&& $uncached['wait'] === false;
	}
	
	/**
	 * A plugin's data file under a PHP name stops before any code runs — W3
	 * Total Cache's config loose in wp-content, AIOS's settings under uploads
	 * — and is listed the way the scan lists it. Judged on the bytes that
	 * ran: the same file seen run as a shell keeps its area's finding, and an
	 * exit that runs code first guards nothing
	 */
	public function judgeAnInertFileThatRan(): bool
	{
		$config = $this->judge('wp-content/w3tc-config/master.php', $this->record(md5(self::W3TC)));
		$settings = $this->judge('wp-content/uploads/aios/settings.php', $this->record());
		$swapped = $this->judge('wp-content/w3tc-config/master.php', $this->record(md5(self::SHELL)));
		$swappedUploads = $this->judge('wp-content/uploads/aios/settings.php', $this->record(md5(self::SHELL)));
		$guarded = $this->judge('wp-content/guarded.php', $this->record());
		
		return ($config['finding']['detector'] ?? '') === 'inert_php'
			&& $config['finding']['tier'] === 'info'
			&& $config['finding']['area'] === 'content'
			&& $config['finding']['path'] === 'w3tc-config/master.php'
			&& str_contains((string)$config['finding']['detail'], 'stops before any code runs')
			&& $config['learn'] === true
			&& ($settings['finding']['detector'] ?? '') === 'inert_php'
			&& $settings['finding']['area'] === 'uploads'
			&& $settings['learn'] === true
			&& ($swapped['finding']['detector'] ?? '') === 'executed_content'
			&& $swapped['finding']['tier'] === 'urgent'
			&& $swapped['learn'] === false
			&& ($swappedUploads['finding']['detector'] ?? '') === 'executed_uploads'
			&& ($guarded['finding']['detector'] ?? '') === 'executed_content'
			&& $guarded['finding']['tier'] === 'urgent';
	}
	
	public function judgeRootContentAndHiddenPaths(): bool
	{
		$root = $this->judge('about.php', $this->record());
		$own = $this->judge('tools/app.php', $this->record());
		$content = $this->judge('wp-content/x.php', $this->record());
		$hidden = $this->judge('wp-content/.hidden/s.php', $this->record());
		$entry = $this->judge('index.php', $this->record());
		
		return ($root['finding']['detector'] ?? '') === 'executed_root'
			&& $root['finding']['tier'] === 'urgent'
			&& $root['finding']['area'] === 'root'
			&& $root['finding']['path'] === 'about.php'
			&& ($own['finding']['detector'] ?? '') === 'executed_root'
			&& $own['finding']['tier'] === 'high'
			&& str_contains((string)$own['finding']['detail'], 'does not own')
			&& ($content['finding']['detector'] ?? '') === 'executed_content'
			&& $content['finding']['area'] === 'content'
			&& $content['finding']['path'] === 'x.php'
			&& ($hidden['finding']['detector'] ?? '') === 'executed_hidden'
			&& $hidden['finding']['tier'] === 'urgent'
			&& $entry['finding'] === null
			&& $entry['learn'] === true;
	}
	
	/** the core list: foreign, modified BY THE MD5 AS IT RAN, shipped — and the md5 on disk when the layer took none */
	public function judgeCoreAgainstTheList(): bool
	{
		$foreign = $this->judge('wp-admin/evil.php', $this->record());
		$modified = $this->judge('wp-includes/version.php', $this->record(md5('an eval appended')));
		$shipped = $this->judge('wp-includes/version.php', $this->record(md5('v')));
		$onDisk = $this->judge('wp-includes/version.php', $this->record(''));
		
		return ($foreign['finding']['detector'] ?? '') === 'executed_core_foreign'
			&& $foreign['finding']['tier'] === 'urgent'
			&& $foreign['finding']['area'] === 'core'
			&& $foreign['finding']['path'] === 'wp-admin/evil.php'
			&& ($modified['finding']['detector'] ?? '') === 'executed_core_modified'
			&& $modified['finding']['tier'] === 'urgent'
			&& $shipped['finding'] === null
			&& $shipped['learn'] === true
			&& $onDisk['finding'] === null
			&& $onDisk['learn'] === true;
	}
	
	public function judgePluginsAgainstTheirLists(): bool
	{
		$foreign = $this->judge('wp-content/plugins/akismet/inc.php', $this->record());
		$shipped = $this->judge('wp-content/plugins/akismet/akismet.php', $this->record(md5('a')));
		$premium = $this->judge('wp-content/plugins/premium/api.php', $this->record());
		$single = $this->judge('wp-content/plugins/hello.php', $this->record());
		$stranger = $this->judge('wp-content/plugins/nobody/x.php', $this->record());
		
		return ($foreign['finding']['detector'] ?? '') === 'executed_plugin_foreign'
			&& $foreign['finding']['tier'] === 'urgent'
			&& $foreign['finding']['area'] === 'plugins'
			&& $foreign['finding']['path'] === 'akismet/inc.php'
			&& $shipped['finding'] === null
			&& $shipped['learn'] === true
			&& ($premium['finding']['detector'] ?? '') === 'executed_unverified'
			&& $premium['finding']['tier'] === 'info'
			&& $premium['learn'] === true
			&& ($single['finding']['detector'] ?? '') === 'executed_unverified'
			&& $single['learn'] === true
			&& ($stranger['finding']['detector'] ?? '') === 'executed_vanished';
	}
	
	public function judgeMuPluginsAndThemesOnce(): bool
	{
		$mu = $this->judge('wp-content/mu-plugins/m.php', $this->record());
		$theme = $this->judge('wp-content/themes/t/f.php', $this->record());
		$store = $this->judge('wp-content/ovos-codesafe/index.php', $this->record());
		
		return ($mu['finding']['detector'] ?? '') === 'executed_unverified'
			&& $mu['finding']['tier'] === 'info'
			&& $mu['finding']['area'] === 'content'
			&& $mu['finding']['path'] === 'mu-plugins/m.php'
			&& $mu['learn'] === true
			&& ($theme['finding']['detector'] ?? '') === 'executed_unverified'
			&& $theme['finding']['area'] === 'themes'
			&& $theme['finding']['path'] === 't/f.php'
			&& $theme['learn'] === true
			&& $store['finding'] === null
			&& $store['learn'] === true;
	}
	
	/** used, then deleted: the finding carries what ran */
	public function judgeVanishedCarriesTheMd5ItRanWith(): bool
	{
		$gone = $this->judge('wp-content/uploads/2026/09/gone.php', $this->record(md5('gone')));
		
		return ($gone['finding']['detector'] ?? '') === 'executed_vanished'
			&& $gone['finding']['tier'] === 'urgent'
			&& $gone['finding']['area'] === 'uploads'
			&& $gone['finding']['path'] === '2026/09/gone.php'
			&& str_contains((string)$gone['finding']['detail'], 'md5 ' . substr(md5('gone'), 0, 12))
			&& $gone['learn'] === false;
	}
	
	/** one list fetch per drain: the second uncached list leaves its path queued for the next one */
	public function judgeWaitsPastTheFetchBudget(): bool
	{
		$entries = $this->entries(false);
		$versions = ['akismet' => '5.7'];
		$first = $entries->judge('wp-content/plugins/akismet/inc.php', $this->record(), $this->roots, $versions);
		$second = $entries->judge('wp-admin/evil.php', $this->record(), $this->roots, $versions);
		
		return ($first['finding']['detector'] ?? '') === 'executed_plugin_foreign'
			&& $first['wait'] === false
			&& $second['finding'] === null
			&& $second['wait'] === true
			&& $second['learn'] === false;
	}
	
	public function theDetailSaysHowOftenWhenAndFromWhere(): bool
	{
		$detail = (string)($this->judge('about.php', $this->record())['finding']['detail'] ?? '');
		
		return str_contains($detail, 'executed 3×')
			&& str_contains($detail, 'first 14.09. 12:46')
			&& str_contains($detail, 'last 14.09. 12:48 UTC')
			&& str_contains($detail, 'from ' . self::IP)
			&& str_contains($detail, 'GET');
	}
	
	public function learnAddsToTheKnownSetBesideTheCoreEntries(): bool
	{
		$this->entries()->learnNow($this->dir, ['wp-content/plugins/akismet/akismet.php', 'wp-content/plugins/premium/api.php']);
		$known = Prepend::known($this->dir);
		$consent = $this->consent();
		
		return $known !== null
			&& $known['core'] === '7.1.2'
			&& ($known['known']['wp-admin/admin-ajax.php'] ?? '') === 'core'
			&& ($known['known']['wp-content/plugins/akismet/akismet.php'] ?? '') === 'learnt'
			&& ($known['known']['wp-content/plugins/premium/api.php'] ?? '') === 'learnt'
			&& Prepend::entry($this->dir, $this->server('wp-content/plugins/akismet/akismet.php'), $consent) === null
			&& Prepend::entry($this->dir, $this->server('wp-content/plugins/akismet/inc.php'), $consent) === 'wp-content/plugins/akismet/inc.php';
	}
	
	/**
	 * RULE: a file that ran inside a plugin's data directory whose plugin is
	 * not installed is a leftover worded by the place — urgent when code ran,
	 * since the directory's name says nothing about who wrote the file, info
	 * and learnt when PHP stops before any of it runs; with its owner
	 * installed the directory is that plugin's and the file is judged as
	 * before. Falsify: let writerOwners() skip installedOwner() — W3 Total
	 * Cache's own config reads as a leftover; drop the inert split — the
	 * firewall log reads urgent; judge ranInert() first — it reads inert_php;
	 * write the plugins/ directory's high here — a shell in a data directory
	 * reads high.
	 */
	public function judgeALeftoverOfAnUninstalledPlugin(): bool
	{
		$code = $this->judge('wp-content/wp-rocket-config/site.php', $this->record());
		$data = $this->judge('wp-content/nfwlog/cache.php', $this->record(md5(self::W3TC)));
		$owned = $this->judge('wp-content/w3tc-config/master.php', $this->record(md5(self::W3TC)));
		$shell = $this->judge('wp-content/w3tc-config/master.php', $this->record(md5(self::SHELL)));
		
		return ($code['finding']['detector'] ?? '') === 'executed_leftover'
			&& $code['finding']['tier'] === 'urgent'
			&& $code['finding']['area'] === 'content'
			&& $code['finding']['path'] === 'wp-rocket-config/site.php'
			&& str_contains((string)$code['finding']['detail'], 'in wp-rocket-config/ (wp-rocket, not installed) · code ran')
			&& $code['learn'] === false
			&& ($data['finding']['detector'] ?? '') === 'executed_leftover'
			&& $data['finding']['tier'] === 'info'
			&& str_contains((string)$data['finding']['detail'], 'in nfwlog/ (ninjafirewall, not installed)')
			&& str_contains((string)$data['finding']['detail'], 'stops before any code runs')
			&& $data['learn'] === true
			&& ($owned['finding']['detector'] ?? '') === 'inert_php'
			&& ($shell['finding']['detector'] ?? '') === 'executed_content'
			&& $shell['finding']['tier'] === 'urgent';
	}
	
	/**
	 * RULE: a plugins/ directory get_plugins() does not list is a leftover —
	 * high when code ran, info when it stops before any runs — while an
	 * installed plugin whose header names no version stays unverified, once.
	 * Falsify: test the version for '' instead of the key — noversion reads
	 * as a leftover; learn the high row — the layer stops recording it;
	 * write the data directory's urgent here — the plugins/ directory reads
	 * urgent.
	 */
	public function judgeAPluginsDirectoryNobodyInstalled(): bool
	{
		$code = $this->judge('wp-content/plugins/leftover/inc.php', $this->record());
		$data = $this->judge('wp-content/plugins/leftover/data.php', $this->record());
		$noVersion = $this->judge('wp-content/plugins/noversion/x.php', $this->record());
		
		return ($code['finding']['detector'] ?? '') === 'executed_leftover'
			&& $code['finding']['tier'] === 'high'
			&& $code['finding']['area'] === 'plugins'
			&& $code['finding']['path'] === 'leftover/inc.php'
			&& str_contains((string)$code['finding']['detail'], 'no installed plugin owns plugins/leftover')
			&& $code['learn'] === false
			&& ($data['finding']['detector'] ?? '') === 'executed_leftover'
			&& $data['finding']['tier'] === 'info'
			&& $data['learn'] === true
			&& ($noVersion['finding']['detector'] ?? '') === 'executed_unverified'
			&& $noVersion['finding']['tier'] === 'info'
			&& str_contains((string)$noVersion['finding']['detail'], 'no version to look up for noversion');
	}
	
	/**
	 * RULE: a shipped file of a plugin active on no site, or a file of such a
	 * plugin wordpress.org has no list for, that ran is executed_inactive —
	 * info, learnt, in words that claim no history (never activated reads
	 * the same); its foreign file stays urgent and says the plugin is not
	 * active; when what runs cannot be known, the verdicts are as they were.
	 * Falsify: ask inactive() before verify() — the foreign file reads
	 * inactive; read null as nothing active — akismet's shipped file reads
	 * not active on a network nobody counted.
	 */
	public function judgeADeactivatedPluginsShippedFile(): bool
	{
		$entries = $this->entries();
		$entries->running = ['plugins' => ['hello', 'w3-total-cache'], 'themes' => ['t', 'twentytwentyfive']];
		$shipped = $this->judge('wp-content/plugins/akismet/akismet.php', $this->record(md5('a')), $entries);
		$foreign = $this->judge('wp-content/plugins/akismet/inc.php', $this->record(), $entries);
		$premium = $this->judge('wp-content/plugins/premium/api.php', $this->record(), $entries);
		$entries->running = null;
		$unknown = $this->judge('wp-content/plugins/akismet/akismet.php', $this->record(md5('a')), $entries);
		$unknownPremium = $this->judge('wp-content/plugins/premium/api.php', $this->record(), $entries);
		
		return ($shipped['finding']['detector'] ?? '') === 'executed_inactive'
			&& $shipped['finding']['tier'] === 'info'
			&& $shipped['learn'] === true
			&& str_contains((string)$shipped['finding']['detail'], 'not active on any site, yet the web server still serves it')
			&& str_contains((string)$shipped['finding']['detail'], 'deactivated') === false
			&& ($foreign['finding']['detector'] ?? '') === 'executed_plugin_foreign'
			&& $foreign['finding']['tier'] === 'urgent'
			&& str_contains((string)$foreign['finding']['detail'], 'not active on any site · not in the wordpress.org list')
			&& $foreign['learn'] === false
			&& ($premium['finding']['detector'] ?? '') === 'executed_inactive'
			&& str_contains((string)$premium['finding']['detail'], 'not active on any site, no wordpress.org list for premium 1.0')
			&& $premium['learn'] === true
			&& $unknown['finding'] === null
			&& $unknown['learn'] === true
			&& ($unknownPremium['finding']['detector'] ?? '') === 'executed_unverified';
	}
	
	/**
	 * RULE: a theme no site runs is executed_inactive, info and learnt; a
	 * theme the site runs stays unverified — one registered a directory deep
	 * (`vendor/t`) too, and a theme only sharing a name with a deeper one
	 * runs nothing. Falsify: leave the themes branch without inactive() — t
	 * reads unverified; compare the theme against the plugins — the running
	 * theme reads inactive; compare the first segment alone — the active
	 * `vendor/t` reads inactive.
	 */
	public function judgeAThemeTheSiteDoesNotRun(): bool
	{
		$entries = $this->entries();
		$entries->running = ['plugins' => ['akismet'], 'themes' => ['twentytwentyfive']];
		$inactive = $this->judge('wp-content/themes/t/f.php', $this->record(), $entries);
		$entries->running = ['plugins' => ['akismet'], 'themes' => ['t', 'twentytwentyfive']];
		$running = $this->judge('wp-content/themes/t/f.php', $this->record(), $entries);
		$entries->running = ['plugins' => ['akismet'], 'themes' => ['vendor/t']];
		$deep = $this->judge('wp-content/themes/vendor/t/f.php', $this->record(), $entries);
		$shallow = $this->judge('wp-content/themes/t/f.php', $this->record(), $entries);
		
		return ($inactive['finding']['detector'] ?? '') === 'executed_inactive'
			&& $inactive['finding']['tier'] === 'info'
			&& $inactive['finding']['area'] === 'themes'
			&& $inactive['finding']['path'] === 't/f.php'
			&& $inactive['learn'] === true
			&& ($running['finding']['detector'] ?? '') === 'executed_unverified'
			&& $running['finding']['area'] === 'themes'
			&& ($deep['finding']['detector'] ?? '') === 'executed_unverified'
			&& $deep['finding']['path'] === 'vendor/t/f.php'
			&& ($shallow['finding']['detector'] ?? '') === 'executed_inactive';
	}
	
	/**
	 * RULE: every word the judge answers has its words for the security
	 * event's line — the listed ones and every executed_ word written in the
	 * judge's source — except inert_php, the scan's own. Falsify: drop
	 * executed_leftover's label — its event names the raw word.
	 */
	public function everyVerdictHasALabel(): bool
	{
		$listed = ['executed_uploads', 'executed_root', 'executed_root_owned', 'executed_hidden', 'executed_content',
			'executed_core_foreign', 'executed_core_modified', 'executed_plugin_foreign', 'executed_plugin_modified',
			'executed_unverified', 'executed_vanished', 'executed_leftover', 'executed_inactive'];
		preg_match_all("~'(executed_[a-z_]+)'~", (string)file_get_contents(__DIR__ . '/../src/Entries.php'), $written);
		$words = array_unique([...$listed, ...$written[1]]);
		
		return array_diff($words, array_keys(BaseEntries::LABELS)) === []
			&& array_key_exists('inert_php', BaseEntries::LABELS) === false
			&& count($written[1]) > 0;
	}
	
	/**
	 * RULE: through a drain, a high leftover is one file_executed event whose
	 * line wears the label and whose extra says the source is unknown and
	 * names the detector; an info row — a theme no site runs — is listed in
	 * the report and raises no event. Falsify: drop the label — the line
	 * names the raw word; report info rows — two events.
	 */
	public function theLeftoverEventWearsTheLabel(): bool
	{
		$GLOBALS['wp']['options'][Config::OPTION] = ['enabled' => true, 'url' => 'https://codesafe.example', 'api_key' => 'k'];
		$sender = new class(new Config) extends Sender
		{
			/** @var list<array<string, mixed>> what the flushes would have posted */
			public array $sent = [];
			
			public function flush(): void
			{
				$this->sent = [...$this->sent, ...$this->queue];
				$this->queue = [];
			}
		};
		$entries = $this->entries(true, $sender);
		$entries->running = ['plugins' => ['akismet'], 'themes' => ['twentytwentyfive']];
		$drained = $entries->drain($this->dir, ['paths' => [
			'wp-content/wp-rocket-config/site.php' => $this->record(),
			'wp-content/themes/t/f.php' => $this->record(),
		], 'dropped' => 0]);
		$event = $sender->sent[0] ?? [];
		
		return $drained['sent'] === 202
			&& count($drained['findings']) === 2
			&& count($sender->sent) === 1
			&& ($event['events'][0]['className'] ?? '') === BaseEntries::KIND
			&& str_contains((string)($event['message'] ?? ''), 'ran inside a directory of software the site does not run')
			&& ($event['extra']['source'] ?? '') === 'unknown'
			&& ($event['extra']['detector'] ?? '') === 'executed_leftover'
			&& ($event['extra']['tier'] ?? '') === 'urgent';
	}
}
