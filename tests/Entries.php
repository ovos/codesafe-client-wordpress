<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Checksums;
use Ovos\Codesafe\Config;
use Ovos\Codesafe\Entries as BaseEntries;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_keys;
use function count;
use function dirname;
use function file_put_contents;
use function is_dir;
use function is_file;
use function md5;
use function mkdir;
use function realpath;
use function rmdir;
use function scandir;
use function str_contains;
use function str_replace;
use function substr;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;

use const DIRECTORY_SEPARATOR;

// the layer's file brings the kernel classes the way the stub does
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php';

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
	
	protected string $root;
	
	protected string $dir;
	
	/** @var array<string, string> */
	protected array $roots;
	
	#[Internal]
	public function prepare(): void
	{
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
			'wp-content/x.php' => '<?php // loose in wp-content',
			'wp-content/.hidden/s.php' => '<?php // hidden',
			'wp-content/uploads/2026/09/x.php' => 'x',
			'wp-content/uploads/2026/index.php' => "<?php\n// Silence is golden.\n",
			'wp-content/plugins/akismet/akismet.php' => 'a',
			'wp-content/plugins/akismet/inc.php' => '<?php // not in akismet\'s list',
			'wp-content/plugins/premium/api.php' => '<?php // no list on wp.org',
			'wp-content/plugins/hello.php' => '<?php // single-file plugin',
			'wp-content/mu-plugins/m.php' => '<?php // must-use',
			'wp-content/themes/t/f.php' => '<?php // a theme file',
			'wp-content/ovos-codesafe/index.php' => "<?php\n// silence is golden\n",
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
	 * The plugin's judge with fixture lists: core vouches for admin-ajax.php
	 * and version.php ('v'), akismet 5.7 for akismet.php ('a'); premium has
	 * no list. `$cached` false makes every list cost a fetch, so the budget
	 * of one shows
	 *
	 * @return BaseEntries&object{learnNow: callable}
	 */
	protected function entries(
		bool $cached = true,
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
				
				return ['wp-admin/admin-ajax.php' => md5('<?php // core entry'), 'wp-includes/version.php' => md5('v')];
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
		
		return new class($config, new Sender($config), null, $lists) extends BaseEntries
		{
			protected function coreVersion(): string
			{
				return '7.1.2';
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
		$versions = ['akismet' => '5.7', 'premium' => '1.0'];
		
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
}
