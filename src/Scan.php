<?php
declare(strict_types=1);
// phpcs:disable WordPress.WP.AlternativeFunctions -- a read-only walk of the site's own tree (scandir, stat, md5_file, a few hundred bytes read per candidate): WP_Filesystem exists for WRITES through FTP credentials and has nothing to offer a shutdown-time read; nothing here ever writes

namespace Ovos\Codesafe;

use function apply_filters;
use function array_pop;
use function basename;
use function bin2hex;
use function class_exists;
use function count;
use function defined;
use function dirname;
use function explode;
use function fclose;
use function file_get_contents;
use function fileperms;
use function fopen;
use function fread;
use function function_exists;
use function get_bloginfo;
use function get_locale;
use function get_option;
use function get_plugins;
use function get_theme_root;
use function gmdate;
use function home_url;
use function implode;
use function in_array;
use function ini_get;
use function is_array;
use function is_dir;
use function is_file;
use function is_link;
use function is_multisite;
use function is_string;
use function max;
use function md5_file;
use function method_exists;
use function microtime;
use function preg_match;
use function preg_replace;
use function preg_split;
use function random_bytes;
use function readlink;
use function realpath;
use function round;
use function rtrim;
use function sanitize_text_field;
use function scandir;
use function stat;
use function str_contains;
use function str_replace;
use function str_starts_with;
use function strlen;
use function strpos;
use function strrpos;
use function strtolower;
use function substr;
use function time;
use function trim;
use function wp_get_environment_type;
use function wp_get_upload_dir;
use function wp_parse_url;
use function wp_unslash;

use const ABSPATH;
use const DIRECTORY_SEPARATOR;
use const PHP_URL_HOST;
use const PHP_VERSION;
use const SCANDIR_SORT_NONE;

/**
 * Integrity scan — the static half of finding the file nobody shipped.
 *
 * Every other sensor in this plugin needs the foreign file to DO something
 * after the plugin is installed: throw (Sender::sourceFor), be saved through
 * the editor (Security), be activated (Inventory). A shell dropped before the
 * plugin arrived, used once and left behind, does none of that. This class
 * asks the tree directly — is there executable code where none belongs, an
 * image that opens with `<?php`, a directive that makes images execute, a
 * drop-in whose owner is not installed, a core or plugin file that is not
 * what wordpress.org shipped (Checksums) — and the database beside it
 * (Database) — and answers with paths, never with contents.
 *
 * READS ONLY. Never writes, deletes, renames or quarantines: a wrong guess
 * must cost a second look, not a file. Never touches .htaccess. Never
 * follows a symlink. Never descends into a plugin-owned data directory
 * (backups can be gigabytes) — the directory itself is the finding.
 *
 * CHUNKED: the walk keeps its whole position in an array (a stack of
 * pending directories, counters, findings so far) that the runner persists
 * between requests, so a shutdown hook can spend 500 ms per request and a
 * button press a few seconds, and both resume where they stopped. Phases
 * run in order of expected value — the root, then uploads, then wp-content
 * itself — so an interrupted pass has already shipped the urgent part. A
 * checksum list that still has to be fetched can YIELD a chunk: the
 * directory goes back on the stack and the next request pays for the fetch.
 *
 * PRECISION FIRST: a scanner that names something innocent gets switched
 * off, which is worse than one that is late. Every heuristic here carries
 * its known false positive and how it is held down (the `index.php` stubs
 * plugins write into uploads, Wordfence's prepend file, managed hosts'
 * drop-ins). The tier on a finding is a PROPOSAL; the console decides.
 */
class Scan
{
	public const TIER_URGENT = 'urgent';
	
	public const TIER_HIGH = 'high';
	
	public const TIER_INFO = 'info';
	
	public const TIERS = [self::TIER_URGENT, self::TIER_HIGH, self::TIER_INFO];
	
	public const AREAS = ['root', 'uploads', 'content', 'plugins', 'core', 'themes', Database::AREA];
	
	/**
	 * Findings carried in full; past this the report counts them per tier.
	 * Urgent-first phase order means the cap eats the least interesting end.
	 */
	public const MAX_FINDINGS = 200;
	
	protected const MAX_PATH = 512;
	
	public const MAX_DETAIL = 160;
	
	protected const MAX_SKIPPED = 50;
	
	protected const MAX_DIRECTIVES_PER_FILE = 10;
	
	/** the polish detectors (dir_changed, owner_anomaly, symlink_outside) each stop listing here */
	protected const MAX_PER_POLISH = 20;
	
	/**
	 * The first block of a media-shaped file — enough to see the `<?php`
	 * that a favicon.ico shell puts behind a few bytes of decoy
	 */
	protected const HEAD_BYTES = 1024;
	
	protected const STUB_BYTES = 256;
	
	protected const DIRECTIVE_BYTES = 65536;
	
	protected const MIN_POLYGLOT_SIZE = 5;
	
	/** a directory changed after its newest file inside this window is worth dating */
	protected const RECENT_CHANGE = 30 * 86400;
	
	/**
	 * Checksum lists fetched per chunk before the walk yields to the next
	 * request: a shutdown chunk pays for one, a button round for a few
	 */
	protected const FETCHES_BACKGROUND = 1;
	
	protected const FETCHES_MANUAL = 3;
	
	/**
	 * Executable-shaped: the PHP family plus what Apache may hand to PHP or
	 * SSI. `.php.` inside the name counts too — `shell.php.jpg` executes
	 * wherever AddHandler (not SetHandler) maps .php.
	 */
	protected const EXECUTABLE = '~\.(?:ph(?:p\d?|tml|ar)|inc|shtml)(?:\.|$)~i';
	
	/**
	 * Media-shaped names probed for a PHP opener. Binary formats everywhere;
	 * text formats only under uploads, where a `.txt` opening with `<?php`
	 * has no honest explanation (a plugin's test fixture might).
	 */
	protected const MEDIA = ['ico', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'pdf', 'svg'];
	
	protected const MEDIA_TEXT = ['txt', 'log', 'csv'];
	
	protected const DIRECTIVE_FILES = ['.htaccess', '.user.ini', 'php.ini'];
	
	/**
	 * Dotfile PHP that developer tooling ships inside packages — a code-style
	 * config is not a hidden shell, and vendored plugins carry them by the
	 * dozen
	 */
	protected const HIDDEN_TOOLING = '~^\.(?:php-cs-fixer|php_cs|phpstorm\.meta|phpunit|phpcs|phpmd|phplint|phpstan|psalm)~i';
	
	/**
	 * WordPress 6.5+ writes translations as PHP (`<locale>.l10n.php`, or
	 * `<textdomain>-<locale>.l10n.php`) under wp-content/languages — core's own
	 * executable-shaped data files, loaded only by name for a requested locale
	 */
	protected const TRANSLATION = '~\.l10n\.php$~';
	
	/**
	 * Never descended: version control (thousands of objects, and its
	 * presence in the docroot is its own posture line) and node_modules
	 */
	protected const SKIP_DIRS = ['.git', '.svn', '.hg', 'node_modules'];
	
	/**
	 * wp-content directories skipped whole: page caches (caching plugins
	 * write PHP-named cache files by the thousand) and core's own upgrade
	 * staging
	 */
	protected const CONTENT_SKIP = ['cache', 'upgrade', 'upgrade-temp-backup'];
	
	/**
	 * A "Silence is golden." index.php — the stub WordPress and half its
	 * plugins write into directories to stop listings: an opener, comments,
	 * an optional closer, nothing else
	 */
	protected const STUB = '~^\s*<\?php\s*(?:(?://|#)[^\n]*\s*)*(?:\?>)?\s*$~';
	
	/**
	 * Drop-ins and other wp-content files WordPress or a plugin writes, and
	 * the plugins that write them. A file here with none of its owners
	 * installed is a stranger wearing a known name.
	 */
	protected const CONTENT_OWNERS = [
		'advanced-cache.php' => ['wp-super-cache', 'w3-total-cache', 'wp-rocket', 'litespeed-cache',
			'wp-fastest-cache', 'hummingbird-performance', 'breeze', 'cache-enabler', 'comet-cache',
			'swift-performance', 'swift-performance-lite', 'nitropack', 'flying-press', 'wp-optimize',
			'sg-cachepress', 'powered-cache', 'hyper-cache', 'simple-cache', 'surge',
			'wp-cloudflare-page-cache', 'seraphinite-accelerator', 'speed-booster-pack'],
		'object-cache.php' => ['redis-cache', 'w3-total-cache', 'litespeed-cache', 'memcached',
			'memcached-redux', 'object-cache-pro', 'wp-redis', 'sqlite-object-cache', 'docket-cache',
			'powered-cache', 'apcu-manager', 'relay-cache', 'wp-spider-cache', 'hummingbird-performance'],
		'db.php' => ['query-monitor', 'ludicrousdb', 'hyperdb', 'w3-total-cache',
			'sqlite-database-integration', 'wp-db-driver'],
		'wp-cache-config.php' => ['wp-super-cache'],
	];
	
	/**
	 * wp-content directories a plugin (or theme) owns and fills with its own
	 * PHP-named data and logs. Never descended; owner installed → listed,
	 * owner missing → a finding.
	 */
	protected const WRITER_DIRS = [
		'wflogs' => ['wordfence'],
		'wfcache' => ['wordfence'],
		'w3tc-config' => ['w3-total-cache'],
		'wp-rocket-config' => ['wp-rocket'],
		'litespeed' => ['litespeed-cache'],
		'sucuri' => ['sucuri-scanner'],
		'nfwlog' => ['ninjafirewall'],
		'wp-cloudflare-super-page-cache' => ['wp-cloudflare-page-cache'],
		'bps-backup' => ['bulletproof-security'],
		'aiowps_backups' => ['all-in-one-wp-security-and-firewall'],
		'backups-dup-lite' => ['duplicator'],
		'backups-dup-pro' => ['duplicator-pro'],
		'ai1wm-backups' => ['all-in-one-wp-migration'],
		'updraft' => ['updraftplus'],
		'wpvividbackups' => ['wpvivid-backuprestore'],
		'wp-security-audit-log' => ['wp-security-audit-log'],
		'ithemes-security' => ['better-wp-security', 'ithemes-security-pro'],
		'siteground-optimizer-assets' => ['sg-cachepress'],
		'smush-webp' => ['wp-smushit', 'wp-smush-pro'],
		'ewww' => ['ewww-image-optimizer'],
		'et-cache' => ['theme:Divi', 'theme:Extra'],
		'backup-db' => ['wp-db-backup'],
	];
	
	/**
	 * PHP files a plugin legitimately puts in the document ROOT (the
	 * executed-file watch, Entries, asks the same question)
	 */
	public const ROOT_OWNERS = [
		'wordfence-waf.php' => ['wordfence'],
	];
	
	/**
	 * The security plugins whose presence answers a posture question — a
	 * login rate limit, a second factor, an upload scanner — by slug among
	 * the ACTIVE plugins. The console prints the gap where none is found:
	 * these are commodity features the plugin deliberately does not
	 * re-implement (docs/plans/wordpress-cyberprotection-brainstorm.md).
	 */
	protected const PROTECTION = [
		'login_protection' => ['limit-login-attempts-reloaded', 'wordfence', 'better-wp-security', 'ithemes-security-pro',
			'all-in-one-wp-security-and-firewall', 'wp-cerber', 'loginizer', 'wp-simple-firewall', 'ninjafirewall',
			'sucuri-scanner', 'login-lockdown', 'wp-limit-login-attempts', 'limit-login-attempts', 'malcare-security',
			'security-malware-firewall', 'defender-security'],
		'two_factor' => ['two-factor', 'wp-2fa', 'miniorange-2-factor-authentication', 'google-authenticator',
			'two-factor-authentication', 'duo-wordpress', 'wordfence', 'better-wp-security', 'ithemes-security-pro',
			'all-in-one-wp-security-and-firewall', 'wp-simple-firewall', 'defender-security'],
		'upload_scanner' => ['wordfence', 'ninjafirewall', 'wp-cerber', 'sucuri-scanner', 'malcare-security',
			'wp-simple-firewall', 'security-malware-firewall', 'defender-security', 'antivirus', 'gotmls'],
	];
	
	/**
	 * Area roots for the pass in progress — set from the state on every
	 * advance() so the helpers can classify without threading the array
	 *
	 * @var array<string, string>
	 */
	protected array $roots = [];
	
	protected ?string $host = null;
	
	protected ?Checksums $sums = null;
	
	/** the core list for this request, loaded once; false = unavailable this pass */
	protected array|false|null $coreList = null;
	
	protected int $fetchLimit = self::FETCHES_BACKGROUND;
	
	public function __construct(
		protected Config $config,
	)
	{
	}
	
	/**
	 * A fresh pass: the phase list, empty counters, no position yet — and
	 * the plugin versions the checksum lists are keyed by
	 */
	public function start(
		string $mode,
	): array
	{
		$roots = $this->roots();
		
		$phases = [['root', $roots['root'], false, []]];
		
		if($roots['uploads'] !== '' && is_dir($roots['uploads']))
		{
			$phases[] = ['uploads', $roots['uploads'], true, []];
		}
		
		$phases[] = ['content', $roots['content'], false, []];
		
		if(is_dir($roots['mu']))
		{
			$phases[] = ['content', $roots['mu'], true, ['mu' => true]];
		}
		
		$phases[] = ['plugins', $roots['plugins'], true, []];
		$phases[] = ['core', $roots['root'] . '/wp-admin', true, []];
		$phases[] = ['core', $roots['root'] . '/wp-includes', true, []];
		$phases[] = ['themes', $roots['themes'], true, []];
		$phases[] = [Database::AREA, '', false, []];
		$phases[] = ['posture', '', false, []];
		
		$areas = [];
		
		foreach(self::AREAS as $area)
		{
			$areas[$area] = [
				'root' => match($area)
				{
					'uploads' => $roots['uploads'],
					'content' => $roots['content'],
					'plugins' => $roots['plugins'],
					'themes' => $roots['themes'],
					Database::AREA => '',
					default => $roots['root'],
				},
				'files' => 0,
				'dirs' => 0,
				'executable' => 0,
				'bytes' => 0,
				'probed' => 0,
				'verified' => 0,
				'modified' => 0,
				'foreign' => 0,
				'missing' => 0,
			];
		}
		
		return [
			'id' => bin2hex(random_bytes(8)),
			'mode' => $mode,
			'started' => time(),
			'elapsed' => 0,
			'chunks' => 0,
			'roots' => $roots,
			'phases' => $phases,
			'phase' => 0,
			'opened' => false,
			'stack' => [],
			'yield' => false,
			'areas' => $areas,
			'findings' => [],
			'counts' => [self::TIER_URGENT => 0, self::TIER_HIGH => 0, self::TIER_INFO => 0],
			'truncated' => [self::TIER_URGENT => 0, self::TIER_HIGH => 0, self::TIER_INFO => 0],
			'polish' => ['dir_changed' => 0, 'owner_anomaly' => 0, 'symlink_outside' => 0],
			'skipped' => [],
			'unreadable' => 0,
			'symlinks' => 0,
			'vcs' => [],
			'uploads_htaccess' => false,
			'uploads_php_denied' => false,
			'versions' => $this->pluginVersions(),
			'core_version' => Inventory::version((string)get_bloginfo('version')),
			'locale' => function_exists('get_locale') ? (string)get_locale() : 'en_US',
			'checksums' => [
				'core' => 'pending',
				'core_locale' => '',
				'plugins' => [],
			],
			'posture' => null,
			'done' => false,
		];
	}
	
	/**
	 * Spend up to $budgetMs on the pass and hand the position back. A
	 * directory is the unit of work: the budget is checked between
	 * directories, so one enormous flat directory may overrun it once. A
	 * checksum list the chunk may not fetch any more YIELDS: the directory
	 * goes back on the stack and the next request continues there.
	 */
	public function advance(
		array $state,
		int $budgetMs,
	): array
	{
		$this->roots = $state['roots'];
		$this->fetchLimit = ($state['mode'] ?? '') === 'manual' ? self::FETCHES_MANUAL : self::FETCHES_BACKGROUND;
		$this->sums ??= new Checksums(($state['mode'] ?? '') === 'manual' ? 4 : 2);
		$this->sums->fetches = 0;
		$this->coreList = null;
		
		$begun = microtime(true);
		$deadline = $begun + $budgetMs / 1000;
		$state['chunks']++;
		$state['yield'] = false;
		
		while($state['done'] === false && microtime(true) < $deadline)
		{
			if($state['phase'] >= count($state['phases']))
			{
				$state['done'] = true;
				
				break;
			}
			
			[$area, $dir, $recursive, $flags] = $state['phases'][$state['phase']];
			
			if($area === 'posture')
			{
				$this->posture($state);
				$state['phase']++;
				
				continue;
			}
			
			if($area === Database::AREA)
			{
				$this->database($state);
				$state['phase']++;
				
				continue;
			}
			
			// the areas the core list vouches for wait for it — one fetch,
			// once per month, and never past this chunk's fetch budget
			if(in_array($area, ['root', 'core', 'themes'], true) && $this->ensureCore($state) === false)
			{
				break;
			}
			
			if($state['opened'] === false)
			{
				$state['stack'] = is_dir($dir)
					? [[$area, $dir, $flags + ['recursive' => $recursive]]]
					: [];
				$state['opened'] = true;
			}
			
			if($state['stack'] === [])
			{
				$state['phase']++;
				$state['opened'] = false;
				
				continue;
			}
			
			[$area, $dir, $flags] = array_pop($state['stack']);
			
			$this->visit($state, $area, $dir, $flags);
			
			if($state['yield'])
			{
				$state['yield'] = false;
				
				break;
			}
		}
		
		$state['elapsed'] += (int)round((microtime(true) - $begun) * 1000);
		
		return $state;
	}
	
	/**
	 * A human-readable position for a progress line: the phase's area and
	 * the files counted so far
	 */
	public static function progress(
		array $state,
	): array
	{
		$phase = $state['phases'][$state['phase']] ?? null;
		$files = 0;
		
		foreach($state['areas'] as $area)
		{
			$files += (int)$area['files'];
		}
		
		return [
			'area' => $phase === null ? '' : (string)$phase[0],
			'files' => $files,
			'findings' => count($state['findings']),
		];
	}
	
	/**
	 * The report — what the console ingests and what wp-admin shows. Area
	 * roots are absolute (the console already knows server paths from
	 * every error's context.dir); finding paths are relative to their area.
	 */
	public function report(
		array $state,
		string $client,
	): array
	{
		$areas = [];
		$files = 0;
		$dirs = 0;
		
		foreach($state['areas'] as $area => $stats)
		{
			$entry = ['root' => $this->clean((string)$stats['root'])];
			
			foreach($stats as $key => $value)
			{
				if($key !== 'root')
				{
					$entry[$key] = (int)$value;
				}
			}
			
			$areas[$area] = $entry;
			$files += (int)$stats['files'];
			$dirs += (int)$stats['dirs'];
		}
		
		$verified = [];
		$unavailable = [];
		
		foreach((array)($state['checksums']['plugins'] ?? []) as $slug => $word)
		{
			if($word === 'verified')
			{
				$verified[] = (string)$slug;
			}
			elseif($word === 'unavailable')
			{
				$unavailable[] = (string)$slug;
			}
		}
		
		$core = (string)($state['checksums']['core'] ?? 'skipped');
		
		$report = [
			'v' => 1,
			'type' => 'files',
			'platform' => 'wordpress',
			'core' => Inventory::version((string)get_bloginfo('version')),
			'php' => Inventory::version(PHP_VERSION),
			'client' => $client,
			'scan' => [
				'id' => (string)$state['id'],
				'mode' => (string)$state['mode'],
				'started' => (int)$state['started'],
				'finished' => time(),
				'duration' => (int)$state['elapsed'],
				'chunks' => (int)$state['chunks'],
				'complete' => (bool)$state['done'],
				'files' => $files,
				'dirs' => $dirs,
				'unreadable' => (int)$state['unreadable'],
				'symlinks' => (int)$state['symlinks'],
				'skipped' => $state['skipped'],
				'counts' => $state['counts'],
				'truncated' => $state['truncated'],
			],
			'checksums' => [
				'core' => $core === 'pending' ? 'skipped' : $core,
				'core_locale' => (string)($state['checksums']['core_locale'] ?? ''),
				'plugins_verified' => $verified,
				'plugins_unavailable' => $unavailable,
			],
			'areas' => $areas,
			'findings' => $state['findings'],
			'posture' => $state['posture'] ?? [],
		];
		
		$release = $this->config->release();
		
		if($release !== '')
		{
			$report['release'] = $release;
		}
		
		$environment = $this->config->environment();
		
		if($environment !== '')
		{
			$report['environment'] = $environment;
		}
		
		return $report;
	}
	
	/**
	 * One directory: files inspected, subdirectories pushed. The root area
	 * lists its files only (wp-admin and wp-includes are the core area's);
	 * the wp-content top level classifies each subdirectory instead of
	 * descending blindly. A plugin's top directory first makes sure its
	 * checksum list is known — or yields the chunk to fetch it next time.
	 */
	protected function visit(
		array &$state,
		string $area,
		string $dir,
		array $flags,
	): void
	{
		if($area === 'plugins' && dirname($dir) === $this->roots['plugins']
			&& $this->ensurePlugin($state, basename($dir)) === false)
		{
			$state['stack'][] = [$area, $dir, $flags];
			$state['yield'] = true;
			
			return;
		}
		
		$entries = @scandir($dir, SCANDIR_SORT_NONE);
		
		if($entries === false)
		{
			$state['unreadable']++;
			
			return;
		}
		
		$state['areas'][$area]['dirs']++;
		
		$top = $area === 'content' && $dir === $this->roots['content'];
		$recursive = (bool)($flags['recursive'] ?? false);
		$names = [];
		$newest = 0;
		$owners = [];
		
		foreach($entries as $name)
		{
			if($name === '.' || $name === '..')
			{
				continue;
			}
			
			$path = $dir . '/' . $name;
			$names[$name] = true;
			
			if(@is_link($path))
			{
				$this->inspectSymlink($state, $area, $path);
				
				continue;
			}
			
			if(@is_dir($path))
			{
				if(in_array($name, self::SKIP_DIRS, true))
				{
					if($area === 'root' && $name !== 'node_modules')
					{
						$state['vcs'][] = $name;
					}
					
					$this->skip($state, $area, $path);
					
					continue;
				}
				
				if($top)
				{
					$this->classifyContentDir($state, $path, $name);
					
					continue;
				}
				
				if($recursive === false)
				{
					continue;
				}
				
				$child = $flags;
				
				if($name[0] === '.')
				{
					$child['hidden'] = true;
				}
				
				$state['stack'][] = [$area, $path, $child];
				
				continue;
			}
			
			$stat = $this->inspect($state, $area, $path, $name, $flags);
			
			if($stat !== null)
			{
				$newest = max($newest, (int)$stat['mtime']);
				$owners[(int)$stat['uid']][] = $name;
			}
		}
		
		$this->missing($state, $area, $dir, $names);
		$this->dirChanged($state, $area, $dir, $newest, count($owners) > 0);
		$this->ownerAnomaly($state, $area, $dir, $owners);
	}
	
	/**
	 * A wp-content subdirectory: the four areas walked on their own are
	 * skipped here, caches and upgrade staging are skipped whole, a
	 * plugin-owned data directory is one finding and never descended,
	 * anything else is walked as content — where executable code is a
	 * stranger.
	 */
	protected function classifyContentDir(
		array &$state,
		string $path,
		string $name,
	): void
	{
		if(in_array($path, [$this->roots['plugins'], $this->roots['themes'],
			$this->roots['uploads'], $this->roots['mu']], true))
		{
			return;
		}
		
		if(in_array($name, self::CONTENT_SKIP, true))
		{
			$this->skip($state, 'content', $path);
			
			return;
		}
		
		if(isset(self::WRITER_DIRS[$name]))
		{
			$owner = $this->installedOwner(self::WRITER_DIRS[$name]);
			
			$this->finding($state, 'content', $path,
				$owner !== null ? 'writer_dir' : 'writer_dir_orphan',
				$owner !== null ? self::TIER_INFO : self::TIER_HIGH,
				$owner !== null
					? 'owned by ' . $owner . ', not scanned'
					: 'owner not installed: ' . implode(', ', self::WRITER_DIRS[$name]));
			
			return;
		}
		
		$flags = ['recursive' => true];
		
		if($name[0] === '.')
		{
			$flags['hidden'] = true;
		}
		
		$state['stack'][] = ['content', $path, $flags];
	}
	
	/**
	 * One file: counted, then shape-checked — executable names by area,
	 * directive files by content, media names for a PHP opener. Answers the
	 * stat so the directory can date itself and compare owners.
	 *
	 * @return array{size: int, mtime: int, uid: int}|null
	 */
	protected function inspect(
		array &$state,
		string $area,
		string $path,
		string $name,
		array $flags,
	): ?array
	{
		$stat = @stat($path);
		$size = $stat !== false ? (int)$stat['size'] : 0;
		$mtime = $stat !== false ? (int)$stat['mtime'] : 0;
		$uid = $stat !== false ? (int)$stat['uid'] : 0;
		
		$state['areas'][$area]['files']++;
		$state['areas'][$area]['bytes'] += $size;
		
		$meta = ['size' => $size, 'mtime' => $mtime];
		$lower = strtolower($name);
		$answer = $stat === false ? null : ['size' => $size, 'mtime' => $mtime, 'uid' => $uid];
		
		if(preg_match(self::EXECUTABLE, $name) === 1)
		{
			$state['areas'][$area]['executable']++;
			
			$this->inspectExecutable($state, $area, $path, $name, $size, $flags, $meta);
			
			return $answer;
		}
		
		if(in_array($lower, self::DIRECTIVE_FILES, true))
		{
			$this->inspectDirectives($state, $area, $path, $meta);
			
			return $answer;
		}
		
		$this->inspectPolyglot($state, $area, $path, $lower, $size, $meta);
		
		return $answer;
	}
	
	/**
	 * Executable-shaped, judged by where it stands. Hidden anywhere is a
	 * finding; under uploads anything but a listing stub is; in the root
	 * anything core did not ship is; at the wp-content top level a drop-in
	 * is judged by its owner and anything else is a stranger; in plugins,
	 * themes and core the checksum list is the judge where one exists.
	 */
	protected function inspectExecutable(
		array &$state,
		string $area,
		string $path,
		string $name,
		int $size,
		array $flags,
		array $meta,
	): void
	{
		if(($flags['hidden'] ?? false) === true || $name[0] === '.')
		{
			if(preg_match(self::HIDDEN_TOOLING, $name) !== 1)
			{
				$this->finding($state, $area, $path, 'hidden_php', self::TIER_HIGH, '', $meta);
			}
			
			return;
		}
		
		switch($area)
		{
			case 'uploads':
				if($this->isStub($path, $size) === false)
				{
					$this->finding($state, $area, $path, 'uploads_php', self::TIER_URGENT, '', $meta);
				}
				
				return;
			
			case 'root':
				if(in_array($name, Sender::CORE_ROOT_FILES, true))
				{
					// compared when listed; wp-config.php is core's own root file
					// the list never carries, and nothing else can stand here
					// without being root_php already
					$this->verify($state, $area, $path, $name, $meta, 'core', null, false);
					
					return;
				}
				
				$owner = isset(self::ROOT_OWNERS[$name])
					? $this->installedOwner(self::ROOT_OWNERS[$name])
					: null;
				
				$this->finding($state, $area, $path,
					$owner !== null ? 'root_php_owned' : 'root_php',
					$owner !== null ? self::TIER_INFO : self::TIER_URGENT,
					$owner !== null ? 'owned by ' . $owner : '', $meta);
				
				return;
			
			case 'content':
				$this->inspectContentExecutable($state, $path, $name, $size, $flags, $meta);
				
				return;
			
			case 'core':
				$this->verify($state, $area, $path, $this->relative($path, $this->roots['root']), $meta, 'core');
				
				return;
			
			case 'plugins':
				$this->verifyInside($state, $path, $meta);
				
				return;
				
			case 'themes':
				// no list vouches for a theme: wp.org has no theme checksums, and
				// the core list's bundled themes are the VERSIONS shipped with that
				// core release, which the theme updater has long since replaced
				return;
			
			default:
				return;
		}
	}
	
	protected function inspectContentExecutable(
		array &$state,
		string $path,
		string $name,
		int $size,
		array $flags,
		array $meta,
	): void
	{
		$parent = dirname($path);
		
		if(($flags['mu'] ?? false) === true)
		{
			// only the top level of mu-plugins is loaded; deeper files are
			// its includes and belong to the file that requires them
			if($parent === $this->roots['mu'])
			{
				$this->finding($state, 'content', $path, 'mu_plugin', self::TIER_INFO, '', $meta);
			}
			
			return;
		}
		
		if($parent !== $this->roots['content'])
		{
			// core's PHP translation files live under languages/ and its
			// plugins/ and themes/ subdirectories, named for their text domain
			// and locale; anything else executable there is a stranger
			$translation = str_starts_with($path, $this->roots['content'] . '/languages/')
				&& preg_match(self::TRANSLATION, $name) === 1;
			
			if($translation === false && $this->isStub($path, $size) === false)
			{
				$this->finding($state, 'content', $path, 'content_php', self::TIER_HIGH, '', $meta);
			}
			
			return;
		}
		
		if($name === 'index.php' && $this->isStub($path, $size))
		{
			return;
		}
		
		if(isset(self::CONTENT_OWNERS[$name]))
		{
			$owner = $this->installedOwner(self::CONTENT_OWNERS[$name]);
			
			if($owner !== null)
			{
				$this->finding($state, 'content', $path, 'dropin', self::TIER_INFO,
					'owned by ' . $owner, $meta);
				
				return;
			}
			
			// managed hosts drop their own object-cache.php with a vendor
			// header and no plugin behind it; a header is not proof, but a
			// drop-in WITHOUT one and without an owner is the stranger
			$this->finding($state, 'content', $path,
				$this->looksVendored($path) ? 'dropin' : 'dropin_orphan',
				$this->looksVendored($path) ? self::TIER_INFO : self::TIER_HIGH,
				'no installed owner', $meta);
			
			return;
		}
		
		if(in_array($name, Sender::CONTENT_DROPINS, true))
		{
			// install.php runs core's installer hooks and has no business on
			// a live site; the rest (maintenance, error pages, sunrise) are
			// hand-written by design and only listed
			$this->finding($state, 'content', $path, 'dropin',
				$name === 'install.php' ? self::TIER_HIGH : self::TIER_INFO,
				$name === 'install.php' ? 'install drop-in on a live site' : '', $meta);
			
			return;
		}
		
		$this->finding($state, 'content', $path, 'content_php', self::TIER_HIGH, '', $meta);
	}
	
	/**
	 * A file under a root wordpress.org vouches for, against a list: listed
	 * and equal → verified; listed and different → MODIFIED; not listed →
	 * FOREIGN — the two verdicts with authority behind them. With no list
	 * this pass, nothing is said.
	 *
	 * @param string $key the list's own path for the file
	 * @param string $kind core|plugin|theme — the detector family and its tier
	 * @param array<string, string>|null $list the plugin's own list; null = core's
	 */
	protected function verify(
		array &$state,
		string $area,
		string $path,
		string $key,
		array $meta,
		string $kind,
		?array $list = null,
		bool $foreignIsFinding = true,
	): void
	{
		$list ??= $this->coreList($state);
		
		if(is_array($list) === false)
		{
			return;
		}
		
		$tier = $kind === 'core' ? self::TIER_URGENT : self::TIER_HIGH;
		
		if(isset($list[$key]) === false)
		{
			if($foreignIsFinding === false)
			{
				return;
			}
			
			$state['areas'][$area]['foreign']++;
			
			$this->finding($state, $area, $path, $kind . '_foreign', $tier,
				'not in the wordpress.org list for this version', $meta);
			
			return;
		}
		
		$md5 = @md5_file($path);
		
		if($md5 === false)
		{
			return;
		}
		
		if(strtolower($md5) === $list[$key])
		{
			$state['areas'][$area]['verified']++;
			
			return;
		}
		
		$state['areas'][$area]['modified']++;
		
		$this->finding($state, $area, $path, $kind . '_modified', $tier,
			'md5 differs from the wordpress.org list for this version', $meta);
	}
	
	/**
	 * A file inside a plugin directory, against the plugin's own wp.org list
	 * where one exists. A single-file plugin (hello.php) has no directory to
	 * key a list by and updates apart from core, so it is not verified; a
	 * premium or custom plugin has no list and is not judged either.
	 */
	protected function verifyInside(
		array &$state,
		string $path,
		array $meta,
	): void
	{
		$relative = $this->relative($path, $this->roots['plugins']);
		$slash = strpos($relative, '/');
		
		if($slash === false)
		{
			return;
		}
		
		$slug = substr($relative, 0, $slash);
		
		if(($state['checksums']['plugins'][$slug] ?? '') !== 'verified')
		{
			return;
		}
		
		$list = $this->sums?->plugin($slug, (string)($state['versions'][$slug] ?? ''));
		
		if($list !== null)
		{
			$this->verify($state, 'plugins', $path, substr($relative, $slash + 1), $meta, 'plugin', $list);
		}
	}
	
	/**
	 * The listed files a directory should hold but does not — counted per
	 * area, never listed: hosts strip readmes, and a missing file is not an
	 * intrusion. Only directories a list speaks for.
	 *
	 * @param array<string, true> $names the entries seen in the directory
	 */
	protected function missing(
		array &$state,
		string $area,
		string $dir,
		array $names,
	): void
	{
		$list = null;
		$directory = '';
		
		if($area === 'core' || $area === 'root')
		{
			$list = $this->coreList($state);
			$directory = $area === 'root' ? '' : $this->relative($dir, $this->roots['root']);
		}
		elseif($area === 'plugins')
		{
			$relative = $this->relative($dir, $this->roots['plugins']);
			$slug = explode('/', $relative, 2)[0];
			
			if($relative !== $slug || $dir !== $this->roots['plugins'])
			{
				if(($state['checksums']['plugins'][$slug] ?? '') === 'verified')
				{
					$list = $this->sums?->plugin($slug, (string)($state['versions'][$slug] ?? ''));
					$directory = $relative === $slug ? '' : substr($relative, strlen($slug) + 1);
				}
			}
		}
		
		if(is_array($list) === false)
		{
			return;
		}
		
		foreach(Checksums::expected($list, $directory) as $name)
		{
			if(isset($names[$name]) === false)
			{
				$state['areas'][$area]['missing']++;
			}
		}
	}
	
	/**
	 * B9 — a directory changed after its newest file: something was deleted
	 * or renamed here recently (the shell the attacker removed, dated).
	 * Uploads and the root only, the last thirty days only, info.
	 */
	protected function dirChanged(
		array &$state,
		string $area,
		string $dir,
		int $newest,
		bool $hasFiles,
	): void
	{
		if(($area !== 'uploads' && $area !== 'root') || $hasFiles === false
			|| $state['polish']['dir_changed'] >= self::MAX_PER_POLISH)
		{
			return;
		}
		
		$stat = @stat($dir);
		$changed = $stat === false ? 0 : (int)$stat['mtime'];
		
		if($changed > $newest + 60 && $changed > time() - self::RECENT_CHANGE)
		{
			$state['polish']['dir_changed']++;
			
			$this->finding($state, $area, $dir === (string)$state['areas'][$area]['root'] ? $dir . '/.' : $dir, 'dir_changed', self::TIER_INFO,
				'directory changed ' . gmdate('Y-m-d H:i', $changed) . ', newest file ' . gmdate('Y-m-d H:i', $newest)
				. ' — something was removed or renamed here', ['mtime' => $changed]);
		}
	}
	
	/**
	 * B11 — a file whose owner differs from its directory's siblings: the
	 * web server wrote among the deploy user's files. Silent on Windows and
	 * on shared hosting, where everything is one uid.
	 *
	 * @param array<int, list<string>> $owners uid → file names
	 */
	protected function ownerAnomaly(
		array &$state,
		string $area,
		string $dir,
		array $owners,
	): void
	{
		if(DIRECTORY_SEPARATOR === '\\' || count($owners) < 2
			|| $state['polish']['owner_anomaly'] >= self::MAX_PER_POLISH)
		{
			return;
		}
		
		$total = 0;
		$majority = 0;
		$majorityUid = 0;
		
		foreach($owners as $uid => $names)
		{
			$total += count($names);
			
			if(count($names) > $majority)
			{
				$majority = count($names);
				$majorityUid = $uid;
			}
		}
		
		if($total < 3)
		{
			return;
		}
		
		foreach($owners as $uid => $names)
		{
			if($uid === $majorityUid)
			{
				continue;
			}
			
			foreach($names as $name)
			{
				if($state['polish']['owner_anomaly'] >= self::MAX_PER_POLISH)
				{
					return;
				}
				
				$state['polish']['owner_anomaly']++;
				
				$this->finding($state, $area, $dir . '/' . $name, 'owner_anomaly', self::TIER_HIGH,
					'owned by uid ' . $uid . ' among files owned by uid ' . $majorityUid);
			}
		}
	}
	
	/**
	 * B12 — a symlink is counted, never followed; one that leaves the site
	 * (another vhost's tree, /etc) is the symlink attack and a finding
	 */
	protected function inspectSymlink(
		array &$state,
		string $area,
		string $path,
	): void
	{
		$state['symlinks']++;
		
		$target = @readlink($path);
		
		if($target === false || $state['polish']['symlink_outside'] >= self::MAX_PER_POLISH)
		{
			return;
		}
		
		$absolute = str_starts_with($target, '/') || preg_match('~^[A-Za-z]:[\\\\/]~', $target) === 1
			? $target
			: dirname($path) . '/' . $target;
		$resolved = @realpath($absolute);
		$resolved = $this->normalize($resolved === false ? $absolute : $resolved);
		
		foreach(['root', 'content', 'uploads'] as $root)
		{
			$prefix = $this->roots[$root];
			
			if($prefix !== '' && ($resolved === $prefix || str_starts_with($resolved, $prefix . '/')))
			{
				return;
			}
		}
		
		$state['polish']['symlink_outside']++;
		
		$this->finding($state, $area, $path, 'symlink_outside', self::TIER_HIGH,
			'symlink leaving the site → ' . $resolved);
	}
	
	/**
	 * A media-shaped name whose first block carries a PHP opener — the
	 * favicon shell, the `.jpg` behind an AddHandler
	 */
	protected function inspectPolyglot(
		array &$state,
		string $area,
		string $path,
		string $lower,
		int $size,
		array $meta,
	): void
	{
		if($size < self::MIN_POLYGLOT_SIZE)
		{
			return;
		}
		
		$dot = strrpos($lower, '.');
		$extension = $dot === false ? '' : substr($lower, $dot + 1);
		
		if(in_array($extension, self::MEDIA, true) === false
			&& ($area !== 'uploads' || in_array($extension, self::MEDIA_TEXT, true) === false))
		{
			return;
		}
		
		$state['areas'][$area]['probed']++;
		
		$head = $this->head($path, self::HEAD_BYTES);
		
		if($head !== null && (str_contains($head, '<?php') || str_contains($head, '<?=')))
		{
			$this->finding($state, $area, $path, 'polyglot', self::TIER_URGENT,
				'PHP opener in a .' . $extension . ' file', $meta);
		}
	}
	
	/**
	 * .htaccess / .user.ini / php.ini: the directives that make a foreign
	 * file execute (a prepend, an image handler, engine on under uploads)
	 * or send visitors elsewhere. The finding names the directive, the file
	 * and the line — never the line's text.
	 */
	protected function inspectDirectives(
		array &$state,
		string $area,
		string $path,
		array $meta,
	): void
	{
		$content = @file_get_contents($path, false, null, 0, self::DIRECTIVE_BYTES);
		
		if(is_string($content) === false)
		{
			return;
		}
		
		$uploads = $area === 'uploads';
		
		if($uploads && dirname($path) === $this->roots['uploads'] && basename($path) === '.htaccess')
		{
			$state['uploads_htaccess'] = true;
			$state['uploads_php_denied'] = $this->deniesPhp($content);
		}
		
		$found = 0;
		
		foreach(preg_split('~\r\n|\r|\n~', $content) ?: [] as $index => $line)
		{
			$line = trim($line);
			
			if($line === '' || $line[0] === '#' || $line[0] === ';')
			{
				continue;
			}
			
			$verdict = $this->judgeDirective($line, $uploads);
			
			if($verdict === null)
			{
				continue;
			}
			
			[$detector, $tier, $detail] = $verdict;
			
			$this->finding($state, $area, $path, $detector, $tier, $detail,
				$meta + ['line' => $index + 1]);
			
			if(++$found >= self::MAX_DIRECTIVES_PER_FILE)
			{
				return;
			}
		}
	}
	
	/**
	 * One directive line → [detector, tier, detail] or null when harmless
	 *
	 * @return array{0: string, 1: string, 2: string}|null
	 */
	protected function judgeDirective(
		string $line,
		bool $uploads,
	): ?array
	{
		if(preg_match('~auto_(prepend|append)_file\s*(?:=|\s)\s*["\']?([^"\'\s;]*)~i', $line, $match) === 1)
		{
			$target = $match[2];
			
			if($target === '' || strtolower($target) === 'none')
			{
				return null;
			}
			
			$owner = $this->ownerOfPath($target);
			
			return $owner !== null
				? ['directive_owned', self::TIER_INFO, 'auto_' . strtolower($match[1]) . '_file owned by ' . $owner]
				: ['directive_prepend', self::TIER_URGENT, 'auto_' . strtolower($match[1]) . '_file → ' . basename($target)];
		}
		
		if(preg_match('~^(?:AddHandler|AddType)\s+(\S*php\S*)\s+(.+)$~i', $line, $match) === 1)
		{
			$foreign = [];
			
			foreach(preg_split('~\s+~', trim($match[2])) ?: [] as $extension)
			{
				if(preg_match('~^\.?(?:php\d?|phtml|phar)$~i', $extension) !== 1)
				{
					$foreign[] = $extension;
				}
			}
			
			return $foreign === []
				? null
				: ['handler_php_extension', self::TIER_URGENT, 'PHP handler for ' . implode(' ', $foreign)];
		}
		
		if(preg_match('~^SetHandler\s+\S*php~i', $line) === 1)
		{
			return ['set_handler_php', $uploads ? self::TIER_URGENT : self::TIER_HIGH, 'SetHandler to PHP'];
		}
		
		if($uploads && preg_match('~^php_(?:admin_)?flag\s+engine\s+on~i', $line) === 1)
		{
			return ['engine_on_uploads', self::TIER_URGENT, 'PHP engine switched on under uploads'];
		}
		
		if($uploads && preg_match('~^(?:Options\b.*\bExecCGI|AddHandler\s+cgi-script)~i', $line) === 1)
		{
			return ['cgi_uploads', self::TIER_HIGH, 'CGI execution under uploads'];
		}
		
		if(preg_match('~^(?:RewriteRule\s+\S+|Redirect(?:Match|Permanent|Temp)?\s+(?:\d{3}\s+)?\S+|ErrorDocument\s+\d{3})\s+["\']?https?://([^/\s"\']+)~i', $line, $match) === 1)
		{
			$host = strtolower($match[1]);
			
			if($this->isForeignHost($host))
			{
				return ['redirect_external', self::TIER_HIGH, 'redirect to ' . $host];
			}
		}
		
		return null;
	}
	
	/**
	 * Whether an uploads .htaccess denies PHP — engine off, or a php
	 * Files/FilesMatch block that denies or unsets the handler
	 */
	protected function deniesPhp(
		string $content,
	): bool
	{
		return preg_match('~php_(?:admin_)?flag\s+engine\s+off~i', $content) === 1
			|| preg_match('~<Files(?:Match)?\s+[^>]*php[^>]*>.*?(?:deny\s+from\s+all|Require\s+all\s+denied|SetHandler\s+(?:none|default-handler))~is', $content) === 1;
	}
	
	/**
	 * The database phase (WS3): the attacker's other filesystem, read by
	 * Database — every finding an id, an option name or a hook, never a
	 * name or a value
	 */
	protected function database(
		array &$state,
	): void
	{
		$result = (new Database)->scan();
		
		foreach($result['findings'] as $finding)
		{
			$this->finding($state, Database::AREA, (string)$finding['path'], (string)$finding['detector'],
				(string)$finding['tier'], (string)($finding['detail'] ?? ''),
				isset($finding['mtime']) ? ['mtime' => (int)$finding['mtime']] : []);
		}
		
		foreach($result['stats'] as $key => $value)
		{
			$state['areas'][Database::AREA][$key] = (int)$value;
		}
	}
	
	/**
	 * The final phase: the site's posture, so the console's advice can say
	 * "and close the door" — plus the one live directive that no file scan
	 * sees, the ini's own auto_prepend_file
	 */
	protected function posture(
		array &$state,
	): void
	{
		$roots = $this->roots;
		$config = $this->configPath($roots['root']);
		$server = $this->server();
		$windows = DIRECTORY_SEPARATOR === '\\';
		
		$debug = defined('WP_DEBUG') && (bool)WP_DEBUG;
		$active = $this->activeSlugs();
		$debugLog = $this->debugLog($roots);
		
		$state['posture'] = [
			'server' => $server,
			'multisite' => function_exists('is_multisite') && is_multisite(),
			'environment' => function_exists('wp_get_environment_type') ? (string)wp_get_environment_type() : '',
			'file_edit_disabled' => defined('DISALLOW_FILE_EDIT') && (bool)DISALLOW_FILE_EDIT,
			'file_mods_disabled' => defined('DISALLOW_FILE_MODS') && (bool)DISALLOW_FILE_MODS,
			'debug' => $debug,
			'debug_display' => $debug && (defined('WP_DEBUG_DISPLAY') === false || (bool)WP_DEBUG_DISPLAY),
			'auto_update_core' => defined('WP_AUTO_UPDATE_CORE') ? $this->constantWord(WP_AUTO_UPDATE_CORE) : null,
			'updater_disabled' => defined('AUTOMATIC_UPDATER_DISABLED') && (bool)AUTOMATIC_UPDATER_DISABLED,
			'users_can_register' => (bool)get_option('users_can_register'),
			'default_role' => Inventory::slugOf((string)get_option('default_role')),
			'xmlrpc' => (bool)apply_filters('xmlrpc_enabled', true),
			'config_world_readable' => $config !== null && $windows === false ? $this->permits($config, 0004) : null,
			'uploads_world_writable' => $roots['uploads'] !== '' && $windows === false ? $this->permits($roots['uploads'], 0002) : null,
			'uploads_htaccess' => (bool)$state['uploads_htaccess'],
			'uploads_php_denied' => in_array($server, ['apache', 'litespeed'], true) ? (bool)$state['uploads_php_denied'] : null,
			'vcs_exposed' => $state['vcs'],
			'readme_html' => is_file($roots['root'] . '/readme.html'),
			'login_protection' => $this->protection('login_protection', $active),
			'two_factor' => $this->protection('two_factor', $active),
			'upload_scanner' => $this->protection('upload_scanner', $active),
			'debug_log' => $debugLog !== null,
			'ini' => [
				'auto_prepend_file' => $this->clean((string)ini_get('auto_prepend_file')),
				'auto_append_file' => $this->clean((string)ini_get('auto_append_file')),
				'user_ini_filename' => $this->clean((string)ini_get('user_ini.filename')),
				'open_basedir' => $this->clean((string)ini_get('open_basedir')),
				'disable_functions' => $this->clean((string)ini_get('disable_functions')),
				'display_errors' => $this->clean((string)ini_get('display_errors')),
				'expose_php' => (bool)ini_get('expose_php'),
				'allow_url_include' => (bool)ini_get('allow_url_include'),
				'opcache' => (bool)ini_get('opcache.enable'),
			],
		];
		
		if($debugLog !== null)
		{
			// WP_DEBUG_LOG on a production site: the log leaks paths, queries
			// and stack traces to anyone who asks for it by URL
			$stat = @stat($debugLog);
			
			$this->finding($state, str_starts_with($debugLog, $roots['content'] . '/') ? 'content' : 'root', $debugLog,
				'debug_log_public', self::TIER_HIGH,
				'WP_DEBUG_LOG writes a web-reachable file' . ($stat === false ? '' : ' (' . (int)round((int)$stat['size'] / 1024) . ' KB)'),
				$stat === false ? [] : ['size' => (int)$stat['size'], 'mtime' => (int)$stat['mtime']]);
		}
		
		foreach(['auto_prepend_file', 'auto_append_file'] as $key)
		{
			$target = trim((string)ini_get($key));
			
			if($target === '' || strtolower($target) === 'none')
			{
				continue;
			}
			
			$owner = $this->ownerOfPath($target);
			
			$this->finding($state, 'root', $this->normalize($target),
				$owner !== null ? 'ini_prepend_owned' : 'ini_prepend',
				$owner !== null ? self::TIER_INFO : self::TIER_URGENT,
				$key . ($owner !== null ? ' owned by ' . $owner : ' is live in php.ini'));
		}
	}
	
	/**
	 * The core list for this pass, fetched once the chunk's budget allows:
	 * true when the phase may go on (list known, or known to be
	 * unavailable), false when the chunk must yield for the fetch
	 */
	protected function ensureCore(
		array &$state,
	): bool
	{
		if(($state['checksums']['core'] ?? 'pending') !== 'pending')
		{
			return true;
		}
		
		$version = (string)$state['core_version'];
		$locale = (string)$state['locale'];
		
		if($this->sums === null || $version === '')
		{
			$state['checksums']['core'] = 'unavailable';
			
			return true;
		}
		
		if($this->sums->coreCached($version, $locale) === false && $this->sums->fetches >= $this->fetchLimit)
		{
			return false;
		}
		
		$list = $this->sums->core($version, $locale);
		$state['checksums']['core'] = $list === null ? 'unavailable' : 'verified';
		$state['checksums']['core_locale'] = $list === null ? '' : $locale;
		
		return true;
	}
	
	/**
	 * The core list, loaded once per request; false when this pass has none
	 */
	protected function coreList(
		array $state,
	): array|false
	{
		if($this->coreList !== null)
		{
			return $this->coreList;
		}
		
		if(($state['checksums']['core'] ?? '') !== 'verified' || $this->sums === null)
		{
			return $this->coreList = false;
		}
		
		$list = $this->sums->core((string)$state['core_version'],
			(string)(($state['checksums']['core_locale'] ?? '') !== '' ? $state['checksums']['core_locale'] : $state['locale']));
		
		return $this->coreList = $list ?? false;
	}
	
	/**
	 * A plugin's list: known (the state remembers verified/unavailable per
	 * slug), or fetched now within the chunk's budget — false when the
	 * chunk must yield for it. A plugin without a version header, or one
	 * wp.org never had, is simply unverified.
	 */
	protected function ensurePlugin(
		array &$state,
		string $slug,
	): bool
	{
		if(isset($state['checksums']['plugins'][$slug]))
		{
			return true;
		}
		
		$version = (string)($state['versions'][$slug] ?? '');
		
		if($this->sums === null || $version === '' || Inventory::slugOf($slug) !== $slug)
		{
			$state['checksums']['plugins'][$slug] = 'unavailable';
			
			return true;
		}
		
		if($this->sums->pluginCached($slug, $version) === false && $this->sums->fetches >= $this->fetchLimit)
		{
			return false;
		}
		
		$state['checksums']['plugins'][$slug] = $this->sums->plugin($slug, $version) === null ? 'unavailable' : 'verified';
		
		return true;
	}
	
	/**
	 * Every installed plugin's version by directory slug — the key wp.org's
	 * lists are kept under. A single-file plugin has no directory and is the
	 * core list's business (hello.php).
	 *
	 * @return array<string, string>
	 */
	public function pluginVersions(): array
	{
		if(function_exists('get_plugins') === false)
		{
			if(defined('ABSPATH') && is_file(ABSPATH . 'wp-admin/includes/plugin.php'))
			{
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			
			if(function_exists('get_plugins') === false)
			{
				return [];
			}
		}
		
		$versions = [];
		
		foreach((array)get_plugins() as $file => $headers)
		{
			$directory = dirname((string)$file);
			
			if($directory === '.' || $directory === '')
			{
				continue;
			}
			
			$versions[$directory] ??= Inventory::version((string)($headers['Version'] ?? ''));
		}
		
		return $versions;
	}
	
	/**
	 * Record one finding, or count it once the report is full. The path is
	 * relative to its area root (absolute when it stands outside, as an ini
	 * target may) and always cleaned: it is attacker-authored.
	 */
	protected function finding(
		array &$state,
		string $area,
		string $path,
		string $detector,
		string $tier,
		string $detail = '',
		array $meta = [],
	): void
	{
		$state['counts'][$tier]++;
		
		if(count($state['findings']) >= self::MAX_FINDINGS)
		{
			$state['truncated'][$tier]++;
			
			return;
		}
		
		$finding = [
			'detector' => $detector,
			'tier' => $tier,
			'area' => $area,
			'path' => $this->clean($this->relative($path, (string)$state['areas'][$area]['root'])),
		];
		
		if(isset($meta['size']))
		{
			$finding['size'] = (int)$meta['size'];
		}
		
		if(isset($meta['mtime']))
		{
			$finding['mtime'] = (int)$meta['mtime'];
		}
		
		if(isset($meta['line']))
		{
			$finding['line'] = (int)$meta['line'];
		}
		
		if($detail !== '')
		{
			$finding['detail'] = $this->clean($detail, self::MAX_DETAIL);
		}
		
		$state['findings'][] = $finding;
	}
	
	protected function skip(
		array &$state,
		string $area,
		string $path,
	): void
	{
		if(count($state['skipped']) < self::MAX_SKIPPED)
		{
			$state['skipped'][] = $area . ':'
				. $this->clean($this->relative($path, (string)$state['areas'][$area]['root']));
		}
	}
	
	/**
	 * The first installed owner of a plugin-written path — plugin slugs, or
	 * `theme:<dir>` — as a label, or null
	 *
	 * @param string[] $owners
	 */
	protected function installedOwner(
		array $owners,
	): ?string
	{
		foreach($owners as $owner)
		{
			[$type, $slug] = str_contains($owner, ':') ? explode(':', $owner, 2) : ['plugin', $owner];
			$root = $type === 'theme' ? $this->roots['themes'] : $this->roots['plugins'];
			
			if($slug !== '' && is_dir($root . '/' . $slug))
			{
				return $owner;
			}
		}
		
		return null;
	}
	
	/**
	 * Who owns an arbitrary path a directive points at: a file inside an
	 * installed plugin's directory, or a known root file whose plugin is
	 * installed (Wordfence's prepend), or this plugin's own prepend stub in
	 * its store directory (wp-content/ovos-codesafe/, or ovos-console/ under its
	 * first name; ovos/console docs/plans/shield-prepend.md) while the plugin is
	 * installed. Anything else is
	 * nobody's.
	 */
	protected function ownerOfPath(
		string $target,
	): ?string
	{
		$target = $this->normalize($target);
		$name = basename($target);
		
		// wp-content/ovos-console/ is the same directory under the plugin's first
		// name: its stub may still be what PHP prepends, and runs this plugin
		if((str_starts_with($target, $this->roots['content'] . '/ovos-codesafe/') || str_starts_with($target, $this->roots['content'] . '/ovos-console/'))
			&& (is_dir($this->roots['plugins'] . '/ovos-codesafe') || is_dir($this->roots['mu'] . '/ovos-codesafe')))
		{
			return 'plugin:ovos-codesafe';
		}
		
		if(isset(self::ROOT_OWNERS[$name]))
		{
			$owner = $this->installedOwner(self::ROOT_OWNERS[$name]);
			
			if($owner !== null)
			{
				return $owner;
			}
		}
		
		foreach(['plugins' => 'plugin', 'mu' => 'mu-plugin'] as $root => $type)
		{
			$prefix = $this->roots[$root] . '/';
			
			if(str_starts_with($target, $prefix))
			{
				$slug = explode('/', substr($target, strlen($prefix)), 2)[0];
				
				if($slug !== '' && (is_dir($prefix . $slug) || is_file($prefix . $slug)))
				{
					return $type . ':' . $slug;
				}
			}
		}
		
		return null;
	}
	
	/**
	 * Whether a redirect target leaves the site — hosts compared without a
	 * leading www., so a move between the two spellings is not a finding
	 */
	protected function isForeignHost(
		string $host,
	): bool
	{
		$this->host ??= $this->siteHost();
		
		$strip = static fn(string $value): string => preg_replace('~^www\.~', '', strtolower(explode(':', $value, 2)[0])) ?? '';
		
		return $this->host !== '' && $strip($host) !== $strip($this->host);
	}
	
	protected function siteHost(): string
	{
		if(function_exists('home_url') === false)
		{
			return '';
		}
		
		$host = wp_parse_url((string)home_url(), PHP_URL_HOST);
		
		return is_string($host) ? $host : '';
	}
	
	public function isStub(
		string $path,
		int $size,
	): bool
	{
		if($size === 0)
		{
			return true;
		}
		
		if($size > self::STUB_BYTES)
		{
			return false;
		}
		
		$head = $this->head($path, self::STUB_BYTES);
		
		return $head !== null && preg_match(self::STUB, $head) === 1;
	}
	
	/**
	 * A drop-in that carries a vendor header — plugin headers, package
	 * tags, a copyright or licence line — in its first kilobyte
	 */
	protected function looksVendored(
		string $path,
	): bool
	{
		$head = $this->head($path, self::HEAD_BYTES);
		
		return $head !== null
			&& preg_match('~Plugin Name:|@package|@author|Copyright|License|Version:~i', $head) === 1;
	}
	
	protected function head(
		string $path,
		int $bytes,
	): ?string
	{
		$handle = @fopen($path, 'rb');
		
		if($handle === false)
		{
			return null;
		}
		
		$head = @fread($handle, $bytes);
		fclose($handle);
		
		return is_string($head) ? $head : null;
	}
	
	protected function permits(
		string $path,
		int $bit,
	): ?bool
	{
		$perms = @fileperms($path);
		
		return $perms === false ? null : ($perms & $bit) !== 0;
	}
	
	/**
	 * wp-config.php stands in ABSPATH or, by core's own convention, one
	 * level above it
	 */
	protected function configPath(
		string $root,
	): ?string
	{
		foreach([$root . '/wp-config.php', dirname($root) . '/wp-config.php'] as $candidate)
		{
			if(is_file($candidate))
			{
				return $candidate;
			}
		}
		
		return null;
	}
	
	/**
	 * The active plugins' slugs — directory names, or the file name of a
	 * single-file plugin — network-activated ones included
	 *
	 * @return list<string>
	 */
	protected function activeSlugs(): array
	{
		$files = (array)get_option('active_plugins', []);
		
		if(function_exists('is_multisite') && is_multisite())
		{
			foreach((array)get_option('active_sitewide_plugins', []) as $file => $time)
			{
				$files[] = $file;
			}
		}
		
		$slugs = [];
		
		foreach($files as $file)
		{
			if(is_string($file) === false)
			{
				continue;
			}
			
			$directory = dirname($file);
			$slugs[] = $directory === '.' || $directory === '' ? basename($file, '.php') : $directory;
		}
		
		return $slugs;
	}
	
	/**
	 * The first active plugin that answers a protection question, '' when
	 * none does. Jetpack counts for the login question only with its
	 * Protect module on.
	 *
	 * @param list<string> $active
	 */
	protected function protection(
		string $kind,
		array $active,
	): string
	{
		foreach(self::PROTECTION[$kind] ?? [] as $slug)
		{
			if(in_array($slug, $active, true))
			{
				return $slug;
			}
		}
		
		if($kind === 'login_protection' && in_array('jetpack', $active, true)
			&& class_exists('Jetpack') && method_exists('Jetpack', 'is_module_active') && \Jetpack::is_module_active('protect'))
		{
			return 'jetpack';
		}
		
		return '';
	}
	
	/**
	 * The debug log's path when WP_DEBUG_LOG writes one UNDER the document
	 * root and the file exists — the leak; null when logging is off, the
	 * file is absent, or it lives outside the site where it belongs
	 */
	protected function debugLog(
		array $roots,
	): ?string
	{
		if(defined('WP_DEBUG_LOG') === false || (bool)WP_DEBUG_LOG === false)
		{
			return null;
		}
		
		$path = is_string(WP_DEBUG_LOG) && WP_DEBUG_LOG !== '' ? WP_DEBUG_LOG : $roots['content'] . '/debug.log';
		$path = $this->normalize($path);
		
		return is_file($path) && str_starts_with($path, $roots['root'] . '/') ? $path : null;
	}
	
	protected function server(): string
	{
		$software = isset($_SERVER['SERVER_SOFTWARE'])
			? strtolower(sanitize_text_field(wp_unslash((string)$_SERVER['SERVER_SOFTWARE'])))
			: '';
		
		return match(true)
		{
			str_contains($software, 'litespeed') => 'litespeed',
			str_contains($software, 'apache') => 'apache',
			str_contains($software, 'nginx') => 'nginx',
			str_contains($software, 'microsoft-iis') => 'iis',
			str_contains($software, 'caddy') => 'caddy',
			default => 'unknown',
		};
	}
	
	protected function constantWord(
		mixed $value,
	): string
	{
		if($value === true)
		{
			return 'true';
		}
		
		if($value === false)
		{
			return 'false';
		}
		
		return $this->clean((string)$value, 32);
	}
	
	/**
	 * The area roots, normalised to forward slashes without a trailing one
	 *
	 * @return array<string, string>
	 */
	public function roots(): array
	{
		$root = $this->normalize((string)ABSPATH);
		$content = defined('WP_CONTENT_DIR') ? $this->normalize((string)WP_CONTENT_DIR) : $root . '/wp-content';
		
		return [
			'root' => $root,
			'content' => $content,
			'plugins' => defined('WP_PLUGIN_DIR') ? $this->normalize((string)WP_PLUGIN_DIR) : $content . '/plugins',
			'mu' => defined('WPMU_PLUGIN_DIR') ? $this->normalize((string)WPMU_PLUGIN_DIR) : $content . '/mu-plugins',
			'themes' => function_exists('get_theme_root') ? $this->normalize((string)get_theme_root()) : $content . '/themes',
			'uploads' => function_exists('wp_get_upload_dir')
				? $this->normalize((string)(wp_get_upload_dir()['basedir'] ?? ''))
				: '',
		];
	}
	
	protected function normalize(
		string $path,
	): string
	{
		return rtrim(str_replace('\\', '/', $path), '/');
	}
	
	protected function relative(
		string $path,
		string $root,
	): string
	{
		$path = $this->normalize($path);
		
		return $root !== '' && str_starts_with($path, $root . '/')
			? substr($path, strlen($root) + 1)
			: $path;
	}
	
	/**
	 * Attacker-authored text on its way to a report: control characters
	 * replaced, length capped
	 */
	protected function clean(
		string $value,
		int $max = self::MAX_PATH,
	): string
	{
		$value = (string)preg_replace('~[\x00-\x1f\x7f]~', '?', $value);
		
		return strlen($value) > $max ? substr($value, 0, $max) : $value;
	}
}
