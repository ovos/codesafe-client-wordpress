<?php
declare(strict_types=1);
// phpcs:disable WordPress.WP.AlternativeFunctions -- the judge reads the site's own files (is_file, md5_file, filesize) the way the integrity scan does; the only writes are the plugin's own store files under wp-content/ovos-codesafe/

namespace Ovos\Codesafe;

use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Prepend;
use Throwable;

use function add_option;
use function basename;
use function bin2hex;
use function count;
use function defined;
use function delete_option;
use function explode;
use function fastcgi_finish_request;
use function filesize;
use function function_exists;
use function get_bloginfo;
use function get_locale;
use function get_option;
use function gmdate;
use function in_array;
use function is_array;
use function is_dir;
use function is_file;
use function is_int;
use function is_string;
use function max;
use function mb_substr;
use function md5_file;
use function microtime;
use function preg_match;
use function random_bytes;
use function realpath;
use function register_shutdown_function;
use function round;
use function rtrim;
use function sprintf;
use function str_contains;
use function str_replace;
use function str_starts_with;
use function strlen;
use function strpos;
use function strtolower;
use function substr;
use function time;
use function update_option;

use const ABSPATH;
use const DIRECTORY_SEPARATOR;
use const PHP_SAPI;
use const PHP_VERSION;

/**
 * The executed-file watch, the plugin's half (ovos/codesafe
 * docs/plans/prepend-entry-watch.md). The prepend layer (Shield\Prepend::entry)
 * records every PHP file PHP runs that is neither a WordPress root entry nor
 * known; this class, with WordPress loaded, does the two things the layer
 * cannot:
 *
 * - EXPORT the known set — wp-admin's entry scripts off the core checksum
 *   list for the running version (never a pattern: `wp-admin/evil.php` would
 *   match one; never the disk vouching for itself, since a compromised tree
 *   would vouch for its own shell), plus every path the judge found shipped —
 *   into the store directory, where the layer reads it;
 * - DRAIN the queue — judge each recorded path against what wordpress.org
 *   shipped (Checksums) and the site's roots (Scan), report what nobody
 *   shipped as an integrity-scan finding in `entry` mode (the console's
 *   ledger, INBOX case, mail and chat digest, removal advice and it-came-back
 *   logic are the scan's), and one security event per foreign file, so the
 *   address that ran it lands on the offender bar and in the attack waves.
 *
 * Both run at shutdown, after the response, at most once per request, behind
 * the scan runner's lock idiom so parallel requests never post twice. Nothing
 * here deletes, quarantines or refuses: a finding is a place to look. Executed
 * is a stronger fact than present — where the scan says high for a plugin's
 * foreign file, this proposes urgent. The console decides.
 */
class Entries
{
	/** a security event of this kind per executed foreign file (the console: App::SECURITY_KINDS) */
	public const KIND = 'file_executed';
	
	/** {core, plugin, exported_at, retry, drained_at, last, refused} — autoloaded, a few bytes */
	public const OPTION = 'ovos_codesafe_entries';
	
	public const LOCK = 'ovos_codesafe_entries_lock';
	
	/** a lock older than this was left by a request that died mid-drain */
	protected const LOCK_TTL = 60;
	
	/** learnt paths kept in the known set, beside the core entries */
	public const KNOWN_MAX = 500;
	
	/** checksum lists the drain may fetch in one request — after the response, like the scan's background chunk */
	protected const FETCHES = 1;
	
	/** seconds before an export without a core list, or a drain the console did not take, is tried again */
	protected const RETRY = 300;
	
	/** wp-admin's entry scripts in the core list: one level, plus network/ and user/ */
	protected const ADMIN_ENTRY = '~^wp-admin/(?:network/|user/)?[^/]+\.php$~';
	
	protected const HIDDEN = '~(?:^|/)\.[^/]~';
	
	/** the detector words in plain words, for the security event's line */
	public const LABELS = [
		'executed_uploads' => 'PHP under uploads ran',
		'executed_root' => 'PHP in the document root that core did not ship ran',
		'executed_root_owned' => 'a plugin\'s root file ran',
		'executed_hidden' => 'PHP in a hidden path ran',
		'executed_content' => 'PHP in wp-content outside any plugin or theme ran',
		'executed_core_foreign' => 'a file under core that wordpress.org never shipped ran',
		'executed_core_modified' => 'a core file differing from what wordpress.org shipped ran',
		'executed_plugin_foreign' => 'a file in a wp.org plugin that its release never shipped ran',
		'executed_plugin_modified' => 'a plugin file differing from what wordpress.org shipped ran',
		'executed_unverified' => 'a file no list vouches for ran',
		'executed_vanished' => 'a file ran and is gone since',
	];
	
	protected int $fetches = 0;
	
	public function __construct(
		protected Config $config,
		protected Sender $sender,
		protected ?Scan $scan = null,
		protected ?Checksums $sums = null,
	)
	{
	}
	
	public function register(): void
	{
		if($this->isEnabled() === false)
		{
			return;
		}
		
		// the last shutdown handler: the drain posts by itself and needs nothing the others do
		register_shutdown_function([$this, 'shutdown']);
	}
	
	/**
	 * The watch's consent: its switch, and a console to report to
	 */
	public function isEnabled(): bool
	{
		return $this->config->entryWatch()
			&& $this->config->enabled()
			&& $this->config->url() !== ''
			&& $this->config->apiKey() !== '';
	}
	
	/**
	 * The site root the layer measures against — realpath of ABSPATH, the
	 * way the layer resolves SCRIPT_FILENAME; '' when it cannot be resolved
	 */
	public static function root(): string
	{
		if(defined('ABSPATH') === false)
		{
			return '';
		}
		
		$root = realpath((string)ABSPATH);
		
		return $root === false ? '' : rtrim(str_replace('\\', '/', $root), '/');
	}
	
	/**
	 * After the response: the known set when it is missing or stale, the
	 * queue when something waits — one request pays, under the lock
	 */
	public function shutdown(): void
	{
		try
		{
			if(PHP_SAPI === 'cli' || $this->isEnabled() === false)
			{
				return;
			}
			
			$dir = Adapter::storeDir();
			
			if($dir === '')
			{
				return;
			}
			
			$export = $this->exportDue($dir);
			$seen = Prepend::seen($dir);
			$drain = $seen['paths'] !== [] && (int)($this->option()['retry_drain'] ?? 0) <= time();
			
			if($export === false && $drain === false)
			{
				return;
			}
			
			if($this->lock() === false)
			{
				return;
			}
			
			try
			{
				if(function_exists('fastcgi_finish_request'))
				{
					@fastcgi_finish_request();
				}
				
				if($export)
				{
					$this->export($dir);
				}
				
				if($drain)
				{
					$this->drain($dir, $seen);
				}
			}
			finally
			{
				$this->unlock();
			}
		}
		catch(Throwable)
		{
			// telemetry must never break the host site
		}
	}
	
	/**
	 * Whether the known set has to be (re)written: never written, or written
	 * for another core or plugin version — the wp-admin entries follow the
	 * core release
	 */
	public function exportDue(
		string $dir,
	): bool
	{
		$stored = $this->option();
		
		if(is_file($dir . DIRECTORY_SEPARATOR . Prepend::ENTRIES) === false)
		{
			return (int)($stored['retry'] ?? 0) <= time();
		}
		
		return (string)($stored['core'] ?? '') !== $this->coreVersion()
			|| (string)($stored['plugin'] ?? '') !== Plugin::VERSION;
	}
	
	/**
	 * The known set: wp-admin's entries off the core list, the learnt paths
	 * carried over. False when the core list is not at hand — the watch
	 * stays inactive rather than guess, and a later request tries again
	 */
	public function export(
		string $dir,
	): bool
	{
		$version = $this->coreVersion();
		$locale = function_exists('get_locale') ? (string)get_locale() : 'en_US';
		$list = $this->sums()->core($version, $locale);
		
		if($list === null)
		{
			$this->remember(['retry' => time() + self::RETRY]);
			
			return false;
		}
		
		$known = [];
		$current = Prepend::known($dir);
		
		foreach((array)($current['known'] ?? []) as $path => $word)
		{
			if($word === 'learnt')
			{
				$known[(string)$path] = 'learnt';
			}
		}
		
		foreach($list as $path => $md5)
		{
			if(preg_match(self::ADMIN_ENTRY, (string)$path) === 1)
			{
				$known[(string)$path] = 'core';
			}
		}
		
		if(Prepend::writeKnown($dir, $version, Plugin::VERSION, $known) === false)
		{
			return false;
		}
		
		$this->remember(['core' => $version, 'plugin' => Plugin::VERSION, 'exported_at' => time(), 'retry' => 0]);
		
		return true;
	}
	
	/**
	 * Every queued path judged; the strangers reported as one `entry`-mode
	 * integrity report and, once the console took it, one security event
	 * each; the shipped ones learnt so the layer stops recording them
	 *
	 * @param array{paths: array<string, array>, dropped: int} $seen
	 * @return array{findings: list<array>, learnt: list<string>, waiting: list<string>, sent: int}
	 */
	public function drain(
		string $dir,
		array $seen,
	): array
	{
		$begun = microtime(true);
		$this->fetches = 0;
		$roots = $this->scan()->roots();
		$versions = null;
		$rows = [];
		$learnt = [];
		$judged = [];
		$waiting = [];
		$counts = ['urgent' => 0, 'high' => 0, 'info' => 0];
		
		foreach($seen['paths'] as $relative => $record)
		{
			$relative = (string)$relative;
			$verdict = $this->judge($relative, $record, $roots, $versions);
			
			if($verdict['wait'])
			{
				$waiting[] = $relative;
				
				continue;
			}
			
			$judged[] = $relative;
			
			if($verdict['learn'])
			{
				$learnt[] = $relative;
			}
			
			if($verdict['finding'] !== null)
			{
				$rows[] = ['finding' => $verdict['finding'], 'relative' => $relative, 'record' => $record];
				$counts[$verdict['finding']['tier']]++;
			}
		}
		
		$findings = [];
		
		foreach($rows as $row)
		{
			$findings[] = $row['finding'];
		}
		
		$this->learn($dir, $learnt);
		
		$sent = -1;
		
		if($findings !== [])
		{
			$sent = ScanRunner::post($this->config, $this->report($roots, $findings, $counts, count($seen['paths']), $begun));
		}
		
		if($findings === [] || $sent === 202)
		{
			Prepend::forget($dir, $judged);
			$this->events($rows);
			$this->remember(['drained_at' => time(), 'retry_drain' => 0, 'last' => $this->lastOf($rows, $sent)]);
		}
		elseif($sent >= 400 && $sent < 500)
		{
			// the console said no (the project's file switch is off, a shape it refuses):
			// the judged paths go, or every request would post the same refusal again
			Prepend::forget($dir, $judged);
			$this->remember(['drained_at' => time(), 'retry_drain' => 0, 'refused' => ['status' => $sent, 'at' => time()], 'last' => $this->lastOf($rows, $sent)]);
		}
		else
		{
			// out of reach: the shipped paths are known now and will not queue again,
			// the strangers wait for a later drain
			Prepend::forget($dir, $learnt);
			$this->remember(['drained_at' => time(), 'retry_drain' => time() + self::RETRY]);
		}
		
		return ['findings' => $findings, 'learnt' => $learnt, 'waiting' => $waiting, 'sent' => $sent];
	}
	
	/**
	 * One recorded path against the roots and the lists. `finding` is the
	 * integrity-scan finding to report or null; `learn` whether the path
	 * joins the known set (shipped, owned, or judged once as unverifiable);
	 * `wait` when a list it needs could not be fetched within this request's
	 * budget — the path stays queued
	 *
	 * @param array<string, mixed> $record the layer's record (Prepend::seen)
	 * @param array<string, string> $roots Scan::roots()
	 * @param ?array<string, string> $versions plugin slug → version, resolved on first need
	 * @return array{finding: ?array, learn: bool, wait: bool}
	 */
	public function judge(
		string $relative,
		array $record,
		array $roots,
		?array &$versions,
	): array
	{
		$file = $roots['root'] . '/' . $relative;
		[$area, $path] = $this->locate($relative, $roots);
		
		if(is_file($file) === false)
		{
			$md5 = (string)($record['md5'] ?? '');
			
			return $this->finding('executed_vanished', Scan::TIER_URGENT, $area, $path, $record,
				'gone since' . ($md5 !== '' ? ' · md5 ' . substr($md5, 0, 12) : ''));
		}
		
		if(preg_match(self::HIDDEN, $relative) === 1)
		{
			return $this->finding('executed_hidden', Scan::TIER_URGENT, $area, $path, $record);
		}
		
		switch($area)
		{
			case 'uploads':
				$size = is_int($record['size'] ?? null) ? $record['size'] : (int)@filesize($file);
				
				if($this->scan()->isStub($file, $size))
				{
					return self::verdict(null, true);
				}
				
				return $this->finding('executed_uploads', Scan::TIER_URGENT, $area, $path, $record);
				
			case 'plugins':
				return $this->judgePlugin($path, $file, $area, $record, $versions);
				
			case 'core':
				return $this->judgeCore($relative, $file, $area, $path, $record);
				
			case 'themes':
				// no list vouches for a theme (wp.org has no theme checksums)
				return $this->finding('executed_unverified', Scan::TIER_INFO, $area, $path, $record, 'a theme file — no list vouches for it', true);
				
			case 'content':
				if(str_starts_with($path, 'ovos-codesafe/') || str_starts_with($path, 'ovos-console/'))
				{
					// the plugin's own store: the stub, under either of its names
					return self::verdict(null, true);
				}
				
				if(str_starts_with($file, $roots['mu'] . '/'))
				{
					// must-use plugins are custom code by definition
					return $this->finding('executed_unverified', Scan::TIER_INFO, $area, $path, $record, 'a must-use plugin — no list vouches for it', true);
				}
				
				return $this->finding('executed_content', Scan::TIER_URGENT, $area, $path, $record);
				
			default:
				return $this->judgeRoot($relative, $area, $path, $record, $roots);
		}
	}
	
	/**
	 * A file in the document root: a core entry the layer should have
	 * skipped, a plugin's own root file, or nobody's; a directory of its
	 * own under the root is a place WordPress does not own — high, not
	 * urgent, since a site may carry a second application there
	 *
	 * @param array<string, string> $roots
	 * @return array{finding: ?array, learn: bool, wait: bool}
	 */
	protected function judgeRoot(
		string $relative,
		string $area,
		string $path,
		array $record,
		array $roots,
	): array
	{
		if(strpos($relative, '/') !== false)
		{
			return $this->finding('executed_root', Scan::TIER_HIGH, $area, $path, $record, 'in a directory WordPress does not own');
		}
		
		if(in_array($relative, Sender::CORE_ROOT_FILES, true))
		{
			return self::verdict(null, true);
		}
		
		foreach(Scan::ROOT_OWNERS[basename($relative)] ?? [] as $owner)
		{
			[$type, $slug] = str_contains($owner, ':') ? explode(':', $owner, 2) : ['plugin', $owner];
			
			if($slug !== '' && is_dir(($type === 'theme' ? $roots['themes'] : $roots['plugins']) . '/' . $slug))
			{
				return $this->finding('executed_root_owned', Scan::TIER_INFO, $area, $path, $record, 'owned by ' . $owner, true);
			}
		}
		
		return $this->finding('executed_root', Scan::TIER_URGENT, $area, $path, $record);
	}
	
	/**
	 * A file inside a plugin directory against the plugin's wp.org list —
	 * judged on the md5 the layer took AS IT RAN, so a file restored after
	 * use is still the modified one that ran. No list (a premium or custom
	 * plugin, a single-file plugin): unverified, once
	 *
	 * @return array{finding: ?array, learn: bool, wait: bool}
	 */
	protected function judgePlugin(
		string $path,
		string $file,
		string $area,
		array $record,
		?array &$versions,
	): array
	{
		$slash = strpos($path, '/');
		
		if($slash === false)
		{
			return $this->finding('executed_unverified', Scan::TIER_INFO, $area, $path, $record, 'a single-file plugin — no list vouches for it', true);
		}
		
		$slug = substr($path, 0, $slash);
		$key = substr($path, $slash + 1);
		$versions ??= $this->scan()->pluginVersions();
		$version = (string)($versions[$slug] ?? '');
		
		if($version === '')
		{
			return $this->finding('executed_unverified', Scan::TIER_INFO, $area, $path, $record, 'not an installed plugin\'s directory', true);
		}
		
		$list = $this->list(fn(): ?array => $this->sums()->plugin($slug, $version), $this->sums()->pluginCached($slug, $version), $waiting);
		
		if($waiting)
		{
			return self::verdict(null, false, true);
		}
		
		if($list === null)
		{
			return $this->finding('executed_unverified', Scan::TIER_INFO, $area, $path, $record, 'no wordpress.org list for ' . $slug . ' ' . $version, true);
		}
		
		return $this->verify($list, $key, $file, 'plugin', $area, $path, $record);
	}
	
	/**
	 * A file under wp-admin/ or wp-includes/ against the core list
	 *
	 * @return array{finding: ?array, learn: bool, wait: bool}
	 */
	protected function judgeCore(
		string $relative,
		string $file,
		string $area,
		string $path,
		array $record,
	): array
	{
		$version = $this->coreVersion();
		$locale = function_exists('get_locale') ? (string)get_locale() : 'en_US';
		$list = $this->list(fn(): ?array => $this->sums()->core($version, $locale), $this->sums()->coreCached($version, $locale), $waiting);
		
		if($waiting)
		{
			return self::verdict(null, false, true);
		}
		
		if($list === null)
		{
			return $this->finding('executed_unverified', Scan::TIER_INFO, $area, $path, $record, 'the wordpress.org core list is unavailable');
		}
		
		return $this->verify($list, $relative, $file, 'core', $area, $path, $record);
	}
	
	/**
	 * The three verdicts a list gives: not in it (foreign), in it with
	 * another md5 (modified), in it byte for byte (shipped — learnt)
	 *
	 * @param array<string, string> $list
	 * @return array{finding: ?array, learn: bool, wait: bool}
	 */
	protected function verify(
		array $list,
		string $key,
		string $file,
		string $kind,
		string $area,
		string $path,
		array $record,
	): array
	{
		if(isset($list[$key]) === false)
		{
			return $this->finding('executed_' . $kind . '_foreign', Scan::TIER_URGENT, $area, $path, $record, 'not in the wordpress.org list for this version');
		}
		
		$ran = strtolower((string)($record['md5'] ?? ''));
		
		if($ran === '')
		{
			$now = @md5_file($file);
			$ran = is_string($now) ? strtolower($now) : '';
		}
		
		if($ran === $list[$key])
		{
			return self::verdict(null, true);
		}
		
		return $this->finding('executed_' . $kind . '_modified', Scan::TIER_URGENT, $area, $path, $record, 'md5 as it ran differs from the wordpress.org list for this version');
	}
	
	/**
	 * A list from the transient, or over the network while this request's
	 * fetch budget lasts; past it `$waiting` is set and the path stays queued
	 *
	 * @param callable(): ?array $fetch
	 */
	protected function list(
		callable $fetch,
		bool $cached,
		?bool &$waiting,
	): ?array
	{
		$waiting = false;
		
		if($cached === false)
		{
			if($this->fetches >= self::FETCHES)
			{
				$waiting = true;
				
				return null;
			}
			
			$this->fetches++;
		}
		
		return $fetch();
	}
	
	/**
	 * The area the executed file falls in and its path relative to that
	 * area's root — the scan's own vocabulary, so the ledger keys the same
	 * file the walk will list next to this
	 *
	 * @param array<string, string> $roots
	 * @return array{0: string, 1: string}
	 */
	protected function locate(
		string $relative,
		array $roots,
	): array
	{
		$file = $roots['root'] . '/' . $relative;
		
		foreach(['uploads' => 'uploads', 'plugins' => 'plugins', 'mu' => 'content', 'themes' => 'themes', 'content' => 'content'] as $root => $area)
		{
			$prefix = ($roots[$root] ?? '') . '/';
			
			if($prefix !== '/' && str_starts_with($file, $prefix))
			{
				$base = $roots[$area === 'content' ? 'content' : $root];
				
				return [$area, str_starts_with($file, $base . '/') ? substr($file, strlen($base) + 1) : substr($file, strlen($prefix))];
			}
		}
		
		if(str_starts_with($relative, 'wp-admin/') || str_starts_with($relative, 'wp-includes/'))
		{
			return ['core', $relative];
		}
		
		return ['root', $relative];
	}
	
	/**
	 * @return array{finding: ?array, learn: bool, wait: bool}
	 */
	protected function finding(
		string $detector,
		string $tier,
		string $area,
		string $path,
		array $record,
		string $more = '',
		bool $learn = false,
	): array
	{
		$finding = [
			'detector' => $detector,
			'tier' => $tier,
			'area' => $area,
			'path' => $path,
			'detail' => $this->detail($record, $more),
		];
		
		foreach(['size', 'mtime'] as $field)
		{
			if(is_int($record[$field] ?? null) && $record[$field] >= 0)
			{
				$finding[$field] = $record[$field];
			}
		}
		
		return self::verdict($finding, $learn);
	}
	
	/**
	 * @return array{finding: ?array, learn: bool, wait: bool}
	 */
	protected static function verdict(
		?array $finding,
		bool $learn,
		bool $wait = false,
	): array
	{
		return ['finding' => $finding, 'learn' => $learn, 'wait' => $wait];
	}
	
	/**
	 * The row's line: how often, when, from where — the request's own facts
	 * ride the security event, this is the file's story in 160 characters
	 */
	protected function detail(
		array $record,
		string $more = '',
	): string
	{
		$n = max(1, (int)($record['n'] ?? 1));
		$first = (int)($record['first'] ?? 0);
		$last = (int)($record['last'] ?? $first);
		$context = is_array($record['context'] ?? null) ? $record['context'] : [];
		$ip = (string)($context['ip'] ?? '');
		$method = (string)($context['method'] ?? '');
		$text = sprintf('executed %d× · first %s · last %s UTC', $n, gmdate('d.m. H:i', $first), gmdate('d.m. H:i', $last));
		
		if($ip !== '')
		{
			$text .= ' · from ' . $ip;
		}
		
		if($method !== '')
		{
			$text .= ' · ' . $method;
		}
		
		if($more !== '')
		{
			$text .= ' · ' . $more;
		}
		
		return mb_substr($text, 0, Scan::MAX_DETAIL);
	}
	
	/**
	 * The `entry`-mode integrity report around the findings: the same shape
	 * the walk sends, never complete — it saw the queue, not the tree, so
	 * the console's ledger never reads a missing path as gone from it
	 *
	 * @param array<string, string> $roots
	 * @param list<array> $findings
	 * @param array<string, int> $counts
	 */
	protected function report(
		array $roots,
		array $findings,
		array $counts,
		int $paths,
		float $begun,
	): array
	{
		$areas = [];
		
		foreach(Scan::AREAS as $area)
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
			];
		}
		
		$report = [
			'v' => 1,
			'type' => 'files',
			'platform' => 'wordpress',
			'core' => $this->coreVersion(),
			'php' => Inventory::version(PHP_VERSION),
			'client' => 'wordpress/' . Plugin::VERSION,
			'scan' => [
				'id' => bin2hex(random_bytes(8)),
				'mode' => 'entry',
				'started' => (int)$begun,
				'finished' => time(),
				'duration' => (int)round((microtime(true) - $begun) * 1000),
				'chunks' => 1,
				'complete' => false,
				'files' => $paths,
				'dirs' => 0,
				'unreadable' => 0,
				'symlinks' => 0,
				'skipped' => [],
				'counts' => $counts,
				'truncated' => ['urgent' => 0, 'high' => 0, 'info' => 0],
			],
			'areas' => $areas,
			'findings' => $findings,
			'posture' => [],
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
	 * One security event per foreign file (not per hit — the count is in
	 * the line and in `extra.hits`), wearing the LAST request's own facts
	 * the way a drained prepend block does: the console's offender score
	 * follows the ip, and its `foreign-file` / `unshipped-file` signatures
	 * read `extra.source`. Info rows (owned, unverified) are listed, not
	 * scored. Flushed explicitly: the Sender's own shutdown flush has run
	 *
	 * @param list<array{finding: array, relative: string, record: array}> $rows
	 */
	protected function events(
		array $rows,
	): void
	{
		$reported = 0;
		
		foreach($rows as $row)
		{
			$finding = $row['finding'];
			
			if($finding['tier'] === Scan::TIER_INFO)
			{
				continue;
			}
			
			$record = $row['record'];
			$n = max(1, (int)($record['n'] ?? 1));
			$context = is_array($record['context'] ?? null) ? $record['context'] : [];
			$context['at'] = (int)($record['last'] ?? time());
			
			$this->sender->reportRefusal(self::KIND,
				sprintf('%s ran %d× — %s', $row['relative'], $n, self::LABELS[$finding['detector']] ?? $finding['detector']),
				[
					// under uploads, or under the site and shipped by nobody (Sender::sourceFor's two words worth a look)
					'source' => $finding['area'] === 'uploads' ? 'uploads' : 'unknown',
					'file' => $row['relative'],
					'detector' => $finding['detector'],
					'tier' => $finding['tier'],
					'hits' => $n,
					'md5' => (string)($record['md5'] ?? ''),
					'layer' => 'prepend',
				],
				Adapter::drained($context));
			$reported++;
		}
		
		if($reported > 0)
		{
			$this->sender->flush();
		}
	}
	
	/**
	 * The learnt paths onto the known set, capped — past KNOWN_MAX the
	 * oldest learnt entries go, the core entries stay
	 *
	 * @param list<string> $paths
	 */
	protected function learn(
		string $dir,
		array $paths,
	): void
	{
		if($paths === [])
		{
			return;
		}
		
		$current = Prepend::known($dir);
		
		if($current === null)
		{
			return;
		}
		
		$known = $current['known'];
		
		foreach($paths as $path)
		{
			$known[$path] = 'learnt';
		}
		
		$learnt = 0;
		
		foreach($known as $path => $word)
		{
			if($word === 'learnt' && ++$learnt > self::KNOWN_MAX)
			{
				unset($known[$path]);
			}
		}
		
		Prepend::writeKnown($dir, $current['core'], $current['plugin'], $known);
	}
	
	/**
	 * What the settings page says: the switch, whether the known set is
	 * exported, how many paths it holds, what waits, and the last drain
	 *
	 * @return array{enabled: bool, exported: bool, core: int, learnt: int, queued: int, dropped: int,
	 *   last: ?array, refused: ?array, exported_at: int}
	 */
	public function status(): array
	{
		$dir = Adapter::storeDir();
		$option = $this->option();
		$known = $dir === '' ? null : Prepend::known($dir);
		$seen = $dir === '' ? ['paths' => [], 'dropped' => 0] : Prepend::seen($dir);
		$core = 0;
		$learnt = 0;
		
		foreach((array)($known['known'] ?? []) as $word)
		{
			if($word === 'core')
			{
				$core++;
			}
			else
			{
				$learnt++;
			}
		}
		
		return [
			'enabled' => $this->isEnabled(),
			'exported' => $known !== null,
			'core' => $core,
			'learnt' => $learnt,
			'queued' => count($seen['paths']),
			'dropped' => $seen['dropped'],
			'last' => is_array($option['last'] ?? null) ? $option['last'] : null,
			'refused' => is_array($option['refused'] ?? null) ? $option['refused'] : null,
			'exported_at' => (int)($option['exported_at'] ?? 0),
		];
	}
	
	/**
	 * The most urgent finding of a drain, for the status line
	 *
	 * @param list<array{finding: array, relative: string, record: array}> $rows
	 */
	protected function lastOf(
		array $rows,
		int $sent,
	): ?array
	{
		$best = null;
		$rank = [Scan::TIER_URGENT => 3, Scan::TIER_HIGH => 2, Scan::TIER_INFO => 1];
		
		foreach($rows as $row)
		{
			if($best === null || ($rank[$row['finding']['tier']] ?? 0) > ($rank[$best['tier']] ?? 0))
			{
				$best = ['path' => $row['relative'], 'tier' => $row['finding']['tier'], 'detector' => $row['finding']['detector'],
					'at' => (int)($row['record']['last'] ?? time()), 'sent' => $sent];
			}
		}
		
		return $best ?? (is_array($this->option()['last'] ?? null) ? $this->option()['last'] : null);
	}
	
	protected function coreVersion(): string
	{
		return Inventory::version((string)get_bloginfo('version'));
	}
	
	protected function scan(): Scan
	{
		return $this->scan ??= new Scan($this->config);
	}
	
	protected function sums(): Checksums
	{
		return $this->sums ??= new Checksums(2);
	}
	
	/**
	 * @return array<string, mixed>
	 */
	protected function option(): array
	{
		return (array)get_option(self::OPTION, []);
	}
	
	protected function remember(
		array $patch,
	): void
	{
		update_option(self::OPTION, $patch + $this->option(), true);
	}
	
	protected function lock(): bool
	{
		$held = get_option(self::LOCK);
		
		if($held !== false && time() - (int)$held < self::LOCK_TTL)
		{
			return false;
		}
		
		if($held !== false)
		{
			delete_option(self::LOCK);
		}
		
		return add_option(self::LOCK, time(), '', false);
	}
	
	protected function unlock(): void
	{
		delete_option(self::LOCK);
	}
}
