<?php
declare(strict_types=1);

namespace Ovos\Codesafe\Shield;

use Ovos\Codesafe\Shield\Consent;
use Ovos\Codesafe\Shield\Facts;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Store;
use stdClass;
use Throwable;

use function array_filter;
use function array_keys;
use function array_slice;
use function array_values;
use function class_exists;
use function count;
use function define;
use function defined;
use function explode;
use function file_get_contents;
use function file_put_contents;
use function header;
use function headers_sent;
use function http_response_code;
use function ini_get;
use function is_array;
use function is_file;
use function is_int;
use function is_string;
use function in_array;
use function json_decode;
use function json_encode;
use function max;
use function md5_file;
use function realpath;
use function register_shutdown_function;
use function rtrim;
use function sprintf;
use function stat;
use function str_contains;
use function str_ends_with;
use function str_replace;
use function str_starts_with;
use function strlen;
use function strtolower;
use function substr;
use function time;
use function trim;
use function var_export;

use const DIRECTORY_SEPARATOR;

// the kernel is one vendored multi-class file; a plain class binds at compile
// time, so the guard sits at the require, never inside the file
if(class_exists(Kernel::class, false) === false)
{
	require_once __DIR__ . DIRECTORY_SEPARATOR . 'Kernel.php';
}

/**
 * The Shield before WordPress (ovos/console docs/plans/shield-prepend.md): the
 * optional `auto_prepend_file` layer. The operator points PHP's prepend at a
 * stub the plugin writes into its own store directory; the stub calls run(),
 * which judges the request against the cached ruleset with the cached consent
 * — no WordPress, no options table, no constants of wp-config.php exist yet —
 * and either stashes an observe verdict for the plugins_loaded adapter to
 * report, or refuses with 403 and queues the block's report for the plugin's
 * next request.
 *
 * What makes it safe to switch on:
 *
 * - the stub lives OUTSIDE the plugin directory (wp-content/ovos-codesafe/), so
 *   removing the plugin never leaves PHP with a missing prepend file — a fatal
 *   on every request — and the stub itself includes this file only if it is
 *   there;
 * - a request carrying a WordPress login cookie is left to the plugins_loaded
 *   judge: only WordPress can say who the user is, the alarm's logged-in
 *   signal needs the user on the row, and an editor must never be refused by
 *   a layer that cannot tell them from a bot;
 * - the consent is what the plugin last wrote (shield-consent.json): the two
 *   checkboxes and the kill constant as of the site's last request, so an
 *   unticked box reaches this layer one request later than it reaches the
 *   adapter;
 * - everything fails open — no consent, no ruleset, a throw of any kind, the
 *   request goes on as if this layer were not there.
 *
 * One verdict per request: the adapter sees Prepend::MARK defined and claims
 * the stash instead of judging again. A request WordPress never loads for
 * (a direct hit on a plugin file, the shape this layer exists for) leaves
 * the stash unclaimed: settle(), at shutdown, queues its report beside the
 * blocks', and the site's next request drains it. Hits are the kernel's
 * (Store::hit) and ride the traffic rollups like the adapter's own.
 *
 * The same layer carries the executed-file watch (ovos/codesafe
 * docs/plans/prepend-entry-watch.md): before the Shield judges, entry()
 * looks at the file PHP is about to run and records it when it is neither
 * a WordPress root entry nor in the known set the plugin exported — the
 * dropped shell, the moment it is used. This half only writes; the plugin
 * (Entries) judges the record against what wordpress.org shipped on the
 * site's next request and reports what nobody shipped.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
final class Prepend
{
	/** the ruleset the adapter's kernel writes and this layer reads (Adapter::FILE is this) */
	public const RULES = 'shield.json';
	
	/** the stub the directive points at, beside shield.json */
	public const STUB = 'prepend.php';
	
	/** the consent the plugin writes for this layer */
	public const CONSENT = 'shield-consent.json';
	
	/** the blocks this layer refused before the plugin could report them */
	public const QUEUE = 'shield-reports.json';
	
	/** at most this many queued reports — a flood is counted by the hits, not narrated */
	public const QUEUE_MAX = 100;
	
	/** defined by run() so the plugins_loaded adapter knows the request was judged */
	public const MARK = 'CODESAFE_SHIELD_PREPENDED';
	
	/** the global the stash rides in: ['verdict' => Verdict, 'report' => [kind, message, extra]|null, 'claimed' => bool] */
	public const STASH = 'ovos_codesafe_shield_prepend';
	
	public const HEADER_RULE = 'X-Shield-Rule';
	
	public const HEADER_LAYER = 'X-Shield-Layer';
	
	/** the stub's marker — a newer plugin rewrites an older stub */
	public const STUB_VERSION = 1;
	
	/** WordPress's login cookie prefix — a request carrying one is the adapter's to judge */
	public const LOGIN_COOKIE = 'wordpress_logged_in_';
	
	/** the executed-file watch's known set, exported by the plugin (Entries): {core, plugin, known: {path: core|learnt}} */
	public const ENTRIES = 'entries.json';
	
	/** the executed files waiting for the plugin's judge: {paths: {path: record}, dropped} */
	public const SEEN = 'entries-seen.json';
	
	/** at most this many distinct paths wait; a flood past it is counted, not listed */
	public const SEEN_MAX = 100;
	
	/**
	 * WordPress's own entry points in the document root — the request that is
	 * the site, checked against a static list so it never costs a file read
	 * (Sender::CORE_ROOT_FILES restated: the layer references no other
	 * class). wp-admin's entries are deliberately NOT a pattern here —
	 * `wp-admin/evil.php` would match one; they come from the core checksum
	 * list, through the known set the plugin exports
	 */
	public const ROOT_ENTRIES = ['index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
		'wp-config.php', 'wp-config-sample.php', 'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
		'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php'];
		
	/**
	 * The stub's one call. Never throws, never blocks a request it cannot
	 * judge; exits only on a block
	 */
	public static function run(
		string $dir,
	): void
	{
		try
		{
			if(PHP_SAPI === 'cli')
			{
				return;
			}
			$consent = self::consent($dir);
			if($consent === null)
			{
				return;
			}
			// the executed-file watch first: it records, whatever the Shield's
			// boxes say, and a signed-in request is recorded like any other
			self::entry($dir, $_SERVER, $consent);
			$judged = self::judge($dir, $_SERVER, $_POST, $_COOKIE, null, $consent);
			if($judged === null)
			{
				return;
			}
			if(defined(self::MARK) === false)
			{
				define(self::MARK, true);
			}
			$GLOBALS[self::STASH] = ['verdict' => $judged['verdict'], 'report' => $judged['report'], 'claimed' => false];
			$verdict = $judged['verdict'];
			if($verdict->isBlock() && $verdict->rule !== null)
			{
				if($judged['report'] !== null)
				{
					self::queue($dir, $judged['report'], self::contextOf($_SERVER, $verdict->status()));
				}
				self::refuse((int)$verdict->rule['id'], $verdict->status(), $verdict->retryAfter);
			}
			// an observe verdict: the adapter claims it at plugins_loaded — unless
			// WordPress never loads for this request, when shutdown queues it
			register_shutdown_function(static fn(): bool => self::settle($dir));
		}
		catch(Throwable)
		{
			// fail open: served as if the layer were not there
		}
	}
	
	/**
	 * The pure part: the consent gate, the login-cookie rule, the judge. Null
	 * when this layer has nothing to say (no consent, detection off, kill,
	 * a signed-in request); otherwise the verdict and the report the
	 * kernel would have sent — the adapter sends it, or the queue holds it
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $post
	 * @param array<string, mixed> $cookies
	 * @param ?array{detect: bool, enforce: bool, kill: bool, prefix: string} $consent the consent read already, or null to read it
	 * @return ?array{verdict: Verdict, report: ?array{0: string, 1: string, 2: array}}
	 */
	public static function judge(
		string $dir,
		array $server,
		array $post = [],
		array $cookies = [],
		?int $now = null,
		?array $consent = null,
	): ?array
	{
		$consent ??= self::consent($dir);
		if($consent === null || $consent['kill'] || $consent['detect'] === false)
		{
			return null;
		}
		foreach(array_keys($cookies) as $name)
		{
			if(str_starts_with((string)$name, self::LOGIN_COOKIE))
			{
				return null;
			}
		}
		$report = null;
		$kernel = new Kernel('', '', new Store($dir . DIRECTORY_SEPARATOR . self::RULES, $consent['prefix']),
			// this layer never pulls: a transport that answers nothing keeps even a mis-call harmless
			static fn(): array => ['status' => 0, 'headers' => [], 'body' => ''],
			static function(string $kind, string $message, array $extra) use (&$report): void
			{
				$report = [$kind, $message, $extra];
			});
		$facts = Facts::fromServer($server, $post, static fn(): string => (string)file_get_contents('php://input'), false,
			user: self::loginName($server, $post));
		$verdict = $kernel->handle($facts, new Consent(true, $consent['enforce'], false), $now);
		if($verdict->isPass())
		{
			return null;
		}
		
		return ['verdict' => $verdict, 'report' => $report];
	}
	
	/**
	 * The consent as the plugin last wrote it — null when the file is not
	 * there or does not parse: the layer then does nothing. `root` is the
	 * site root the executed-file watch measures against (realpath of
	 * ABSPATH), `entries` whether that watch is on
	 *
	 * @return ?array{detect: bool, enforce: bool, kill: bool, prefix: string, root: string, entries: bool}
	 */
	public static function consent(
		string $dir,
	): ?array
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::CONSENT;
		if(is_file($path) === false)
		{
			return null;
		}
		$decoded = json_decode((string)file_get_contents($path), true);
		if(is_array($decoded) === false)
		{
			return null;
		}
		
		return [
			'detect' => ($decoded['detect'] ?? false) === true,
			'enforce' => ($decoded['enforce'] ?? false) === true,
			'kill' => ($decoded['kill'] ?? false) === true,
			'prefix' => is_string($decoded['prefix'] ?? null) ? $decoded['prefix'] : '',
			'root' => is_string($decoded['root'] ?? null) ? $decoded['root'] : '',
			'entries' => ($decoded['entries'] ?? false) === true,
		];
	}
	
	/**
	 * The plugin's half: the consent written when it differs from what is
	 * there (one small read per request, one write per change)
	 *
	 * @param array{detect: bool, enforce: bool, kill: bool, prefix: string, root?: string, entries?: bool} $consent
	 * @return bool whether the file was (re)written
	 */
	public static function writeConsent(
		string $dir,
		array $consent,
	): bool
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::CONSENT;
		$current = self::consent($dir);
		$wanted = [
			'detect' => $consent['detect'] === true,
			'enforce' => $consent['enforce'] === true,
			'kill' => $consent['kill'] === true,
			'prefix' => (string)$consent['prefix'],
			'root' => (string)($consent['root'] ?? ''),
			'entries' => ($consent['entries'] ?? false) === true,
		];
		if($current === $wanted)
		{
			return false;
		}
		
		return @file_put_contents($path, (string)json_encode($wanted + ['written_at' => time()]), LOCK_EX) !== false;
	}
	
	/**
	 * The executed-file watch: the file PHP is about to run, recorded when
	 * it is neither a WordPress root entry nor known. Returns the path
	 * recorded, relative to the site root, or null when there was nothing
	 * to record — the request that is the site (index.php) costs a realpath
	 * and one isset() and never reads a file; a wp-admin page or a plugin's
	 * own endpoint reads the known set; only a stranger writes. Never
	 * throws, never refuses: this half is a recorder
	 *
	 * @param array<string, mixed> $server
	 * @param array{root: string, entries: bool} $consent
	 */
	public static function entry(
		string $dir,
		array $server,
		array $consent,
		?int $now = null,
	): ?string
	{
		try
		{
			if(($consent['entries'] ?? false) !== true || ($consent['root'] ?? '') === '')
			{
				return null;
			}
			$script = $server['SCRIPT_FILENAME'] ?? '';
			$file = is_string($script) && $script !== '' ? realpath($script) : false;
			if($file === false)
			{
				return null;
			}
			$file = str_replace('\\', '/', $file);
			$root = rtrim(str_replace('\\', '/', (string)$consent['root']), '/') . '/';
			if(str_starts_with($file, $root) === false)
			{
				// outside the site: a shared library, another vhost — cannot know
				return null;
			}
			$relative = substr($file, strlen($root));
			if(in_array($relative, self::ROOT_ENTRIES, true))
			{
				return null;
			}
			$known = self::known($dir);
			if($known === null || isset($known['known'][$relative]))
			{
				return null;
			}
			self::record($dir, $relative, $file, $server, $now ?? time());
			
			return $relative;
		}
		catch(Throwable)
		{
			return null;
		}
	}
	
	/**
	 * The known set the plugin exported — wp-admin's entries off the core
	 * checksum list (`core`) and the paths the judge found shipped
	 * (`learnt`) — or null when it never did: the watch then has nothing to
	 * measure against and records nothing
	 *
	 * @return ?array{core: string, plugin: string, known: array<string, string>}
	 */
	public static function known(
		string $dir,
	): ?array
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::ENTRIES;
		if(is_file($path) === false)
		{
			return null;
		}
		$decoded = json_decode((string)file_get_contents($path), true);
		if(is_array($decoded) === false || is_array($decoded['known'] ?? null) === false)
		{
			return null;
		}
		
		return [
			'core' => is_string($decoded['core'] ?? null) ? $decoded['core'] : '',
			'plugin' => is_string($decoded['plugin'] ?? null) ? $decoded['plugin'] : '',
			'known' => $decoded['known'],
		];
	}
	
	/**
	 * The plugin's half: the known set, written whole
	 *
	 * @param array<string, string> $known path → core|learnt
	 */
	public static function writeKnown(
		string $dir,
		string $core,
		string $plugin,
		array $known,
	): bool
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::ENTRIES;
		
		return @file_put_contents($path, (string)json_encode([
			'core' => $core,
			'plugin' => $plugin,
			'known' => $known === [] ? new stdClass : $known,
			'written_at' => time(),
		]), LOCK_EX) !== false;
	}
	
	/**
	 * What waits for the judge: per path the hit count, first and last
	 * time, the file as it was when first run (size, mtime, md5 — the
	 * evidence that survives its deletion) and the last request's own
	 * facts (contextOf); `dropped` counts hits past SEEN_MAX
	 *
	 * @return array{paths: array<string, array>, dropped: int}
	 */
	public static function seen(
		string $dir,
	): array
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::SEEN;
		$decoded = is_file($path) ? json_decode((string)file_get_contents($path), true) : null;
		$paths = is_array($decoded) && is_array($decoded['paths'] ?? null) ? array_filter($decoded['paths'], 'is_array') : [];
		
		return ['paths' => $paths, 'dropped' => is_array($decoded) ? max(0, (int)($decoded['dropped'] ?? 0)) : 0];
	}
	
	/**
	 * The plugin's half, after a judge: the judged paths leave the queue,
	 * whatever arrived meanwhile stays; the dropped count starts over
	 *
	 * @param list<string> $judged
	 */
	public static function forget(
		string $dir,
		array $judged,
	): void
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::SEEN;
		$seen = self::seen($dir);
		foreach($judged as $relative)
		{
			unset($seen['paths'][$relative]);
		}
		if($seen['paths'] === [])
		{
			@file_put_contents($path, '{"paths":{},"dropped":0}', LOCK_EX);
			
			return;
		}
		@file_put_contents($path, (string)json_encode(['paths' => $seen['paths'], 'dropped' => 0]), LOCK_EX);
	}
	
	/**
	 * One executed stranger onto the queue: a path seen before counts one
	 * more hit and takes this request's facts; a new one is measured as it
	 * is right now, before whatever it does
	 *
	 * @param array<string, mixed> $server
	 */
	protected static function record(
		string $dir,
		string $relative,
		string $file,
		array $server,
		int $now,
	): void
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::SEEN;
		$seen = self::seen($dir);
		$context = self::contextOf($server, null);
		if(isset($seen['paths'][$relative]))
		{
			$seen['paths'][$relative]['n'] = (int)($seen['paths'][$relative]['n'] ?? 0) + 1;
			$seen['paths'][$relative]['last'] = $now;
			$seen['paths'][$relative]['context'] = $context;
		}
		elseif(count($seen['paths']) >= self::SEEN_MAX)
		{
			$seen['dropped']++;
		}
		else
		{
			$stat = @stat($file);
			$md5 = @md5_file($file);
			$seen['paths'][$relative] = [
				'n' => 1,
				'first' => $now,
				'last' => $now,
				'size' => is_array($stat) ? (int)$stat['size'] : null,
				'mtime' => is_array($stat) ? (int)$stat['mtime'] : null,
				'md5' => is_string($md5) ? $md5 : '',
				'context' => $context,
			];
		}
		@file_put_contents($path, (string)json_encode($seen), LOCK_EX);
	}
	
	/**
	 * The stub, written or refreshed: a comment with the version, the absolute
	 * path of this file, an include guarded by is_file() — nothing else. Returns
	 * the stub's path, '' when it could not be written.
	 *
	 * $at writes it somewhere else than $dir while it still judges against
	 * $dir: the stub ovos-console left in wp-content/ovos-console/, which a
	 * site's PHP configuration may still name, runs this plugin that way
	 */
	public static function ensureStub(
		string $dir,
		?string $at = null,
	): string
	{
		$path = $at ?? $dir . DIRECTORY_SEPARATOR . self::STUB;
		$source = str_replace('\\', '/', __FILE__);
		$marker = sprintf('ovos codesafe shield prepend v%d', self::STUB_VERSION);
		$store = $at === null ? '__DIR__' : var_export($dir, true);
		if(is_file($path))
		{
			$existing = (string)file_get_contents($path);
			if(str_contains($existing, $marker) && str_contains($existing, $source) && str_contains($existing, '::run(' . $store . ')'))
			{
				return $path;
			}
		}
		$stub = "<?php\n"
			. "// " . $marker . " — the Shield before WordPress (auto_prepend_file). Written by the\n"
			. "// ovos codesafe plugin; safe to delete: PHP's prepend then points at nothing and the\n"
			. "// plugin writes it again on its next request. Judges the request against the cached\n"
			. "// ruleset only if the plugin's Prepend.php is still where it was; fails open otherwise.\n"
			. "\$ovosCodesafePrepend = '" . str_replace("'", "\\'", $source) . "';\n"
			. "if(is_file(\$ovosCodesafePrepend))\n"
			. "{\n"
			. "\t@include_once \$ovosCodesafePrepend;\n"
			. "\tif(class_exists('Ovos\\\\Codesafe\\\\Shield\\\\Prepend', false))\n"
			. "\t{\n"
			. "\t\t\\Ovos\\Codesafe\\Shield\\Prepend::run(" . $store . ");\n"
			. "\t}\n"
			. "}\n"
			. "unset(\$ovosCodesafePrepend);\n";
		
		return @file_put_contents($path, $stub, LOCK_EX) === false ? '' : $path;
	}
	
	/**
	 * A block's report, kept for the plugin's next request — the layer has no
	 * Sender. Capped: past QUEUE_MAX the oldest go, the hits keep the count
	 *
	 * @param array{0: string, 1: string, 2: array} $report
	 * @param array<string, int|string> $context the request's facts (contextOf())
	 */
	public static function queue(
		string $dir,
		array $report,
		array $context = [],
	): void
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::QUEUE;
		$queued = is_file($path) ? json_decode((string)file_get_contents($path), true) : [];
		$queued = is_array($queued) ? array_values(array_filter($queued, 'is_array')) : [];
		$queued[] = ['kind' => $report[0], 'message' => $report[1], 'extra' => $report[2], 'context' => $context, 'at' => time()];
		if(count($queued) > self::QUEUE_MAX)
		{
			$queued = array_slice($queued, -self::QUEUE_MAX);
		}
		@file_put_contents($path, (string)json_encode($queued), LOCK_EX);
	}
	
	/**
	 * The adapter's claim on this request's verdict: the stashed report, once,
	 * and the stash marked claimed so settle() leaves it alone. Null when
	 * this layer did not judge, had nothing to report, or was claimed already
	 *
	 * @return ?array{0: string, 1: string, 2: array}
	 */
	public static function claim(): ?array
	{
		$stash = $GLOBALS[self::STASH] ?? null;
		if(is_array($stash) === false || ($stash['claimed'] ?? false) === true)
		{
			return null;
		}
		$GLOBALS[self::STASH]['claimed'] = true;
		$report = $stash['report'] ?? null;
		
		return is_array($report) && is_string($report[0] ?? null) && is_string($report[1] ?? null)
			? [$report[0], $report[1], is_array($report[2] ?? null) ? $report[2] : []]
			: null;
	}
	
	/**
	 * Shutdown's half: a stash nobody claimed — WordPress never loaded for the
	 * request, so no adapter ran — goes to the queue for the site's next
	 * request, with this request's facts and the status it ended with. True
	 * when a report was queued
	 *
	 * @param ?array<string, mixed> $server the request, $_SERVER by default
	 * @param ?int $status the response status, PHP's own by default
	 */
	public static function settle(
		string $dir,
		?array $server = null,
		?int $status = null,
	): bool
	{
		$report = self::claim();
		if($report === null)
		{
			return false;
		}
		if($status === null)
		{
			$code = http_response_code();
			$status = is_int($code) ? $code : null;
		}
		self::queue($dir, $report, self::contextOf($server ?? $_SERVER, $status));
		
		return true;
	}
	
	/**
	 * The refused request's own facts for its row — the plugin reports a
	 * queued verdict from a LATER request, whose URI, address and user agent
	 * are somebody else's; the console's offender score follows the ip. Raw
	 * here (no WordPress to sanitize with); the adapter scrubs on the drain
	 *
	 * @param array<string, mixed> $server
	 * @return array<string, int|string>
	 */
	public static function contextOf(
		array $server,
		?int $status,
	): array
	{
		$context = [
			'uri' => trim((string)($server['REQUEST_URI'] ?? '')),
			'method' => trim((string)($server['REQUEST_METHOD'] ?? '')),
			'ip' => trim((string)($server['REMOTE_ADDR'] ?? '')),
			'ua' => trim((string)($server['HTTP_USER_AGENT'] ?? '')),
			'referer' => trim((string)($server['HTTP_REFERER'] ?? '')),
			'host' => trim((string)($server['HTTP_HOST'] ?? '')),
			'at' => time(),
		];
		if($status !== null && $status >= 100 && $status <= 599)
		{
			$context['status'] = $status;
		}
		
		return $context;
	}
	
	/**
	 * The plugin's half: every queued report through the Sender, then an
	 * empty queue. Returns how many were handed on. The fourth argument is
	 * the refused request's own facts (contextOf()) — the Sender's row for
	 * a report it sends from a later request must not wear that request's
	 *
	 * @param callable(string $kind, string $message, array $extra, array $context): mixed $report
	 */
	public static function drain(
		string $dir,
		callable $report,
	): int
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::QUEUE;
		if(is_file($path) === false)
		{
			return 0;
		}
		$queued = json_decode((string)file_get_contents($path), true);
		@file_put_contents($path, '[]', LOCK_EX);
		$handed = 0;
		foreach(is_array($queued) ? $queued : [] as $entry)
		{
			if(is_array($entry) && is_string($entry['kind'] ?? null) && is_string($entry['message'] ?? null))
			{
				$extra = is_array($entry['extra'] ?? null) ? $entry['extra'] : [];
				$extra['layer'] = 'prepend';
				$report($entry['kind'], $entry['message'], $extra, is_array($entry['context'] ?? null) ? $entry['context'] : []);
				$handed++;
			}
		}
		
		return $handed;
	}
	
	/**
	 * What the settings page says about this layer, off PHP's own ini value:
	 * `active` when the directive names the stub, `other` when it names
	 * something else (a host's or another plugin's prepend — this one never
	 * chains), `legacy` when it names the stub ovos-console left ($legacy,
	 * rewritten to run this plugin), `inactive` when there is none
	 *
	 * @return array{state: string, ini: string, stub: string}
	 */
	public static function status(
		string $dir,
		?string $ini = null,
		?string $legacy = null,
	): array
	{
		$ini ??= (string)ini_get('auto_prepend_file');
		$ini = trim($ini);
		$stub = $dir . DIRECTORY_SEPARATOR . self::STUB;
		$same = static fn(string $path): string => strtolower(rtrim(str_replace('\\', '/', $path), '/'));
		if($ini === '' || strtolower($ini) === 'none')
		{
			$state = 'inactive';
		}
		elseif($same($ini) === $same($stub))
		{
			$state = 'active';
		}
		elseif($legacy !== null && $same($ini) === $same($legacy))
		{
			$state = 'legacy';
		}
		else
		{
			$state = 'other';
		}
		
		return ['state' => $state, 'ini' => $ini, 'stub' => $stub];
	}
	
	/** the two lines an operator pastes — the ini form and the .htaccess form — for the settings page */
	public static function lines(
		string $dir,
	): array
	{
		$stub = $dir . DIRECTORY_SEPARATOR . self::STUB;
		
		return [
			'ini' => 'auto_prepend_file = "' . $stub . '"',
			'htaccess' => 'php_value auto_prepend_file "' . $stub . '"',
		];
	}
	
	/**
	 * Who a `user`-keyed rate rule counts on an anonymous request: the name a
	 * wp-login.php POST tries (`log`) — the spray against one account from
	 * many addresses; '' for anything else, and the rule skips the request
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $post
	 */
	public static function loginName(
		array $server,
		array $post,
	): string
	{
		$path = explode('?', (string)($server['REQUEST_URI'] ?? ''), 2)[0];
		$name = $post['log'] ?? null;
		if(str_ends_with($path, '/wp-login.php') === false || is_string($name) === false || trim($name) === '')
		{
			return '';
		}
		
		return 'login:' . strtolower(trim($name));
	}
	
	/**
	 * This layer's refusal: 403 for a match rule, 429 with Retry-After for a
	 * rate rule past its limit — the rule and the layer named, a plain body,
	 * and the request ends here
	 */
	protected static function refuse(
		int $ruleId,
		int $status = 403,
		int $retryAfter = 0,
	): void
	{
		$limited = $status === 429;
		if(headers_sent() === false)
		{
			http_response_code($limited ? 429 : 403);
			header(self::HEADER_RULE . ': ' . $ruleId);
			header(self::HEADER_LAYER . ': prepend');
			header('Content-Type: text/plain; charset=UTF-8');
			if($limited)
			{
				header('Retry-After: ' . max(1, $retryAfter));
			}
		}
		echo $limited ? 'Too Many Requests' : 'Forbidden';
		exit;
	}
}
