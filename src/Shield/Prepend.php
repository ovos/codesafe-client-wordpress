<?php
declare(strict_types=1);

namespace Ovos\Codesafe\Shield;

use Ovos\Codesafe\Shield\Consent;
use Ovos\Codesafe\Shield\Facts;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Wordpress;
use stdClass;
use Throwable;

use function array_filter;
use function array_keys;
use function array_reverse;
use function array_slice;
use function array_values;
use function basename;
use function bin2hex;
use function class_exists;
use function count;
use function define;
use function defined;
use function explode;
use function file_get_contents;
use function file_put_contents;
use function glob;
use function header;
use function headers_sent;
use function http_response_code;
use function in_array;
use function inet_pton;
use function ini_get;
use function is_array;
use function is_dir;
use function is_file;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use function max;
use function mkdir;
use function md5_file;
use function parse_str;
use function preg_match;
use function preg_replace_callback;
use function random_bytes;
use function rawurldecode;
use function rawurlencode;
use function realpath;
use function register_shutdown_function;
use function rename;
use function rtrim;
use function sprintf;
use function stat;
use function str_contains;
use function str_ends_with;
use function str_replace;
use function str_starts_with;
use function strlen;
use function strpos;
use function strtolower;
use function strtoupper;
use function strtr;
use function substr;
use function time;
use function trim;
use function unlink;
use function var_export;

use const DIRECTORY_SEPARATOR;

// the kernel is one vendored multi-class file; a plain class binds at compile
// time, so the guard sits at the require, never inside the file
try
{
	// an upgrade copies the plugin file by file: a require of a file not there yet is a fatal no catch stops
	if(class_exists(Kernel::class, false) === false && is_file(__DIR__ . DIRECTORY_SEPARATOR . 'Kernel.php'))
	{
		require_once __DIR__ . DIRECTORY_SEPARATOR . 'Kernel.php';
	}
	// WordPress's kernel module, right after the kernel and by path: it implements the
	// kernel's Platform, which no autoloader finds, and the stubs include this file with none
	if(class_exists(Wordpress::class, false) === false && is_file(__DIR__ . DIRECTORY_SEPARATOR . 'Wordpress.php'))
	{
		require_once __DIR__ . DIRECTORY_SEPARATOR . 'Wordpress.php';
	}
}
catch(Throwable)
{
	// a half-copied file, or the module before its kernel: the request goes unjudged (ready())
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
 * - a request carrying a WordPress login cookie to a file WordPress runs
 *   through is left to the plugins_loaded judge: only WordPress can say who
 *   the user is, the alarm's logged-in signal needs the user on the row, and
 *   an editor must never be refused by a layer that cannot tell them from a
 *   bot. Anywhere else — a direct hit on a plugin's file — no adapter will
 *   ever run, and the cookie's NAME proves nothing, so this layer judges
 *   (loadsWordPress(), 1.0.3); a REST request carrying Basic credentials is
 *   left to it the same way — an application password, which WordPress
 *   checks only after this layer, makes it a user's (isRest(), by the REST
 *   prefix the plugin keeps in the consent);
 * - every file it reads or writes but the stub and the kernel's ruleset
 *   begins with `<?php exit; ?>` (GUARD), and the ruleset's name is drawn at
 *   random: the directory's .htaccess is read by Apache alone (1.0.3);
 * - the consent is what the plugin last wrote (shield-consent.php): the two
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
	/**
	 * The ruleset's name before 1.0.3, a fixed one in a web-served directory.
	 * Since then the kernel's store is `shield-<24 hex>.json`, the name drawn
	 * once and kept in the consent (rules()): the kernel writes plain JSON and
	 * is not this plugin's to change, so where no .htaccess is read (nginx,
	 * IIS) an unguessable name is what keeps the CVE patterns off the web
	 * (security audit 2026-10-03 M13). migrate() renames an old one
	 */
	public const RULES = 'shield.json';
	
	/** the ruleset's name, as the consent may carry it */
	public const RULES_PATTERN = '~^shield-[0-9a-f]{24}\.json$~';
	
	/** the stub the directive points at, beside the store */
	public const STUB = 'prepend.php';
	
	/**
	 * What every file this layer and the plugin write begins with (1.0.3,
	 * M13): served by a web server that ignores the directory's .htaccess,
	 * the file is PHP that exits before a byte of its JSON goes out
	 */
	public const GUARD = "<?php exit; ?>\n";
	
	/** the consent the plugin writes for this layer */
	public const CONSENT = 'shield-consent.php';
	
	/** the blocks this layer refused before the plugin could report them */
	public const QUEUE = 'shield-reports.php';
	
	/** the names before 1.0.3 — plain JSON, served wherever .htaccess is not read — and what each became */
	public const LEGACY_FILES = [
		'shield-consent.json' => self::CONSENT,
		'shield-reports.json' => self::QUEUE,
		'entries.json' => self::ENTRIES,
		'entries-seen.json' => self::SEEN,
	];
	
	/** at most this many queued reports — a flood is counted by the hits, not narrated */
	public const QUEUE_MAX = 100;
	
	/** defined by run() so the plugins_loaded adapter knows the request was judged */
	public const MARK = 'CODESAFE_SHIELD_PREPENDED';
	
	/** defined by run() as it starts: of the prepend and the mu-plugin, the first judges and the second does nothing */
	public const RAN = 'CODESAFE_SHIELD_RAN';
	
	/** defined by run() when it judged the request and passed it: judged again at plugins_loaded, a rate rule would count it twice */
	public const JUDGED = 'CODESAFE_SHIELD_JUDGED';
	
	/** the mu-plugin the plugin keeps in WPMU_PLUGIN_DIR (ovos/codesafe docs/plans/shield-auto-deploy.md P7.g) */
	public const MU_PLUGIN = 'ovos-codesafe-shield.php';
	
	/** the mu-plugin's marker: a newer plugin rewrites an older one, and only a file carrying it is ever touched */
	public const MU_MARKER = 'ovos codesafe shield mu-plugin';
	
	public const MU_VERSION = 1;
	
	/** the global the stash rides in: ['verdict' => Verdict, 'report' => [kind, message, extra]|null, 'claimed' => bool] */
	public const STASH = 'ovos_codesafe_shield_prepend';
	
	public const HEADER_RULE = 'X-Shield-Rule';
	
	public const HEADER_LAYER = 'X-Shield-Layer';
	
	/** the stub's marker — a newer plugin rewrites an older stub */
	public const STUB_VERSION = 1;
	
	/** WordPress's login cookie prefix — a request carrying one is the adapter's to judge */
	public const LOGIN_COOKIE = 'wordpress_logged_in_';
	
	/** WordPress's REST prefix unless a filter changes it (rest_get_url_prefix()) */
	public const REST_PREFIX = 'wp-json';
	
	/** the executed-file watch's known set, exported by the plugin (Entries): {core, plugin, known: {path: core|learnt}} */
	public const ENTRIES = 'entries.php';
	
	/** the executed files waiting for the plugin's judge: {paths: {path: record}, dropped} */
	public const SEEN = 'entries-seen.php';
	
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
	 * The root entries a request runs WordPress THROUGH — every plugin loaded,
	 * plugins_loaded fired, the adapter judging with the user known. Only a
	 * request to one of these (or to wp-admin's own, loadsWordPress()) may
	 * leave a login cookie to the adapter: on any other file nothing would
	 * judge it at all (security audit 2026-10-03 M12)
	 */
	public const LOADS_WORDPRESS = ['index.php', 'wp-activate.php', 'wp-blog-header.php', 'wp-comments-post.php',
		'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-signup.php',
		'wp-trackback.php', 'xmlrpc.php'];
	
	/** wp-admin files that load WordPress without its plugins — the adapter never runs there */
	public const ADMIN_WITHOUT_PLUGINS = ['load-scripts.php', 'load-styles.php'];
	
	/**
	 * Redactor's secret names and query names, restated: this layer references
	 * no other plugin class, and a queued uri is scrubbed BEFORE it is written
	 * (M13). Tests\Prepend holds both copies equal to Redactor's
	 */
	public const SECRET_NAMES = 'pass(?:word|wd)?|pwd|token|secret|authorization|cookie|api[-_]key'
		. '|jwt|bearer|signature'
		. '|(?<![a-z])nonce|wpnonce'
		. '|rp[-_]?key'
		. '|card[-_]?(?:num(?:ber)?|no(?![a-z])|code|cvc|cvv|exp(?:iry|iration|(?![a-z])))'
		. '|cc[-_]?(?:num(?:ber)?|no(?![a-z]))'
		. '|(?<![a-z])(?:cvv2?|cvc2?|csc|ccv)(?![a-z])|security[-_]?code'
		. '|(?:account|acct)[-_]?(?:num(?:ber)?|no(?![a-z]))|(?<![a-z])iban(?![a-z])';
	
	public const QUERY_NAMES = ['key', 'auth', 'code', 'sig', 'signature', 'otp', 'pin', 'hash'];
	
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
			if(PHP_SAPI === 'cli' || defined(self::RAN))
			{
				return;
			}
			define(self::RAN, true);
			$consent = self::consent($dir);
			if($consent === null)
			{
				return;
			}
			$ip = self::clientIp($_SERVER, $consent['proxy_header'], $consent['proxies']);
			// the executed-file watch first: it records, whatever the Shield's
			// boxes say, and a signed-in request is recorded like any other
			self::entry($dir, $_SERVER, $consent);
			$ran = false;
			// the mu-plugin stage runs inside WordPress, which defined ABSPATH; the prepend layer runs before it
			$judged = self::judge($dir, $_SERVER, $_POST, $_COOKIE, null, $consent, $ran, $_GET, $_FILES, defined('ABSPATH') ? true : null);
			if($judged === null)
			{
				if($ran && defined(self::JUDGED) === false)
				{
					define(self::JUDGED, true);
				}
				
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
					self::queue($dir, $judged['report'], self::contextOf($_SERVER, $verdict->status(), $ip));
				}
				self::refuse((int)$verdict->rule['id'], $verdict->status(), $verdict->retryAfter);
			}
			// an observe verdict: the adapter claims it at plugins_loaded — unless
			// WordPress never loads for this request, when shutdown queues it
			register_shutdown_function(static fn(): bool => self::settle($dir, null, null, $ip));
		}
		catch(Throwable)
		{
			// fail open: served as if the layer were not there
		}
	}
	
	/**
	 * The pure part: the consent gate, the login-cookie rule, the judge. Null
	 * when this layer has nothing to say (no consent, detection off, kill,
	 * the kernel not ready(), a signed-in request, a REST request with Basic credentials); otherwise
	 * the verdict and the report the kernel would have sent — the adapter
	 * sends it, or the queue holds it
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $post
	 * @param array<string, mixed> $cookies
	 * @param ?array{detect: bool, enforce: bool, kill: bool, prefix: string, rest_prefix?: string} $consent the consent read already, or null to read it
	 * @param ?bool $judged set: whether the kernel judged the request (false when the layer left it alone)
	 * @param ?array<string, mixed> $get the parsed query; null = the raw URI's
	 * @param array<string, mixed> $files the uploads — a virtual patch reads their names
	 * @param ?bool $wordpress whether WordPress loads for this request: true from the mu-plugin stage, which
	 *     runs inside it; null tells it by the script (loadsWordPress())
	 * @return ?array{verdict: Verdict, report: ?array{0: string, 1: string, 2: array}}
	 */
	public static function judge(
		string $dir,
		array $server,
		array $post = [],
		array $cookies = [],
		?int $now = null,
		?array $consent = null,
		?bool &$judged = null,
		?array $get = null,
		array $files = [],
		?bool $wordpress = null,
	): ?array
	{
		$judged = false;
		$consent ??= self::consent($dir);
		if($consent === null || $consent['kill'] || $consent['detect'] === false || self::ready() === false)
		{
			return null;
		}
		$loads = $wordpress ?? self::loadsWordPress($server, (string)($consent['root'] ?? ''));
		$restPrefix = self::restPrefixOf($consent['rest_prefix'] ?? null);
		$query = $get ?? self::queryOf($server);
		// a login cookie is the adapter's — but only where WordPress runs and the
		// adapter with it; anyone can send a cookie by that NAME, and a direct hit
		// on a plugin file is the request this layer exists for (M12)
		if($loads)
		{
			foreach(array_keys($cookies) as $name)
			{
				if(str_starts_with((string)$name, self::LOGIN_COOKIE))
				{
					return null;
				}
			}
			// an application password signs a REST request in only when WordPress
			// checks it, after this layer; the adapter names its user, so the whole
			// request is its: a refusal then reports who it refused
			if(self::carriesBasicAuth($server) && self::isRest($server, $query, $post, $restPrefix))
			{
				return null;
			}
		}
		$report = null;
		$kernel = new Kernel('', '', new Store(self::rules($dir, $consent), $consent['prefix']),
			// this layer never pulls: a transport that answers nothing keeps even a mis-call harmless
			static fn(): array => ['status' => 0, 'headers' => [], 'body' => ''],
			static function(string $kind, string $message, array $extra) use (&$report): void
			{
				$report = [$kind, $message, $extra];
			}, platforms: self::platforms());
		// who WordPress will run it as is told only later for an XML-RPC call (inside each method) and a
		// REST request with a token another plugin reads; the adapter cannot name that caller either, so
		// the rules for anyone are judged here and what depends on who waits for the adapter
		$known = ($loads && (self::isXmlRpc($server) || (self::carriesToken($server) && self::isRest($server, $query, $post, $restPrefix)))) === false;
		// before WordPress: no user (the request is anonymous here) and no nonce check — a
		// virtual patch that needs one only observes
		$facts = Facts::fromServer($server, $post, static fn(): string => (string)file_get_contents('php://input'), false,
			ip: self::clientIp($server, (string)($consent['proxy_header'] ?? ''), (array)($consent['proxies'] ?? [])),
			user: self::loginName($server, $post), get: $get, cookies: $cookies, files: $files, callerKnown: $known, platforms: $kernel->platforms(),
			options: [Wordpress::OPTION_REST_PREFIX => $restPrefix]);
		$verdict = $kernel->judge($facts, new Consent(true, $consent['enforce'], false), $now);
		// a blocking vpatch this layer could not answer (a nonce it cannot check): where
		// WordPress loads, the adapter judges it with wp_verify_nonce — left to it, counted
		// nowhere yet; a junk nonce must not turn a block into an observe here
		if($verdict->reason === Verdict::REASON_UNANSWERED && $loads)
		{
			return null;
		}
		$judged = true;
		if($verdict->isPass())
		{
			return null;
		}
		$kernel->count($verdict, $now);
		$kernel->report($verdict, $facts);
		
		return ['verdict' => $verdict, 'report' => $report];
	}
	
	/**
	 * The consent as the plugin last wrote it — null when the file is not
	 * there or does not parse: the layer then does nothing. `root` is the
	 * site root the executed-file watch measures against (realpath of
	 * ABSPATH), `entries` whether that watch is on, `rules` the ruleset's
	 * name in the store (RULES_PATTERN, '' for none), `proxy_header` and
	 * `proxies` the trusted proxy the site named (clientIp()), `rest_prefix`
	 * the site's REST prefix (restPrefixOf(), WordPress's default when none)
	 *
	 * @return ?array{detect: bool, enforce: bool, kill: bool, prefix: string, root: string, entries: bool, rules: string, proxy_header: string, proxies: list<string>, rest_prefix: string}
	 */
	public static function consent(
		string $dir,
	): ?array
	{
		$decoded = self::read($dir . DIRECTORY_SEPARATOR . self::CONSENT);
		if(is_array($decoded) === false)
		{
			return null;
		}
		$rules = is_string($decoded['rules'] ?? null) && preg_match(self::RULES_PATTERN, $decoded['rules']) === 1 ? $decoded['rules'] : '';
		$header = is_string($decoded['proxy_header'] ?? null) && preg_match('~^[A-Za-z0-9-]{1,64}$~', $decoded['proxy_header']) === 1
			? $decoded['proxy_header']
			: '';
		
		return [
			'detect' => ($decoded['detect'] ?? false) === true,
			'enforce' => ($decoded['enforce'] ?? false) === true,
			'kill' => ($decoded['kill'] ?? false) === true,
			'prefix' => is_string($decoded['prefix'] ?? null) ? $decoded['prefix'] : '',
			'root' => is_string($decoded['root'] ?? null) ? $decoded['root'] : '',
			'entries' => ($decoded['entries'] ?? false) === true,
			'rules' => $rules,
			'proxy_header' => $header,
			'proxies' => is_array($decoded['proxies'] ?? null) ? array_values(array_filter($decoded['proxies'], 'is_string')) : [],
			'rest_prefix' => self::restPrefixOf($decoded['rest_prefix'] ?? null),
		];
	}
	
	/**
	 * The plugin's half: the consent written when it differs from what is
	 * there (one small read per request, one write per change). The ruleset's
	 * name is drawn once and kept: the one there, else the one given, else a
	 * new one. The REST prefix is kept unless given: the writer before
	 * plugins_loaded cannot know it (writeRestPrefix())
	 *
	 * @param array{detect: bool, enforce: bool, kill: bool, prefix: string, root?: string, entries?: bool, rules?: string, proxy_header?: string, proxies?: list<string>, rest_prefix?: string} $consent
	 * @return bool whether the file was (re)written
	 */
	public static function writeConsent(
		string $dir,
		array $consent,
	): bool
	{
		$current = self::consent($dir);
		$rules = match(true)
		{
			($current['rules'] ?? '') !== '' => $current['rules'],
			is_string($consent['rules'] ?? null) && preg_match(self::RULES_PATTERN, $consent['rules']) === 1 => $consent['rules'],
			default => 'shield-' . bin2hex(random_bytes(12)) . '.json',
		};
		$wanted = [
			'detect' => $consent['detect'] === true,
			'enforce' => $consent['enforce'] === true,
			'kill' => $consent['kill'] === true,
			'prefix' => (string)$consent['prefix'],
			'root' => (string)($consent['root'] ?? ''),
			'entries' => ($consent['entries'] ?? false) === true,
			'rules' => $rules,
			'proxy_header' => (string)($consent['proxy_header'] ?? ''),
			'proxies' => array_values(array_filter((array)($consent['proxies'] ?? []), 'is_string')),
			'rest_prefix' => self::restPrefixOf($consent['rest_prefix'] ?? $current['rest_prefix'] ?? null),
		];
		if($current === $wanted)
		{
			return false;
		}
		
		return self::write($dir . DIRECTORY_SEPARATOR . self::CONSENT, $wanted + ['written_at' => time()]);
	}
	
	/**
	 * The plugin's half at init: the site's REST prefix, every plugin's and
	 * the theme's filter applied, into the consent — rewritten only when it
	 * changed. False when it did not, or there is no consent to carry it
	 */
	public static function writeRestPrefix(
		string $dir,
		string $prefix,
	): bool
	{
		$current = self::consent($dir);
		if($current === null || $current['rest_prefix'] === self::restPrefixOf($prefix))
		{
			return false;
		}
		
		return self::writeConsent($dir, ['rest_prefix' => $prefix] + $current);
	}
	
	/** a REST prefix as the consent keeps it: without its slashes, WordPress's default when there is none */
	public static function restPrefixOf(
		mixed $prefix,
	): string
	{
		$prefix = is_string($prefix) ? trim($prefix, '/') : '';
		
		return $prefix === '' ? self::REST_PREFIX : $prefix;
	}
	
	/**
	 * The kernel modules a WordPress site's kernel reads: WordPress's own, always —
	 * its REST routes and batches, its shortcode and block attributes. This layer
	 * and the adapter hand them to the kernel and to Facts alike
	 *
	 * @return list<Platform>
	 */
	public static function platforms(): array
	{
		return [new Wordpress()];
	}
	
	/**
	 * Whether the kernel and WordPress's module both loaded: while an upgrade
	 * is still copying them, the request goes unjudged, as on a site without the Shield
	 */
	public static function ready(): bool
	{
		return class_exists(Kernel::class, false) && class_exists(Wordpress::class, false);
	}
	
	/**
	 * Whether a request is addressed to WordPress's REST API: the prefix as a
	 * path segment anywhere in the path — a site in a subdirectory and
	 * /index.php/<prefix>/ included — decoded once or twice, as WordPress
	 * matches it, or a rest_route in the form or the query that WordPress's
	 * empty() takes. Which file runs is not asked here
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $get
	 * @param array<string, mixed> $post
	 */
	public static function isRest(
		array $server,
		array $get,
		array $post,
		string $prefix,
	): bool
	{
		foreach([$post['rest_route'] ?? null, $get['rest_route'] ?? null] as $route)
		{
			if(is_string($route) && $route !== '' && $route !== '0')
			{
				return true;
			}
		}
		$uri = is_string($server['REQUEST_URI'] ?? null) ? $server['REQUEST_URI'] : '';
		$path = Facts::decodeOnce(explode('?', $uri, 2)[0]);
		$needle = '/' . self::restPrefixOf($prefix) . '/';
		
		return str_contains($path . '/', $needle) || str_contains(rawurldecode($path) . '/', $needle);
	}
	
	/**
	 * Whether the request carries HTTP Basic credentials: parsed by the server
	 * already, or still in the Authorization header, which WordPress parses
	 * itself only once it loads
	 *
	 * @param array<string, mixed> $server
	 */
	public static function carriesBasicAuth(
		array $server,
	): bool
	{
		if(isset($server['PHP_AUTH_USER']))
		{
			return true;
		}
		foreach(['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $key)
		{
			if(is_string($server[$key] ?? null) && preg_match('~^Basic ~i', $server[$key]) === 1)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Whether the request carries a token another plugin may sign it in with:
	 * an Authorization header that is no Basic credentials (Bearer, a JWT,
	 * OAuth, any other scheme)
	 *
	 * @param array<string, mixed> $server
	 */
	public static function carriesToken(
		array $server,
	): bool
	{
		foreach(['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $key)
		{
			if(is_string($server[$key] ?? null) && trim($server[$key]) !== '' && preg_match('~^Basic ~i', $server[$key]) !== 1)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/** whether the request runs WordPress's XML-RPC endpoint, whose methods sign their caller in themselves */
	public static function isXmlRpc(
		array $server,
	): bool
	{
		$script = str_replace('\\', '/', (string)($server['SCRIPT_FILENAME'] ?? ''));
		
		return strtolower(basename($script)) === 'xmlrpc.php';
	}
	
	/**
	 * The query as PHP parses it off the raw URI, for a caller without $_GET
	 *
	 * @param array<string, mixed> $server
	 * @return array<string, mixed>
	 */
	protected static function queryOf(
		array $server,
	): array
	{
		$query = [];
		$uri = is_string($server['REQUEST_URI'] ?? null) ? $server['REQUEST_URI'] : '';
		parse_str(explode('?', $uri, 2)[1] ?? '', $query);
		
		return $query;
	}
	
	/**
	 * The full path of the ruleset the kernel's store keeps — '' when there is
	 * no consent naming one: the kernel then runs on APCu alone
	 *
	 * @param ?array{rules: string} $consent the consent read already, or null to read it
	 */
	public static function rules(
		string $dir,
		?array $consent = null,
	): string
	{
		$consent ??= self::consent($dir);
		$name = (string)($consent['rules'] ?? '');
		
		return $name === '' ? '' : $dir . DIRECTORY_SEPARATOR . $name;
	}
	
	/**
	 * One of the store's files, read: the JSON after the GUARD (or a whole
	 * plain-JSON file, as a test or an older plugin writes it), null when the
	 * file is not there or does not parse
	 */
	public static function read(
		string $path,
	): mixed
	{
		if(is_file($path) === false)
		{
			return null;
		}
		$raw = (string)file_get_contents($path);
		if(str_starts_with($raw, self::GUARD))
		{
			$raw = substr($raw, strlen(self::GUARD));
		}
		
		return json_decode($raw, true);
	}
	
	/** one of the store's files, written behind the GUARD; false when it could not be */
	public static function write(
		string $path,
		mixed $data,
	): bool
	{
		$json = json_encode($data);
		
		return is_string($json) && @file_put_contents($path, self::GUARD . $json, LOCK_EX) !== false;
	}
	
	/**
	 * The store as 1.0.2 and earlier left it, brought to this version's: each
	 * plain-JSON file rewritten behind the GUARD (the queue and the seen list
	 * carry reports not sent yet), the ruleset renamed to the name the consent
	 * draws, and the old files gone. $to is where the data lives now
	 * (CODESAFE_STORE_DIR), $from by default: a store the constant moved is
	 * carried over the same way, the stub alone staying behind. Run by the
	 * plugin AFTER it wrote the consent in $to; returns how many files moved
	 */
	public static function migrate(
		string $from,
		?string $to = null,
	): int
	{
		$to ??= $from;
		$moved = 0;
		$files = self::LEGACY_FILES;
		if($to !== $from)
		{
			$files += [self::CONSENT => self::CONSENT, self::QUEUE => self::QUEUE, self::ENTRIES => self::ENTRIES, self::SEEN => self::SEEN];
		}
		foreach($files as $old => $new)
		{
			$path = $from . DIRECTORY_SEPARATOR . $old;
			if(is_file($path) === false)
			{
				continue;
			}
			$data = self::read($path);
			$target = $to . DIRECTORY_SEPARATOR . $new;
			// the consent is the plugin's, written in $to on this request; the
			// others carry what has not been judged or sent yet
			if($new !== self::CONSENT && is_array($data) && is_file($target) === false)
			{
				self::write($target, $data);
			}
			@unlink($path);
			$moved++;
		}
		$rules = self::rules($to);
		$old = glob($from . DIRECTORY_SEPARATOR . 'shield*.json') ?: [];
		foreach($old as $path)
		{
			$name = basename($path);
			if($name !== self::RULES && preg_match(self::RULES_PATTERN, $name) !== 1)
			{
				continue;
			}
			if($path === $rules)
			{
				continue;
			}
			if($rules !== '' && is_file($rules) === false && @rename($path, $rules))
			{
				$moved++;
				
				continue;
			}
			@unlink($path);
		}
		
		return $moved;
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
			self::record($dir, $relative, $file, $server, $now ?? time(),
				self::clientIp($server, (string)($consent['proxy_header'] ?? ''), (array)($consent['proxies'] ?? [])));
			
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
		$decoded = self::read($dir . DIRECTORY_SEPARATOR . self::ENTRIES);
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
		return self::write($dir . DIRECTORY_SEPARATOR . self::ENTRIES, [
			'core' => $core,
			'plugin' => $plugin,
			'known' => $known === [] ? new stdClass : $known,
			'written_at' => time(),
		]);
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
		$decoded = self::read($dir . DIRECTORY_SEPARATOR . self::SEEN);
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
		self::write($path, ['paths' => $seen['paths'] === [] ? new stdClass : $seen['paths'], 'dropped' => 0]);
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
		string $ip = '',
	): void
	{
		$path = $dir . DIRECTORY_SEPARATOR . self::SEEN;
		$seen = self::seen($dir);
		$context = self::contextOf($server, null, $ip);
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
		self::write($path, $seen);
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
	 * The mu-plugin (ovos/codesafe docs/plans/shield-auto-deploy.md P7.g): this
	 * layer's judge before the other plugins load — where a vulnerable
	 * plugin's own file has not run yet — without the server edit the prepend
	 * needs. It includes this file only while it is there, on the PHP this
	 * plugin needs, and calls run(): an anonymous request is judged, a
	 * signed-in one left to plugins_loaded. Written only when it is not the
	 * current one, never over a file by that name it did not write; '' when
	 * it is not there (the plugins_loaded judge then stands alone)
	 */
	public static function ensureMuPlugin(
		string $dir,
		string $muDir,
	): string
	{
		$path = rtrim($muDir, '/\\') . DIRECTORY_SEPARATOR . self::MU_PLUGIN;
		$source = str_replace('\\', '/', __FILE__);
		$marker = sprintf('%s v%d', self::MU_MARKER, self::MU_VERSION);
		$store = var_export($dir, true);
		if(is_file($path))
		{
			$existing = (string)file_get_contents($path);
			if(str_contains($existing, $marker) && str_contains($existing, $source) && str_contains($existing, '::run(' . $store . ')'))
			{
				return $path;
			}
			if(str_contains($existing, self::MU_MARKER) === false)
			{
				return '';
			}
		}
		if(is_dir($muDir) === false && @mkdir($muDir, 0755, true) === false && is_dir($muDir) === false)
		{
			return '';
		}
		$stub = "<?php\n"
			. "/*\n"
			. " * Plugin Name: ovos codesafe Shield, early stage\n"
			. " * Description: Judges anonymous requests against the Shield's rules before the other plugins load. Kept by the ovos codesafe plugin while its Shield is on.\n"
			. " */\n"
			. "// " . $marker . " — safe to delete: the plugin writes it again while its Shield is on.\n"
			. "// Does nothing once the plugin's Prepend.php is gone or the PHP is older than the plugin's.\n"
			. "\$ovosCodesafeShield = '" . str_replace("'", "\\'", $source) . "';\n"
			. "if(PHP_VERSION_ID >= 80300 && is_file(\$ovosCodesafeShield))\n"
			. "{\n"
			. "\t@include_once \$ovosCodesafeShield;\n"
			. "\tif(class_exists('Ovos\\\\Codesafe\\\\Shield\\\\Prepend', false))\n"
			. "\t{\n"
			. "\t\t\\Ovos\\Codesafe\\Shield\\Prepend::run(" . $store . ");\n"
			. "\t}\n"
			. "}\n"
			. "unset(\$ovosCodesafeShield);\n";
		
		return @file_put_contents($path, $stub, LOCK_EX) === false ? '' : $path;
	}
	
	/** the mu-plugin taken away — only one this plugin wrote, never another file by that name */
	public static function removeMuPlugin(
		string $muDir,
	): bool
	{
		$path = rtrim($muDir, '/\\') . DIRECTORY_SEPARATOR . self::MU_PLUGIN;
		if(is_file($path) === false || str_contains((string)file_get_contents($path), self::MU_MARKER) === false)
		{
			return false;
		}
		
		return @unlink($path);
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
		$queued = self::read($path);
		$queued = is_array($queued) ? array_values(array_filter($queued, 'is_array')) : [];
		$queued[] = ['kind' => $report[0], 'message' => $report[1], 'extra' => $report[2], 'context' => $context, 'at' => time()];
		if(count($queued) > self::QUEUE_MAX)
		{
			$queued = array_slice($queued, -self::QUEUE_MAX);
		}
		self::write($path, $queued);
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
	 * @param ?string $ip the visitor's address (clientIp()), REMOTE_ADDR by default
	 */
	public static function settle(
		string $dir,
		?array $server = null,
		?int $status = null,
		?string $ip = null,
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
		self::queue($dir, $report, self::contextOf($server ?? $_SERVER, $status, $ip));
		
		return true;
	}
	
	/**
	 * The refused request's own facts for its row — the plugin reports a
	 * queued verdict from a LATER request, whose URI, address and user agent
	 * are somebody else's; the console's offender score follows the ip. The
	 * uri and referer are scrubbed HERE, before the file holds them (scrubUri(),
	 * M13) — the adapter scrubs them again with the Redactor on the drain;
	 * the rest is raw (no WordPress to sanitize with)
	 *
	 * @param array<string, mixed> $server
	 * @param ?string $ip the visitor's address (clientIp()), REMOTE_ADDR by default
	 * @return array<string, int|string>
	 */
	public static function contextOf(
		array $server,
		?int $status,
		?string $ip = null,
	): array
	{
		$context = [
			'uri' => self::scrubUri(trim((string)($server['REQUEST_URI'] ?? ''))),
			'method' => trim((string)($server['REQUEST_METHOD'] ?? '')),
			'ip' => trim($ip ?? (string)($server['REMOTE_ADDR'] ?? '')),
			'ua' => trim((string)($server['HTTP_USER_AGENT'] ?? '')),
			'referer' => self::scrubUri(trim((string)($server['HTTP_REFERER'] ?? ''))),
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
		$queued = self::read($path);
		if($queued === [])
		{
			return 0;
		}
		self::write($path, []);
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
	 * Whether the file this request runs is one WordPress runs through — a
	 * root entry of LOADS_WORDPRESS, or a file directly in wp-admin/,
	 * wp-admin/network/ or wp-admin/user/ but the two that load no plugin —
	 * measured against the site root the consent carries. False when the root
	 * is unknown or the file is outside it: then nothing proves the adapter
	 * will judge, and this layer does
	 *
	 * @param array<string, mixed> $server
	 */
	public static function loadsWordPress(
		array $server,
		string $root,
	): bool
	{
		$script = $server['SCRIPT_FILENAME'] ?? '';
		$file = $root !== '' && is_string($script) && $script !== '' ? realpath($script) : false;
		if($file === false)
		{
			return false;
		}
		$file = str_replace('\\', '/', $file);
		$root = rtrim(str_replace('\\', '/', $root), '/') . '/';
		if(str_starts_with($file, $root) === false)
		{
			return false;
		}
		$relative = substr($file, strlen($root));
		if(in_array($relative, self::LOADS_WORDPRESS, true))
		{
			return true;
		}
		
		return preg_match('~^wp-admin/(?:(?:network|user)/)?([a-z0-9_-]+\.php)$~', $relative, $match) === 1
			&& in_array($match[1], self::ADMIN_WITHOUT_PLUGINS, true) === false;
	}
	
	/**
	 * The visitor's address (security audit 2026-10-03 M5): REMOTE_ADDR, unless
	 * a header is named AND REMOTE_ADDR is in one of the trusted ranges — then
	 * the address that header carries. A list (X-Forwarded-For) is walked from
	 * the right, past every hop a trusted proxy added, to the first that is
	 * not one; anything that is not an address falls back to REMOTE_ADDR. The
	 * one rule for the whole plugin: the Sender, the security events and the
	 * adapter call this, the layer reads its header and ranges from the consent
	 *
	 * @param array<string, mixed> $server
	 * @param list<string> $ranges CIDRs or bare addresses (Kernel::inCidr)
	 */
	public static function clientIp(
		array $server,
		string $header = '',
		array $ranges = [],
	): string
	{
		$remote = trim(is_string($server['REMOTE_ADDR'] ?? null) ? $server['REMOTE_ADDR'] : '');
		if($header === '' || $ranges === [] || self::trusted($remote, $ranges) === false)
		{
			return $remote;
		}
		$value = $server['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? null;
		if(is_string($value) === false || trim($value) === '')
		{
			return $remote;
		}
		$visitor = $remote;
		foreach(array_reverse(explode(',', $value)) as $hop)
		{
			$hop = self::bareAddress($hop);
			if($hop === '')
			{
				return $remote;
			}
			$visitor = $hop;
			if(self::trusted($hop, $ranges) === false)
			{
				break;
			}
		}
		
		return $visitor;
	}
	
	/** whether an address is in one of the ranges */
	protected static function trusted(
		string $address,
		array $ranges,
	): bool
	{
		// the kernel not loaded (an upgrade still copying it): no range can be checked, so no header is trusted
		if(class_exists(Kernel::class, false) === false)
		{
			return false;
		}
		foreach($ranges as $range)
		{
			if(is_string($range) && Kernel::inCidr($range, $address))
			{
				return true;
			}
		}
		
		return false;
	}
	
	/** one hop of a forwarding header as a bare address — a port or IPv6 brackets dropped — '' when it is none */
	protected static function bareAddress(
		string $hop,
	): string
	{
		$hop = trim($hop);
		if(preg_match('~^\[([0-9A-Fa-f:.]+)\](?::\d+)?$~', $hop, $match) === 1)
		{
			$hop = $match[1];
		}
		elseif(preg_match('~^(\d{1,3}(?:\.\d{1,3}){3}):\d+$~', $hop, $match) === 1)
		{
			$hop = $match[1];
		}
		
		return @inet_pton($hop) === false ? '' : $hop;
	}
	
	/**
	 * A uri scrubbed before this layer writes it to a file (M13): the value of
	 * every secret-named query parameter (SECRET_NAMES, QUERY_NAMES) dropped,
	 * the name judged DECODED — percent-encoded, behind an encoded `=`
	 * (`token%3Dx`), or inside a URL carried as a value (wp-login's
	 * redirect_to) — exactly as Redactor::scrubUrl() judges it. SECRETS only
	 * since 1.0.6: the e-mails and usernames stay, as everywhere the plugin
	 * reports to codesafe, which masks them on arrival and keeps the original
	 * for an audited reveal (codesafe docs/plans/identity-round-2026-10.md).
	 * The adapter's Redactor adds what only it knows (token-shaped path
	 * segments) on the drain; Tests\Prepend holds the two equal on queries
	 */
	public static function scrubUri(
		string $uri,
		int $depth = 0,
	): string
	{
		$at = strpos($uri, '?');
		
		return $at === false ? $uri : substr($uri, 0, $at + 1) . self::scrubQuery(substr($uri, $at + 1), $depth);
	}
	
	/** scrubUri()'s query half — Redactor::scrubQuery() with the secrets alone */
	protected static function scrubQuery(
		string $query,
		int $depth,
	): string
	{
		return (string)preg_replace_callback('~(^|&)([^&]*)~', static function(array $match) use ($depth): string
		{
			$equals = strpos($match[2], '=');
			if($match[2] === '' || $equals === false)
			{
				$decoded = self::decoded($match[2]);
				$cut = strpos($decoded, '=');
				
				return $cut !== false && self::isSecretParameter(substr($decoded, 0, $cut))
					? $match[1] . strtr(rawurlencode(substr($decoded, 0, $cut)), ['%5B' => '[', '%5D' => ']']) . '=[redacted]'
					: $match[0];
			}
			$name = substr($match[2], 0, $equals);
			if(self::isSecretParameter(self::decoded($name)))
			{
				return $match[1] . $name . '=[redacted]';
			}
			$value = self::decoded(substr($match[2], $equals + 1));
			if($depth >= 3 || str_contains($value, '=') === false)
			{
				return $match[0];
			}
			$clean = str_contains($value, '?') ? self::scrubUri($value, $depth + 1) : self::scrubQuery($value, $depth + 1);
			
			return $clean === $value
				? $match[0]
				: $match[1] . $name . '=' . strtr(rawurlencode($clean), ['%40' => '@', '%2A' => '*', '%5B' => '[', '%5D' => ']']);
		}, $query);
	}
	
	/** a name whose value never leaves the site — Redactor::isSecretParameter() restated */
	protected static function isSecretParameter(
		string $name,
	): bool
	{
		return preg_match('/' . self::SECRET_NAMES . '/i', $name) === 1
			|| in_array(strtolower(trim($name)), self::QUERY_NAMES, true);
	}
	
	/** percent-decoded until it holds still, at most three rounds — Redactor::decoded() restated */
	protected static function decoded(
		string $value,
	): string
	{
		for($round = 0; $round < 3; $round++)
		{
			$next = rawurldecode($value);
			if($next === $value)
			{
				break;
			}
			$value = $next;
		}
		
		return $value;
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
