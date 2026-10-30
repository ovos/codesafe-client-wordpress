<?php
declare(strict_types=1);

namespace Ovos\Codesafe\Shield;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Entries;
use Ovos\Codesafe\Legacy;
use Ovos\Codesafe\Redactor;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Consent;
use Ovos\Codesafe\Shield\Facts;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Platform;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;
use Ovos\Codesafe\Shield\Wordpress;
use Throwable;
use WP_Application_Passwords;
use WP_User;

use function __;
use function _n;
use function add_action;
use function add_filter;
use function array_filter;
use function array_map;
use function ceil;
use function class_exists;
use function constant;
use function count;
use function current_user_can;
use function defined;
use function esc_html__;
use function file_get_contents;
use function file_put_contents;
use function function_exists;
use function get_current_user_id;
use function get_option;
use function get_user_by;
use function header;
use function headers_sent;
use function human_time_diff;
use function is_admin;
use function is_array;
use function is_dir;
use function is_email;
use function is_file;
use function is_int;
use function is_string;
use function is_user_logged_in;
use function is_wp_error;
use function is_writable;
use function max;
use function md5;
use function method_exists;
use function mkdir;
use function parse_str;
use function parse_url;
use function preg_replace;
use function realpath;
use function register_shutdown_function;
use function rest_get_url_prefix;
use function rtrim;
use function sanitize_text_field;
use function sprintf;
use function str_replace;
use function strpos;
use function strtolower;
use function substr;
use function time;
use function trim;
use function user_can;
use function wp_check_password;
use function wp_date;
use function wp_die;
use function wp_is_application_passwords_available;
use function wp_is_application_passwords_available_for_user;
use function wp_kses_normalize_entities;
use function wp_kses_post;
use function wp_remote_get;
use function wp_remote_retrieve_body;
use function wp_remote_retrieve_headers;
use function wp_remote_retrieve_response_code;
use function wp_unslash;
use function wp_verify_nonce;

use const DIRECTORY_SEPARATOR;
use const PHP_INT_MAX;
use const PHP_SAPI;
use const PHP_URL_QUERY;
use const WP_CONTENT_DIR;

// the kernel is one vendored multi-class file (ovos/console client-php/Shield.php,
// byte-identical here as Kernel.php); a plain class binds at compile time, so
// the guard sits at the require, never inside the file
try
{
	// an upgrade copies the plugin file by file: a require of a file not there yet is a fatal no catch stops
	if(class_exists(Kernel::class, false) === false && is_file(__DIR__ . DIRECTORY_SEPARATOR . 'Kernel.php'))
	{
		require_once __DIR__ . DIRECTORY_SEPARATOR . 'Kernel.php';
	}
	// WordPress's kernel module (Wordpress.php, byte-identical as client-php/Shield/Wordpress.php),
	// right after the kernel and by path: autoloaded first, it would not find the kernel's Platform
	if(class_exists(Wordpress::class, false) === false && is_file(__DIR__ . DIRECTORY_SEPARATOR . 'Wordpress.php'))
	{
		require_once __DIR__ . DIRECTORY_SEPARATOR . 'Wordpress.php';
	}
}
catch(Throwable)
{
	// a half-copied file, or the module before its kernel: no kernel is built, every hook fails open
}

/**
 * The Shield in WordPress — the adapter around the console's request-side
 * kernel (Kernel.php beside this file). The kernel pulls this site's LIVE
 * exploit rules from the console the plugin already reports to (the request
 * shapes of the CVEs the software inventory matched), judges every request
 * against them before WordPress runs, and reports a match as a security
 * event; this class reads the site owner's consent, names the store, hands
 * the match to the Sender and turns a `block` into WordPress's own 403.
 *
 * Consent is two settings, on by default, read per request and never cached
 * in the ruleset — switching one off stops the next request, not the next
 * pull: `shield_detect` (pull and OBSERVE, report matches, block nothing; off
 * with CODESAFE_SHIELD_DETECT false) and `shield_enforce` (403 on a rule set
 * to BLOCK, inert without detection; off with CODESAFE_SHIELD_ENFORCE
 * false). `CODESAFE_SHIELD_KILL`
 * is a constant only: off entirely, no network — the switch for a host that
 * must never call home. Four gates stand before any request is refused: the
 * console's per-project switch, the rule's `block` mode, and these two.
 *
 * Hooked at `plugins_loaded`, priority 0 — every plugin has loaded, nothing
 * of the application has run (an mu-plugin fires earlier but a normal plugin
 * is not loaded yet when it does). The store is APCu plus a ruleset file
 * under `WP_CONTENT_DIR/ovos-codesafe/` (or CODESAFE_STORE_DIR) whose name the
 * consent draws, beside files that each begin with a PHP exit, behind a deny
 * .htaccess and an index.php; a host without APCu runs on the file alone. On
 * a multisite network the main site alone drives it. The pull rides a
 * shutdown function: one cache read per request, a conditional GET only
 * when the kernel's five-minute interval is due.
 *
 * Who the request is, is asked as WordPress will answer it (caller()). At
 * plugins_loaded a REST request is not authenticated yet: an application
 * password in Basic credentials is checked here, read-only, and is its
 * user; a login cookie without a valid wp_rest nonce is no one, as
 * WordPress runs it. A caller WordPress tells only later — a REST request
 * with a token another plugin reads, every XML-RPC call — is unknown to the
 * kernel: what depends on who it is waits, and the request is judged again
 * where WordPress has settled the user (judgeRequest()). What cannot be told
 * is held, never refused.
 *
 * Fails open on everything: the shield may never be why a page does not
 * load.
 *
 * The optional layer BEFORE this one (Prepend, ovos/console docs/plans/
 * shield-prepend.md): an operator may point PHP's auto_prepend_file at the
 * stub in the store directory, and anonymous requests are then judged
 * before WordPress exists — direct hits on plugin files included. This
 * adapter keeps that layer fed (the consent file and the stub, synced on
 * every request), reports what it stashed instead of judging twice, and
 * drains the blocks it queued.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
final class Adapter
{
	/** plugins_loaded: before any plugin's own hooks at the default priority */
	public const HOOK_PRIORITY = 0;
	
	public const DIR = 'ovos-codesafe';
	
	/** the store directory under the plugin's first name, ovos-console */
	public const LEGACY_DIR = 'ovos-console';
	
	public const FILE = Prepend::RULES;
	
	public const HEADER_RULE = 'X-Shield-Rule';
	
	/** the rollup field prefix of each outcome the kernel store counts: the verdicts, then a vpatch's evidence (Kernel::tallied()) */
	public const HIT_FIELDS = ['so:' => 'observe', 'sb:' => 'block', 'se:' => 'entry', 'sm:' => 'match', 'sa:' => 'authed'];
	
	/** what checking an application password needs of WordPress — all of it loaded by plugins_loaded */
	protected const APPLICATION_PASSWORD_FUNCTIONS = ['wp_is_application_passwords_available',
		'wp_is_application_passwords_available_for_user', 'get_user_by', 'is_email'];
	
	protected ?Kernel $kernel = null;
	
	protected ?string $prefix = null;
	
	/**
	 * The request held until WordPress has settled its caller: what it was
	 * judged on, and the verdict that waits (judgeRequest())
	 *
	 * @var ?array{request: array{0: array, 1: array, 2: array, 3: array, 4: array}, ip: string, restPrefix: string, facts: Facts, verdict: Verdict}
	 */
	protected ?array $held = null;
	
	/** @var array<string, true> the store directories this request has made sure of */
	protected static array $made = [];
	
	/**
	 * What hears the software version the pull's answer carries
	 * (X-Codesafe-Software) — the inventory's nudge; null = nothing listens
	 *
	 * @var callable(string): mixed|null
	 */
	protected $software = null;
	
	/** $kernel stands in for the one kernel() builds from the configuration */
	public function __construct(
		protected Config $config,
		protected Sender $sender,
		?Kernel $kernel = null,
	)
	{
		$this->kernel = $kernel;
	}
	
	public function register(): void
	{
		add_action('plugins_loaded', [$this, 'judge'], self::HOOK_PRIORITY);
		register_shutdown_function([$this, 'tick']);
	}
	
	/** the software version on the pull's answer goes to $hook — the inventory's nudge */
	public function onSoftware(
		callable $hook,
	): void
	{
		$this->software = $hook;
	}
	
	/** the plugin's master switch and transport, detection ticked, the kill constant not set */
	public function isEnabled(): bool
	{
		return $this->config->enabled()
			&& $this->config->url() !== ''
			&& $this->config->apiKey() !== ''
			&& $this->consent()->active();
	}
	
	/** the site owner's word, read now — never from the cached ruleset */
	public function consent(): Consent
	{
		return new Consent(
			$this->config->shieldDetect(),
			$this->config->shieldEnforce(),
			$this->config->shieldKill(),
		);
	}
	
	/** plugins_loaded: judge, count, report, tally the evidence — and refuse a block the WordPress way */
	public function judge(): void
	{
		try
		{
			if(PHP_SAPI === 'cli' || $this->isEnabled() === false)
			{
				return;
			}
			// the blocks the prepend layer refused since the last request, through the
			// Sender now — HERE, at plugins_loaded, because the Sender flushes its queue
			// at shutdown before this adapter's own tick runs, and a report handed over
			// in the tick would have been lost (the bed found exactly that, 2026-09-24)
			$dir = self::storeDir();
			if($dir !== '')
			{
				Prepend::drain($dir, fn(string $kind, string $message, array $extra, array $context) => $this->sender->reportRefusal($kind, $message, $extra, self::drained($context)));
			}
			// asked first: it settles the current user, and with it $wp_rest_auth_cookie
			$signedIn = function_exists('is_user_logged_in') && is_user_logged_in();
			$restPrefix = self::restPrefix();
			// xmlrpc.php says so before it loads WordPress
			$xmlrpc = defined('XMLRPC_REQUEST') && constant('XMLRPC_REQUEST') === true;
			// plugins_loaded runs before wp_magic_quotes(): the superglobals are still unslashed
			$caller = self::caller($_SERVER, $_GET, $_POST, $signedIn, self::servesRest($_SERVER, $_GET, $_POST, $restPrefix), $xmlrpc);
			// $_REQUEST as PHP built it: WordPress rebuilds it from the query and the form only after plugins_loaded
			$request = [$_SERVER, $_GET, $_POST, $_COOKIE, $_FILES, $_REQUEST];
			// the prepend layer judged this request already: one verdict, one count —
			// this hook only lends it the Sender, with the request's full context;
			// claiming the stash tells the layer's shutdown that it need not queue it
			if(defined(Prepend::MARK))
			{
				$report = Prepend::claim();
				if($report !== null)
				{
					$extra = $report[2];
					$extra['layer'] = 'prepend';
					$this->sender->reportRefusal($report[0], $report[1], $extra);
				}
				$this->tallyRequest($request, $caller, $this->sender->clientIp(), $restPrefix);
				
				return;
			}
			// the mu-plugin or the prepend judged it and passed it: judged again
			// here, a rate rule would count it twice — only its evidence is counted
			if(defined(Prepend::JUDGED))
			{
				$this->tallyRequest($request, $caller, $this->sender->clientIp(), $restPrefix);
				
				return;
			}
			$this->judgeRequest($request, $caller, $this->sender->clientIp(), $restPrefix, $xmlrpc);
		}
		catch(Throwable)
		{
			// fail open: served as if the shield were not there
		}
	}
	
	/**
	 * One request judged — counted, reported, a block refused — for the
	 * caller WordPress runs it as. When that caller waits on WordPress
	 * (caller() `known` false) and so does the verdict, it is held instead:
	 * judged again where WordPress has settled the user (judgeAgain(), on
	 * rest_pre_dispatch for REST, after its authentication, or on
	 * xmlrpc_call, after an XML-RPC method's login), else settled as the
	 * observe it was on WordPress's shutdown (settleHeld()). The verdict,
	 * null while held
	 *
	 * @param array{0: array<string, mixed>, 1: array<string, mixed>, 2: array<string, mixed>, 3: array<string, mixed>, 4: array<string, mixed>} $request
	 *     the server parameters, the query, the form, the cookies and the uploads
	 * @param array{authed: bool, user: string, can: ?Closure(string): bool, nonce: ?Closure(string, string): bool, known?: bool} $caller
	 */
	public function judgeRequest(
		array $request,
		array $caller,
		string $ip,
		string $restPrefix,
		bool $xmlrpc = false,
	): ?Verdict
	{
		$facts = self::facts($request[0], $request[1], $request[2], $request[3], $request[4], $caller, $ip, $restPrefix, $request[5] ?? null);
		$verdict = $this->kernel()->judge($facts, $this->consent());
		if(($caller['known'] ?? true) === false && $verdict->reason === Verdict::REASON_UNANSWERED)
		{
			$this->held = ['request' => $request, 'ip' => $ip, 'restPrefix' => $restPrefix, 'facts' => $facts, 'verdict' => $verdict];
			if(function_exists('add_filter') && function_exists('add_action'))
			{
				$xmlrpc ? add_action('xmlrpc_call', [$this, 'judgeAgain'], self::HOOK_PRIORITY) : add_filter('rest_pre_dispatch', [$this, 'judgeAgain'], self::HOOK_PRIORITY);
				// WordPress's shutdown action runs before the plugins' shutdown functions, the Sender's flush among them
				add_action('shutdown', [$this, 'settleHeld'], self::HOOK_PRIORITY);
			}
			
			return null;
		}
		$this->settle($facts, $verdict);
		
		return $verdict;
	}
	
	/**
	 * The held request judged again, once, for the caller WordPress has
	 * settled by now — $caller when given, else the current user — and
	 * counted, reported and refused as any verdict. A filter's value goes
	 * back unchanged; never throws
	 *
	 * @param ?array{authed: bool, user: string, can: ?Closure(string): bool, nonce: ?Closure(string, string): bool, known?: bool} $caller
	 */
	public function judgeAgain(
		mixed $result = null,
		?array $caller = null,
	): mixed
	{
		try
		{
			$held = $this->held;
			if($held === null)
			{
				return $result;
			}
			$this->held = null;
			[$server, $get, $post, $cookies, $files] = $held['request'];
			$bag = $held['request'][5] ?? null;
			// WordPress has authenticated the request by now: the current user is the one it runs
			$caller ??= self::caller($server, $get, $post, function_exists('is_user_logged_in') && is_user_logged_in(), false);
			$facts = self::facts($server, $get, $post, $cookies, $files, $caller, $held['ip'], $held['restPrefix'], $bag);
			$this->settle($facts, $this->kernel()->judge($facts, $this->consent()));
		}
		catch(Throwable)
		{
			// fail open: served as if the shield were not there
		}
		
		return $result;
	}
	
	/**
	 * The evidence of a request an earlier layer judged — the vpatches it
	 * reached and the counting's heartbeat (Kernel::tally()) — for the caller
	 * WordPress runs it as, which the layer before WordPress could not tell.
	 * Judged nothing, counted nothing else; never throws
	 *
	 * @param array{0: array<string, mixed>, 1: array<string, mixed>, 2: array<string, mixed>, 3: array<string, mixed>, 4: array<string, mixed>} $request
	 * @param array{authed: bool, user: string, can: ?Closure(string): bool, nonce: ?Closure(string, string): bool, known?: bool} $caller
	 */
	public function tallyRequest(
		array $request,
		array $caller,
		string $ip,
		string $restPrefix,
	): void
	{
		try
		{
			$this->kernel()->tally(self::facts($request[0], $request[1], $request[2], $request[3], $request[4], $caller, $ip, $restPrefix, $request[5] ?? null),
				$this->consent());
		}
		catch(Throwable)
		{
			// a lost count never breaks the host site
		}
	}
	
	/** WordPress's shutdown: a held verdict nobody judged again is the observe it was, counted and reported once */
	public function settleHeld(): void
	{
		try
		{
			$held = $this->held;
			$this->held = null;
			if($held !== null)
			{
				$this->settle($held['facts'], $held['verdict']);
			}
		}
		catch(Throwable)
		{
			// never break the host site
		}
	}
	
	/** a verdict counted, reported and its evidence tallied as Kernel::handle() would, and a block refused the WordPress way */
	protected function settle(
		Facts $facts,
		Verdict $verdict,
	): void
	{
		$kernel = $this->kernel();
		if($verdict->isPass() === false)
		{
			$kernel->count($verdict);
			$kernel->report($verdict, $facts);
		}
		// before the refusal: wp_die() ends the request
		$kernel->tally($facts, $this->consent());
		if($verdict->isBlock() && $verdict->rule !== null)
		{
			$this->refuse((int)$verdict->rule['id'], $verdict->status(), $verdict->retryAfter);
		}
	}
	
	/** shutdown: the conditional GET when the interval is due — off under kill or without detection */
	public function tick(): void
	{
		try
		{
			if(PHP_SAPI === 'cli' || $this->isEnabled() === false)
			{
				return;
			}
			$this->kernel()->pull($this->consent());
		}
		catch(Throwable)
		{
			// never break the host site
		}
	}
	
	/**
	 * The rules' hits of one minute as rollup fields — `so:<id>` observed,
	 * `sb:<id>` blocked — taken from the kernel store once, for the Rollup's
	 * flush hook; nothing while the shield is not enabled
	 *
	 * @return array<string, int>
	 */
	public function hits(
		int $minute,
	): array
	{
		if($this->isEnabled() === false)
		{
			return [];
		}
		$fields = [];
		foreach($this->kernel()->store()->takeHits($minute) as $id => $counts)
		{
			foreach(self::HIT_FIELDS as $prefix => $outcome)
			{
				if(($counts[$outcome] ?? 0) > 0)
				{
					$fields[$prefix . $id] = $counts[$outcome];
				}
			}
		}
		
		return $fields;
	}
	
	/**
	 * The settings page's one line about the Shield (Settings::shieldStatusRow):
	 * why it is off, or what the store holds — the rules live, how many of
	 * them are set to BLOCK and so may block, when the ruleset was pulled, and
	 * whether this site blocks. Read off the store alone, no network, and only
	 * a record sealed under this site's key counts; a consent file the early
	 * layers judge by that the plugin could not rewrite is said with it.
	 * $dir is the store directory, storeDir() by default
	 */
	public function status(
		?string $dir = null,
	): string
	{
		if($this->config->shieldKill())
		{
			return __('off — CODESAFE_SHIELD_KILL is set: nothing is pulled, nothing is matched, no one is called.', 'ovos-codesafe');
		}
		if($this->config->shieldDetect() === false)
		{
			return __('off — CODESAFE_SHIELD_DETECT switches detection off on this site: no rules are pulled and no request is matched.', 'ovos-codesafe');
		}
		if($this->config->enabled() === false || $this->config->url() === '' || $this->config->apiKey() === '')
		{
			return __('off — the console URL and API key above are what the rules are pulled with.', 'ovos-codesafe');
		}
		$line = $this->storeLine();
		$dir ??= self::storeDir();
		$consent = $dir . DIRECTORY_SEPARATOR . Prepend::CONSENT;
		
		return match(self::staleConsent($this->config, $dir))
		{
			'seal' => $line . ' ' . sprintf(
				/* translators: %s: the consent file's path */
				__('WARNING: the layers before WordPress (the auto_prepend_file stub, the must-use plugin) cannot read the rules: their consent file %s was not rewritten after the API key changed, so requests are judged only at plugins_loaded and direct hits on plugin files pass unjudged. Check that the web server can write that file and its directory.', 'ovos-codesafe'), $consent),
			'settings' => $line . ' ' . sprintf(
				/* translators: %s: the consent file's path */
				__('WARNING: the layers before WordPress (the auto_prepend_file stub, the must-use plugin) judge by switches this page no longer shows: their consent file %s could not be rewritten. Check that the web server can write that file and its directory.', 'ovos-codesafe'), $consent),
			default => $line,
		};
	}
	
	/**
	 * What the store holds, as the kernel judges by it: the rules live, how
	 * many may block, when they were pulled, whether this site blocks
	 */
	protected function storeLine(): string
	{
		try
		{
			$kernel = $this->kernel();
			$record = $kernel->store()->read();
			// as the kernel judges by it: sealed under this site's key and pulled with its modules, else no ruleset at all
			$ruleset = Ruleset::fromRecord($record, Kernel::sealKey($this->config->apiKey()),
				array_map(static fn(Platform $platform): string => $platform->name(), $kernel->platforms()));
		}
		catch(Throwable)
		{
			$record = null;
			$ruleset = null;
		}
		if(is_array($record) === false)
		{
			return __('no ruleset yet — the first request after saving pulls it from the console (then every five minutes).', 'ovos-codesafe');
		}
		// planted, sealed under another key, or unsealed: the kernel judges nothing by it and pulls the ruleset whole
		if($ruleset === null)
		{
			return __('no ruleset in use — the stored one is not sealed under this site\'s key (another key, an older plugin version, or not written by this plugin) and is ignored; the ruleset is pulled whole from the console at the end of this request.', 'ovos-codesafe');
		}
		// what the pull writes in a refused record's place while the console does not answer
		if($ruleset->isRefused())
		{
			return __('no ruleset in use — the stored one was not sealed under this site\'s key and the console has not answered the pull that replaces it yet; it is asked again every five minutes.', 'ovos-codesafe');
		}
		$rules = $ruleset->rules;
		$blocks = 0;
		foreach($rules as $rule)
		{
			// `block`, or `proven` from a codesafe before rule modes
			if(is_array($rule) && Ruleset::blocks($rule['mode'] ?? ''))
			{
				$blocks++;
			}
		}
		$fetchedAt = $ruleset->fetchedAt;
		$pulled = $fetchedAt > 0
			? sprintf(
				/* translators: 1: a time of day, 2: a human duration such as "3 mins" */
				__('pulled %1$s (%2$s ago)', 'ovos-codesafe'), wp_date('H:i', $fetchedAt), human_time_diff($fetchedAt, time()))
			: __('never pulled', 'ovos-codesafe');
		$blocking = $this->config->shieldEnforce()
			? __('blocking ON — a request a rule set to BLOCK matches is answered 403', 'ovos-codesafe')
			: __('blocking off — every match is reported, nothing is refused', 'ovos-codesafe');
		$line = sprintf(
			/* translators: 1: number of live rules, 2: number of rules set to block, 3: when the ruleset was pulled, 4: the blocking state */
			_n('%1$d rule live, %2$d of them set to BLOCK — %3$s · %4$s', '%1$d rules live, %2$d of them set to BLOCK — %3$s · %4$s', count($rules), 'ovos-codesafe'),
			count($rules), $blocks, $pulled, $blocking);
		if($ruleset->usable === false)
		{
			$line .= ' ' . __('The last pull carried a ruleset this version cannot run; the rules above are the ones kept.', 'ovos-codesafe');
		}
		
		return $line;
	}
	
	/**
	 * Whether the consent the early layers read lags behind this request's
	 * configuration — syncPrepend() rewrites it on every request, so a lag is
	 * a file the plugin could not write (its owner, its permissions, a
	 * read-only filesystem): 'seal' when it holds another key's seal, so
	 * those layers read no rules; 'settings' when another field differs;
	 * '' when it is current, or there is none to compare
	 */
	protected static function staleConsent(
		Config $config,
		string $dir,
	): string
	{
		try
		{
			$written = $dir === '' ? null : Prepend::consent($dir);
			if($written === null)
			{
				return '';
			}
			$wanted = self::consentOf($config);
			if($written['seal'] !== $wanted['seal'])
			{
				return 'seal';
			}
			foreach($wanted as $field => $value)
			{
				if(($written[$field] ?? null) !== $value)
				{
					return 'settings';
				}
			}
		}
		catch(Throwable)
		{
			// the settings page never fails over this line
		}
		
		return '';
	}
	
	/**
	 * codesafe's answer said the project's ruleset version (an ingest answer's
	 * `shield`, ovos/codesafe docs/plans/shield-auto-deploy.md P7.d): the
	 * kernel pulls on its next tick when it differs. Nothing while the
	 * shield is off
	 */
	public function nudge(
		string $version,
	): bool
	{
		try
		{
			return $this->isEnabled() && $this->kernel()->nudge($version);
		}
		catch(Throwable)
		{
			return false;
		}
	}
	
	public function kernel(): Kernel
	{
		return $this->kernel ??= new Kernel(
			$this->config->url(),
			$this->config->apiKey(),
			new Store($this->file(), $this->prefix()),
			[$this, 'transport'],
			fn(string $kind, string $message, array $extra) => $this->sender->reportRefusal($kind, $message, $extra),
			// WordPress's module: without it the pull would leave every REST, shortcode and block rule out
			platforms: Prepend::platforms(),
		);
	}
	
	/**
	 * The durable tier: the ruleset in the store directory under the name the
	 * consent drew (Prepend::rules) — JSON that is never included, and that no
	 * one can ask a web server for by name. '' when there is no store or no
	 * consent yet: the kernel runs on APCu alone, or fails open
	 */
	public function file(): string
	{
		$dir = self::storeDir();
		
		return $dir === '' ? '' : Prepend::rules($dir);
	}
	
	/**
	 * Where the store's DATA lives — the consent, the ruleset, the queued
	 * reports and the executed-file lists: the directory CODESAFE_STORE_DIR
	 * names when it is set and can be written (an absolute path OUTSIDE the
	 * document root is what it is for — security audit 2026-10-03 M13), else
	 * the stub's own directory under wp-content. '' when neither can be
	 * written
	 */
	public static function storeDir(): string
	{
		$named = defined('CODESAFE_STORE_DIR') ? trim((string)constant('CODESAFE_STORE_DIR')) : '';
		if($named !== '')
		{
			$dir = self::made(rtrim($named, '/\\'));
			if($dir !== '')
			{
				return $dir;
			}
		}
		
		return self::stubDir();
	}
	
	/**
	 * wp-content/ovos-codesafe/, made once with its deny .htaccess and
	 * index.php: where the prepend stub lives whatever CODESAFE_STORE_DIR says
	 * — the path an operator pasted into PHP's configuration never moves —
	 * and the data with it unless the constant moves that. '' when
	 * wp-content is not there or cannot be written
	 */
	public static function stubDir(): string
	{
		if(defined('WP_CONTENT_DIR') === false)
		{
			return '';
		}
		
		return self::made(rtrim((string)WP_CONTENT_DIR, '/\\') . DIRECTORY_SEPARATOR . self::DIR);
	}
	
	/**
	 * The store's directories spelled as storeDir(), stubDir() and
	 * legacyStub() spell them, creating nothing: the integrity scan reads the
	 * store and may not write. The spelling matters, since the stub and the
	 * mu-plugin carry the data directory's path as PHP source. '' for a
	 * directory that cannot be named
	 *
	 * @return array{store: string, stub: string, legacy: string}
	 */
	public static function storePaths(): array
	{
		$content = defined('WP_CONTENT_DIR') ? rtrim((string)WP_CONTENT_DIR, '/\\') : '';
		$stub = $content === '' ? '' : $content . DIRECTORY_SEPARATOR . self::DIR;
		$named = defined('CODESAFE_STORE_DIR') ? rtrim(trim((string)constant('CODESAFE_STORE_DIR')), '/\\') : '';
		
		return [
			// storeDir() falls back to the stub's directory when the named one cannot be written
			'store' => $named !== '' && is_dir($named) && is_writable($named) ? $named : $stub,
			'stub' => $stub,
			'legacy' => $content === '' ? '' : $content . DIRECTORY_SEPARATOR . self::LEGACY_DIR,
		];
	}
	
	/**
	 * Whether the store's data is out of the web's reach by its PLACE — the
	 * CODESAFE_STORE_DIR directory, or a server that reads the deny .htaccess
	 * (Apache, LiteSpeed). Elsewhere the files' GUARD and the ruleset's drawn
	 * name are what protect them, and the settings page says so
	 */
	public static function storeIsShielded(): bool
	{
		$data = self::storeDir();
		
		return ($data !== '' && $data !== self::stubDir()) || self::readsHtaccess();
	}
	
	/** WordPress's own answer to "does this server read .htaccess" — Apache and LiteSpeed */
	public static function readsHtaccess(): bool
	{
		return ($GLOBALS['is_apache'] ?? false) === true;
	}
	
	/** a store directory, made with its deny .htaccess and index.php when it is not there; '' when it cannot be */
	protected static function made(
		string $dir,
	): string
	{
		// asked several times a request (the sync, the drain, the store, the
		// watch): the stats are paid once
		if(isset(self::$made[$dir]))
		{
			return $dir;
		}
		try
		{
			if(is_dir($dir) === false && @mkdir($dir, 0755, true) === false)
			{
				return '';
			}
			if(is_writable($dir) === false)
			{
				return '';
			}
			if(is_file($dir . DIRECTORY_SEPARATOR . '.htaccess') === false)
			{
				@file_put_contents($dir . DIRECTORY_SEPARATOR . '.htaccess', "# ovos codesafe: the shield's rule cache is read by PHP alone\nRequire all denied\n");
			}
			if(is_file($dir . DIRECTORY_SEPARATOR . 'index.php') === false)
			{
				@file_put_contents($dir . DIRECTORY_SEPARATOR . 'index.php', "<?php\n// silence is golden\n");
			}
		}
		catch(Throwable)
		{
			return '';
		}
		self::$made[$dir] = true;
		
		return $dir;
	}
	
	/**
	 * The prepend layer kept fed (ovos/console docs/plans/shield-prepend.md):
	 * the consent file with the two checkboxes, the kill constant and the store
	 * prefix as this request read them, rewritten only when it changed, and
	 * the stub the directive points at. Runs on every request whether or not
	 * detection is on — an unticked box has to reach the layer too. Never
	 * throws
	 */
	public static function syncPrepend(
		Config $config,
	): void
	{
		try
		{
			// on a multisite network the store is ONE for every site and the
			// layer cannot tell them apart: the main site's word alone (M14)
			if(PHP_SAPI === 'cli' || $config->ownsSharedStore() === false)
			{
				return;
			}
			$dir = self::storeDir();
			$stubDir = self::stubDir();
			if($dir === '' || $stubDir === '')
			{
				return;
			}
			$consent = self::consentOf($config);
			Prepend::writeConsent($dir, $consent);
			// 1.0.2's plain-JSON files, or a store CODESAFE_STORE_DIR has moved since
			if(is_file($stubDir . DIRECTORY_SEPARATOR . 'shield-consent.json')
				|| ($dir !== $stubDir && is_file($stubDir . DIRECTORY_SEPARATOR . Prepend::CONSENT)))
			{
				Prepend::migrate($stubDir, $dir);
			}
			// the stub stays where the operator's configuration names it; it judges
			// against the data wherever that lives
			Prepend::ensureStub($dir, $dir === $stubDir ? null : $stubDir . DIRECTORY_SEPARATOR . Prepend::STUB);
			// PHP may still name an older stub — this directory's prepend.php, or
			// the one ovos-console left: kept running this plugin, never deleted
			// while named, since PHP fails every request whose prepend file is gone
			Prepend::tendOldStub($dir, $stubDir, Prepend::status($stubDir, null, self::legacyStub() ?: null));
			$judges = $consent['detect'] && $consent['kill'] === false;
			// the mu-plugin stage (ovos/codesafe docs/plans/shield-auto-deploy.md P7.g):
			// the judge before the other plugins load, kept while the Shield is on
			if(defined('WPMU_PLUGIN_DIR'))
			{
				if($judges)
				{
					Prepend::ensureMuPlugin($dir, (string)constant('WPMU_PLUGIN_DIR'));
				}
				else
				{
					Prepend::removeMuPlugin((string)constant('WPMU_PLUGIN_DIR'));
				}
			}
			// the REST prefix the early layers tell a REST request by: known only
			// once the other plugins and the theme have added their filters
			if($judges)
			{
				add_action('init', [self::class, 'syncRestPrefix'], PHP_INT_MAX);
			}
		}
		catch(Throwable)
		{
			// the layer then judges on what it last had, or nothing
		}
	}
	
	/**
	 * The consent the prepend layer reads, as this request's configuration
	 * gives it (Prepend::consent()). It carries the seal key of the API key,
	 * never the key: syncPrepend() compares it on every request, so a new
	 * key — a settings save, a Connect, a constant — reaches the file on the
	 * next one, whose shutdown pull seals the store under that key
	 *
	 * @return array{detect: bool, enforce: bool, kill: bool, prefix: string, root: string, content: string, entries: bool, proxy_header: string, proxies: list<string>, seal: string}
	 */
	public static function consentOf(
		Config $config,
	): array
	{
		$connected = $config->enabled() && $config->url() !== '' && $config->apiKey() !== '';
		
		return [
			'detect' => $config->shieldDetect() && $connected,
			'enforce' => $config->shieldEnforce(),
			'kill' => $config->shieldKill(),
			'prefix' => self::prefixOf(),
			// the executed-file watch (Entries) rides the same layer with its own switch
			'root' => Entries::root(),
			// the update working directories the layer's guard refuses scripts in lie below it
			'content' => self::contentRoot(),
			'entries' => $config->entryWatch() && $connected,
			// the visitor's address behind a proxy the site trusts
			'proxy_header' => $config->trustedProxyHeader(),
			'proxies' => $config->trustedProxies(),
			// the key kernel() seals the store under: the layer reads the record with it and the same modules (Prepend::platforms())
			'seal' => $connected && class_exists(Kernel::class, false) ? Kernel::sealKey($config->apiKey()) : '',
		];
	}
	
	/** what the settings page says about the prepend layer: its state, PHP's ini value, the stub and the two lines to paste */
	public static function prependStatus(): array
	{
		$dir = self::stubDir();
		if($dir === '')
		{
			return ['state' => 'unavailable', 'ini' => '', 'stub' => '', 'lines' => ['ini' => '', 'htaccess' => '']];
		}
		
		return Prepend::status($dir, null, self::legacyStub() ?: null) + ['lines' => Prepend::lines($dir)];
	}
	
	/** WP_CONTENT_DIR resolved, with forward slashes and no trailing one: what the prepend layer's guard measures against; '' when unknown */
	public static function contentRoot(): string
	{
		if(defined('WP_CONTENT_DIR') === false)
		{
			return '';
		}
		
		$content = realpath(WP_CONTENT_DIR);
		
		return $content === false ? '' : rtrim(str_replace('\\', '/', $content), '/');
	}
	
	/** where ovos-console wrote its prepend stub, wp-content/ovos-console/prepend.php */
	public static function legacyStub(): string
	{
		if(defined('WP_CONTENT_DIR') === false)
		{
			return '';
		}
		
		return rtrim((string)WP_CONTENT_DIR, '/\\') . DIRECTORY_SEPARATOR . self::LEGACY_DIR . DIRECTORY_SEPARATOR . Prepend::LEGACY_STUB;
	}
	
	/**
	 * The pull's transport: WordPress's own HTTP API, so a proxy, the
	 * ovos_codesafe_sslverify filter (a console behind a self-signed
	 * certificate opts out the way it does for the Sender) and the site's
	 * HTTP settings all apply. The kernel's shape: status, lowercase
	 * headers, body; a transport error is status 0 and the cache is left alone
	 *
	 * @param list<string> $headers `Name: value` lines
	 */
	public function transport(
		string $url,
		array $headers,
		int $timeoutMs,
	): array
	{
		$named = [];
		foreach($headers as $line)
		{
			$at = strpos((string)$line, ':');
			if($at !== false)
			{
				$named[trim(substr((string)$line, 0, $at))] = trim(substr((string)$line, $at + 1));
			}
		}
		$response = wp_remote_get($url, [
			'timeout' => max(1, (int)ceil($timeoutMs / 1000)),
			'redirection' => 0,
			// the kernel refuses an answer past BODY_MAX unread: one byte more is all it needs to see
			'limit_response_size' => Kernel::BODY_MAX + 1,
			'headers' => $named,
			'user-agent' => Kernel::USER_AGENT . ' wordpress',
			'sslverify' => (bool)Legacy::filter('ovos_codesafe_sslverify', true),
		]);
		if(is_wp_error($response))
		{
			return ['status' => 0, 'headers' => [], 'body' => ''];
		}
		$lower = [];
		$raw = wp_remote_retrieve_headers($response);
		foreach((is_array($raw) ? $raw : $raw->getAll()) as $name => $value)
		{
			$lower[strtolower((string)$name)] = is_array($value) ? (string)($value[0] ?? '') : (string)$value;
		}
		$status = (int)wp_remote_retrieve_response_code($response);
		// codesafe's software version rides the pull, the 200 and the 304
		// alike — read here, so the vendored kernel stays as it is
		$software = Sender::token($lower['x-codesafe-software'] ?? '');
		if($this->software !== null && ($status === 200 || $status === 304) && $software !== '')
		{
			try
			{
				($this->software)($software);
			}
			catch(Throwable)
			{
				// the pull never fails over a listener
			}
		}
		
		return [
			'status' => $status,
			'headers' => $lower,
			'body' => (string)wp_remote_retrieve_body($response),
		];
	}
	
	/** this site's APCu namespace, the Rollup's scheme: the home URL's hash keeps two sites in one pool apart */
	public function prefix(): string
	{
		return $this->prefix ??= self::prefixOf();
	}
	
	/**
	 * A queued report's request facts, as the Sender's row takes them: the
	 * strings sanitized the way the Sender reads $_SERVER, the URL copies
	 * read raw and scrubbed of secrets (the people in them left for codesafe
	 * to mask and keep, like the Sender's own uri), the status and the time as
	 * integers,
	 * and the request section rebuilt from the refused URI's query — the
	 * Sender would otherwise attach the DRAINING request's GET (the body is
	 * not kept: the kernel's report says whether one was read). Nothing else
	 * from the file reaches the payload
	 *
	 * @param array<string, mixed> $context
	 * @return array<string, mixed>
	 */
	public static function drained(
		array $context,
	): array
	{
		$text = static fn(string $key): string => sanitize_text_field(wp_unslash((string)($context[$key] ?? '')));
		// the two URLs raw, like the Sender's own (Redactor::rawUrl()):
		// sanitize_text_field() strips the percent-encoded octets
		$url = static fn(string $key): string => Redactor::scrubUrl(
			Redactor::rawUrl(wp_unslash((string)($context[$key] ?? ''))), identities: false);
		$uri = $url('uri');
		$get = [];
		parse_str((string)(parse_url($uri, PHP_URL_QUERY) ?: ''), $get);
		$clean = [
			'uri' => $uri,
			'method' => $text('method'),
			'ip' => $text('ip'),
			'ua' => $text('ua'),
			'referer' => $url('referer'),
			'host' => $text('host'),
			// rebuilt from the uri scrubUrl() answered above: the query names are
			// [redacted] before the bag is parsed, the people in it kept for
			// codesafe to mask and vault
			'request' => $get !== [] ? ['get' => Redactor::scrub($get, identities: false)] : [],
		];
		foreach(['status', 'at'] as $number)
		{
			if(is_int($context[$number] ?? null) && $context[$number] > 0)
			{
				$clean[$number] = $context[$number];
			}
		}
		
		return array_filter($clean, static fn(mixed $value): bool => $value !== '');
	}
	
	/** this install's APCu key prefix, off the site's home URL — the same for the adapter and the prepend layer */
	public static function prefixOf(): string
	{
		$site = function_exists('get_option') ? (string)get_option('home') : '';
		
		return 'ovos:codesafe:shield:' . substr(md5($site), 0, 8) . ':';
	}
	
	/**
	 * The request as the kernel reads it at plugins_loaded: the parsed bags a
	 * virtual patch's conditions read, and who the caller is (caller()) —
	 * whether signed in, and WordPress's two answers for them: whether they
	 * have a capability, whether a nonce is valid. Either answer is null
	 * where it cannot be given: the rule then only observes; and, read by
	 * WordPress's kernel module (Prepend::platforms()), the REST prefix a
	 * `rest` condition finds the route after
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $get
	 * @param array<string, mixed> $post
	 * @param array<string, mixed> $cookies
	 * @param array<string, mixed> $files
	 * @param array{authed: bool, user: string, can: ?Closure(string): bool, nonce: ?Closure(string, string): bool, known?: bool} $caller
	 */
	public static function facts(
		array $server,
		array $get,
		array $post,
		array $cookies,
		array $files,
		array $caller,
		string $ip,
		string $restPrefix = 'wp-json',
		?array $request = null,
	): Facts
	{
		return Facts::fromServer(
			$server,
			$post,
			static fn(): string => (string)file_get_contents('php://input'),
			$caller['authed'],
			ip: $ip,
			user: $caller['user'],
			get: $get,
			cookies: $cookies,
			files: $files,
			can: $caller['can'],
			nonce: $caller['nonce'],
			callerKnown: $caller['known'] ?? true,
			kses: function_exists('wp_kses_post') ? self::htmlUnsafe(...) : null,
			platforms: Prepend::platforms(),
			options: [Wordpress::OPTION_REST_PREFIX => $restPrefix],
			request: $request,
		);
	}
	
	/**
	 * Whether WordPress's post filter would take markup out of a value (a
	 * vpatch's unsafe_html): wp_kses_post() against the value, both with
	 * their entities normalized and `&lt;`/`&gt;` read as the brackets — so
	 * `a & b` or `5 > 3`, which the filter only spells otherwise, is no
	 * markup, and a `<script>` or an `onclick` it strips is
	 */
	public static function htmlUnsafe(
		string $value,
	): bool
	{
		$spelled = static fn(string $html): string => str_replace(['&lt;', '&gt;'], ['<', '>'], wp_kses_normalize_entities($html));
		
		return $spelled(wp_kses_post($value)) !== $spelled($value);
	}
	
	/**
	 * Who WordPress will run the request as, told at plugins_loaded: whether
	 * signed in, the key a `user` rate rule counts, the capability and nonce
	 * answers for that user, and whether it is known yet. A REST request
	 * (servesRest()) is answered as WordPress decides it later: the login
	 * cookie counts only with a valid wp_rest nonce (rest_cookie_check_errors()),
	 * and Basic credentials holding an application password are that
	 * password's user. A caller WordPress tells only later — a REST request
	 * with a token another plugin reads (Bearer, JWT, OAuth), every XML-RPC
	 * call, whose credentials are checked inside each method — and one that
	 * cannot be told are unknown (`known` false): a rule that asks waits
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $get
	 * @param array<string, mixed> $post
	 * @return array{authed: bool, user: string, can: ?Closure(string): bool, nonce: ?Closure(string, string): bool, known: bool}
	 */
	public static function caller(
		array $server,
		array $get,
		array $post,
		bool $signedIn,
		bool $rest,
		bool $xmlrpc = false,
	): array
	{
		$current = [
			'authed' => $signedIn,
			'user' => self::userOf($signedIn, $server, $post),
			'can' => function_exists('current_user_can') ? static fn(string $capability): bool => current_user_can($capability) : null,
			// 1 or 2 is a valid nonce (its age), false an invalid one
			'nonce' => function_exists('wp_verify_nonce') ? static fn(string $action, string $value): bool => wp_verify_nonce($value, $action) !== false : null,
			'known' => true,
		];
		$unknown = ['authed' => true, 'user' => '', 'can' => null, 'nonce' => null, 'known' => false];
		if($xmlrpc)
		{
			return $unknown;
		}
		if($rest === false)
		{
			return $current;
		}
		try
		{
			if($signedIn)
			{
				// signed in by other means than the login cookie: WordPress asks no nonce
				if(($GLOBALS['wp_rest_auth_cookie'] ?? null) !== true)
				{
					return $current;
				}
				
				return match(self::restNonce($server, $get, $post))
				{
					true => $current,
					// WordPress runs it as user 0, or refuses it: a nonce is checked for user 0 then, not for the current user
					false => ['authed' => false, 'user' => '', 'can' => static fn(string $capability): bool => false, 'nonce' => null, 'known' => true],
					null => ['user' => $current['user']] + $unknown,
				};
			}
			$user = self::applicationPasswordUser($server);
			if($user === false)
			{
				// a token another plugin reads signs the request in only when WordPress asks it, after this hook
				return Prepend::carriesToken($server) ? $unknown : $current;
			}
			if($user === null)
			{
				return $unknown;
			}
			
			return [
				'authed' => true,
				'user' => 'user:' . $user->ID,
				'can' => function_exists('user_can') ? static fn(string $capability): bool => user_can($user, $capability) : null,
				// WordPress checks a nonce for the user it runs as, and this one is not the current user yet
				'nonce' => null,
				'known' => true,
			];
		}
		catch(Throwable)
		{
			return $unknown;
		}
	}
	
	/**
	 * Whether WordPress will answer this request from its REST API: addressed
	 * to it (Prepend::isRest()) and run through the front end's index.php,
	 * the one place WordPress routes a REST request — an admin page or
	 * admin-ajax.php with a rest_route field is none
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $get
	 * @param array<string, mixed> $post
	 */
	public static function servesRest(
		array $server,
		array $get,
		array $post,
		string $prefix,
	): bool
	{
		if((function_exists('is_admin') && is_admin()) || ($GLOBALS['pagenow'] ?? 'index.php') !== 'index.php')
		{
			return false;
		}
		
		return Prepend::isRest($server, $get, $post, $prefix);
	}
	
	/**
	 * The REST prefix this site's requests are told by: the one the init hook
	 * stored for the early layers (syncRestPrefix()), every plugin's and the
	 * theme's filter applied, else WordPress's answer at this point. The
	 * kernel's Facts carry it for WordPress's module (Wordpress::OPTION_REST_PREFIX)
	 */
	public static function restPrefix(): string
	{
		$dir = self::storeDir();
		$consent = $dir === '' ? null : Prepend::consent($dir);
		if($consent !== null)
		{
			return $consent['rest_prefix'];
		}
		
		return Prepend::restPrefixOf(function_exists('rest_get_url_prefix') ? rest_get_url_prefix() : null);
	}
	
	/**
	 * init, last: the site's REST prefix into the consent the early layers
	 * read, written only when it changed — by now every plugin's and the
	 * theme's rest_url_prefix filter is in place, which syncPrepend(), before
	 * plugins_loaded, cannot see. $dir is the store, storeDir() when empty
	 * (init hands its callbacks an empty string). Never throws
	 */
	public static function syncRestPrefix(
		string $dir = '',
	): bool
	{
		try
		{
			$dir = $dir === '' ? self::storeDir() : $dir;
			$prefix = function_exists('rest_get_url_prefix') ? rest_get_url_prefix() : null;
			
			return $dir !== '' && is_string($prefix) && Prepend::writeRestPrefix($dir, $prefix);
		}
		catch(Throwable)
		{
			return false;
		}
	}
	
	/**
	 * Who a `user`-keyed rate rule counts: the signed-in user's id, else the
	 * name a wp-login.php POST tries — '' otherwise, and the rule skips the
	 * request. Only ever a counter's key: it is not sent anywhere
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $post
	 */
	public static function userOf(
		bool $signedIn,
		array $server,
		array $post,
	): string
	{
		if($signedIn && function_exists('get_current_user_id'))
		{
			$id = (int)get_current_user_id();
			if($id > 0)
			{
				return 'user:' . $id;
			}
		}
		
		return Prepend::loginName($server, $post);
	}
	
	/**
	 * The wp_rest nonce of a cookie-signed REST request, read where
	 * rest_cookie_check_errors() reads it — _wpnonce from the request (the
	 * form's over the query's, as WordPress merges $_REQUEST), else
	 * X-WP-Nonce: true when valid, false when absent or invalid, null when
	 * it cannot be checked
	 *
	 * @param array<string, mixed> $server
	 * @param array<string, mixed> $get
	 * @param array<string, mixed> $post
	 */
	protected static function restNonce(
		array $server,
		array $get,
		array $post,
	): ?bool
	{
		$nonce = $post['_wpnonce'] ?? $get['_wpnonce'] ?? $server['HTTP_X_WP_NONCE'] ?? null;
		// none: WordPress runs the request anonymous; an array is no nonce it accepts
		if(is_string($nonce) === false)
		{
			return false;
		}
		if(function_exists('wp_verify_nonce') === false)
		{
			return null;
		}
		
		return wp_verify_nonce($nonce, 'wp_rest') !== false;
	}
	
	/**
	 * The user Basic credentials sign in with one of their application
	 * passwords, checked as wp_authenticate_application_password() checks
	 * them, read-only: no action fires, no use is recorded. False when they
	 * sign no one in — WordPress then runs the request anonymous — null when
	 * that cannot be told
	 *
	 * @param array<string, mixed> $server
	 */
	protected static function applicationPasswordUser(
		array $server,
	): WP_User|false|null
	{
		$login = $server['PHP_AUTH_USER'] ?? null;
		$password = $server['PHP_AUTH_PW'] ?? null;
		// WordPress tries the two together or not at all
		if(is_string($login) === false || is_string($password) === false)
		{
			return false;
		}
		foreach(self::APPLICATION_PASSWORD_FUNCTIONS as $function)
		{
			if(function_exists($function) === false)
			{
				return null;
			}
		}
		if(class_exists(WP_Application_Passwords::class) === false)
		{
			return null;
		}
		// switched off by a filter or by plain HTTP, or never used on this network
		if((bool)wp_is_application_passwords_available() === false || WP_Application_Passwords::is_in_use() === false)
		{
			return false;
		}
		$user = get_user_by('login', $login);
		if($user === false && is_email($login) !== false)
		{
			$user = get_user_by('email', $login);
		}
		if($user instanceof WP_User === false || (bool)wp_is_application_passwords_available_for_user($user) === false)
		{
			return false;
		}
		// 6.8 hashes them with wp_fast_hash(), which wp_check_password() cannot read
		$check = match(true)
		{
			method_exists(WP_Application_Passwords::class, 'check_password') => WP_Application_Passwords::check_password(...),
			function_exists('wp_check_password') => wp_check_password(...),
			default => null,
		};
		if($check === null)
		{
			return null;
		}
		// generated passwords are letters and digits; the spaces that group them are not part of one
		$password = (string)preg_replace('/[^a-z\d]/i', '', $password);
		foreach(WP_Application_Passwords::get_user_application_passwords($user->ID) as $item)
		{
			if(is_string($item['password'] ?? null) && (bool)$check($password, $item['password']))
			{
				return $user;
			}
		}
		
		return false;
	}
	
	/**
	 * WordPress's own refusal — wp_die knows whether this is a page, an
	 * XML-RPC call or a REST request: 403 for a match rule, 429 with
	 * Retry-After for a rate rule past its limit
	 */
	protected function refuse(
		int $ruleId,
		int $status = 403,
		int $retryAfter = 0,
	): void
	{
		if(function_exists('wp_die') === false)
		{
			return;
		}
		$limited = $status === 429;
		if(headers_sent() === false)
		{
			header(self::HEADER_RULE . ': ' . $ruleId);
			if($limited)
			{
				header('Retry-After: ' . max(1, $retryAfter));
			}
		}
		$words = $limited ? esc_html__('Too Many Requests', 'ovos-codesafe') : esc_html__('Forbidden', 'ovos-codesafe');
		wp_die($words, $words, ['response' => $limited ? 429 : 403]);
	}
}
