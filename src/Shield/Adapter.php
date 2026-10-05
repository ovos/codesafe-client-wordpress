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
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Throwable;

use function __;
use function _n;
use function add_action;
use function array_filter;
use function ceil;
use function class_exists;
use function constant;
use function count;
use function defined;
use function dirname;
use function esc_html__;
use function file_get_contents;
use function file_put_contents;
use function function_exists;
use function get_current_user_id;
use function get_option;
use function header;
use function headers_sent;
use function human_time_diff;
use function is_array;
use function is_dir;
use function is_file;
use function is_int;
use function is_user_logged_in;
use function is_wp_error;
use function is_writable;
use function max;
use function md5;
use function mkdir;
use function parse_str;
use function parse_url;
use function register_shutdown_function;
use function rtrim;
use function sanitize_text_field;
use function sprintf;
use function strpos;
use function strtolower;
use function substr;
use function time;
use function trim;
use function wp_date;
use function wp_die;
use function wp_remote_get;
use function wp_remote_retrieve_body;
use function wp_remote_retrieve_headers;
use function wp_remote_retrieve_response_code;
use function wp_unslash;

use const DIRECTORY_SEPARATOR;
use const PHP_SAPI;
use const PHP_URL_QUERY;
use const WP_CONTENT_DIR;

// the kernel is one vendored multi-class file (ovos/console client-php/Shield.php,
// byte-identical here as Kernel.php); a plain class binds at compile time, so
// the guard sits at the require, never inside the file
if(class_exists(Kernel::class, false) === false)
{
	require_once __DIR__ . DIRECTORY_SEPARATOR . 'Kernel.php';
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
 * Consent is the two checkboxes on the settings page, read per request and
 * never cached in the ruleset — unticking stops the next request, not the
 * next pull: "Exploit detection" (`shield_detect`: pull and OBSERVE, report
 * matches, block nothing) and "Block detected exploits" (`shield_enforce`:
 * 403 on a PROVEN rule, inert without detection). `CODESAFE_SHIELD_KILL`
 * is a constant only: off entirely, no network — the switch for a host that
 * must never call home. Four gates stand before any request is refused: the
 * console's per-project switch, the rule's `proven` mode, and these two.
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
	
	protected ?Kernel $kernel = null;
	
	protected ?string $prefix = null;
	
	/** @var array<string, true> the store directories this request has made sure of */
	protected static array $made = [];
	
	public function __construct(
		protected Config $config,
		protected Sender $sender,
	)
	{
	}
	
	public function register(): void
	{
		add_action('plugins_loaded', [$this, 'judge'], self::HOOK_PRIORITY);
		register_shutdown_function([$this, 'tick']);
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
	
	/** plugins_loaded: judge, count, report — and refuse a block the WordPress way */
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
				
				return;
			}
			$signedIn = function_exists('is_user_logged_in') && is_user_logged_in();
			$facts = Facts::fromServer(
				$_SERVER,
				$_POST,
				static fn(): string => (string)file_get_contents('php://input'),
				$signedIn,
				ip: $this->sender->clientIp(),
				user: self::userOf($signedIn),
			);
			$verdict = $this->kernel()->handle($facts, $this->consent());
			if($verdict->isBlock() && $verdict->rule !== null)
			{
				$this->refuse((int)$verdict->rule['id'], $verdict->status(), $verdict->retryAfter);
			}
		}
		catch(Throwable)
		{
			// fail open: served as if the shield were not there
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
			if(($counts['observe'] ?? 0) > 0)
			{
				$fields['so:' . $id] = (int)$counts['observe'];
			}
			if(($counts['block'] ?? 0) > 0)
			{
				$fields['sb:' . $id] = (int)$counts['block'];
			}
		}
		
		return $fields;
	}
	
	/**
	 * The settings page's one line about the Shield (Settings::shieldStatusRow):
	 * why it is off, or what the store holds — the rules live, how many of
	 * them are PROVEN and so may block, when the ruleset was pulled, and
	 * whether this site blocks. Read off the store alone, no network
	 */
	public function status(): string
	{
		if($this->config->shieldKill())
		{
			return __('off — CODESAFE_SHIELD_KILL is set: nothing is pulled, nothing is matched, no one is called.', 'ovos-codesafe');
		}
		if($this->config->shieldDetect() === false)
		{
			return __('off — Exploit detection is unticked: no rules are pulled and no request is matched.', 'ovos-codesafe');
		}
		if($this->config->enabled() === false || $this->config->url() === '' || $this->config->apiKey() === '')
		{
			return __('off — the console URL and API key above are what the rules are pulled with.', 'ovos-codesafe');
		}
		try
		{
			$record = $this->kernel()->store()->read();
		}
		catch(Throwable)
		{
			$record = null;
		}
		if(is_array($record) === false)
		{
			return __('no ruleset yet — the first request after saving pulls it from the console (then every five minutes).', 'ovos-codesafe');
		}
		$rules = is_array($record['rules'] ?? null) ? $record['rules'] : [];
		$proven = 0;
		foreach($rules as $rule)
		{
			if(is_array($rule) && ($rule['mode'] ?? '') === Ruleset::MODE_PROVEN)
			{
				$proven++;
			}
		}
		$fetchedAt = (int)($record['fetched_at'] ?? 0);
		$pulled = $fetchedAt > 0
			? sprintf(
				/* translators: 1: a time of day, 2: a human duration such as "3 mins" */
				__('pulled %1$s (%2$s ago)', 'ovos-codesafe'), wp_date('H:i', $fetchedAt), human_time_diff($fetchedAt, time()))
			: __('never pulled', 'ovos-codesafe');
		$blocking = $this->config->shieldEnforce()
			? __('blocking ON — a request a PROVEN rule matches is answered 403', 'ovos-codesafe')
			: __('blocking off — every match is reported, nothing is refused', 'ovos-codesafe');
		$line = sprintf(
			/* translators: 1: number of live rules, 2: number of proven rules, 3: when the ruleset was pulled, 4: the blocking state */
			_n('%1$d rule live, %2$d of them PROVEN — %3$s · %4$s', '%1$d rules live, %2$d of them PROVEN — %3$s · %4$s', count($rules), 'ovos-codesafe'),
			count($rules), $proven, $pulled, $blocking);
		if(($record['usable'] ?? true) === false)
		{
			$line .= ' ' . __('The last pull carried a ruleset this version cannot run; the rules above are the ones kept.', 'ovos-codesafe');
		}
		
		return $line;
	}
	
	public function kernel(): Kernel
	{
		return $this->kernel ??= new Kernel(
			$this->config->url(),
			$this->config->apiKey(),
			new Store($this->file(), $this->prefix()),
			[$this, 'transport'],
			fn(string $kind, string $message, array $extra) => $this->sender->reportRefusal($kind, $message, $extra),
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
			$connected = $config->enabled() && $config->url() !== '' && $config->apiKey() !== '';
			Prepend::writeConsent($dir, [
				'detect' => $config->shieldDetect() && $connected,
				'enforce' => $config->shieldEnforce(),
				'kill' => $config->shieldKill(),
				'prefix' => self::prefixOf(),
				// the executed-file watch (Entries) rides the same layer with its own switch
				'root' => Entries::root(),
				'entries' => $config->entryWatch() && $connected,
				// the visitor's address behind a proxy the site trusts (M5)
				'proxy_header' => $config->trustedProxyHeader(),
				'proxies' => $config->trustedProxies(),
			]);
			// 1.0.2's plain-JSON files, or a store CODESAFE_STORE_DIR has moved since
			if(is_file($stubDir . DIRECTORY_SEPARATOR . 'shield-consent.json')
				|| ($dir !== $stubDir && is_file($stubDir . DIRECTORY_SEPARATOR . Prepend::CONSENT)))
			{
				Prepend::migrate($stubDir, $dir);
			}
			// the stub stays where the operator's configuration names it; it judges
			// against the data wherever that lives
			Prepend::ensureStub($dir, $dir === $stubDir ? null : $stubDir . DIRECTORY_SEPARATOR . Prepend::STUB);
			// a site that ran ovos-console may still point PHP at its stub: that
			// stub is rewritten to run this plugin, never deleted — PHP fails every
			// request whose prepend file is gone
			$legacy = self::legacyStub();
			if($legacy !== '' && Prepend::status($stubDir, null, $legacy)['state'] === 'legacy' && is_dir(dirname($legacy)))
			{
				Prepend::ensureStub($dir, $legacy);
			}
		}
		catch(Throwable)
		{
			// the layer then judges on what it last had, or nothing
		}
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
	
	/** where ovos-console wrote its prepend stub, wp-content/ovos-console/prepend.php */
	public static function legacyStub(): string
	{
		if(defined('WP_CONTENT_DIR') === false)
		{
			return '';
		}
		
		return rtrim((string)WP_CONTENT_DIR, '/\\') . DIRECTORY_SEPARATOR . self::LEGACY_DIR . DIRECTORY_SEPARATOR . Prepend::STUB;
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
		
		return [
			'status' => (int)wp_remote_retrieve_response_code($response),
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
	 * Who a `user`-keyed rate rule counts: the signed-in user's id, else the
	 * name a wp-login.php POST tries — '' otherwise, and the rule skips the
	 * request. Only ever a counter's key: it is not sent anywhere
	 */
	public static function userOf(
		bool $signedIn,
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
		
		return Prepend::loginName($_SERVER, $_POST);
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
