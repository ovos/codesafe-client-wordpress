<?php
declare(strict_types=1);
// phpcs:disable WordPress.PHP.DevelopmentFunctions -- error_reporting()/set_error_handler() are this plugin's purpose: it captures PHP errors, chaining any previous handler
// phpcs:disable WordPress.WP.AlternativeFunctions.curl_curl_init, WordPress.WP.AlternativeFunctions.curl_curl_setopt_array, WordPress.WP.AlternativeFunctions.curl_curl_exec -- the fire-and-forget ingest call needs millisecond timeouts (300 ms connect / 1 s total) the WP HTTP API cannot express; wp_remote_post() is the fallback when curl is missing

namespace Ovos\Codesafe;

use ErrorException;
use Throwable;

use function array_map;
use function array_replace;
use function array_slice;
use function array_values;
use function count;
use function curl_exec;
use function curl_init;
use function curl_setopt_array;
use function defined;
use function error_get_last;
use function error_reporting;
use function function_exists;
use function gmdate;
use function http_response_code;
use function in_array;
use function is_int;
use function is_string;
use function json_encode;
use function max;
use function mb_substr;
use function min;
use function register_shutdown_function;
use function rtrim;
use function session_id;
use function session_status;
use function set_error_handler;
use function spl_object_id;
use function str_replace;
use function str_starts_with;
use function strlen;
use function strpos;
use function substr;
use function trim;

use const PHP_SESSION_ACTIVE;
use const PHP_URL_HOST;

/**
 * Reports collected errors to a central ovos/console instance —
 * standalone WordPress port of the php-library Console\Sender.
 *
 * Fire-and-forget by contract: every public method swallows all
 * failures and the single HTTP call happens once per request from
 * the shutdown handler with a hard timeout — the console must never
 * break or noticeably slow the host site.
 *
 * Non-fatal errors are captured via a chained set_error_handler
 * (error_reporting() and the @ operator are respected, behavior is
 * never altered); fatals — uncaught exceptions included — via
 * error_get_last() at shutdown. There is deliberately no
 * set_exception_handler: replacing it would change WordPress'
 * fatal handling (recovery mode, display).
 */
class Sender
{
	/**
	 * The closed security-event vocabulary — must mirror the console's
	 * App::SECURITY_KINDS exactly; the console refuses unknown kinds
	 * wholesale, so this list only grows in a deliberate two-sided change
	 */
	public const SECURITY_KINDS = [
		'auth_failure',
		'auth_success',
		'csrf_reject',
		'permission_denied',
		'rate_limited',
		'validation_refused',
		'privileged_action',
		// the Shield's own (Shield\Adapter): a request a rule matched and let
		// through, one it refused, and a rate rule past its limit — observed,
		// or answered with 429
		'shield_observe',
		'shield_block',
		'shield_rate',
		// the executed-file watch (Entries): a PHP file nobody shipped ran
		Entries::KIND,
	];
	
	/**
	 * Fixed 60-second cap on security-event reports, so a credential-stuffing
	 * run cannot turn this reporter into the flood it is meant to surface
	 */
	protected const MAX_SECURITY_PER_MINUTE = 60;
	
	protected const MAX_QUEUE = 100;
	
	protected const MAX_BATCH = 50;
	
	protected const MAX_BODY = 262144;
	
	/**
	 * What the console's REPLAY needs to re-issue the request that failed
	 * (docs/SENDER.md §context.request): the raw body, its content type and
	 * the headers that change what the site answers. The caps are the
	 * console's own — a longer body is CUT, not dropped, since the head of a
	 * body is still a body.
	 */
	protected const BODY_MAX = 16384;
	
	protected const CONTENT_TYPE_MAX = 128;
	
	protected const HEADER_VALUE_MAX = 1024;
	
	protected const HEADERS_MAX = 24;
	
	/** the standard names worth sending; the site's own `x-…` go too (buildHeaders) */
	protected const REQUEST_HEADERS = ['accept', 'accept-language', 'accept-charset', 'accept-encoding',
		'content-type', 'x-requested-with'];
	
	/**
	 * Never sent. The forwarding family describes the VISITOR — their address,
	 * the host they asked for — and a replay carrying them would claim to come
	 * from that person, through headers plugins routinely trust for rate
	 * limits, geo and access rules.
	 */
	protected const HEADERS_NEVER = ['x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port',
		'x-forwarded-proto', 'x-forwarded-server', 'x-real-ip', 'forwarded'];
	
	
	/**
	 * The PHP files WordPress itself puts in the document root. A `.php` file
	 * sitting beside them that is NOT on this list was put there by somebody,
	 * which is the whole point of sourceFor()'s `unknown`.
	 */
	public const CORE_ROOT_FILES = ['index.php', 'wp-activate.php', 'wp-blog-header.php',
		'wp-comments-post.php', 'wp-config.php', 'wp-config-sample.php', 'wp-cron.php',
		'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php', 'wp-settings.php',
		'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php'];
	
	/**
	 * The drop-ins WordPress loads out of `wp-content/` by name. A caching
	 * plugin installs `advanced-cache.php` on half the sites in the world, so
	 * they get their own label rather than reading as `unknown` forever.
	 */
	public const CONTENT_DROPINS = ['advanced-cache.php', 'object-cache.php', 'db.php',
		'db-error.php', 'install.php', 'maintenance.php', 'fatal-error-handler.php',
		'php-error.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php',
		'blog-suspended.php'];
	
	
	protected const FATAL_TYPES = [
		E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_RECOVERABLE_ERROR,
	];
	
	/**
	 * Queued payloads, keyed by spl_object_id for throwables so one
	 * object is never double-reported
	 */
	protected array $queue = [];
	
	protected bool $flushing = false;
	
	/**
	 * @var callable|null
	 */
	protected $previousErrorHandler = null;
	
	public function __construct(
		protected Config $config,
	)
	{
	}
	
	public function register(): void
	{
		$this->previousErrorHandler = set_error_handler([$this, 'handleError']);
		
		register_shutdown_function([$this, 'handleShutdown']);
	}
	
	public function isEnabled(): bool
	{
		return $this->config->enabled()
			&& $this->config->url() !== ''
			&& $this->config->apiKey() !== '';
	}
	
	public function captureException(
		Throwable $event,
		array $extra = [],
		?int $priority = null,
	): static
	{
		try
		{
			$this->queue[spl_object_id($event)] =
				Payload::fromThrowable($event, $priority, $extra);
		}
		catch(Throwable)
		{
			// never break the host site
		}
		
		return $this;
	}
	
	public function captureMessage(
		string $message,
		int $priority = 5,
		array $extra = [],
	): static
	{
		try
		{
			$this->queue[] = Payload::fromMessage($message, $priority, $extra);
		}
		catch(Throwable)
		{
			// never break the host site
		}
		
		return $this;
	}
	
	/**
	 * Reports a not-found access event as a type=404 report (priority 6, INFO).
	 * The console groups these apart from real errors, never turns them into
	 * issues, and its per-project report_404 switch decides acceptance. No-op
	 * unless report_404 is enabled here. The path (query stripped and scrubbed
	 * with the request patterns) is the message so distinct probes stay distinct
	 * while one hammered path folds together; the report ships from the shutdown
	 * flush like any other.
	 */
	public function capture404(
		string $path = '',
		array $extra = [],
	): void
	{
		if($this->config->report404() === false
			|| count($this->queue) >= self::MAX_QUEUE)
		{
			return;
		}
		
		try
		{
			$path = Redactor::scrubUrl($path !== '' ? $path : $this->server('REQUEST_URI'));
			
			$mark = strpos($path, '?');
			if($mark !== false)
			{
				$path = substr($path, 0, $mark);
			}
			
			$payload = Payload::fromMessage('404 Not Found: ' . mb_substr($path, 0, 512), 6, $extra);
			// the KIND (console ≥ 2026-09: runtime · entry · kind); `type` is the
			// legacy slot older consoles read — kept for the transition
			$payload['kind'] = 'not_found';
			$payload['type'] = '404';
			
			$this->queue[] = $payload;
		}
		catch(Throwable)
		{
			// never break the host site
		}
	}
	
	/**
	 * Reports a refused action as a kind=security event — what was REFUSED,
	 * beside what broke: failed logins, rejected nonce checks, forbidden REST
	 * calls, sensitive admin changes. $kind must come from SECURITY_KINDS (the
	 * console refuses unknown kinds; anything else is a silent no-op) and rides
	 * events[0].className, the same slot an exception's class occupies. No-op
	 * unless the security_events setting is on; rate-capped so an attack cannot
	 * flood its own report channel. The console accepts these apart from the
	 * project's severity threshold (a kind, not a severity) but has its own
	 * per-project off switch.
	 *
	 * $priority is the site's word that THIS one matters: codesafe stores the
	 * event at its kind's default (a refusal INFO) unless a MORE severe value
	 * (0-7) is named here, and never below the default (codesafe
	 * docs/plans/sender-security-priority.md). Without one the event goes out
	 * at INFO, below every kind's default.
	 */
	public function reportRefusal(
		string $kind,
		string $message = '',
		array $extra = [],
		array $context = [],
		?int $priority = null,
	): void
	{
		// a shield kind rides on "Exploit detection" alone: detection is its own
		// consent, and an unreported match is a shield nobody can see; the
		// executed-file watch's kind rides on its own switch the same way
		$gate = match(true)
		{
			str_starts_with($kind, 'shield_') => $this->config->shieldDetect(),
			$kind === Entries::KIND => $this->config->entryWatch(),
			default => $this->config->securityEvents(),
		};
		if($gate === false
			|| in_array($kind, self::SECURITY_KINDS, true) === false
			|| count($this->queue) >= self::MAX_QUEUE
			|| $this->allowSecurity() === false)
		{
			return;
		}
		
		try
		{
			$message = $message !== ''
				? Redactor::maskEmails(mb_substr($message, 0, 512))
				: $kind;
			
			$payload = Payload::fromMessage($message, $priority === null ? 6 : max(0, min(7, $priority)), $extra);
			$payload['kind'] = 'security';
			$payload['type'] = 'security';
			$payload['events'] = [
				[
					'message' => $message,
					'className' => $kind,
					'file' => '',
					'line' => 0,
					'backtrace' => '',
					'previous' => false,
				],
			];
			// the caller's word on the request context — the account it holds
			// before the session does (wp_login fires before the current user
			// is set); the flush merges it over the base it builds. Its word on
			// WHEN too: a report the prepend layer queued is sent from a later
			// request, and the row's time is the refused request's
			$at = $context['at'] ?? null;
			unset($context['at']);
			if(is_int($at) && $at > 0)
			{
				$payload['timestamp'] = gmdate('c', $at);
			}
			if($context !== [])
			{
				$payload['context'] = $context;
			}
			
			$this->queue[] = $payload;
		}
		catch(Throwable)
		{
			// never break the host site
		}
	}
	
	/**
	 * Fixed 60-second window cap on security reports (a transient counter,
	 * same mechanism as the 404 throttle)
	 */
	protected function allowSecurity(): bool
	{
		$key = 'ovos_codesafe_security_rate';
		$count = (int)get_transient($key);
		
		if($count >= self::MAX_SECURITY_PER_MINUTE)
		{
			return false;
		}
		
		set_transient($key, $count + 1, 60);
		
		return true;
	}
	
	/**
	 * set_error_handler callback — captures, then hands over to the
	 * previous handler (or to PHP's own, by returning false)
	 */
	public function handleError(
		int $severity,
		string $message,
		string $file = '',
		int $line = 0,
	): bool
	{
		try
		{
			if((error_reporting() & $severity) !== 0
				&& Payload::severityPriority($severity) <= $this->config->logLevel()
				&& count($this->queue) < self::MAX_QUEUE)
			{
				$this->captureException(
					new ErrorException($message, 0, $severity, $file, $line));
			}
		}
		catch(Throwable)
		{
			// never break the host site
		}
		
		if($this->previousErrorHandler !== null)
		{
			return (bool)($this->previousErrorHandler)($severity, $message, $file, $line);
		}
		
		return false;
	}
	
	public function handleShutdown(): void
	{
		try
		{
			$error = error_get_last();
			
			if($error !== null
				&& in_array((int)($error['type'] ?? 0), self::FATAL_TYPES, true))
			{
				$this->queue[] = Payload::fromFatal($error);
			}
		}
		catch(Throwable)
		{
			// never break the host site
		}
		
		$this->flush();
	}
	
	/**
	 * Builds and posts the batch — called once from the shutdown handler
	 * after the response went out
	 */
	public function flush(): void
	{
		if($this->flushing || $this->isEnabled() === false)
		{
			return;
		}
		
		$this->flushing = true;
		
		try
		{
			$logLevel = $this->config->logLevel();
			$context = null;
			
			$errors = [];
			
			foreach($this->queue as $payload)
			{
				// 404 access events and security events ride the INFO band but
				// are KINDS, not severities — the log_level gate (a severity
				// filter) must not drop them; only errors are judged by it
				$kind = (string)($payload['kind'] ?? 'error');
				if($kind === 'error' && $payload['priority'] > $logLevel)
				{
					continue;
				}
				
				$context ??= $this->buildContext();
				
				$errors[] = $this->decorate($payload, $context);
				
				if(count($errors) === self::MAX_BATCH)
				{
					break;
				}
			}
			
			if($errors !== [])
			{
				$json = $this->encode($errors);
				
				while(strlen($json) > self::MAX_BODY && count($errors) > 1)
				{
					$errors = array_slice($errors, 0, (int)(count($errors) / 2));
					$json = $this->encode($errors);
				}
				
				$this->send($json);
			}
		}
		catch(Throwable)
		{
			// silence is the contract
		}
		finally
		{
			$this->queue = [];
			$this->flushing = false;
		}
	}
	
	/**
	 * Posts one synchronous test error and returns the HTTP status —
	 * used by the settings page, the only non-silent path
	 */
	public function sendTest(): int
	{
		$payload = $this->decorate(
			Payload::fromMessage('Test error from the ovos codesafe WordPress plugin', 3),
			$this->buildContext());
		
		$response = wp_remote_post($this->config->url() . '/api/v1/ingest', [
			'timeout' => 5,
			'headers' => [
				'Content-Type' => 'application/json',
				'X-Codesafe-Key' => $this->config->apiKey(),
				'X-Console-Key' => $this->config->apiKey(),
			],
			'body' => $this->encode([$payload]),
			'sslverify' => $this->verifyTls(),
		]);
		
		if(is_wp_error($response))
		{
			return 0;
		}
		
		return (int)wp_remote_retrieve_response_code($response);
	}
	
	/**
	 * Merges context, WP extras and the release label into a payload
	 */
	protected function decorate(
		array $payload,
		array $context,
	): array
	{
		// the three axes every console ≥ 2026-09 reads: what ran the code, how
		// it was entered, what the event is. A kind the payload already carries
		// (not_found, security) stands; everything else is an error. `type` is
		// the legacy slot older consoles still read — kept until every console
		// this plugin may talk to has updated
		$payload['runtime'] = 'php';
		$payload['entry'] = $context['entry'];
		$payload['kind'] ??= 'error';
		$payload['type'] ??= $context['type'];
		// the sender naming itself: the console shows the last one per
		// project and the row's in META, so a misbehaving plugin version can
		// be told apart from a healthy one without opening the site
		$payload['client'] = 'wordpress/' . Plugin::VERSION;
		// a per-event context (reportRefusal's fourth argument) wins over the
		// base built at the flush — the identity a caller knew at its moment
		$payload['context'] = array_replace($context['context'], $payload['context'] ?? [])
			+ ['extra' => Redactor::scrub($payload['extra']) + $this->buildWpExtra($payload)];
		unset($payload['extra']);
		
		$release = $this->config->release();
		
		if($release !== '')
		{
			$payload['release'] = $release;
		}
		
		$environment = $this->config->environment();
		
		if($environment !== '')
		{
			$payload['environment'] = $environment;
		}
		
		// the tags this site stamps on every report (the Tags setting or
		// CODESAFE_TAGS) — the console's TAGS column, one filter per tag
		$tags = $this->config->tags();
		
		if($tags !== [])
		{
			$payload['tags'] = $tags;
		}
		
		return $payload;
	}
	
	/**
	 * @return array{type: string, context: array}
	 */
	protected function buildContext(): array
	{
		$isCli = PHP_SAPI === 'cli' || defined('WP_CLI');
		
		$context = [
			'dir' => defined('ABSPATH') ? rtrim(ABSPATH, '/\\') : '',
			// correlates every error of this request in the console — across
			// services when an inbound traceparent is propagated
			'traceId' => Trace::id(),
		];
		
		if($isCli)
		{
			$context['host'] = $this->homeHost();
			$context['args'] = isset($_SERVER['argv'])
				? Redactor::scrubArgs(array_values(
					array_map('sanitize_text_field', wp_unslash((array)$_SERVER['argv']))))
				: [];
		}
		else
		{
			$host = $this->server('HTTP_HOST');
			
			$context['host'] = $host !== '' ? $host : $this->homeHost();
			// secrets and e-mails travel in query strings too — scrub the
			// url copies the same way request.get is scrubbed
			$context['uri'] = Redactor::scrubUrl($this->server('REQUEST_URI'));
			$context['method'] = $this->server('REQUEST_METHOD');
			$context['referer'] = Redactor::scrubUrl($this->server('HTTP_REFERER'));
			$context['ip'] = $this->server('REMOTE_ADDR');
			$context['ua'] = $this->server('HTTP_USER_AGENT');
			// the response status the request ended with — final here, since
			// buildContext() runs from the shutdown flush after the response
			// went out (WordPress' own 404 page has set 404 by then). Only an
			// HTTP status counts; false (none decided) sends nothing rather
			// than a guess — the console indexes it as the STATUS filter
			$status = http_response_code();
			
			if(is_int($status) && $status >= 100 && $status <= 599)
			{
				$context['status'] = $status;
			}
			
			if(session_status() === PHP_SESSION_ACTIVE)
			{
				$context['sessionId'] = (string)session_id();
			}
			
			if(function_exists('get_current_user_id'))
			{
				$userId = (int)get_current_user_id();
				
				if($userId > 0)
				{
					$context['userId'] = (string)$userId;
				}
			}
			
			$context['request'] = $this->buildRequest();
		}
		
		return [
			'type' => $isCli ? 'cli' : 'http',
			'entry' => $isCli ? 'cli' : 'web',
			'context' => $context,
		];
	}
	
	/**
	 * One $_SERVER string, unslashed and sanitized
	 */
	protected function server(
		string $key,
	): string
	{
		return isset($_SERVER[$key])
			? sanitize_text_field(wp_unslash((string)$_SERVER[$key]))
			: '';
	}
	
	/**
	 * Request variables, redacted before sending (the console scrubs
	 * again server-side as a backstop).
	 *
	 * Beside get/post this logs what the console's REPLAY needs to re-issue
	 * the request that failed (docs/SENDER.md §context.request): the raw
	 * BODY with its content type, and the request headers that change what
	 * the site answers. A REST or admin-ajax call carrying JSON has an EMPTY
	 * $_POST — the body is a stream PHP never parses into fields — so
	 * without these the console can only replay such a write as a bare
	 * method and URL, which is a different request wearing the same name.
	 */
	protected function buildRequest(): array
	{
		// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput -- request variables are collected as diagnostic payload, never processed; secrets are redacted here and again server-side
		$request = [];
		
		// the request data keeps its e-mail addresses and usernames: the
		// console masks them on arrival and keeps the original encrypted for
		// an audited reveal and a replay (console docs/plans/reveal-everything.md).
		// Secrets are dropped here exactly as always; src/Body.php does the same
		if(!empty($_GET))
		{
			$request['get'] = Redactor::scrub(wp_unslash((array)$_GET), identities: false);
		}
		
		if(!empty($_POST))
		{
			$request['post'] = Redactor::scrub(wp_unslash((array)$_POST), identities: false);
		}
		// phpcs:enable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		
		$contentType = $this->server('CONTENT_TYPE');
		if($contentType !== '')
		{
			$request['contentType'] = substr($contentType, 0, self::CONTENT_TYPE_MAX);
		}
		
		// PARSED, not pattern-matched (src/Body.php). The flat regex this
		// replaces had six holes, and the two worst were the shapes WordPress
		// posts in: `opts[api_key]` from every settings form, and XML-RPC,
		// which names its credentials not at all. The URI decides first —
		// wp-login.php and xmlrpc.php send no body whatever the mode says.
		$body = $this->readBody($contentType);
		if($body !== '')
		{
			$reduced = Body::redact(
				$body,
				$contentType,
				$this->config->requestBody(),
				$this->server('REQUEST_URI'),
			);
			
			if($reduced !== null)
			{
				$request['body'] = $reduced;
			}
		}
		
		$headers = $this->buildHeaders();
		if($headers !== [])
		{
			$request['headers'] = $headers;
		}
		
		return $request;
	}
	
	/**
	 * The raw request body, capped. php://input is re-readable for every
	 * content type EXCEPT multipart/form-data, which is skipped anyway: an
	 * upload's body is megabytes of binary and $_POST already carries its
	 * fields. A GET never has one worth reading.
	 */
	protected function readBody(
		string $contentType,
	): string
	{
		if($this->server('REQUEST_METHOD') === 'GET'
			|| stripos($contentType, 'multipart/form-data') !== false)
		{
			return '';
		}
		
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- php://input is the request body, not a filesystem read; WP_Filesystem does not address it
		$body = @file_get_contents('php://input', false, null, 0, self::BODY_MAX);
		
		return is_string($body) ? $body : '';
	}
	
	/**
	 * The request headers worth sending: the ones that change what the site
	 * ANSWERS, plus its own X- names — never a cookie, an authorization or
	 * anything else secret by name, and never the forwarding family, which
	 * describes the VISITOR (their address, the host they asked for): a
	 * replay carrying those would claim to come from that person, through
	 * headers plugins routinely trust for rate limits, geo and access.
	 *
	 * @return array<string, string>
	 */
	protected function buildHeaders(): array
	{
		$headers = [];
		
		foreach(array_keys($_SERVER) as $key)
		{
			if(count($headers) >= self::HEADERS_MAX)
			{
				break;
			}
			
			$key = (string)$key;
			if(strpos($key, 'HTTP_') !== 0)
			{
				continue;
			}
			
			$name = strtolower(str_replace('_', '-', substr($key, 5)));
			if(!in_array($name, self::REQUEST_HEADERS, true) && strpos($name, 'x-') !== 0)
			{
				continue;
			}
			
			// the secret names are the Redactor's one list, never a copy of it
			if(in_array($name, self::HEADERS_NEVER, true) || Redactor::isSecretName($name))
			{
				continue;
			}
			
			$headers[$name] = substr($this->server($key), 0, self::HEADER_VALUE_MAX);
		}
		
		return $headers;
	}
	
	/**
	 * WordPress diagnostics per payload: core version, active theme and
	 * source attribution — which plugin/theme the error file lives in
	 */
	protected function buildWpExtra(
		array $payload,
	): array
	{
		$extra = [
			'wpVersion' => (string)($GLOBALS['wp_version'] ?? ''),
		];
		
		if(function_exists('get_stylesheet'))
		{
			$extra['theme'] = (string)get_stylesheet();
		}
		
		$source = $this->sourceFor((string)($payload['events'][0]['file'] ?? ''));
		
		if($source !== '')
		{
			$extra['source'] = $source;
		}
		
		return $extra;
	}
	
	/**
	 * Attributes an error's file to the component that shipped it: a plugin,
	 * a mu-plugin, a theme, WordPress core — or nobody.
	 *
	 * That last case is why this method matters beyond tidy reporting. The
	 * fallback used to be `core` for every path outside a plugin or theme
	 * root, so a PHP error thrown from `wp-content/uploads/2026/09/x.php` was
	 * filed as an error in WordPress itself. A dropped webshell is precisely
	 * the file that throws once and never again, and `core` is the one label
	 * that makes it invisible.
	 *
	 * The vocabulary is closed:
	 *
	 *   plugin:<slug>, mu-plugin:<slug>, theme:<slug>   it lives there
	 *   core      wp-admin/, wp-includes/, or one of core's own root files
	 *   dropin    a wp-content/ drop-in WordPress loads by name
	 *   uploads   under the uploads directory, where no PHP belongs
	 *   unknown   under the site and shipped by nobody — the interesting one
	 *
	 * `uploads` and `unknown` are not accusations. They are the two labels
	 * worth a second look, and the console is where that look happens.
	 */
	protected function sourceFor(
		string $file,
	): string
	{
		if($file === '')
		{
			return '';
		}
		
		$file = str_replace('\\', '/', $file);
		
		$roots = [
			'plugin' => defined('WP_PLUGIN_DIR') ? (string)WP_PLUGIN_DIR : '',
			'mu-plugin' => defined('WPMU_PLUGIN_DIR') ? (string)WPMU_PLUGIN_DIR : '',
			'theme' => function_exists('get_theme_root') ? (string)get_theme_root() : '',
		];
		
		foreach($roots as $type => $root)
		{
			if($root === '')
			{
				continue;
			}
			
			$root = rtrim(str_replace('\\', '/', $root), '/') . '/';
			
			if(str_starts_with($file, $root))
			{
				$segment = substr($file, strlen($root));
				$slash = strpos($segment, '/');
				
				return $type . ':' . ($slash === false ? $segment : substr($segment, 0, $slash));
			}
		}
		
		// wp_get_upload_dir() is the variant that does NOT create the directory
		// as a side effect the way wp_upload_dir() does — an error path must
		// never write to disk
		$uploads = function_exists('wp_get_upload_dir')
			? (string)(wp_get_upload_dir()['basedir'] ?? '')
			: '';
		
		if($uploads !== ''
			&& str_starts_with($file, rtrim(str_replace('\\', '/', $uploads), '/') . '/'))
		{
			return 'uploads';
		}
		
		return $this->coreOrUnknown($file);
	}
	
	/**
	 * Core's tree is `wp-admin/`, `wp-includes/` and a fixed set of root
	 * files. Anything else under the document root arrived some other way,
	 * and anything outside it is not ours to label at all.
	 */
	protected function coreOrUnknown(
		string $file,
	): string
	{
		$root = defined('ABSPATH')
			? rtrim(str_replace('\\', '/', (string)ABSPATH), '/') . '/'
			: '';
		
		if($root === '' || str_starts_with($file, $root) === false)
		{
			// a system include, a symlinked library, an eval'd frame: outside
			// the site, so "unknown" states the truth without accusing anyone
			return 'unknown';
		}
		
		$relative = substr($file, strlen($root));
		
		if(str_starts_with($relative, 'wp-admin/') || str_starts_with($relative, 'wp-includes/'))
		{
			return 'core';
		}
		
		if(in_array($relative, self::CORE_ROOT_FILES, true))
		{
			return 'core';
		}
		
		$content = defined('WP_CONTENT_DIR')
			? rtrim(str_replace('\\', '/', (string)WP_CONTENT_DIR), '/') . '/'
			: '';
		
		if($content !== '' && str_starts_with($file, $content)
			&& in_array(substr($file, strlen($content)), self::CONTENT_DROPINS, true))
		{
			return 'dropin';
		}
		
		return 'unknown';
	}
	
	protected function homeHost(): string
	{
		if(function_exists('home_url') === false)
		{
			return '';
		}
		
		$host = wp_parse_url((string)home_url(), PHP_URL_HOST);
		
		return $host === false || $host === null ? '' : (string)$host;
	}
	
	protected function encode(
		array $errors,
	): string
	{
		return (string)json_encode($errors,
			JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
	}
	
	/**
	 * TLS peer verification for the ingest call — on by default; a console
	 * behind a self-signed certificate (intranet instances) opts out via
	 * add_filter('ovos_codesafe_sslverify', '__return_false')
	 */
	protected function verifyTls(): bool
	{
		return (bool)Legacy::filter('ovos_codesafe_sslverify', true);
	}
	
	/**
	 * Tells the console a release shipped — the deploy step a WordPress site
	 * rarely has (SENDER.md §7): POST /api/v1/ingest/release with the key,
	 * the configured release label unless one is given, optional at / ref /
	 * source / environment. Synchronous through the WP HTTP API — an admin
	 * request or a deploy hook, never the front end — and best-effort: the
	 * response code back, 0 when the sender is off, no label is known or the
	 * console is out of reach. Plugin::announceRelease() calls it when the
	 * configured label changes.
	 *
	 * @param array{at?: int|string, ref?: string, source?: string, environment?: string} $options
	 */
	public function announceRelease(
		string $release = '',
		array $options = [],
	): int
	{
		if($this->isEnabled() === false)
		{
			return 0;
		}
		$label = mb_substr(trim($release !== '' ? $release : $this->config->release()), 0, 64);
		if($label === '')
		{
			return 0;
		}
		
		$payload = [
			'release' => $label,
			'source' => mb_substr(trim((string)($options['source'] ?? 'wordpress-plugin')), 0, 32),
		];
		$at = $options['at'] ?? null;
		if(is_int($at) || (is_string($at) && trim($at) !== ''))
		{
			$payload['at'] = is_int($at) ? $at : trim($at);
		}
		$ref = trim((string)($options['ref'] ?? ''));
		if($ref !== '')
		{
			$payload['ref'] = mb_substr($ref, 0, 128);
		}
		$environment = trim((string)($options['environment'] ?? $this->config->environment()));
		if($environment !== '')
		{
			$payload['environment'] = mb_substr($environment, 0, 64);
		}
		
		$response = wp_remote_post($this->config->url() . '/api/v1/ingest/release', [
			'timeout' => 5,
			'headers' => [
				'Content-Type' => 'application/json',
				'X-Codesafe-Key' => $this->config->apiKey(),
				'X-Console-Key' => $this->config->apiKey(),
			],
			'body' => (string)json_encode($payload),
			'sslverify' => $this->verifyTls(),
		]);
		
		if(is_wp_error($response))
		{
			return 0;
		}
		
		return (int)wp_remote_retrieve_response_code($response);
	}
	
	protected function send(
		string $json,
	): void
	{
		// the response is already sent — release the connection so the
		// HTTP call is invisible to the end user
		if(function_exists('fastcgi_finish_request') && PHP_SAPI !== 'cli')
		{
			@fastcgi_finish_request();
		}
		
		$endpoint = $this->config->url() . '/api/v1/ingest';
		$verify = $this->verifyTls();
		
		if(function_exists('curl_init'))
		{
			$handle = curl_init($endpoint);
			
			curl_setopt_array($handle, [
				CURLOPT_POST => true,
				CURLOPT_POSTFIELDS => $json,
				CURLOPT_HTTPHEADER => [
					'Content-Type: application/json',
					'X-Codesafe-Key: ' . $this->config->apiKey(),
					'X-Console-Key: ' . $this->config->apiKey(),
				],
				CURLOPT_RETURNTRANSFER => true,
				// a libcurl without the threaded resolver times sub-second
				// timeouts via SIGALRM, which cannot do sub-second at all —
				// it refuses with errno 28 BEFORE even resolving, losing
				// every batch. NOSIGNAL switches to poll-based timing, where
				// the 300ms connect bound works; only the DNS phase itself
				// is then bounded by the system resolver instead.
				CURLOPT_NOSIGNAL => true,
				CURLOPT_CONNECTTIMEOUT_MS => 300,
				CURLOPT_TIMEOUT_MS => 1000,
				CURLOPT_SSL_VERIFYPEER => $verify,
				CURLOPT_SSL_VERIFYHOST => $verify ? 2 : 0,
			]);
			
			curl_exec($handle);
			
			return;
		}
		
		wp_remote_post($endpoint, [
			'timeout' => 1,
			'headers' => [
				'Content-Type' => 'application/json',
				'X-Codesafe-Key' => $this->config->apiKey(),
				'X-Console-Key' => $this->config->apiKey(),
			],
			'body' => $json,
			'sslverify' => $verify,
		]);
	}
}
