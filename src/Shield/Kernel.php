<?php
declare(strict_types=1);

/**
 * ovos/codesafe Shield kernel — zero dependencies, vendor this file.
 *
 *   require_once __DIR__ . '/Shield.php';
 *   use Ovos\Codesafe\Shield\{Kernel, Store, Facts, Consent, Verdict};
 *
 *   $kernel = new Kernel(
 *       'https://codesafe.example',                 // codesafe instance base URL
 *       $apiKey,                                   // the project api_key the sender already holds (secret!)
 *       new Store('/var/cache/app/shield.json', 'myapp:shield'),   // file tier + APCu prefix
 *       report: fn(string $kind, string $message, array $extra) => $sender->reportRefusal($kind, $message, $extra),
 *   );
 *   $consent = new Consent(detect: $config['shield_detect'], enforce: $config['shield_enforce'], kill: $config['shield_kill']);
 *   $verdict = $kernel->handle(Facts::fromServer($_SERVER, $_POST, fn() => file_get_contents('php://input')), $consent);
 *   if($verdict->isBlock())
 *   {
 *       // the adapter's own 403 — the kernel never emits a response
 *   }
 *   // on the host's own tick (the sender's minute flush, a shutdown hook, cron):
 *   $kernel->pull($consent);
 *
 * The kernel knows three things — Facts (what the adapter says about the
 * request; the kernel never reads a superglobal), Consent (three switches
 * read from the host's OWN config on every request: detect = observe,
 * enforce = block on the rules set to block, kill = nothing and no network)
 * and the Store
 * (rules and counters, two tiers: APCu for speed, a JSON file for
 * durability — a cleared APCu re-primes from the file, a host without APCu
 * runs on the file alone). It does three things: pull() — a conditional GET
 * of the project's live rules under the store's lock, on the host's tick,
 * every INTERVAL seconds, a 304 costs nothing, a failure leaves the cache
 * alone; judge() — pure over the cached ruleset, returns pass | observe |
 * block and never a response; report() — hands the match to a callable the
 * adapter supplied (the host's sender) as a `shield_observe` /
 * `shield_block` security event, `matched` capped at 200 bytes.
 *
 * Fails open on everything: a missing store, an unknown contract, a rule
 * the engine cannot run, a thrown anything — the request passes. A missing
 * store also forces the very next pull. A ruleset older than CEILING (24 h,
 * a codesafe instance gone silent) lifts by itself; a successful pull — 200 or 304 —
 * renews it. The verdict is `block` only when the rule is set to block AND
 * consent.enforce is on; an `observe` rule never blocks whatever the
 * switches say — the per-rule safety lives here. A rule's blocking word is
 * `block`, served to a kernel that names `mode-block` in X-Shield-Kinds;
 * an older codesafe says `proven`, and this kernel reads both
 * (Ruleset::blocks()).
 *
 * Rules are codesafe's one grammar for every runtime (dialect re2-2026,
 * contract 1): {field: uri|ua|ip|body, op: equals|prefix|contains|cidr|regex,
 * value, ci}. Literal ops fold ASCII only; regex runs as `~…~D[i]`, never
 * `u` — the two semantics codesafe's conformance corpus pins.
 *
 * Two kinds. A match rule (no `kind` key) decides on its own: observe or a
 * 403. A rate rule (`kind: rate`, `rate: {key: ip|user|route, limit,
 * window}`) is the same predicate plus a counter — over `limit` requests per
 * `window` seconds for one address, one user or the route itself, it
 * observes or answers 429 with Retry-After; an IPv6 address counts as its
 * /64, as in the Node twin (Kernel::rateAddress()). The match rules are judged
 * first; a rate rule counts only a request no match rule decided. Counting
 * needs APCu (the file tier cannot count): without it rate rules are
 * skipped, and the limit is per POOL — one server's APCu, not the site's.
 * The pull names `X-Shield-Kinds: match,rate,threat,vpatch,mode-block`, and the door
 * serves each kind only to a kernel that names it, so a kernel older than
 * rate rules never reads one as a match rule.
 *
 * Virtual patches (kind `vpatch`): an entry point, a parameter, a typed test
 * and WHO — `{who, conditions: [{target, decode, test, value, ci}]}`, every
 * condition holding, over the request as the platform parsed it (Facts'
 * query, form, JSON, cookies, headers, file names, and an upload's head and
 * tail when a condition names its contents). `who` is anyone,
 * anonymous or lacks:<capability>, and a nonce test asks the platform: a
 * blocking vpatch whose who or nonce the adapter cannot answer, or that
 * reads what the kernel could not (an upload, a JSON body past
 * Facts::JSON_CAP, a batch not read in full), is held with the reason `unanswered`
 * (Verdict::REASON_UNANSWERED), never blocked.
 * Every vpatch a request reaches is counted per minute beside the hits,
 * whether or not it decided the verdict: `entry` (its selecting entries
 * held, Ruleset::selects()), `match` (it held, who included) and `authed`
 * (a match by a caller signed in or one the host cannot tell) — the
 * evidence codesafe reads an observing rule by. Every request the counting
 * ran on is also an `entry` of rule 0 (HEARTBEAT): against the site's
 * request count it tells codesafe this site counts, so a vpatch's zero is
 * a zero and not a site that cannot say.
 *
 * Threat addresses (kind `threat`, served to a kernel that names it): a
 * `threats` section beside the rules — `{mode, pass, addresses}`, the
 * addresses codesafe saw send exploits. They are judged first: a request
 * from one that is not signed in and not to a `pass` path (where a person
 * behind the same NAT signs in) is blocked under enforce when the mode
 * blocks, else observed — counted as hits of the reserved rule 0, never
 * reported as an event, so a refusal never feeds the score that listed it.
 *
 * Fast pickup: the door says the project's ruleset version (X-Shield-Version,
 * one value whatever kinds a kernel reads) on every 200 and 304, and the
 * kernel stores it beside the rules. codesafe's ingest answers carry the
 * same version (`shield`); the host hands it to nudge(), which forces the
 * next pull when it differs — a rule switched off in codesafe lands on the
 * next tick after the site's next report, not at the interval.
 *
 * PHP 8.3 floor. codesafe's own suite tests this file (Tests\Shield\KernelSync
 * holds the vendored copies to it); consumers keep it byte-identical
 * (sha1-compare after sync) and load
 * it with require_once — like any PHP class file, a second include is a
 * fatal error (the classes bind at compile time, so no guard can help).
 *
 * @author Marcin Gil <mg@ovos.at>
 */

namespace Ovos\Codesafe\Shield;

use APCUIterator;
use Closure;
use LengthException;
use Throwable;

use function abs;
use function apcu_add;
use function apcu_delete;
use function apcu_enabled;
use function apcu_fetch;
use function apcu_inc;
use function apcu_store;
use function array_filter;
use function array_is_list;
use function array_key_exists;
use function array_keys;
use function array_slice;
use function array_values;
use function base64_decode;
use function ceil;
use function chr;
use function class_exists;
use function count;
use function crc32;
use function curl_exec;
use function curl_getinfo;
use function curl_init;
use function curl_setopt_array;
use function explode;
use function fclose;
use function file_get_contents;
use function file_put_contents;
use function fopen;
use function fstat;
use function function_exists;
use function hash;
use function hexdec;
use function http_get_last_response_headers;
use function implode;
use function in_array;
use function inet_ntop;
use function inet_pton;
use function intdiv;
use function is_array;
use function is_bool;
use function is_file;
use function is_int;
use function is_readable;
use function is_scalar;
use function is_string;
use function is_uploaded_file;
use function json_decode;
use function json_encode;
use function ltrim;
use function max;
use function ord;
use function parse_str;
use function preg_match;
use function preg_match_all;
use function preg_quote;
use function preg_replace;
use function preg_replace_callback;
use function preg_split;
use function rawurldecode;
use function rename;
use function rtrim;
use function sprintf;
use function str_contains;
use function str_ends_with;
use function str_ireplace;
use function str_replace;
use function str_starts_with;
use function strcasecmp;
use function stream_context_create;
use function stream_get_contents;
use function stripcslashes;
use function stripos;
use function strlen;
use function strncasecmp;
use function strpbrk;
use function strpos;
use function strrpos;
use function strspn;
use function strtolower;
use function strtoupper;
use function substr;
use function time;
use function trim;
use function uniqid;
use function unlink;

use const CURLINFO_RESPONSE_CODE;
use const CURLOPT_CONNECTTIMEOUT_MS;
use const CURLOPT_HEADER;
use const CURLOPT_HTTPHEADER;
use const CURLOPT_NOSIGNAL;
use const CURLOPT_RETURNTRANSFER;
use const CURLOPT_TIMEOUT_MS;
use const CURLOPT_URL;
use const CURLOPT_USERAGENT;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use const LOCK_EX;
use const PREG_SET_ORDER;

/**
 * What the adapter tells the kernel about the request. The kernel never
 * reads a superglobal; fromServer() takes the arrays as arguments so the
 * shaping — the URI decoded once, the body flattened or capped — is shared
 * and tested while the reading stays the adapter's.
 */
final class Facts
{
	/** a body rule cannot see past this, and the report says so */
	public const BODY_CAP = 65536;
	
	/** a JSON body past this is not decoded, and its json: conditions hold unanswered (jsonUnread()): padding never hides one */
	public const JSON_CAP = 1048576;
	
	/**
	 * how deep JSON may nest, as json_decode() counts it (512 holds containers
	 * 511 deep): its own default, so a document an app decodes is never one a
	 * rule cannot read
	 */
	public const JSON_DEPTH = 512;
	
	/** an upload is read as its first FILE_HEAD bytes and its last FILE_TAIL, one value: a payload hides at either end */
	public const FILE_HEAD = 65536;
	
	public const FILE_TAIL = 4096;
	
	protected ?string $body = null;
	
	protected bool $bodyRead = false;
	
	protected bool $bodyCapped = false;
	
	protected mixed $json = null;
	
	protected bool $jsonRead = false;
	
	protected bool $jsonUnread = false;
	
	/** @var array<string, ?string> the uploads read, by temp path */
	protected array $fileContents = [];
	
	/** @var array<string, ?bool> the host's answers, by question: a rule judged twice asks once */
	protected array $answers = [];
	
	/** the batch request a sub-request came in, whose superglobals its handler reads too (subRequest()) */
	protected ?Facts $outer = null;
	
	/** the REST API's path prefix without slashes — WordPress's rest_get_url_prefix() */
	public readonly string $restPrefix;
	
	/**
	 * @param array<string, mixed> $query the query as the platform parsed it ($_GET)
	 * @param array<string, mixed> $form the form fields as the platform parsed them ($_POST)
	 * @param array<string, string> $headers lowercase names
	 * @param array<string, mixed> $files field => the uploaded file's name (or names)
	 * @param ?Closure(): mixed $jsonReader a JSON body, decoded; it throws a LengthException for a body too large to read
	 * @param ?Closure(string): ?bool $can whether the signed-in user has a capability; null when the host cannot say
	 * @param ?Closure(string, string): ?bool $nonce whether a nonce is valid for an action; null when the host cannot say
	 * @param string $restPrefix the REST API's path prefix (restPrefixOf())
	 * @param bool $callerKnown whether the host could tell who the caller is: false leaves `authed` a guess,
	 *     and what depends on it — a vpatch's anonymous or lacks:, a threat address — only observes
	 * @param ?Closure(string): ?bool $kses whether the host's HTML filter would change a value (WordPress:
	 *     wp_kses_post()); null when the host cannot say
	 * @param array<string, mixed> $uploads field => the upload's temp path (or paths), nested as $files nests the names
	 * @param ?Closure(string): ?string $fileReader an upload's bytes by its temp path; null when the host cannot read it
	 */
	public function __construct(
		public readonly string $method,
		public readonly string $uri,
		public readonly string $ua,
		public readonly string $ip,
		public readonly bool $authed = false,
		protected ?Closure $bodyReader = null,
		public readonly string $user = '',
		public readonly array $query = [],
		public readonly array $form = [],
		public readonly array $cookies = [],
		public readonly array $headers = [],
		public readonly array $files = [],
		protected ?Closure $jsonReader = null,
		protected ?Closure $can = null,
		protected ?Closure $nonce = null,
		string $restPrefix = 'wp-json',
		public readonly bool $callerKnown = true,
		protected ?Closure $kses = null,
		public readonly array $uploads = [],
		protected ?Closure $fileReader = null,
	)
	{
		$this->restPrefix = self::restPrefixOf($restPrefix);
	}
	
	/**
	 * A WordPress batch's sub-request as its route's handler sees it: its
	 * method, its path under this site's REST prefix with its query, its body
	 * as the form and the JSON, its headers — and this request's caller, whom
	 * WordPress runs every sub-request as. Its handler also reads the
	 * superglobals, which stay this request's: its cookies, uploads, query,
	 * form and headers count beside the sub-request's own (Kernel::values()),
	 * and its host is this request's
	 *
	 * @param array<string, mixed> $headers
	 */
	public function subRequest(
		string $method,
		string $path,
		mixed $body,
		array $headers,
	): self
	{
		parse_str(explode('?', $path, 2)[1] ?? '', $query);
		$names = [];
		foreach($headers as $name => $value)
		{
			// WordPress keeps a header's values as a list: the first is the one read
			$names[strtolower((string)$name)] = is_array($value) ? (string)(array_values($value)[0] ?? '') : (is_scalar($value) ? (string)$value : '');
		}
		
		$sub = new self(strtoupper($method), self::decodeOnce('/' . $this->restPrefix . $path), $this->ua, $this->ip, $this->authed, null, $this->user, $query,
			is_array($body) ? $body : [], [], $names, [], static fn(): mixed => $body, $this->can, $this->nonce, $this->restPrefix, $this->callerKnown,
			$this->kses);
		$sub->outer = $this;
		
		return $sub;
	}
	
	/** the batch request this sub-request came in; null for a request of its own */
	public function outer(): ?Facts
	{
		return $this->outer;
	}
	
	/** the host the request named (its Host header) as authorityHost() reads one: '' when it named none */
	public function host(): string
	{
		// a sub-request runs on the site its batch reached
		if($this->outer !== null)
		{
			return $this->outer->host();
		}
		
		return self::hostOf((string)($this->headers['host'] ?? ''));
	}
	
	/** a host and port as a host: the port gone (an IPv6 address keeps its brackets), lower case, no trailing dot */
	public static function hostOf(
		string $hostPort,
	): string
	{
		$host = (string)preg_replace('~:[0-9]*$~D', '', trim($hostPort));
		
		return rtrim(strtolower($host), '.');
	}
	
	/** a REST prefix without its slashes; none is WordPress's default, wp-json */
	public static function restPrefixOf(
		string $prefix,
	): string
	{
		$prefix = trim($prefix, '/');
		
		return $prefix === '' ? 'wp-json' : $prefix;
	}
	
	/**
	 * @param array<string, mixed> $server the request's server parameters ($_SERVER or a PSR-7 equivalent)
	 * @param array<string, mixed> $post the parsed form fields ($_POST) — files never
	 * @param ?callable(): string $input the raw body reader (fn() => file_get_contents('php://input'))
	 * @param string $user who a `user`-keyed rate rule counts: the signed-in identity, or the name a login POST tries ('' = none, the rule is skipped)
	 * @param ?array<string, mixed> $get the parsed query ($_GET); null = the raw URI's query through parse_str
	 * @param array<string, mixed> $cookies the parsed cookies ($_COOKIE)
	 * @param array<string, mixed> $files the uploads ($_FILES): their names, and their temp files for a file-content condition
	 * @param ?callable(string): ?bool $can whether the signed-in user has a capability (a vpatch's `lacks:`)
	 * @param ?callable(string, string): ?bool $nonce whether a nonce is valid for an action (a vpatch's nonce test)
	 * @param string $restPrefix the REST API's path prefix — WordPress's rest_get_url_prefix(), wp-json elsewhere
	 * @param bool $callerKnown whether the host could tell who the caller is (Facts::$callerKnown)
	 * @param ?callable(string): ?bool $kses whether the host's HTML filter would change a value (a vpatch's unsafe_html)
	 * @param ?callable(string): ?string $fileReader an upload's bytes by its temp path; null reads PHP's own (uploadReader())
	 */
	public static function fromServer(
		array $server,
		array $post = [],
		?callable $input = null,
		bool $authed = false,
		?string $ip = null,
		string $user = '',
		?array $get = null,
		array $cookies = [],
		array $files = [],
		?callable $can = null,
		?callable $nonce = null,
		string $restPrefix = 'wp-json',
		bool $callerKnown = true,
		?callable $kses = null,
		?callable $fileReader = null,
	): self
	{
		$uri = is_string($server['REQUEST_URI'] ?? null) ? $server['REQUEST_URI'] : '/';
		if($get === null)
		{
			// the RAW query, as PHP would have parsed it — the URI is decoded once below
			parse_str(explode('?', $uri, 2)[1] ?? '', $get);
		}
		$contentType = is_string($server['CONTENT_TYPE'] ?? null) ? $server['CONTENT_TYPE'] : '';
		
		return new self(
			is_string($server['REQUEST_METHOD'] ?? null) ? $server['REQUEST_METHOD'] : 'GET',
			self::decodeOnce($uri),
			is_string($server['HTTP_USER_AGENT'] ?? null) ? $server['HTTP_USER_AGENT'] : '',
			$ip ?? (is_string($server['REMOTE_ADDR'] ?? null) ? $server['REMOTE_ADDR'] : ''),
			$authed,
			self::bodyReader($contentType, $post, $input),
			$user,
			$get,
			$post,
			$cookies,
			self::headersOf($server),
			self::fileNames($files),
			self::jsonReader($contentType, $input),
			$can === null ? null : Closure::fromCallable($can),
			$nonce === null ? null : Closure::fromCallable($nonce),
			$restPrefix,
			$callerKnown,
			$kses === null ? null : Closure::fromCallable($kses),
			self::uploadPaths($files),
			$fileReader === null ? self::uploadReader() : Closure::fromCallable($fileReader),
		);
	}
	
	/** the request headers by lowercase name, off the server's HTTP_* keys */
	public static function headersOf(
		array $server,
	): array
	{
		$headers = [];
		foreach($server as $key => $value)
		{
			if(is_string($value) && str_starts_with((string)$key, 'HTTP_'))
			{
				$headers[strtolower(str_replace('_', '-', substr((string)$key, 5)))] = $value;
			}
		}
		foreach(['CONTENT_TYPE' => 'content-type', 'CONTENT_LENGTH' => 'content-length'] as $key => $name)
		{
			if(is_string($server[$key] ?? null))
			{
				$headers[$name] = $server[$key];
			}
		}
		
		return $headers;
	}
	
	/** $_FILES as names: field => name, a multiple upload's names as a list — the bytes are never read */
	public static function fileNames(
		array $files,
	): array
	{
		$names = [];
		foreach($files as $field => $file)
		{
			if(is_array($file) && isset($file['name']))
			{
				$names[(string)$field] = $file['name'];
			}
		}
		
		return $names;
	}
	
	/** $_FILES as temp paths: field => tmp_name, a multiple upload's as a list — nested as fileNames() nests the names */
	public static function uploadPaths(
		array $files,
	): array
	{
		$paths = [];
		foreach($files as $field => $file)
		{
			if(is_array($file) && isset($file['tmp_name']))
			{
				$paths[(string)$field] = $file['tmp_name'];
			}
		}
		
		return $paths;
	}
	
	/** PHP's own temp files, read by headAndTail(): a path PHP did not write for this request's upload is never opened */
	public static function uploadReader(): Closure
	{
		return static fn(string $path): ?string => is_uploaded_file($path) ? self::headAndTail($path) : null;
	}
	
	/** a file's first $head bytes and its last $tail as one value, the whole file when it is no longer; null when it cannot be read */
	public static function headAndTail(
		string $path,
		int $head = self::FILE_HEAD,
		int $tail = self::FILE_TAIL,
	): ?string
	{
		$handle = is_file($path) && is_readable($path) ? fopen($path, 'rb') : false;
		if($handle === false)
		{
			return null;
		}
		try
		{
			$stat = fstat($handle);
			$size = $stat === false ? 0 : $stat['size'];
			if($size <= $head + $tail)
			{
				$bytes = stream_get_contents($handle);
			}
			else
			{
				// the middle is never read: a large upload costs what a small one does
				$start = stream_get_contents($handle, $head);
				$end = stream_get_contents($handle, $tail, $size - $tail);
				$bytes = $start === false || $end === false ? false : $start . $end;
			}
		}
		finally
		{
			fclose($handle);
		}
		
		return $bytes === false ? null : $bytes;
	}
	
	/** a JSON body, decoded — read only when a json: target asks; past the cap it throws, and json() says the body went unread */
	public static function jsonReader(
		string $contentType,
		?callable $input,
		int $cap = self::JSON_CAP,
	): ?Closure
	{
		if($input === null || self::jsonType($contentType) === false)
		{
			return null;
		}
		
		return static function() use ($input, $cap): mixed
		{
			$raw = $input();
			// the app may still decode what the kernel will not: unread, never "no JSON"
			if(is_string($raw) && strlen($raw) > $cap)
			{
				throw new LengthException('a JSON body past the cap');
			}
			
			// nested deeper than JSON_DEPTH allows: no JSON at all
			return is_string($raw) ? json_decode($raw, true, Facts::JSON_DEPTH) : null;
		};
	}
	
	/** whether a body of this content type is JSON to a rule: `application/json`, a `+json` type, or one WordPress reads as JSON */
	public static function jsonType(
		string $contentType,
	): bool
	{
		$type = strtolower(trim(explode(';', $contentType, 2)[0]));
		
		return $type === 'application/json' || str_ends_with($type, '+json') || self::wordpressJson($contentType);
	}
	
	/**
	 * Whether WordPress reads a body of this content type as JSON:
	 * WP_REST_Request::get_content_type()'s value — cut at a `;` past the
	 * first byte, lower case, holding a `/`, trimmed — through
	 * wp_is_json_media_type()'s pattern
	 */
	public static function wordpressJson(
		string $contentType,
	): bool
	{
		// WordPress tests strpos() for truth: a `;` as the first byte cuts nothing
		$value = strtolower(strpos($contentType, ';') ? explode(';', $contentType, 2)[0] : $contentType);
		
		return str_contains($value, '/') && preg_match('/(^|\s|,)application\/([\w!#\$&-\^\.\+]+\+)?json(\+oembed)?($|\s|;|,)/i', trim($value)) === 1;
	}
	
	/**
	 * What the body IS to a rule: for a form (urlencoded, multipart) the
	 * parsed fields flattened to `name=value` lines — PHP has parsed them and
	 * multipart's raw stream is gone by then; for JSON, XML and anything
	 * else the raw input, capped at BODY_CAP, decoded once like the URI. Read
	 * lazily: nothing is touched until a body rule asks
	 *
	 * @return ?Closure(): array{string, bool} the body and whether it was capped; null = no body to read
	 */
	public static function bodyReader(
		string $contentType,
		array $post,
		?callable $input,
		int $cap = self::BODY_CAP,
	): ?Closure
	{
		$type = strtolower(trim(explode(';', $contentType, 2)[0]));
		if($type === 'application/x-www-form-urlencoded' || $type === 'multipart/form-data')
		{
			return static fn(): array => [self::flatten($post), false];
		}
		if($input === null)
		{
			return null;
		}
		
		return static function() use ($input, $cap): array
		{
			$raw = $input();
			$raw = is_string($raw) ? $raw : '';
			$capped = strlen($raw) > $cap;
			
			return [self::decodeOnce($capped ? substr($raw, 0, $cap) : $raw), $capped];
		};
	}
	
	/** the parsed fields as `name=value` lines, nested arrays as `a[b]=value` */
	public static function flatten(
		array $fields,
		string $prefix = '',
	): string
	{
		$lines = '';
		foreach($fields as $name => $value)
		{
			$key = $prefix === '' ? (string)$name : $prefix . '[' . $name . ']';
			if(is_array($value))
			{
				$lines .= self::flatten($value, $key);
				
				continue;
			}
			$lines .= $key . '=' . (is_string($value) ? $value : (string)json_encode($value)) . "\n";
		}
		
		return $lines;
	}
	
	/** URL-decoding, once — `%2e%2e/` reads as `../`, `%252e` as `%2e` */
	public static function decodeOnce(
		string $value,
	): string
	{
		return rawurldecode($value);
	}
	
	/** the body as a rule reads it; null when the request has none the kernel can read */
	public function body(): ?string
	{
		if($this->bodyRead === false)
		{
			$this->bodyRead = true;
			if($this->bodyReader !== null)
			{
				try
				{
					[$this->body, $this->bodyCapped] = ($this->bodyReader)();
				}
				catch(Throwable)
				{
					$this->body = null;
				}
			}
		}
		
		return $this->body;
	}
	
	public function bodyWasRead(): bool
	{
		return $this->bodyRead;
	}
	
	public function bodyWasCapped(): bool
	{
		return $this->bodyCapped;
	}
	
	/** a JSON body, decoded; null when there is none, or none the kernel read (jsonUnread()) */
	public function json(): mixed
	{
		if($this->jsonRead === false)
		{
			$this->jsonRead = true;
			try
			{
				$this->json = $this->jsonReader === null ? null : ($this->jsonReader)();
			}
			catch(LengthException)
			{
				$this->jsonUnread = true;
			}
			catch(Throwable)
			{
				$this->json = null;
			}
		}
		
		return $this->json;
	}
	
	/** whether the body is JSON too large to read (Facts::JSON_CAP): what its json: conditions ask is not known */
	public function jsonUnread(): bool
	{
		$this->json();
		
		return $this->jsonUnread;
	}
	
	/** whether the signed-in user has a capability; null when the host cannot say */
	public function can(
		string $capability,
	): ?bool
	{
		return $this->answer('can:' . $capability, $this->can, $capability);
	}
	
	/** a host's answer, asked once per request and question: only a boolean is one, a throw none */
	protected function answer(
		string $question,
		?Closure $host,
		string ...$arguments,
	): ?bool
	{
		if(array_key_exists($question, $this->answers) === false)
		{
			try
			{
				$answer = $host === null ? null : $host(...$arguments);
			}
			catch(Throwable)
			{
				$answer = null;
			}
			$this->answers[$question] = is_bool($answer) ? $answer : null;
		}
		
		return $this->answers[$question];
	}
	
	/**
	 * An upload's contents as a rule reads them, its head and tail
	 * (FILE_HEAD, FILE_TAIL), read once; null when the host cannot read it.
	 * A payload padded into the middle of a larger upload is never read, so a
	 * file-content condition passes it
	 */
	public function fileContent(
		string $path,
	): ?string
	{
		if(array_key_exists($path, $this->fileContents) === false)
		{
			try
			{
				$bytes = $this->fileReader === null ? null : ($this->fileReader)($path);
			}
			catch(Throwable)
			{
				$bytes = null;
			}
			$bytes = is_string($bytes) ? $bytes : null;
			// a host's reader may hand the whole file: a rule reads its head and tail all the same
			if($bytes !== null && strlen($bytes) > self::FILE_HEAD + self::FILE_TAIL)
			{
				$bytes = substr($bytes, 0, self::FILE_HEAD) . substr($bytes, -self::FILE_TAIL);
			}
			$this->fileContents[$path] = $bytes;
		}
		
		return $this->fileContents[$path];
	}
	
	/** whether the host's HTML filter would change a value; null when the host cannot say */
	public function htmlUnsafe(
		string $value,
	): ?bool
	{
		return $this->answer('kses:' . $value, $this->kses, $value);
	}
	
	/** whether a nonce is valid for an action; null when the host cannot say */
	public function nonceValid(
		string $action,
		string $value,
	): ?bool
	{
		// the action's length keeps `a` + `b:c` apart from `a:b` + `c`
		return $this->answer('nonce:' . strlen($action) . ':' . $action . ':' . $value, $this->nonce, $action, $value);
	}
	
	/** the path alone — what a report line names; the query may carry what the body may not */
	public function path(): string
	{
		$path = explode('?', $this->uri, 2)[0];
		
		return $path === '' ? '/' : $path;
	}
	
	/** the subject a field reads — null when this request has none */
	public function field(
		string $field,
	): ?string
	{
		return match($field)
		{
			Ruleset::FIELD_URI => $this->uri,
			Ruleset::FIELD_UA => $this->ua,
			Ruleset::FIELD_IP => $this->ip,
			Ruleset::FIELD_BODY => $this->body(),
			default => null,
		};
	}
}

/**
 * The three switches, read from the host's OWN config on every request and
 * never baked into the cached ruleset — unticking stops the next request,
 * not the next pull. detect = pull and observe; enforce = refuse on a
 * rule set to block (inert without detect); kill = nothing, and no network
 */
final class Consent
{
	public function __construct(
		public readonly bool $detect = false,
		public readonly bool $enforce = false,
		public readonly bool $kill = false,
	)
	{
	}
	
	public function active(): bool
	{
		return $this->kill === false && $this->detect;
	}
	
	public function blocks(): bool
	{
		return $this->active() && $this->enforce;
	}
}

/** pass | observe | block — and why, for the log; never a response (status() says which one the adapter sends) */
final class Verdict
{
	public const PASS = 'pass';
	
	public const OBSERVE = 'observe';
	
	public const BLOCK = 'block';
	
	public const KIND_OBSERVE = 'shield_observe';
	
	public const KIND_BLOCK = 'shield_block';
	
	/** a rate rule's verdict, observed or answered — `mode` in the report says which */
	public const KIND_RATE = 'shield_rate';
	
	/**
	 * A blocking vpatch held as an observe because the host could not answer
	 * its who or its nonce: a layer that judges before the host can (the
	 * WordPress prepend) leaves such a request to the one that can
	 */
	public const REASON_UNANSWERED = 'unanswered';
	
	/**
	 * @param ?array<string, mixed> $rule the rule that matched, as served
	 * @param string $matched the fragment that matched, capped by the kernel
	 * @param int $count a rate rule's count in its window (the sliding estimate, rounded up)
	 * @param int $retryAfter a rate rule's seconds to the window's end — the 429's Retry-After
	 */
	public function __construct(
		public readonly string $outcome,
		public readonly ?array $rule = null,
		public readonly string $matched = '',
		public readonly string $reason = '',
		public readonly int $count = 0,
		public readonly int $retryAfter = 0,
	)
	{
	}
	
	public static function pass(
		string $reason,
	): self
	{
		return new self(self::PASS, null, '', $reason);
	}
	
	public function isPass(): bool
	{
		return $this->outcome === self::PASS;
	}
	
	public function isBlock(): bool
	{
		return $this->outcome === self::BLOCK;
	}
	
	public function isRate(): bool
	{
		return $this->rule !== null && Ruleset::isRate($this->rule);
	}
	
	/** the security kind the report carries */
	public function kind(): string
	{
		if($this->isRate())
		{
			return self::KIND_RATE;
		}
		
		return $this->outcome === self::BLOCK ? self::KIND_BLOCK : self::KIND_OBSERVE;
	}
	
	/** what the adapter answers: 403 for a match block, 429 (with Retry-After) for a rate block, 200 = carry on */
	public function status(): int
	{
		if($this->isBlock() === false)
		{
			return 200;
		}
		
		return $this->isRate() ? 429 : 403;
	}
}

/**
 * The published ruleset as the kernel holds it: the rules that passed the
 * shape check, the digest the next conditional GET sends back, when it was
 * fetched, and whether the contract is one this kernel knows. An unknown
 * contract or dialect is stored — so the kernel does not hammer the door —
 * and unusable: every request passes
 */
final class Ruleset
{
	public const CONTRACT = 1;
	
	public const DIALECT = 're2-2026';
	
	public const FIELD_URI = 'uri';
	
	public const FIELD_UA = 'ua';
	
	public const FIELD_IP = 'ip';
	
	public const FIELD_BODY = 'body';
	
	public const FIELDS = [self::FIELD_URI, self::FIELD_UA, self::FIELD_IP, self::FIELD_BODY];
	
	public const OP_EQUALS = 'equals';
	
	public const OP_PREFIX = 'prefix';
	
	public const OP_CONTAINS = 'contains';
	
	public const OP_CIDR = 'cidr';
	
	public const OP_REGEX = 'regex';
	
	public const OPS = [self::OP_EQUALS, self::OP_PREFIX, self::OP_CONTAINS, self::OP_CIDR, self::OP_REGEX];
	
	public const MODE_OBSERVE = 'observe';
	
	/** the blocking mode, served to a kernel that names KIND_MODE_BLOCK */
	public const MODE_BLOCK = 'block';
	
	/** the blocking mode as a codesafe before rule modes says it — read as MODE_BLOCK */
	public const MODE_PROVEN = 'proven';
	
	/** named in X-Shield-Kinds: this kernel reads MODE_BLOCK — never a rule's kind */
	public const KIND_MODE_BLOCK = 'mode-block';
	
	public const VALUE_MAX = 600;
	
	public const KIND_MATCH = 'match';
	
	public const KIND_RATE = 'rate';
	
	public const KIND_VPATCH = 'vpatch';
	
	public const KINDS = [self::KIND_MATCH, self::KIND_RATE, self::KIND_VPATCH];
	
	/** a vpatch's targets without a name — `rest` is the REST route in either spelling — and the prefixes that take one (`query:file`) */
	public const TARGETS = ['method', 'path', 'rest'];
	
	/** `request:` is $_REQUEST's reading: the query's values and the body's; `file:` an upload's name, `file-content:` its bytes */
	public const TARGET_PREFIXES = ['query', 'body', 'request', 'json', 'cookie', 'header', 'file', 'file-content', 'query-keys', 'body-keys'];
	
	/** the decode steps; `json:<dot.path>` is json walked to a path, as the json: target walks a body */
	public const DECODES = ['url', 'base64', 'json'];
	
	/** the values a condition's decode steps yield that are read at most: past them the condition holds unanswered */
	public const DECODED_MAX = 256;
	
	/** the shortcodes or blocks one decode step reads in a value at most: past them the value is not read in full and the condition holds unanswered */
	public const OCCURRENCES_MAX = 256;
	
	/** a shortcode tag as add_shortcode() takes one, in printable ASCII: never `<>&/[]=` or a space */
	public const SHORTCODE_TAG = '~^[^<>&/\[\]\x00-\x20=\x7f-\xff]{1,100}$~D';
	
	/** a block's `namespace/name` as WordPress's block parser reads one */
	public const BLOCK_NAME = '~^[a-z][a-z0-9_-]*/[a-z][a-z0-9_-]*$~D';
	
	public const TESTS = ['equals', 'in', 'not_in', 'prefix', 'suffix', 'contains', 'regex', 'not_prefix', 'not_suffix', 'not_contains',
		'not_regex', 'numeric', 'not_numeric', 'exists', 'longer_than', 'greater_than', 'less_than', 'offsite', 'has_quote', 'has_markup',
		'unsafe_html', 'nonce_invalid'];
	
	/** the tests whose value is a list, and those that take none */
	public const LIST_TESTS = ['in', 'not_in'];
	
	public const BARE_TESTS = ['numeric', 'not_numeric', 'exists', 'offsite', 'has_quote', 'has_markup', 'unsafe_html'];
	
	/** the tests the host answers: unanswered they only observe, and never sit in a group, where one branch would answer for the others */
	public const HOST_TESTS = ['nonce_invalid', 'unsafe_html'];
	
	/** the tests a condition names the handler a request reaches with, not what an exploit carries (selects()) */
	public const ENTRY_TESTS = ['equals', 'in', 'prefix', 'suffix'];
	
	/** the integer the number tests compare against at most, either way — fifteen digits, which every runtime holds exactly */
	public const NUMBER_MAX = 999999999999999;
	
	public const CONDITIONS_MAX = 6;
	
	public const LIST_MAX = 50;
	
	/** the decode steps one condition chains at most */
	public const DECODE_STEPS_MAX = 2;
	
	/** an entry `{"any": [...]}` holds when one of its GROUP_MIN to GROUP_MAX plain conditions does; it counts as one */
	public const GROUP_ANY = 'any';
	
	public const GROUP_MIN = 2;
	
	public const GROUP_MAX = 4;
	
	public const WHO_ANYONE = 'anyone';
	
	public const WHO_ANONYMOUS = 'anonymous';
	
	public const WHO_LACKS = 'lacks:';
	
	/** the threat-address section's kind, named in X-Shield-Kinds — never a rule's */
	public const KIND_THREAT = 'threat';
	
	/** the rule id a threat address's hits are counted under: a rule's id is never 0 */
	public const THREAT_RULE = 0;
	
	/** at most this many addresses, this many pass paths of at most PASS_MAX bytes */
	public const THREATS_MAX = 5000;
	
	public const PASSES_MAX = 20;
	
	public const PASS_MAX = 100;
	
	/** one address · one user (Facts::$user) · the route itself, whoever asks */
	public const RATE_KEY_IP = 'ip';
	
	public const RATE_KEY_USER = 'user';
	
	public const RATE_KEY_ROUTE = 'route';
	
	public const RATE_KEYS = [self::RATE_KEY_IP, self::RATE_KEY_USER, self::RATE_KEY_ROUTE];
	
	public const RATE_LIMIT_MAX = 1000000;
	
	public const RATE_WINDOW_MAX = 3600;
	
	/**
	 * @param list<array<string, mixed>> $rules
	 */
	public function __construct(
		public readonly array $rules,
		public readonly string $digest,
		public readonly int $fetchedAt,
		public readonly bool $usable,
		public readonly string $project = '',
		public readonly string $version = '',
		public readonly ?array $threats = null,
	)
	{
	}
	
	/**
	 * The door's payload, checked: contract and dialect this kernel knows,
	 * every rule with an int id, a field and an op off the lists, a
	 * non-empty value under VALUE_MAX, a mode — anything else is left out.
	 * The digest is the door's (X-Shield-Sha256) or, absent, the sha256 of
	 * the rules as received — the same bytes the door hashes. The version is
	 * the door's X-Shield-Version, '' when it said none. The threat section is
	 * kept only whole — a mode, pass paths, addresses PHP can read (threats())
	 */
	public static function fromPayload(
		array $payload,
		int $fetchedAt,
		string $digest = '',
		string $version = '',
	): self
	{
		$usable = ($payload['contract'] ?? null) === self::CONTRACT
			&& ($payload['dialect'] ?? null) === self::DIALECT
			&& is_array($payload['rules'] ?? null);
		$rules = [];
		if($usable)
		{
			foreach($payload['rules'] as $rule)
			{
				if(self::wellFormed($rule))
				{
					$rules[] = $rule;
				}
			}
		}
		if(preg_match('~^[0-9a-f]{64}$~', $digest) !== 1)
		{
			$digest = hash('sha256', (string)json_encode(is_array($payload['rules'] ?? null) ? $payload['rules'] : [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
				. (isset($payload['threats']) ? (string)json_encode($payload['threats'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : ''));
		}
		
		return new self($rules, $digest, $fetchedAt, $usable, is_string($payload['project'] ?? null) ? $payload['project'] : '',
			self::isVersion($version) ? $version : '', $usable ? self::threats($payload['threats'] ?? null) : null);
	}
	
	/** the stored record back into a ruleset; null when the record is not one */
	public static function fromRecord(
		mixed $record,
	): ?self
	{
		if(is_array($record) === false || is_array($record['rules'] ?? null) === false || is_int($record['fetched_at'] ?? null) === false)
		{
			return null;
		}
		
		return new self(
			$record['rules'],
			is_string($record['sha256'] ?? null) ? $record['sha256'] : '',
			$record['fetched_at'],
			($record['usable'] ?? false) === true,
			is_string($record['project'] ?? null) ? $record['project'] : '',
			is_string($record['version'] ?? null) && self::isVersion($record['version']) ? $record['version'] : '',
			// stored as checked (a lookup map): read per request, never checked again
			is_array($record['threats']['addresses'] ?? null) ? $record['threats'] : null,
		);
	}
	
	/**
	 * The door's threat section, checked: a mode off the list, at most
	 * PASSES_MAX pass paths (each `/…`, under PASS_MAX bytes), at most
	 * THREATS_MAX addresses in their canonical form as a lookup map — an
	 * address PHP cannot read is left out. Null when there is none
	 *
	 * @return ?array{mode: string, pass: list<string>, addresses: array<string, int>}
	 */
	public static function threats(
		mixed $section,
	): ?array
	{
		if(is_array($section) === false || in_array($section['mode'] ?? null, [self::MODE_OBSERVE, self::MODE_BLOCK, self::MODE_PROVEN], true) === false
			|| is_array($section['addresses'] ?? null) === false)
		{
			return null;
		}
		$pass = [];
		foreach(is_array($section['pass'] ?? null) ? $section['pass'] : [] as $path)
		{
			if(is_string($path) && str_starts_with($path, '/') && strlen($path) <= self::PASS_MAX && count($pass) < self::PASSES_MAX)
			{
				$pass[] = $path;
			}
		}
		$addresses = [];
		foreach($section['addresses'] as $address)
		{
			$canonical = is_string($address) ? self::canonical($address) : '';
			if($canonical !== '')
			{
				$addresses[$canonical] = 1;
			}
			if(count($addresses) >= self::THREATS_MAX)
			{
				break;
			}
		}
		
		return ['mode' => $section['mode'], 'pass' => $pass, 'addresses' => $addresses];
	}
	
	/**
	 * An address in the one form every side compares: the `::ffff:` form
	 * unwrapped to its v4 address, then inet_ntop(inet_pton()) — RFC 5952 for
	 * v6, as the Node twin writes it; '' when it is none
	 */
	public static function canonical(
		string $address,
	): string
	{
		$address = trim($address);
		if(preg_match('~^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$~i', $address, $mapped) === 1)
		{
			$address = $mapped[1];
		}
		// @: inet_pton() warns on anything that is not an address
		$packed = @inet_pton($address);
		
		return $packed === false ? '' : (string)inet_ntop($packed);
	}
	
	/** what the store keeps — JSON, never PHP */
	public function toRecord(): array
	{
		return [
			'contract' => self::CONTRACT,
			'dialect' => self::DIALECT,
			'project' => $this->project,
			'fetched_at' => $this->fetchedAt,
			'sha256' => $this->digest,
			'version' => $this->version,
			'threats' => $this->threats,
			'usable' => $this->usable,
			'rules' => $this->rules,
		];
	}
	
	/** renewed by a 304 — with the version it said, when it said one */
	public function withFetchedAt(
		int $fetchedAt,
		string $version = '',
	): self
	{
		return new self($this->rules, $this->digest, $fetchedAt, $this->usable, $this->project,
			self::isVersion($version) ? $version : $this->version, $this->threats);
	}
	
	/** a version is the door's sha256, lowercase hex */
	public static function isVersion(
		string $version,
	): bool
	{
		return preg_match('~^[0-9a-f]{64}$~', $version) === 1;
	}
	
	/** past the ceiling: a codesafe instance gone silent lifts its shield */
	public function isStale(
		int $now,
		int $ceiling,
	): bool
	{
		return $this->fetchedAt + $ceiling <= $now;
	}
	
	public static function wellFormed(
		mixed $rule,
	): bool
	{
		if(is_array($rule) && self::isVpatch($rule))
		{
			return self::vpatchWellFormed($rule);
		}
		
		return is_array($rule)
			&& is_int($rule['id'] ?? null)
			&& in_array($rule['field'] ?? null, self::FIELDS, true)
			&& in_array($rule['op'] ?? null, self::OPS, true)
			&& is_string($rule['value'] ?? null) && trim($rule['value']) !== '' && strlen($rule['value']) <= self::VALUE_MAX
			&& (isset($rule['ci']) === false || is_bool($rule['ci']))
			&& is_string($rule['mode'] ?? null)
			&& (isset($rule['kind']) === false || in_array($rule['kind'], self::KINDS, true))
			&& (self::isRate($rule) === false || self::rateWellFormed($rule['rate'] ?? null));
	}
	
	public static function isVpatch(
		array $rule,
	): bool
	{
		return ($rule['kind'] ?? self::KIND_MATCH) === self::KIND_VPATCH;
	}
	
	/**
	 * Whether a vpatch entry selects the handler a request reaches — its
	 * entry point: a route, or an ENTRY_TESTS test on a value as sent (no
	 * decode steps) of any target but an upload's contents; a group when
	 * every member does. A negation, a payload test, a nonce or exists says
	 * what the exploit carries
	 */
	public static function selects(
		array $entry,
	): bool
	{
		if(isset($entry[self::GROUP_ANY]))
		{
			foreach((array)$entry[self::GROUP_ANY] as $member)
			{
				if(self::selects((array)$member) === false)
				{
					return false;
				}
			}
			
			return true;
		}
		$target = (string)($entry['target'] ?? '');
		
		return $target === 'rest' || (in_array($entry['test'] ?? null, self::ENTRY_TESTS, true) && ($entry['decode'] ?? []) === []
			&& str_starts_with($target, 'file-content:') === false);
	}
	
	/**
	 * Whether a rule's (or the threat section's) mode blocks under enforce:
	 * `block`, or `proven` from a codesafe before rule modes. Anything else —
	 * observe, a word this kernel does not know — only observes
	 */
	public static function blocks(
		mixed $mode,
	): bool
	{
		return $mode === self::MODE_BLOCK || $mode === self::MODE_PROVEN;
	}
	
	/** a vpatch: an int id, a mode, a `who` off the vocabulary, 1 to CONDITIONS_MAX entries each well formed */
	public static function vpatchWellFormed(
		array $rule,
	): bool
	{
		$conditions = $rule['conditions'] ?? null;
		if(is_int($rule['id'] ?? null) === false || is_string($rule['mode'] ?? null) === false
			|| self::whoWellFormed($rule['who'] ?? null) === false
			|| is_array($conditions) === false || array_is_list($conditions) === false
			|| count($conditions) < 1 || count($conditions) > self::CONDITIONS_MAX)
		{
			return false;
		}
		foreach($conditions as $condition)
		{
			if(self::entryWellFormed($condition) === false)
			{
				return false;
			}
		}
		
		return true;
	}
	
	/** a vpatch's entry: a plain condition, or a group of GROUP_MIN to GROUP_MAX plain conditions under `any` and nothing else */
	public static function entryWellFormed(
		mixed $entry,
	): bool
	{
		if(is_array($entry) && array_key_exists(self::GROUP_ANY, $entry))
		{
			$members = $entry[self::GROUP_ANY];
			if(count($entry) !== 1 || is_array($members) === false || array_is_list($members) === false
				|| count($members) < self::GROUP_MIN || count($members) > self::GROUP_MAX)
			{
				return false;
			}
			foreach($members as $member)
			{
				// no group in a group, nothing the host answers or reads: one unanswered branch would answer for the others
				if(is_array($member) === false || array_key_exists(self::GROUP_ANY, $member)
					|| in_array($member['test'] ?? null, self::HOST_TESTS, true)
					|| (is_string($member['target'] ?? null) && str_starts_with($member['target'], 'file-content:'))
					|| self::conditionWellFormed($member) === false)
				{
					return false;
				}
			}
			
			return true;
		}
		
		return self::conditionWellFormed($entry);
	}
	
	public static function whoWellFormed(
		mixed $who,
	): bool
	{
		return $who === self::WHO_ANYONE || $who === self::WHO_ANONYMOUS
			|| (is_string($who) && preg_match('~^lacks:[a-z0-9_]{1,64}$~D', $who) === 1);
	}
	
	/** a target off the vocabulary; a decode list off its own; a value the test can read — a list, a count, or a bounded string */
	public static function conditionWellFormed(
		mixed $condition,
	): bool
	{
		if(is_array($condition) === false || self::targetWellFormed($condition['target'] ?? null) === false
			|| in_array($condition['test'] ?? null, self::TESTS, true) === false
			|| (isset($condition['ci']) && is_bool($condition['ci']) === false))
		{
			return false;
		}
		$decode = $condition['decode'] ?? [];
		if(is_array($decode) === false || array_is_list($decode) === false || count($decode) > self::DECODE_STEPS_MAX)
		{
			return false;
		}
		foreach($decode as $step)
		{
			if(self::decodeWellFormed($step) === false)
			{
				return false;
			}
		}
		$test = $condition['test'];
		$value = $condition['value'] ?? null;
		if(in_array($test, self::BARE_TESTS, true))
		{
			return true;
		}
		if(in_array($test, self::LIST_TESTS, true))
		{
			if(is_array($value) === false || array_is_list($value) === false || $value === [] || count($value) > self::LIST_MAX)
			{
				return false;
			}
			foreach($value as $item)
			{
				if(is_string($item) === false || strlen($item) > self::VALUE_MAX)
				{
					return false;
				}
			}
			
			return true;
		}
		if($test === 'longer_than')
		{
			return is_int($value) && $value >= 0 && $value <= Facts::BODY_CAP;
		}
		if($test === 'greater_than' || $test === 'less_than')
		{
			return is_int($value) && abs($value) <= self::NUMBER_MAX;
		}
		
		return is_string($value) && trim($value) !== '' && strlen($value) <= self::VALUE_MAX;
	}
	
	/** a decode step: one of DECODES, or `json:` and a path the json: target would take */
	public static function decodeWellFormed(
		mixed $step,
	): bool
	{
		return in_array($step, self::DECODES, true)
			|| (is_string($step) && str_starts_with($step, 'json:') && $step !== 'json:' && self::targetWellFormed($step))
			|| self::shortcodeStep($step) !== null || self::blockStep($step) !== null;
	}
	
	/**
	 * `shortcode:<tag>.<attribute>` as [tag, attribute]: split at the last
	 * `.`, as an attribute name holds none; the attribute lower-cased as
	 * WordPress lower-cases names — a name, a position (`0`, `1`, …) or `*`
	 * for every one. Null when the step is not one
	 *
	 * @return ?array{string, string}
	 */
	public static function shortcodeStep(
		mixed $step,
	): ?array
	{
		if(is_string($step) === false || str_starts_with($step, 'shortcode:') === false || strlen($step) > 200)
		{
			return null;
		}
		$rest = substr($step, strlen('shortcode:'));
		$at = strrpos($rest, '.');
		if($at === false)
		{
			return null;
		}
		$tag = substr($rest, 0, $at);
		$attribute = strtolower(substr($rest, $at + 1));
		
		return preg_match(self::SHORTCODE_TAG, $tag) === 1 && preg_match('~^(?:[a-z0-9_-]{1,100}|\*)$~D', $attribute) === 1 ? [$tag, $attribute] : null;
	}
	
	/**
	 * `block:<namespace/name>.<dot.path>` as [name, path], the path as the
	 * json: target walks one. Null when the step is not one
	 *
	 * @return ?array{string, string}
	 */
	public static function blockStep(
		mixed $step,
	): ?array
	{
		if(is_string($step) === false || str_starts_with($step, 'block:') === false || strlen($step) > 200)
		{
			return null;
		}
		[$name, $path] = explode('.', substr($step, strlen('block:')), 2) + [1 => ''];
		
		return preg_match(self::BLOCK_NAME, $name) === 1 && $path !== '' ? [$name, $path] : null;
	}
	
	/** `method`, `path`, `rest`, or a prefix and a name (`query:file`); the keys targets may name the top level ('') */
	public static function targetWellFormed(
		mixed $target,
	): bool
	{
		if(is_string($target) === false || strlen($target) > 200)
		{
			return false;
		}
		if(in_array($target, self::TARGETS, true))
		{
			return true;
		}
		// a target without ':' has no name (null)
		[$prefix, $name] = explode(':', $target, 2) + [1 => null];
		
		return in_array($prefix, self::TARGET_PREFIXES, true) && is_string($name)
			&& ($name !== '' || $prefix === 'query-keys' || $prefix === 'body-keys');
	}
	
	/** no `kind` key is a match rule — every rule a kernel older than rate rules ever saw */
	public static function isRate(
		array $rule,
	): bool
	{
		return ($rule['kind'] ?? self::KIND_MATCH) === self::KIND_RATE;
	}
	
	public static function rateWellFormed(
		mixed $rate,
	): bool
	{
		return is_array($rate)
			&& in_array($rate['key'] ?? null, self::RATE_KEYS, true)
			&& is_int($rate['limit'] ?? null) && $rate['limit'] >= 1 && $rate['limit'] <= self::RATE_LIMIT_MAX
			&& is_int($rate['window'] ?? null) && $rate['window'] >= 1 && $rate['window'] <= self::RATE_WINDOW_MAX;
	}
}

/**
 * Two tiers. Fast: APCu under a per-install prefix ('' = no APCu tier). Durable:
 * a JSON file the pull writes with write-temp-and-rename into a writable,
 * non-web-served directory the adapter names ('' = none). A read that
 * misses APCu reads the file and re-primes APCu, so a cleared APCu costs
 * an attacker nothing; a host without APCu runs on the file alone. Positive
 * empty: an empty rules array is knowledge and is cached like anything
 * else; a MISSING store is ignorance — read() answers null, the kernel
 * passes the request and forces the next pull. The lock and the counters
 * are APCu-only; losing them costs one duplicate pull or a minute's counts
 */
final class Store
{
	public const LOCK_TTL = 30;
	
	/** counters live three minutes: the flush that folds them runs every one */
	public const HITS_TTL = 180;
	
	protected bool $apcu;
	
	protected bool $forced = false;
	
	public function __construct(
		public readonly string $file = '',
		public readonly string $prefix = '',
		?bool $apcu = null,
	)
	{
		$this->apcu = $apcu ?? ($prefix !== '' && function_exists('apcu_enabled') && apcu_enabled());
	}
	
	public function hasApcu(): bool
	{
		return $this->apcu;
	}
	
	/** the record, from APCu, else from the file (re-priming APCu); null = no store */
	public function read(): ?array
	{
		if($this->apcu)
		{
			$hit = apcu_fetch($this->key('rules'));
			if(is_array($hit))
			{
				return $hit;
			}
		}
		if($this->file === '' || is_file($this->file) === false)
		{
			return null;
		}
		try
		{
			$record = json_decode((string)file_get_contents($this->file), true);
		}
		catch(Throwable)
		{
			return null;
		}
		if(is_array($record) === false)
		{
			return null;
		}
		if($this->apcu)
		{
			apcu_store($this->key('rules'), $record);
		}
		
		return $record;
	}
	
	/** both tiers; true when at least one took it */
	public function write(
		array $record,
	): bool
	{
		$written = false;
		if($this->file !== '')
		{
			// a temp file of its own: concurrent writers never share one, and rename() swaps the file whole
			$temp = $this->file . '.' . uniqid('', true) . '.tmp';
			try
			{
				$json = (string)json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
				// a short write (a full disk) never replaces the good file
				if(file_put_contents($temp, $json, LOCK_EX) === strlen($json) && rename($temp, $this->file))
				{
					$written = true;
				}
				elseif(is_file($temp))
				{
					unlink($temp);
				}
			}
			catch(Throwable)
			{
				if(is_file($temp))
				{
					@unlink($temp);
				}
			}
		}
		if($this->apcu)
		{
			// apcu_store() first, so it runs even when the file took the record
			$written = apcu_store($this->key('rules'), $record) || $written;
		}
		if($written)
		{
			// knowledge again: a pending forced pull is satisfied
			$this->forcePull(false);
		}
		
		return $written;
	}
	
	/** one puller per pool: apcu_add wins once; without APCu everyone may pull (a duplicate GET is harmless) */
	public function lock(
		string $name,
		int $ttl = self::LOCK_TTL,
	): bool
	{
		if($this->apcu === false)
		{
			return true;
		}
		
		return apcu_add($this->key('lock:' . $name), 1, $ttl);
	}
	
	public function unlock(
		string $name,
	): void
	{
		if($this->apcu)
		{
			apcu_delete($this->key('lock:' . $name));
		}
	}
	
	/** ignorance seen: the very next tick pulls regardless of the interval (APCu, and this instance for a host without) */
	public function forcePull(
		bool $on = true,
	): void
	{
		$this->forced = $on;
		if($this->apcu)
		{
			if($on)
			{
				apcu_store($this->key('force'), 1, 3600);
			}
			else
			{
				apcu_delete($this->key('force'));
			}
		}
	}
	
	public function pullForced(): bool
	{
		if($this->forced)
		{
			return true;
		}
		
		return $this->apcu && apcu_fetch($this->key('force')) === 1;
	}
	
	/** one more hit for a rule in this minute — uncapped, the truth the events cannot carry */
	public function hit(
		int $minute,
		int $ruleId,
		string $outcome,
	): void
	{
		if($this->apcu === false)
		{
			return;
		}
		$key = $this->key('hits:' . $minute . ':' . $ruleId . ':' . $outcome);
		// apcu_inc creates a missing key itself, so two first hits of a minute both count; the add is for an increment that failed
		if(apcu_inc($key, 1, $success, self::HITS_TTL) === false || $success === false)
		{
			apcu_add($key, 1, self::HITS_TTL);
		}
	}
	
	/**
	 * One more request for a rate rule's key, and the count in its window: fixed
	 * windows, two adjacent buckets — the current bucket's count plus the
	 * previous one's weighted by how much of it the sliding window still
	 * covers. Null without APCu: the file tier cannot count, and the rule is
	 * skipped
	 */
	public function rate(
		int $ruleId,
		string $key,
		int $window,
		int $now,
	): ?float
	{
		if($this->apcu === false || $window < 1)
		{
			return null;
		}
		$bucket = intdiv($now, $window);
		// the key as crc32, a short fixed-width name: two keys that collide share a count
		$head = 'rate:' . $ruleId . ':' . crc32($key) . ':';
		// a bucket outlives the next window, which reads it as the previous one
		$ttl = 2 * $window + 1;
		$name = $this->key($head . $bucket);
		$current = apcu_inc($name, 1, $success, $ttl);
		if($current === false || $success === false)
		{
			// apcu_inc creates a missing bucket itself; an increment that failed gets one add, else one more increment
			$current = apcu_add($name, 1, $ttl) ? 1 : (int)apcu_inc($name, 1, $success, $ttl);
		}
		$previous = apcu_fetch($this->key($head . ($bucket - 1)));
		// the share of the previous bucket the sliding window still covers
		$covered = 1 - ($now - $bucket * $window) / $window;
		
		return (float)$current + (is_int($previous) ? $previous * $covered : 0.0);
	}
	
	/** true the first time a name is claimed within its ttl — the report-once gate; false without APCu */
	public function once(
		string $name,
		int $ttl,
	): bool
	{
		// at least 1: an APCu ttl of 0 never expires
		return $this->apcu && apcu_add($this->key('once:' . $name), 1, max(1, $ttl));
	}
	
	/**
	 * A minute's counters, taken (fetched and deleted) for the fragment that
	 * ships them: [rule id => [outcome => n]], the verdicts (observe, block)
	 * and a vpatch's evidence (entry, match, authed — Kernel::tallied())
	 *
	 * @return array<int, array{observe: int, block: int, entry: int, match: int, authed: int}>
	 */
	public function takeHits(
		int $minute,
	): array
	{
		if($this->apcu === false || class_exists(APCUIterator::class) === false)
		{
			return [];
		}
		$hits = [];
		$head = $this->key('hits:' . $minute . ':');
		foreach(new APCUIterator('~^' . preg_quote($head, '~') . '~') as $entry)
		{
			$key = (string)$entry['key'];
			// the key's tail is `<rule id>:<outcome>`
			[$ruleId, $outcome] = explode(':', substr($key, strlen($head)), 2) + [1 => ''];
			$id = (int)$ruleId;
			$hits[$id] ??= ['observe' => 0, 'block' => 0, 'entry' => 0, 'match' => 0, 'authed' => 0];
			if(isset($hits[$id][$outcome]))
			{
				$hits[$id][$outcome] += (int)$entry['value'];
			}
			apcu_delete($key);
		}
		
		return $hits;
	}
	
	protected function key(
		string $name,
	): string
	{
		return $this->prefix . ':' . $name;
	}
}

/**
 * pull() · judge() · report(). See the file header
 */
final class Kernel
{
	/** the pull interval — resolution latency: a resolved finding lifts its rule within this */
	public const INTERVAL = 300;
	
	/** the ceiling — a codesafe instance gone silent this long lifts the shield; a codesafe incident does not disarm the fleet */
	public const CEILING = 86400;
	
	public const TIMEOUT_MS = 2000;
	
	/** `matched` is attacker-controlled: bounded here, scrubbed by the sender */
	public const MATCHED_MAX = 200;
	
	public const DOOR = '/api/v1/shield';
	
	public const USER_AGENT = 'ovos-codesafe-shield/1';
	
	/**
	 * what this kernel reads — the door serves rate rules only to a pull that
	 * names them, and says a blocking rule `block` only to one naming `mode-block`
	 */
	public const HEADER_KINDS = 'X-Shield-Kinds';
	
	public const KINDS = 'match,rate,threat,vpatch,mode-block';
	
	/** WordPress's batch route: each request it lists reaches its own route's handler */
	public const BATCH_ROUTE = '/batch/v1';
	
	/** the batch's sub-requests judged at most — WordPress takes 25 unless a site raises it; past this the batch holds unanswered */
	public const BATCH_MAX = 1000;

	/** the rule the counting's heartbeat is an `entry` of, once per request it ran on: rule 0, the threat addresses', whose evidence nothing else counts */
	public const HEARTBEAT = Ruleset::THREAT_RULE;
	
	/** WordPress's shortcode_parse_atts() pattern (get_shortcode_atts_regex()), as it is */
	public const SHORTCODE_ATTRIBUTES = '/([\w-]+)\s*=\s*"([^"]*)"(?:\s|$)|([\w-]+)\s*=\s*\'([^\']*)\'(?:\s|$)|([\w-]+)\s*=\s*([^\s\'"]+)(?:\s|$)|"([^"]*)"(?:\s|$)|\'([^\']*)\'(?:\s|$)|(\S+)(?:\s|$)/';
	
	/** the bytes PCRE's `\w` and a hyphen are: what may not follow a shortcode's tag */
	public const WORD_BYTES = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-';
	
	/** the bytes PCRE's `\s` is */
	public const SPACE_BYTES = " \t\n\x0B\f\r";
	
	/** the schemes whose slashes a browser reads loosely and whose authority names a host (`offsite`) */
	public const SPECIAL_SCHEMES = ['http', 'https', 'ftp', 'ws', 'wss'];
	
	/** the bytes JavaScript's trim() takes off a byte string, as the Node twin reads an address: never `\0`, which PHP's trim() takes */
	protected const TRIM_BYTES = " \t\n\x0B\f\r\xA0";
	
	/** an IPv4 part as Node's net.isIPv4() reads one: 0 to 255, no leading zero */
	protected const IPV4_PART = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])';
	
	protected const IPV4 = '(?:' . self::IPV4_PART . '\.){3}' . self::IPV4_PART;
	
	protected const IPV6_PART = '(?:[0-9a-fA-F]{1,4})';
	
	/** Node's net.isIPv6() pattern, ported so that no platform's inet_pton() decides: eight parts, `::`, a v4 tail, a zone id */
	protected const IPV6 = '~^(?:'
		. '(?:' . self::IPV6_PART . ':){7}(?:' . self::IPV6_PART . '|:)|'
		. '(?:' . self::IPV6_PART . ':){6}(?:' . self::IPV4 . '|:' . self::IPV6_PART . '|:)|'
		. '(?:' . self::IPV6_PART . ':){5}(?::' . self::IPV4 . '|(?::' . self::IPV6_PART . '){1,2}|:)|'
		. '(?:' . self::IPV6_PART . ':){4}(?:(?::' . self::IPV6_PART . '){0,1}:' . self::IPV4 . '|(?::' . self::IPV6_PART . '){1,3}|:)|'
		. '(?:' . self::IPV6_PART . ':){3}(?:(?::' . self::IPV6_PART . '){0,2}:' . self::IPV4 . '|(?::' . self::IPV6_PART . '){1,4}|:)|'
		. '(?:' . self::IPV6_PART . ':){2}(?:(?::' . self::IPV6_PART . '){0,3}:' . self::IPV4 . '|(?::' . self::IPV6_PART . '){1,5}|:)|'
		. '(?:' . self::IPV6_PART . ':){1}(?:(?::' . self::IPV6_PART . '){0,4}:' . self::IPV4 . '|(?::' . self::IPV6_PART . '){1,6}|:)|'
		. '(?::(?:(?::' . self::IPV6_PART . '){0,5}:' . self::IPV4 . '|(?::' . self::IPV6_PART . '){1,7}|:))'
		. ')(?:%[0-9a-zA-Z.:\-]+)?$~D';
	
	/** the project's ruleset version, one value whatever kinds a kernel reads — what nudge() compares */
	public const HEADER_VERSION = 'X-Shield-Version';
	
	public const PULL_OFF = 'off';
	
	public const PULL_SKIPPED = 'skipped';
	
	public const PULL_LOCKED = 'locked';
	
	public const PULL_FRESH = 'fresh';
	
	public const PULL_UNCHANGED = 'unchanged';
	
	public const PULL_REFUSED = 'refused';
	
	public const PULL_FAILED = 'failed';
	
	protected ?Closure $http;
	
	protected ?Closure $report;
	
	protected ?Closure $log;
	
	protected ?Ruleset $ruleset = null;
	
	protected bool $rulesetRead = false;
	
	/**
	 * @param string $url codesafe instance base URL
	 * @param string $key the project api_key
	 * @param ?callable(string $url, array<string> $headers, int $timeoutMs): array{status: int, headers: array<string, string>, body: string} $http the transport; null = curl or streams
	 * @param ?callable(string $kind, string $message, array<string, mixed> $extra): mixed $report the host's sender
	 * @param ?callable(string $line): mixed $log the host's log
	 */
	public function __construct(
		protected string $url,
		protected string $key,
		protected Store $store,
		?callable $http = null,
		?callable $report = null,
		?callable $log = null,
		protected int $interval = self::INTERVAL,
		protected int $ceiling = self::CEILING,
		protected int $timeoutMs = self::TIMEOUT_MS,
	)
	{
		$this->url = rtrim($url, '/');
		$this->http = $http === null ? null : Closure::fromCallable($http);
		$this->report = $report === null ? null : Closure::fromCallable($report);
		$this->log = $log === null ? null : Closure::fromCallable($log);
	}
	
	public function store(): Store
	{
		return $this->store;
	}
	
	/** the cached ruleset, read once per request; null = no store (ignorance) */
	public function ruleset(): ?Ruleset
	{
		if($this->rulesetRead === false)
		{
			$this->rulesetRead = true;
			try
			{
				$this->ruleset = Ruleset::fromRecord($this->store->read());
			}
			catch(Throwable)
			{
				$this->ruleset = null;
			}
		}
		
		return $this->ruleset;
	}
	
	/**
	 * Over the cached ruleset. pass when consent says so, when there is no
	 * store (and the next tick will pull), when the contract is unknown, when
	 * the ruleset is past the ceiling; else the first MATCH or VPATCH rule
	 * that matches — in the door's order, blocking first — as block (set to
	 * block AND enforce, a vpatch's who and nonce answered) or observe; a vpatch that
	 * could not be answered observes unless a later rule blocks; else the
	 * first RATE rule whose predicate matches and whose key
	 * is over its limit, the same way. A rule the engine cannot run matches
	 * nothing. The one side effect: a rate rule's predicate that matches
	 * counts the request
	 */
	public function judge(
		Facts $facts,
		Consent $consent,
		?int $now = null,
	): Verdict
	{
		try
		{
			if($consent->kill)
			{
				return Verdict::pass('kill');
			}
			if($consent->detect === false)
			{
				return Verdict::pass('detect off');
			}
			$ruleset = $this->ruleset();
			// no store: pass, and the next tick pulls regardless of the interval
			if($ruleset === null)
			{
				$this->store->forcePull();
				
				return Verdict::pass('no ruleset');
			}
			if($ruleset->usable === false)
			{
				return Verdict::pass('unknown contract');
			}
			// past the ceiling the rules lift until a pull renews them
			if($ruleset->isStale($now ?? time(), $this->ceiling))
			{
				$this->store->forcePull();
				
				return Verdict::pass('ceiling');
			}
			// a vpatch that would block but could not be answered: observed unless a later rule blocks
			$held = null;
			// a listed address is judged before any rule
			$threat = $this->threatened($ruleset, $facts);
			if($threat !== null)
			{
				$blocks = Ruleset::blocks($threat['mode']) && $consent->blocks();
				if($facts->callerKnown || $blocks === false)
				{
					return new Verdict($blocks ? Verdict::BLOCK : Verdict::OBSERVE, $threat, $facts->ip);
				}
				// a caller the host cannot tell may be signed in: held, and a rule after it may still block
				$held = new Verdict(Verdict::OBSERVE, $threat, $facts->ip, Verdict::REASON_UNANSWERED);
			}
			$rates = [];
			$subs = self::batched($facts);
			$unreadBatch = self::batchUnread($facts);
			foreach($ruleset->rules as $rule)
			{
				// rate rules count only a request no match rule decided: judged after this loop
				if(Ruleset::isRate($rule))
				{
					$rates[] = $rule;
					
					continue;
				}
				if(Ruleset::isVpatch($rule))
				{
					$hit = self::patched($rule, $facts);
					foreach($subs as $sub)
					{
						// a batch's sub-request reaches its route's handler as a request of its own; an answered hit wins
						$subHit = $hit !== null && $hit['resolved'] ? null : self::patched($rule, $sub);
						if($subHit !== null && ($hit === null || $subHit['resolved']))
						{
							$hit = $subHit;
						}
					}
					// a batch the kernel could not read may have reached it: held, never blocked, never passed in silence
					if($hit === null && $unreadBatch && self::batchReaches($rule, $facts))
					{
						$hit = ['matched' => '', 'resolved' => false];
					}
					if($hit === null)
					{
						continue;
					}
					$blocks = Ruleset::blocks($rule['mode'] ?? '') && $consent->blocks();
					$verdict = new Verdict($blocks && $hit['resolved'] ? Verdict::BLOCK : Verdict::OBSERVE, $rule,
						substr($hit['matched'], 0, self::MATCHED_MAX));
					// what the host could not answer (who, a nonce) only observes — and a blocking rule after it may still block
					if($blocks && $hit['resolved'] === false)
					{
						$held ??= new Verdict(Verdict::OBSERVE, $rule, $verdict->matched, Verdict::REASON_UNANSWERED);
						
						continue;
					}
					
					// an observe after a held vpatch: the earlier, held verdict wins
					return $verdict->isBlock() ? $verdict : ($held ?? $verdict);
				}
				$matched = $this->matched($rule, $facts);
				if($matched === null)
				{
					continue;
				}
				$blocks = Ruleset::blocks($rule['mode'] ?? '') && $consent->blocks();
				$verdict = new Verdict($blocks ? Verdict::BLOCK : Verdict::OBSERVE, $rule, substr($matched, 0, self::MATCHED_MAX));
				
				return $verdict->isBlock() ? $verdict : ($held ?? $verdict);
			}
			if($held !== null)
			{
				return $held;
			}
			$now ??= time();
			foreach($rates as $rule)
			{
				$verdict = $this->rated($rule, $facts, $consent, $now);
				if($verdict !== null)
				{
					return $verdict;
				}
			}
			
			return Verdict::pass('no match');
		}
		catch(Throwable $e)
		{
			$this->log('judge failed open: ' . $e->getMessage());
			
			return Verdict::pass('exception');
		}
	}
	
	/**
	 * The threat section's word on this request: the pseudo-rule it is judged
	 * by (id THREAT_RULE, the section's mode) when the address is listed, the
	 * request is not signed in and its path ends in none of the pass paths;
	 * null otherwise
	 *
	 * @return ?array{id: int, kind: string, mode: string}
	 */
	protected function threatened(
		Ruleset $ruleset,
		Facts $facts,
	): ?array
	{
		$threats = $ruleset->threats;
		// a caller the host cannot tell is not known to be signed in
		if($threats === null || ($facts->authed && $facts->callerKnown) || isset($threats['addresses'][Ruleset::canonical($facts->ip)]) === false)
		{
			return null;
		}
		$path = $facts->path();
		foreach((array)($threats['pass'] ?? []) as $pass)
		{
			if(str_ends_with($path, (string)$pass))
			{
				return null;
			}
		}
		
		return ['id' => Ruleset::THREAT_RULE, 'kind' => Ruleset::KIND_THREAT, 'mode' => (string)$threats['mode']];
	}
	
	/** a rule's predicate over the request: the fragment, or null */
	protected function matched(
		array $rule,
		Facts $facts,
	): ?string
	{
		$subject = $facts->field((string)$rule['field']);
		
		return $subject === null ? null : self::match($rule, $subject);
	}
	
	/**
	 * A rate rule: its predicate, its key, one more in its window — a verdict
	 * past the limit, else null. A `user` rule on a request with no user and a
	 * store without APCu count nothing
	 */
	protected function rated(
		array $rule,
		Facts $facts,
		Consent $consent,
		int $now,
	): ?Verdict
	{
		$matched = $this->matched($rule, $facts);
		if($matched === null)
		{
			return null;
		}
		$rate = (array)$rule['rate'];
		$key = self::rateKey($rule, $facts);
		// no address or no user to count by
		if($key === '')
		{
			return null;
		}
		$window = (int)$rate['window'];
		$count = $this->store->rate((int)$rule['id'], $key, $window, $now);
		if($count === null || $count <= (int)$rate['limit'])
		{
			return null;
		}
		$blocks = Ruleset::blocks($rule['mode'] ?? '') && $consent->blocks();
		
		return new Verdict($blocks ? Verdict::BLOCK : Verdict::OBSERVE, $rule, substr($matched, 0, self::MATCHED_MAX),
			'over limit', (int)ceil($count), $window - ($now % $window));
	}
	
	/** the counter a request falls under; `route` is one counter for every request the rule matches, '' none */
	protected static function rateKey(
		array $rule,
		Facts $facts,
	): string
	{
		return match(((array)$rule['rate'])['key'])
		{
			Ruleset::RATE_KEY_IP => self::rateAddress($facts->ip),
			Ruleset::RATE_KEY_USER => $facts->user,
			default => '*',
		};
	}
	
	/**
	 * The address an ip-keyed rate rule counts, byte for byte the Node twin's
	 * (Facts.address(), then Kernel.rateAddress()): a v4 address as it is, a
	 * v6 one as its /64 — the block one subscriber is handed, where every one
	 * of 2^64 addresses is free to use, so counting them one by one counts
	 * nothing; '' for what is no address, so the rule skips the request
	 */
	public static function rateAddress(
		string $ip,
	): string
	{
		$ip = trim($ip, self::TRIM_BYTES);
		// the dual-stack `::ffff:` form is its v4 address
		if(preg_match('~^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$~iD', $ip, $mapped) === 1)
		{
			$ip = $mapped[1];
		}
		if(preg_match('~^' . self::IPV4 . '$~D', $ip) === 1)
		{
			return $ip;
		}
		if(preg_match(self::IPV6, $ip) !== 1)
		{
			return '';
		}
		// a zone id is kept whole, as Node keeps it; @: inet_pton() warns on anything it cannot read
		$packed = str_contains($ip, '%') ? false : @inet_pton($ip);
		if($packed === false || strlen($packed) !== 16)
		{
			return $ip;
		}
		$words = [];
		for($at = 0; $at < 8; $at+= 2)
		{
			$words[] = sprintf('%x', ord($packed[$at]) << 8 | ord($packed[$at + 1]));
		}
		
		return implode(':', $words) . '::/64';
	}
	
	/** judge, count, report — the adapter turns block into its own 403, or a rate block into its 429 */
	public function handle(
		Facts $facts,
		Consent $consent,
		?int $now = null,
	): Verdict
	{
		$verdict = $this->judge($facts, $consent, $now);
		if($verdict->isPass() === false)
		{
			$this->count($verdict, $now);
			$this->report($verdict, $facts);
		}
		$this->tally($facts, $consent, $now);
		
		return $verdict;
	}
	
	/**
	 * The evidence counters of every vpatch the request reached (tallied()),
	 * under the rules judge() reads by; nothing without a store that counts.
	 * Never fails the request
	 */
	public function tally(
		Facts $facts,
		Consent $consent,
		?int $now = null,
	): void
	{
		try
		{
			$now ??= time();
			$ruleset = $consent->kill || $consent->detect === false || $this->store->hasApcu() === false ? null : $this->ruleset();
			if($ruleset === null || $ruleset->usable === false || $ruleset->isStale($now, $this->ceiling))
			{
				return;
			}
			// the counting ran on this request: what codesafe weighs a vpatch's zero against
			$this->store->hit(intdiv($now, 60), self::HEARTBEAT, 'entry');
			foreach(self::tallied($ruleset->rules, $facts) as $id => $counts)
			{
				foreach($counts as $outcome => $counted)
				{
					if($counted)
					{
						$this->store->hit(intdiv($now, 60), $id, $outcome);
					}
				}
			}
		}
		catch(Throwable)
		{
			// a lost count never fails the request
		}
	}
	
	/**
	 * What a request did to each vpatch, whether or not it decided the
	 * verdict: rule id => entry (every selecting entry held, Ruleset::selects();
	 * never for a rule with none), match (the rule held, who included,
	 * answered or not) and authed (a match by a caller signed in or one the
	 * host cannot tell, who may be) — for the rules it reached or matched. A
	 * batch counts once with its sub-requests; one the kernel could not read
	 * matches what it may have reached (batchReaches()), never as an entry
	 *
	 * @return array<int, array{entry: bool, match: bool, authed: bool}>
	 */
	public static function tallied(
		array $rules,
		Facts $facts,
	): array
	{
		$tally = [];
		$requests = [$facts, ...self::batched($facts)];
		$unreadBatch = self::batchUnread($facts);
		foreach($rules as $rule)
		{
			if(Ruleset::isVpatch($rule) === false)
			{
				continue;
			}
			$selecting = array_filter((array)($rule['conditions'] ?? []), static fn(mixed $entry): bool => Ruleset::selects((array)$entry));
			$entry = false;
			$matched = null;
			foreach($requests as $request)
			{
				// the entry point first: a request that misses it cannot match
				foreach($selecting as $condition)
				{
					if(self::held((array)$condition, $request) === null)
					{
						continue 2;
					}
				}
				$entry = $entry || $selecting !== [];
				$matched ??= self::patched($rule, $request) === null ? null : $request;
			}
			// held as judge() holds it: whose request it is says whether it was signed in
			if($matched === null && $unreadBatch && self::batchReaches($rule, $facts))
			{
				$matched = $facts;
			}
			if($entry || $matched !== null)
			{
				$tally[(int)$rule['id']] = ['entry' => $entry, 'match' => $matched !== null,
					'authed' => $matched !== null && ($matched->authed || $matched->callerKnown === false)];
			}
		}
		
		return $tally;
	}
	
	/** the match through the adapter's sender as a security event; never throws */
	public function report(
		Verdict $verdict,
		Facts $facts,
	): void
	{
		// a threat address is counted, never reported: the event would feed the
		// score that listed it, and the block would renew itself
		if($this->report === null || $verdict->isPass() || $verdict->rule === null
			|| ($verdict->rule['kind'] ?? '') === Ruleset::KIND_THREAT)
		{
			return;
		}
		try
		{
			$rule = $verdict->rule;
			if($verdict->isRate())
			{
				$this->reportRate($verdict, $facts);
				
				return;
			}
			// codesafe's Shield\Alarm reads the rule id off the message's `shield rule N ` start
			($this->report)($verdict->kind(), sprintf('shield rule %d %s %s %s', (int)$rule['id'],
				$verdict->isBlock() ? 'refused' : 'observed', $facts->method, substr($facts->path(), 0, 200)), [
				'rule' => (int)$rule['id'],
				'finding' => is_string($rule['finding'] ?? null) ? $rule['finding'] : '',
				'cve' => is_string($rule['cve'] ?? null) ? $rule['cve'] : '',
				'origin' => is_string($rule['origin'] ?? null) ? $rule['origin'] : '',
				// a vpatch has no field or op: its conditions name what it reads, `who` whom
				'field' => Ruleset::isVpatch($rule) ? Ruleset::KIND_VPATCH : (string)$rule['field'],
				'op' => Ruleset::isVpatch($rule) ? 'conditions' : (string)$rule['op'],
				'mode' => (string)$rule['mode'],
				'matched' => $verdict->matched,
				'authed' => $facts->authed,
				'body_capped' => $facts->bodyWasCapped(),
			] + (Ruleset::isVpatch($rule) ? ['who' => (string)($rule['who'] ?? '')] : []));
		}
		catch(Throwable $e)
		{
			$this->log('report failed: ' . $e->getMessage());
		}
	}
	
	/**
	 * A rate verdict, ONCE per rule, key and window — the hits count every
	 * request past the limit, the event says it started. Never "refused":
	 * codesafe's alarm reads `shield rule N refused` as a match rule turning
	 * people away, and a route ceiling doing its job is not that
	 */
	protected function reportRate(
		Verdict $verdict,
		Facts $facts,
	): void
	{
		$rule = (array)$verdict->rule;
		$rate = (array)$rule['rate'];
		$window = (int)$rate['window'];
		$key = self::rateKey($rule, $facts);
		// claimed until the window ends: the next window's first request past the limit reports again
		if($this->store->once('rate:' . (int)$rule['id'] . ':' . crc32($key), max(1, $verdict->retryAfter)) === false)
		{
			return;
		}
		($this->report)(Verdict::KIND_RATE, sprintf('shield rule %d %s %s %s (%d/%d per %ds)', (int)$rule['id'],
			$verdict->isBlock() ? 'limited' : 'over-limit', $facts->method, substr($facts->path(), 0, 200),
			$verdict->count, (int)$rate['limit'], $window), [
			'rule' => (int)$rule['id'],
			'finding' => is_string($rule['finding'] ?? null) ? $rule['finding'] : '',
			'cve' => is_string($rule['cve'] ?? null) ? $rule['cve'] : '',
			'origin' => is_string($rule['origin'] ?? null) ? $rule['origin'] : '',
			'field' => (string)$rule['field'],
			'op' => (string)$rule['op'],
			'mode' => (string)$rule['mode'],
			'matched' => $verdict->matched,
			'key' => (string)$rate['key'],
			'limit' => (int)$rate['limit'],
			'window' => $window,
			'count' => $verdict->count,
			'authed' => $facts->authed,
		]);
	}
	
	/** the uncapped per-rule counter for this minute */
	public function count(
		Verdict $verdict,
		?int $now = null,
	): void
	{
		if($verdict->isPass() || $verdict->rule === null)
		{
			return;
		}
		try
		{
			$this->store->hit(intdiv($now ?? time(), 60), (int)$verdict->rule['id'], $verdict->outcome);
		}
		catch(Throwable)
		{
			// a lost count never fails the request
		}
	}
	
	/**
	 * A codesafe answer said the project's ruleset version (the ingest
	 * answers' `shield`): when the stored ruleset's version is known and
	 * differs, the next pull is forced — no network here, the host's tick
	 * pulls. Nothing stored, a version never said, or a malformed one compare
	 * nothing. True when it forced
	 */
	public function nudge(
		string $version,
	): bool
	{
		try
		{
			$current = $this->ruleset();
			if(Ruleset::isVersion($version) === false || $current === null
				|| $current->version === '' || $current->version === $version)
			{
				return false;
			}
			$this->store->forcePull();
			
			return true;
		}
		catch(Throwable)
		{
			return false;
		}
	}
	
	/**
	 * The conditional GET, on the host's tick: off under kill or without
	 * detect (no network); skipped inside the interval unless forced;
	 * locked when another request of the pool is pulling; fresh (200,
	 * stored), unchanged (304, the ceiling renewed), refused (a contract this
	 * kernel does not know — stored unusable so the door is not hammered),
	 * failed (anything else — the cache is left alone)
	 */
	public function pull(
		Consent $consent,
		?int $now = null,
		bool $force = false,
	): string
	{
		if($consent->active() === false)
		{
			return self::PULL_OFF;
		}
		$now ??= time();
		try
		{
			$current = Ruleset::fromRecord($this->store->read());
			if($force === false && $current !== null && $this->store->pullForced() === false && $current->fetchedAt + $this->interval > $now)
			{
				return self::PULL_SKIPPED;
			}
			if($this->store->lock('pull') === false)
			{
				return self::PULL_LOCKED;
			}
			try
			{
				return $this->fetch($current, $now);
			}
			finally
			{
				$this->store->unlock('pull');
			}
		}
		catch(Throwable $e)
		{
			$this->log('pull failed: ' . $e->getMessage());
			
			return self::PULL_FAILED;
		}
	}
	
	protected function fetch(
		?Ruleset $current,
		int $now,
	): string
	{
		// both names of the key header: an instance older than the rename to
		// codesafe reads only X-Console-Key
		$headers = ['X-Codesafe-Key: ' . $this->key, 'X-Console-Key: ' . $this->key, 'Accept: application/json',
			self::HEADER_KINDS . ': ' . self::KINDS];
		// the digest as the ETag: an unchanged ruleset answers 304
		if($current !== null && $current->digest !== '')
		{
			$headers[] = 'If-None-Match: "' . $current->digest . '"';
		}
		$response = ($this->http ?? Closure::fromCallable([$this, 'transport']))($this->url . self::DOOR, $headers, $this->timeoutMs);
		$status = (int)($response['status'] ?? 0);
		if($status === 304 && $current !== null)
		{
			$this->store->write($current->withFetchedAt($now, self::header($response, self::HEADER_VERSION))->toRecord());
			// the next ruleset() call reads the new record
			$this->rulesetRead = false;
			
			return self::PULL_UNCHANGED;
		}
		if($status !== 200)
		{
			$this->log('pull answered ' . $status);
			
			return self::PULL_FAILED;
		}
		$payload = json_decode((string)($response['body'] ?? ''), true);
		if(is_array($payload) === false)
		{
			$this->log('pull answered no JSON');
			
			return self::PULL_FAILED;
		}
		$ruleset = Ruleset::fromPayload($payload, $now, self::header($response, 'X-Shield-Sha256'),
			self::header($response, self::HEADER_VERSION));
		// stored even when unusable, so an unknown contract is not fetched again on every tick
		$this->store->write($ruleset->toRecord());
		$this->rulesetRead = false;
		if($ruleset->usable === false)
		{
			$this->log('pull refused: contract ' . json_encode($payload['contract'] ?? null) . ' dialect ' . json_encode($payload['dialect'] ?? null));
			
			return self::PULL_REFUSED;
		}
		
		return self::PULL_FRESH;
	}
	
	/** one header of the transport's answer, any case; '' when absent */
	protected static function header(
		array $response,
		string $name,
	): string
	{
		foreach((array)($response['headers'] ?? []) as $key => $value)
		{
			if(strtolower((string)$key) === strtolower($name) && is_string($value))
			{
				return trim($value);
			}
		}
		
		return '';
	}
	
	/**
	 * A vpatch over the request: the value that passed (a parameter's, else
	 * the frame's) and whether all of it was answered — `who` and any nonce
	 * test — or null when it does not hold. A request that is not signed in
	 * lacks every capability; a signed-in one asks Facts::can()
	 *
	 * @return ?array{matched: string, resolved: bool}
	 */
	public static function patched(
		array $rule,
		Facts $facts,
	): ?array
	{
		$resolved = true;
		$who = (string)($rule['who'] ?? '');
		if($facts->callerKnown === false)
		{
			// whom the patch is for waits on the host: the match holds unanswered
			$resolved = $who === Ruleset::WHO_ANYONE;
		}
		else if($who === Ruleset::WHO_ANONYMOUS && $facts->authed)
		{
			return null;
		}
		else if(str_starts_with($who, Ruleset::WHO_LACKS) && $facts->authed)
		{
			$can = $facts->can(substr($who, strlen(Ruleset::WHO_LACKS)));
			// the user has the capability: the patch is not for them
			if($can === true)
			{
				return null;
			}
			// null: the host cannot say, so the match stays unanswered
			$resolved = $can === false;
		}
		$matched = '';
		$framed = '';
		$entries = (array)($rule['conditions'] ?? []);
		// an upload's contents are read last, once every cheaper condition held
		$entries = [...array_filter($entries, static fn(mixed $entry): bool => self::readsUpload($entry) === false),
			...array_filter($entries, static fn(mixed $entry): bool => self::readsUpload($entry))];
		foreach($entries as $entry)
		{
			$hit = self::held((array)$entry, $facts);
			if($hit === null)
			{
				return null;
			}
			$resolved = $resolved && $hit['resolved'];
			// a method, path or route value only stands in when no parameter's value matched
			if($hit['frame'])
			{
				$framed = $framed === '' ? $hit['matched'] : $framed;
			}
			else if($matched === '')
			{
				$matched = $hit['matched'];
			}
		}
		
		return ['matched' => $matched !== '' ? $matched : $framed, 'resolved' => $resolved];
	}
	
	/** whether an entry reads an upload's contents — a plain condition: a group never holds one (Ruleset::entryWellFormed) */
	protected static function readsUpload(
		mixed $entry,
	): bool
	{
		return str_starts_with((string)(((array)$entry)['target'] ?? ''), 'file-content:');
	}
	
	/**
	 * One entry: a plain condition, or a group — its first member that holds
	 * answered, else its first that holds unanswered (a body or a decode step
	 * the kernel could not read; no member waits on the host, a nonce test
	 * never being in one) — with `frame` saying whether the holding target is
	 * a frame target
	 *
	 * @return ?array{matched: string, resolved: bool, frame: bool}
	 */
	public static function held(
		array $entry,
		Facts $facts,
	): ?array
	{
		$members = isset($entry[Ruleset::GROUP_ANY]) ? (array)$entry[Ruleset::GROUP_ANY] : [$entry];
		$pending = null;
		foreach($members as $member)
		{
			$hit = self::condition((array)$member, $facts);
			if($hit !== null)
			{
				$hit['frame'] = in_array((string)($member['target'] ?? ''), Ruleset::TARGETS, true);
				// an unread branch never answers for one that holds answered
				if($hit['resolved'])
				{
					return $hit;
				}
				$pending ??= $hit;
			}
		}
		
		return $pending;
	}
	
	/**
	 * One condition: the value that passed it and whether it was answered, or
	 * null when none passes. Any value of a target with several (an array, a
	 * wildcard, the keys) is enough; an absent one never holds — but a nonce
	 * that is not there is an invalid one, and a present one needs the host,
	 * and an upload the host cannot read holds unanswered where no value
	 * passes; a JSON body the kernel did not read holds every json: condition
	 * unanswered
	 *
	 * @return ?array{matched: string, resolved: bool}
	 */
	public static function condition(
		array $condition,
		Facts $facts,
	): ?array
	{
		$target = (string)$condition['target'];
		// before exists and nonce_invalid: an unread body is neither absent nor missing its nonce
		if(str_starts_with($target, 'json:') && $facts->jsonUnread())
		{
			return ['matched' => '', 'resolved' => false];
		}
		[$values, $unread] = str_starts_with($target, 'file-content:')
			? self::contents($facts, substr($target, strlen('file-content:'))) : [self::values($target, $facts), false];
		$test = (string)$condition['test'];
		if($test === 'exists')
		{
			// an upload that could not be read is there all the same
			return $values === [] && $unread === false ? null : ['matched' => $values[0] ?? '', 'resolved' => true];
		}
		if($test === 'nonce_invalid')
		{
			// no nonce sent is an invalid one
			if($values === [])
			{
				return ['matched' => '', 'resolved' => true];
			}
			$resolved = true;
			foreach($values as $value)
			{
				$valid = $facts->nonceValid((string)$condition['value'], $value);
				// one valid nonce and the condition fails
				if($valid === true)
				{
					return null;
				}
				// null: the host cannot say
				$resolved = $resolved && $valid === false;
			}
			
			return ['matched' => $values[0], 'resolved' => $resolved];
		}
		// past DECODED_MAX values the decode steps yield, the rest is not read: the condition holds unanswered
		$capped = (array)($condition['decode'] ?? []) !== [];
		$read = 0;
		if($test === 'unsafe_html')
		{
			// the first value the filter changes; a value it cannot judge keeps the match unanswered
			$pending = null;
			foreach($values as $value)
			{
				[$decodedValues, $cut] = self::decoded($value, (array)($condition['decode'] ?? []));
				// what a decode step left unread may hold
				$unread = $unread || $cut;
				foreach($decodedValues as $decoded)
				{
					if($capped && ++$read > Ruleset::DECODED_MAX)
					{
						return ['matched' => $values[0], 'resolved' => false];
					}
					$unsafe = $facts->htmlUnsafe($decoded);
					if($unsafe === true)
					{
						return ['matched' => $decoded, 'resolved' => true];
					}
					$pending ??= $unsafe === null ? $decoded : null;
				}
			}
			
			// an upload the host could not read is a value the filter could not judge
			return $pending === null && $unread === false ? null : ['matched' => $pending ?? '', 'resolved' => false];
		}
		foreach($values as $value)
		{
			[$decodedValues, $cut] = self::decoded($value, (array)($condition['decode'] ?? []));
			// what a decode step left unread may hold
			$unread = $unread || $cut;
			foreach($decodedValues as $decoded)
			{
				if($capped && ++$read > Ruleset::DECODED_MAX)
				{
					return ['matched' => $values[0], 'resolved' => false];
				}
				if(self::passes($test, $decoded, $condition, $facts->host()))
				{
					return ['matched' => $decoded, 'resolved' => true];
				}
			}
		}
		
		// an upload the host could not read may hold what no value read did
		return $unread ? ['matched' => '', 'resolved' => false] : null;
	}
	
	/**
	 * A target's values over the request; over a batch's sub-request its
	 * own, then its batch's: the handler reads the superglobals too, which
	 * stay the batch's — never the batch's JSON, which is the batch itself,
	 * and an upload's bytes contents() reads both of
	 *
	 * @return list<string>
	 */
	public static function values(
		string $target,
		Facts $facts,
	): array
	{
		if($target === 'method')
		{
			return [strtoupper($facts->method)];
		}
		if($target === 'path')
		{
			return [$facts->path()];
		}
		if($target === 'rest')
		{
			return self::routes($facts);
		}
		[$prefix, $name] = explode(':', $target, 2) + [1 => ''];
		// Facts::$headers is keyed by lowercase name
		$header = strtolower($name);
		
		$values = match($prefix)
		{
			'query' => self::pick($facts->query, $name),
			'request' => [...self::pick($facts->query, $name), ...self::pick($facts->form, $name)],
			'body' => self::pick($facts->form, $name),
			'json' => self::pickJson($facts->json(), $name),
			'cookie' => self::pick($facts->cookies, $name),
			'header' => isset($facts->headers[$header]) ? [(string)$facts->headers[$header]] : [],
			'file' => self::pick($facts->files, $name),
			'file-content' => self::contents($facts, $name)[0],
			'query-keys' => self::keys($facts->query, $name),
			'body-keys' => self::keys($facts->form, $name),
			default => [],
		};
		$outer = $facts->outer();
		if($outer === null || in_array($prefix, ['json', 'file-content'], true))
		{
			return $values;
		}
		
		return [...$values, ...self::values($target, $outer)];
	}
	
	/**
	 * An upload field's contents (Facts::fileContent()) and whether the host
	 * could not read one; a failed upload, with no temp path, never reached
	 * the app and is not there. A batch's sub-request has none of its own:
	 * its handler reads its batch's, through the batch's own reads
	 *
	 * @return array{list<string>, bool}
	 */
	public static function contents(
		Facts $facts,
		string $name,
	): array
	{
		$contents = [];
		$unread = false;
		foreach(self::pick($facts->uploads, $name) as $path)
		{
			if($path === '')
			{
				continue;
			}
			$content = $facts->fileContent($path);
			$unread = $unread || $content === null;
			if($content !== null)
			{
				$contents[] = $content;
			}
		}
		$outer = $facts->outer();
		if($outer === null)
		{
			return [$contents, $unread];
		}
		// read once per request, however many sub-requests reach the rule
		[$outers, $outerUnread] = self::contents($outer, $name);
		
		return [[...$contents, ...$outers], $unread || $outerUnread];
	}
	
	/**
	 * The REST routes a request addresses, as WordPress finds them: the
	 * path's spelling decoded once and, when that differs, twice (WordPress
	 * matches a percent-encoded prefix on the decoded path and decodes the
	 * capture again), then `rest_route` from the query and the body; each
	 * ending in one newline also without it, since WordPress matches a route
	 * as `@^route$@i`, whose `$` ends before a final newline
	 *
	 * @return list<string>
	 */
	public static function routes(
		Facts $facts,
	): array
	{
		$routes = [];
		$path = $facts->path();
		foreach([$path, rawurldecode($path)] as $spelling)
		{
			$route = self::routeIn($spelling, $facts->restPrefix);
			if($route !== null && in_array($route, $routes, true) === false)
			{
				$routes[] = $route;
			}
		}
		foreach([...self::pick($facts->query, 'rest_route'), ...self::pick($facts->form, 'rest_route')] as $value)
		{
			// WordPress's empty(): '' and '0' address no route, and an untrailed '0' is the index
			if($value !== '' && $value !== '0')
			{
				$route = self::untrailed($value);
				$routes[] = $route === '0' ? '/' : $route;
			}
		}
		foreach($routes as $route)
		{
			// not untrailed again: WordPress untrails before the newline, never after
			$bare = str_ends_with($route, "\n") ? substr($route, 0, -1) : null;
			if($bare !== null && in_array($bare, $routes, true) === false)
			{
				$routes[] = $bare;
			}
		}
		
		return $routes;
	}
	
	/**
	 * The sub-requests of a WordPress batch — a request to `/batch/v1` whose
	 * `requests` list them (batchList()) — each as its route's handler sees
	 * it (Facts::subRequest: POST when it names no method); none for any
	 * other request, and none past BATCH_MAX (batchUnread())
	 *
	 * @return list<Facts>
	 */
	public static function batched(
		Facts $facts,
	): array
	{
		$list = self::batchList($facts);
		// a list WordPress's own validation refuses runs nothing
		if(is_array($list) === false)
		{
			return [];
		}
		$subs = [];
		foreach(array_slice(array_values($list), 0, self::BATCH_MAX) as $request)
		{
			if(is_array($request) && is_string($request['path'] ?? null))
			{
				$subs[] = $facts->subRequest(is_string($request['method'] ?? null) ? $request['method'] : 'POST', $request['path'], $request['body'] ?? null,
					is_array($request['headers'] ?? null) ? $request['headers'] : []);
			}
		}
		
		return $subs;
	}
	
	/** whether a request addresses WordPress's batch route */
	public static function isBatch(
		Facts $facts,
	): bool
	{
		return array_filter(self::routes($facts), static fn(string $route): bool => strcasecmp($route, self::BATCH_ROUTE) === 0) !== [];
	}
	
	/**
	 * A batch's `requests` where WordPress's WP_REST_Request::get_param()
	 * finds them: the JSON body when WordPress reads it as JSON, then the
	 * form, then the query — the first that sets it (isset(): null is not
	 * set), taken whatever it holds, as WordPress takes it. Null off the
	 * batch route, when none sets it, and when the JSON body that comes
	 * first went unread (batchUnread())
	 */
	protected static function batchList(
		Facts $facts,
	): mixed
	{
		// the route first: the body is read only for a batch
		if(self::isBatch($facts) === false)
		{
			return null;
		}
		$sources = [];
		if(self::jsonFirst($facts))
		{
			if($facts->jsonUnread())
			{
				return null;
			}
			$sources[] = $facts->json();
		}
		foreach([...$sources, $facts->form, $facts->query] as $source)
		{
			if(is_array($source) && isset($source['requests']))
			{
				return $source['requests'];
			}
		}
		
		return null;
	}
	
	/**
	 * Whether WordPress reads a batch's JSON body before its form: when its
	 * content type is one WordPress reads as JSON (Facts::wordpressJson()),
	 * else whenever the adapter named no content type and handed a JSON body
	 */
	protected static function jsonFirst(
		Facts $facts,
	): bool
	{
		$type = $facts->headers['content-type'] ?? null;
		
		return is_string($type) === false || Facts::wordpressJson($type);
	}
	
	/**
	 * Whether a request is a batch whose sub-requests the kernel did not
	 * read in full: the JSON body that comes first past JSON_CAP
	 * (Facts::jsonUnread()), or a list past BATCH_MAX
	 */
	public static function batchUnread(
		Facts $facts,
	): bool
	{
		// the route first: the body is read only for a batch
		if(self::isBatch($facts) === false)
		{
			return false;
		}
		if(self::jsonFirst($facts) && $facts->jsonUnread())
		{
			return true;
		}
		$list = self::batchList($facts);
		
		return is_array($list) && count($list) > self::BATCH_MAX;
	}
	
	/**
	 * Whether a batch the kernel could not read may have reached a vpatch: a
	 * sub-request runs a REST route's handler, which a vpatch names with a
	 * `rest` condition (in a group too), and runs it as this request's
	 * caller, so `who` must take this caller in. Nothing else rules a vpatch
	 * out: the handler reads this request's cookies and uploads, and the
	 * sub-request's method, path, query, body and headers are the sender's
	 */
	public static function batchReaches(
		array $rule,
		Facts $facts,
	): bool
	{
		$routed = false;
		foreach((array)($rule['conditions'] ?? []) as $entry)
		{
			$entry = (array)$entry;
			foreach(isset($entry[Ruleset::GROUP_ANY]) ? (array)$entry[Ruleset::GROUP_ANY] : [$entry] as $member)
			{
				$routed = $routed || (((array)$member)['target'] ?? '') === 'rest';
			}
		}
		
		// who alone, as patched() judges it for this caller
		return $routed && self::patched(['who' => $rule['who'] ?? '', 'conditions' => []], $facts) !== null;
	}
	
	/**
	 * The route after the first `/<prefix>` followed by a slash or the end,
	 * as WordPress's rewrite reads it, with case; null for none
	 */
	public static function routeIn(
		string $path,
		string $prefix,
	): ?string
	{
		$needle = '/' . $prefix;
		$at = strpos($path, $needle);
		while($at !== false)
		{
			$rest = substr($path, $at + strlen($needle));
			// `/wp-jsonx` is not the prefix: look further
			if($rest === '' || $rest[0] === '/')
			{
				return self::untrailed($rest);
			}
			$at = strpos($path, $needle, $at + 1);
		}
		
		return null;
	}
	
	/** a route as WordPress's untrailingslashit() leaves it; none is the index route */
	public static function untrailed(
		string $route,
	): string
	{
		$route = rtrim($route, '/\\');
		
		return $route === '' ? '/' : $route;
	}
	
	/**
	 * A bag's values at a name: `a[b][c]` walks nested arrays, a segment
	 * ending in `*` (or empty, `a[]`) takes every key with that prefix; an
	 * array reached gives every leaf
	 *
	 * @return list<string>
	 */
	public static function pick(
		array $bag,
		string $name,
	): array
	{
		$values = [];
		foreach(self::walk([$bag], self::segments($name)) as $node)
		{
			self::leaves($node, $values);
		}
		
		return $values;
	}
	
	/**
	 * The keys of the arrays at a name ('' = the bag's own) — a key is input too
	 *
	 * @return list<string>
	 */
	public static function keys(
		array $bag,
		string $name,
	): array
	{
		$keys = [];
		foreach(self::walk([$bag], self::segments($name)) as $node)
		{
			if(is_array($node))
			{
				foreach(array_keys($node) as $key)
				{
					$keys[] = (string)$key;
				}
			}
		}
		
		return $keys;
	}
	
	/**
	 * A JSON body's values at a dot path, `*` for any key or element
	 *
	 * @return list<string>
	 */
	public static function pickJson(
		mixed $json,
		string $path,
	): array
	{
		if(is_array($json) === false || $path === '')
		{
			return [];
		}
		$values = [];
		foreach(self::walk([$json], explode('.', $path)) as $node)
		{
			self::leaves($node, $values);
		}
		
		return $values;
	}
	
	/** `a[b][c]` as [a, b, c]; '' as none */
	public static function segments(
		string $name,
	): array
	{
		if($name === '')
		{
			return [];
		}
		$at = strpos($name, '[');
		if($at === false)
		{
			return [$name];
		}
		preg_match_all('~\[([^\]]*)\]~', substr($name, $at), $brackets);
		
		return [substr($name, 0, $at), ...$brackets[1]];
	}
	
	/** the nodes the segments reach from the given ones; a segment ending in `*`, or empty, takes every key with that prefix */
	protected static function walk(
		array $nodes,
		array $segments,
	): array
	{
		foreach($segments as $segment)
		{
			$segment = (string)$segment;
			$next = [];
			foreach($nodes as $node)
			{
				if(is_array($node) === false)
				{
					continue;
				}
				if($segment === '' || str_ends_with($segment, '*'))
				{
					$prefix = rtrim($segment, '*');
					foreach($node as $key => $child)
					{
						if(str_starts_with((string)$key, $prefix))
						{
							$next[] = $child;
						}
					}
				}
				else if(array_key_exists($segment, $node))
				{
					$next[] = $node[$segment];
				}
			}
			$nodes = $next;
		}
		
		return $nodes;
	}
	
	/** every scalar under a node, as the string a test reads */
	protected static function leaves(
		mixed $node,
		array &$values,
	): void
	{
		if(is_array($node))
		{
			foreach($node as $child)
			{
				self::leaves($child, $values);
			}
			
			return;
		}
		$values[] = match(true)
		{
			$node === true => '1',
			$node === false, $node === null => '',
			is_scalar($node) => (string)$node,
			default => '',
		};
	}
	
	/**
	 * A value through the decode steps: every value the last step yields,
	 * and whether a step read only part of what it was given. url and
	 * base64 yield one or none; a step's values past DECODED_MAX are not
	 * carried on — one past it is, so the condition still sees there were more
	 *
	 * @return array{list<string>, bool}
	 */
	public static function decoded(
		string $value,
		array $steps,
	): array
	{
		$values = [$value];
		$cut = false;
		foreach($steps as $step)
		{
			$next = [];
			foreach($values as $one)
			{
				[$out, $short] = self::step((string)$step, $one);
				$cut = $cut || $short;
				foreach($out as $decoded)
				{
					$next[] = $decoded;
				}
			}
			if(count($next) > Ruleset::DECODED_MAX + 1)
			{
				$next = array_slice($next, 0, Ruleset::DECODED_MAX + 1);
				$cut = true;
			}
			$values = $next;
		}
		
		return [$values, $cut];
	}
	
	/**
	 * One decode step over one value: the values it yields — none when it
	 * cannot read the value — and whether it read only part of it (shortcodes
	 * and blocks past OCCURRENCES_MAX or JSON_CAP)
	 *
	 * @return array{list<string>, bool}
	 */
	protected static function step(
		string $step,
		string $value,
	): array
	{
		if($step === 'url')
		{
			return [[rawurldecode($value)], false];
		}
		if($step === 'base64')
		{
			// strict: a character outside the alphabet fails the step
			$bytes = base64_decode($value, true);
			
			return [$bytes === false ? [] : [$bytes], false];
		}
		if($step === 'json' || str_starts_with($step, 'json:'))
		{
			// an object or an array read as the json: target reads a body: a scalar or invalid JSON yields nothing
			$json = json_decode($value, true, Facts::JSON_DEPTH);
			if(is_array($json) === false)
			{
				return [[], false];
			}
			$values = [];
			if($step === 'json')
			{
				self::leaves($json, $values);
				
				return [$values, false];
			}
			
			return [self::pickJson($json, substr($step, strlen('json:'))), false];
		}
		$shortcode = Ruleset::shortcodeStep($step);
		if($shortcode !== null)
		{
			[$found, $cut] = self::shortcodes($value, $shortcode[0]);
			$values = [];
			foreach($found as $attributes)
			{
				foreach($attributes as $name => $one)
				{
					// a positional attribute's name is its place
					if($shortcode[1] === '*' || (string)$name === $shortcode[1])
					{
						$values[] = $one;
					}
				}
			}
			
			return [$values, $cut];
		}
		$block = Ruleset::blockStep($step);
		if($block !== null)
		{
			[$found, $cut] = self::blocks($value, $block[0]);
			$values = [];
			foreach($found as $attributes)
			{
				foreach(self::pickJson($attributes, $block[1]) as $one)
				{
					$values[] = $one;
				}
			}
			
			return [$values, $cut];
		}
		
		return [[], false];
	}
	
	/**
	 * Every `[<tag>` in a value with its attributes as WordPress reads them
	 * (shortcodeAttributes()): an occurrence not followed by a word character
	 * or a hyphen, its attribute text up to the first `]` less a
	 * self-closing `/` — get_shortcode_regex()'s third group — read in
	 * do_shortcode()'s view of the value (shortcodeView()) and, where it holds
	 * markup, in the value as written too: a shortcode inside an element's
	 * attribute runs there. Every occurrence, an escaped `[[tag]]` too: a
	 * nested do_shortcode() sees only its content and may run one the whole
	 * value shows escaped. An attribute text that spans a tag WordPress
	 * rewrites first is not read in full; so is the rest past OCCURRENCES_MAX
	 * occurrences or JSON_CAP bytes of attribute text — the second value says so
	 *
	 * @return array{list<array<int|string, string>>, bool}
	 */
	public static function shortcodes(
		string $value,
		string $tag,
	): array
	{
		$found = [];
		$cut = false;
		$budget = Facts::JSON_CAP;
		$open = '[' . $tag;
		[$shown, $rewritten] = self::shortcodeView($value);
		foreach(str_contains($value, '<') ? [[$shown, $rewritten], [$value, []]] : [[$shown, $rewritten]] as [$view, $spans])
		{
			$length = strlen($view);
			for($at = strpos($view, $open); $at !== false; $at = strpos($view, $open, $at + 1))
			{
				$after = $at + strlen($open);
				// `[tagx` and `[tag-x` are other tags
				if($after < $length && strspn($view, self::WORD_BYTES, $after, 1) === 1)
				{
					continue;
				}
				$close = strpos($view, ']', $after);
				// no `]` after this one: none after a later one either
				if($close === false)
				{
					break;
				}
				$budget -= $close - $after;
				if(count($found) === Ruleset::OCCURRENCES_MAX || $budget < 0)
				{
					return [$found, true];
				}
				foreach($spans as [$from, $to])
				{
					// a tag WordPress rewrites before it reads this text: what it reads there is not known
					$cut = $cut || ($from < $close && $to > $after);
				}
				$end = $close > $after && $view[$close - 1] === '/' ? $close - 1 : $close;
				$found[] = self::shortcodeAttributes(substr($view, $after, $end - $after));
			}
		}
		
		return [$found, $cut];
	}
	
	/**
	 * A value as WordPress's do_shortcode() matches shortcodes in it, after
	 * do_shortcodes_in_html_tags(): `&#91;` and `&#93;` written `&#091;` and
	 * `&#093;`, and the brackets inside every HTML element escaped — an
	 * element as wp_html_split() cuts one: a comment to its `-->`, a CDATA
	 * section to its `]]>`, anything else to its `>`, each to the end when
	 * unclosed. So a shortcode's attribute text runs on past a `]` inside an
	 * element, as WordPress reads it. With the view, the spans of the tags
	 * WordPress rewrites before it reads it — a tag holding both brackets,
	 * whose attributes' shortcodes run first and are filtered through kses —
	 * as [start, end) offsets in the view
	 *
	 * @return array{string, list<array{int, int}>}
	 */
	public static function shortcodeView(
		string $value,
	): array
	{
		$value = strtr($value, ['&#91;' => '&#091;', '&#93;' => '&#093;']);
		$view = '';
		$rewritten = [];
		$at = 0;
		for($open = strpos($value, '<'); $open !== false; $open = strpos($value, '<', $at))
		{
			$escaped = substr($value, $open + 1, 3) === '!--' || substr($value, $open + 1, 8) === '![CDATA[';
			$close = match(true)
			{
				substr($value, $open + 1, 3) === '!--' => self::through($value, '-->', $open + 2),
				substr($value, $open + 1, 8) === '![CDATA[' => self::through($value, ']]>', $open + 9),
				default => self::through($value, '>', $open + 1),
			};
			$element = substr($value, $open, $close - $open);
			$view .= substr($value, $at, $open - $at);
			$start = strlen($view);
			$view .= strtr($element, ['[' => '&#91;', ']' => '&#93;']);
			if($escaped === false && str_contains($element, '[') && str_contains($element, ']'))
			{
				$rewritten[] = [$start, strlen($view)];
			}
			$at = $close;
			if($at >= strlen($value))
			{
				break;
			}
		}
		
		return [$view . substr($value, $at), $rewritten];
	}
	
	/** the offset just past the first `$end` at or after `$from`, or the value's end */
	protected static function through(
		string $value,
		string $end,
		int $from,
	): int
	{
		$at = $from <= strlen($value) ? strpos($value, $end, $from) : false;
		
		return $at === false ? strlen($value) : $at + strlen($end);
	}
	
	/**
	 * A shortcode's attribute text as WordPress's shortcode_parse_atts()
	 * reads it, its own steps in its order: no-break and zero-width spaces
	 * as one space (not UTF-8: no attributes), its pattern's six forms, names
	 * lower-cased with a later one winning and a name empty() drops dropped,
	 * a positional value appended, stripcslashes() on every value, and a
	 * value with an unclosed element blanked
	 *
	 * @return array<int|string, string>
	 */
	public static function shortcodeAttributes(
		string $text,
	): array
	{
		$atts = [];
		$text = preg_replace('/[\x{00a0}\x{200b}]+/u', ' ', $text);
		if(is_string($text) === false || preg_match_all(self::SHORTCODE_ATTRIBUTES, $text, $matches, PREG_SET_ORDER) < 1)
		{
			return $atts;
		}
		foreach($matches as $m)
		{
			if(empty($m[1]) === false)
			{
				$atts[strtolower($m[1])] = stripcslashes($m[2]);
			}
			else if(empty($m[3]) === false)
			{
				$atts[strtolower($m[3])] = stripcslashes($m[4]);
			}
			else if(empty($m[5]) === false)
			{
				$atts[strtolower($m[5])] = stripcslashes($m[6]);
			}
			else if(isset($m[7]) && strlen($m[7]) > 0)
			{
				$atts[] = stripcslashes($m[7]);
			}
			else if(isset($m[8]) && strlen($m[8]) > 0)
			{
				$atts[] = stripcslashes($m[8]);
			}
			else if(isset($m[9]))
			{
				$atts[] = stripcslashes($m[9]);
			}
		}
		foreach($atts as $name => $one)
		{
			// a `<` no `>` closes after it
			if(str_contains($one, '<') && preg_match('/^[^<]*+(?:<[^>]*+>[^<]*+)*+$/', $one) !== 1)
			{
				$atts[$name] = '';
			}
		}
		
		return $atts;
	}
	
	/**
	 * The attributes of every `<!-- wp:<namespace/name> … -->` opener or void
	 * block in a value, as WordPress's block parser reads a comment: each
	 * `<!--` on its own (a superset of the tokens WordPress reads one after
	 * another), a bare `wp:x` being `core/x`, the attributes `{` up to the
	 * first `}` that whitespace, an optional `/` and `-->` follow, decoded
	 * as json_decode() does; invalid JSON is none. At most OCCURRENCES_MAX
	 * of them and JSON_CAP bytes of attributes; past either the rest is not
	 * read, and the second value says so
	 *
	 * @return array{list<array>, bool}
	 */
	public static function blocks(
		string $value,
		string $name,
	): array
	{
		$found = [];
		$budget = Facts::JSON_CAP;
		$count = 0;
		$length = strlen($value);
		// the closing braces, found once: a brace that whitespace, an optional `/` and `-->` follow
		$braces = [];
		for($at = strpos($value, '}'); $at !== false; $at = strpos($value, '}', $at + 1))
		{
			$space = strspn($value, self::SPACE_BYTES, $at + 1);
			$after = $at + 1 + $space;
			if($space > 0 && substr($value, ($value[$after] ?? '') === '/' ? $after + 1 : $after, 3) === '-->')
			{
				$braces[] = $at;
			}
		}
		$brace = 0;
		for($at = strpos($value, '<!--'); $at !== false; $at = strpos($value, '<!--', $at + 1))
		{
			$i = $at + 4;
			$space = strspn($value, self::SPACE_BYTES, $i);
			// a closer (`<!-- /wp:`) carries no attributes
			if($space === 0 || substr($value, $i + $space, 3) !== 'wp:')
			{
				continue;
			}
			$i += $space + 3;
			$word = self::blockWord($value, $i);
			$read = 'core/' . substr($value, $i, $word);
			$i += $word;
			if($word > 0 && $i < $length && $value[$i] === '/')
			{
				$second = self::blockWord($value, $i + 1);
				$read = substr($value, $i - $word, $word) . '/' . substr($value, $i + 1, $second);
				$i += 1 + $second;
				$word = $second;
			}
			$space = strspn($value, self::SPACE_BYTES, $i);
			if($word === 0 || $space === 0 || $read !== $name)
			{
				continue;
			}
			$i += $space;
			$attrs = null;
			if($i < $length && $value[$i] === '{')
			{
				while($brace < count($braces) && $braces[$brace] <= $i)
				{
					$brace++;
				}
				// no closing brace: not a block comment
				if($brace === count($braces))
				{
					continue;
				}
				$attrs = substr($value, $i, $braces[$brace] - $i + 1);
				$i = $braces[$brace] + 1;
				$i += strspn($value, self::SPACE_BYTES, $i);
			}
			if($i < $length && $value[$i] === '/')
			{
				$i++;
			}
			if(substr($value, $i, 3) !== '-->')
			{
				continue;
			}
			$budget -= strlen((string)$attrs);
			if(++$count > Ruleset::OCCURRENCES_MAX || $budget < 0)
			{
				return [$found, true];
			}
			$json = $attrs === null ? [] : json_decode($attrs, true, Facts::JSON_DEPTH);
			if(is_array($json))
			{
				$found[] = $json;
			}
		}
		
		return [$found, false];
	}
	
	/** the length of a block name's part at an offset — `[a-z][a-z0-9_-]*` — 0 for none */
	protected static function blockWord(
		string $value,
		int $at,
	): int
	{
		if($at >= strlen($value) || strspn($value, 'abcdefghijklmnopqrstuvwxyz', $at, 1) === 0)
		{
			return 0;
		}
		
		return 1 + strspn($value, 'abcdefghijklmnopqrstuvwxyz0123456789_-', $at + 1);
	}
	
	/** one value under one test — the literal ops fold ASCII, as a match rule's do */
	public static function passes(
		string $test,
		string $value,
		array $condition,
		string $host = '',
	): bool
	{
		$ci = ($condition['ci'] ?? true) === true;
		$expected = $condition['value'] ?? '';
		$text = is_string($expected) ? $expected : '';
		
		return match($test)
		{
			'equals' => $ci ? strcasecmp($text, $value) === 0 : $text === $value,
			'in' => self::among($value, (array)$expected, $ci),
			'not_in' => self::among($value, (array)$expected, $ci) === false,
			'prefix' => self::match(['op' => Ruleset::OP_PREFIX, 'value' => $text, 'ci' => $ci], $value) !== null,
			'suffix' => self::endsWith($value, $text, $ci),
			'contains' => self::match(['op' => Ruleset::OP_CONTAINS, 'value' => $text, 'ci' => $ci], $value) !== null,
			'regex' => self::match(['op' => Ruleset::OP_REGEX, 'value' => $text, 'ci' => $ci], $value) !== null,
			'not_prefix' => self::match(['op' => Ruleset::OP_PREFIX, 'value' => $text, 'ci' => $ci], $value) === null,
			'not_suffix' => self::endsWith($value, $text, $ci) === false,
			'not_contains' => self::match(['op' => Ruleset::OP_CONTAINS, 'value' => $text, 'ci' => $ci], $value) === null,
			// only a pattern that ran and did not match: one the engine refuses holds on nothing
			'not_regex' => self::regexes($text, $value, $ci) === false,
			'numeric' => preg_match('~^[+-]?[0-9]+$~D', $value) === 1,
			'not_numeric' => preg_match('~^[+-]?[0-9]+$~D', $value) !== 1,
			'longer_than' => is_int($expected) && strlen($value) > $expected,
			'greater_than' => is_int($expected) && ($number = self::integer($value)) !== null && $number > $expected,
			'less_than' => is_int($expected) && ($number = self::integer($value)) !== null && $number < $expected,
			'has_quote' => strpbrk($value, "'\"`") !== false,
			'has_markup' => self::markup($value),
			// the value as given, or once percent-decoded, as an app that decodes it again would follow it
			'offsite' => self::offsite($value, $host) || self::offsite(rawurldecode($value), $host),
			default => false,
		};
	}
	
	/** a value written as an integer of at most fifteen digits, signed or not, leading zeros allowed; null for anything else */
	protected static function integer(
		string $value,
	): ?int
	{
		return preg_match('~^[+-]?0*[0-9]{1,15}$~D', $value) === 1 ? (int)$value : null;
	}
	
	/**
	 * Whether a value carries markup, as written or with its character
	 * references decoded (numeric ones to ASCII, the named ones markup is
	 * written with): a tag opener, an on…= handler after a space, a quote or
	 * a slash, or a javascript:, vbscript: or data: scheme at the start or
	 * after a quote, `=` or `(` once control characters and spaces are
	 * squeezed out, as a browser reads a URL
	 */
	public static function markup(
		string $value,
	): bool
	{
		foreach([$value, self::referencesDecoded($value)] as $text)
		{
			if(preg_match('~<[a-zA-Z!/?]~', $text) === 1 || preg_match('~[\x09-\x0d\x20"\'`/]on[a-zA-Z]+[\x09-\x0d\x20]*=~i', $text) === 1)
			{
				return true;
			}
			$squeezed = (string)preg_replace('~[\x00-\x20]+~', '', $text);
			if(preg_match('~(?:^|["\'`=(])(?:javascript|vbscript|data):~i', $squeezed) === 1)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/** a value with its numeric character references to ASCII decoded, and the named ones markup is written with */
	protected static function referencesDecoded(
		string $value,
	): string
	{
		$value = (string)preg_replace_callback('~&#(?:[xX]0*([0-9a-fA-F]{1,6})|0*([0-9]{1,7}));?~', static function(array $reference): string
		{
			$code = ($reference[1] ?? '') !== '' ? (int)hexdec($reference[1]) : (int)$reference[2];
			
			return $code < 128 ? chr($code) : $reference[0];
		}, $value);
		
		return str_ireplace(['&lt;', '&gt;', '&quot;', '&apos;', '&colon;', '&lpar;', '&rpar;', '&tab;', '&newline;', '&amp;'],
			['<', '>', '"', "'", ':', '(', ')', "\t", "\n", '&'], $value);
	}
	
	/** a value ending in a text, ASCII case folded or not */
	protected static function endsWith(
		string $value,
		string $text,
		bool $ci,
	): bool
	{
		return strlen($value) >= strlen($text)
			&& ($ci ? strcasecmp(substr($value, strlen($value) - strlen($text)), $text) === 0 : str_ends_with($value, $text));
	}
	
	/**
	 * A rule's regex as PCRE runs it: `~…~D[i]`, never `u`; every `~` the
	 * value has not escaped itself (after an even run of backslashes) gets
	 * one, so it cannot close the delimiter
	 */
	protected static function regexPattern(
		string $value,
		bool $ci,
	): string
	{
		return '~' . (string)preg_replace('#(?<!\\\\)((?:\\\\\\\\)*)~#', '$1\\~', $value) . '~D' . ($ci ? 'i' : '');
	}
	
	/** whether a regex matches, as match() runs it: null when the engine refuses the pattern */
	protected static function regexes(
		string $pattern,
		string $subject,
		bool $ci,
	): ?bool
	{
		// @: a pattern PCRE refuses warns and returns false
		$found = @preg_match(self::regexPattern($pattern, $ci), $subject);
		
		return $found === false ? null : $found === 1;
	}
	
	/**
	 * Whether a URL takes a browser to another host than $host, read as a
	 * browser reads it: every tab and newline dropped, control characters
	 * and spaces at either end too; two slashes or backslashes in any mix
	 * open an authority, so does a special scheme (http, https, ftp, ws, wss)
	 * with or without its slashes; any other scheme (javascript:, data:)
	 * leaves the site too. A relative path stays; an unknown $host makes
	 * every authority another host's
	 */
	public static function offsite(
		string $url,
		string $host,
	): bool
	{
		$url = trim(str_replace(["\t", "\n", "\r"], '', $url), "\x00..\x20");
		if(preg_match('~^([a-zA-Z][a-zA-Z0-9+.\-]*):(.*)$~sD', $url, $scheme) === 1)
		{
			if(in_array(strtolower($scheme[1]), self::SPECIAL_SCHEMES, true) === false)
			{
				return true;
			}
			
			return self::otherHost(self::authorityHost(ltrim($scheme[2], '/\\')), $host);
		}
		if(preg_match('~^[/\\\\]{2}~', $url) === 1)
		{
			return self::otherHost(self::authorityHost(ltrim($url, '/\\')), $host);
		}
		
		return false;
	}
	
	/** the host an authority names: up to its path, query or fragment, after any user part, without its port, lower case, no trailing dot */
	protected static function authorityHost(
		string $authority,
	): string
	{
		$authority = (string)(preg_split('~[/\\\\?#]~', $authority, 2)[0] ?? '');
		$at = strrpos($authority, '@');
		$hostPort = $at === false ? $authority : substr($authority, $at + 1);
		
		return Facts::hostOf($hostPort);
	}
	
	/** whether an authority's host is not the request's: an empty one counts as another, and so does every one when the request named none */
	protected static function otherHost(
		string $found,
		string $host,
	): bool
	{
		return $found === '' || $found !== $host;
	}
	
	/** a value in a list, ASCII case folded or not */
	protected static function among(
		string $value,
		array $list,
		bool $ci,
	): bool
	{
		foreach($list as $item)
		{
			if(is_string($item) && ($ci ? strcasecmp($item, $value) === 0 : $item === $value))
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * One rule over one subject: the fragment that matched, or null. The
	 * literal ops fold ASCII only; regex runs as `~…~D[i]`, never `u`; a
	 * pattern the engine refuses matches nothing
	 */
	public static function match(
		array $rule,
		string $subject,
	): ?string
	{
		$value = (string)($rule['value'] ?? '');
		$ci = ($rule['ci'] ?? true) === true;
		switch($rule['op'] ?? '')
		{
			case Ruleset::OP_EQUALS:
				return ($ci ? strcasecmp($value, $subject) === 0 : $value === $subject) ? $subject : null;
			case Ruleset::OP_PREFIX:
				$hit = $ci ? strlen($subject) >= strlen($value) && strncasecmp($value, $subject, strlen($value)) === 0 : str_starts_with($subject, $value);
				
				return $hit ? substr($subject, 0, strlen($value)) : null;
			case Ruleset::OP_CONTAINS:
				$at = $ci ? stripos($subject, $value) : strpos($subject, $value);
				
				return $at === false ? null : substr($subject, $at, strlen($value));
			case Ruleset::OP_CIDR:
				return self::inCidr($value, $subject) ? $subject : null;
			case Ruleset::OP_REGEX:
				$pattern = self::regexPattern($value, $ci);
				
				// @: a pattern PCRE refuses warns, returns false and matches nothing
				return @preg_match($pattern, $subject, $m) === 1 ? (string)$m[0] : null;
			default:
				return null;
		}
	}
	
	/** an address in a prefix (`10.0.0.0/8`, `2001:db8::/32`) or equal to a bare one — v4 and v6, never a name */
	public static function inCidr(
		string $cidr,
		string $address,
	): bool
	{
		$cidr = trim($cidr);
		$slash = strpos($cidr, '/');
		$prefix = @inet_pton($slash === false ? $cidr : substr($cidr, 0, $slash));
		$packed = @inet_pton(trim($address));
		// different lengths: a v4 address never sits in a v6 prefix, nor the reverse
		if($prefix === false || $packed === false || strlen($packed) !== strlen($prefix))
		{
			return false;
		}
		$max = strlen($prefix) * 8;
		// a bare address compares every bit
		$bits = $max;
		if($slash !== false)
		{
			$given = substr($cidr, $slash + 1);
			// a prefix length past 32 (v4) or 128 (v6) matches nothing
			if(preg_match('~^\d{1,3}$~', $given) !== 1 || (int)$given > $max)
			{
				return false;
			}
			$bits = (int)$given;
		}
		// byte by byte under the mask; the last byte the prefix reaches is masked in part
		for($i = 0, $n = strlen($packed); $i < $n && $bits > 0; $i++, $bits -= 8)
		{
			$mask = $bits >= 8 ? 0xFF : (0xFF << (8 - $bits)) & 0xFF;
			if((ord($packed[$i]) & $mask) !== (ord($prefix[$i]) & $mask))
			{
				return false;
			}
		}
		
		return true;
	}
	
	/** the default transport: curl when it is there, streams otherwise; never throws */
	protected function transport(
		string $url,
		array $headers,
		int $timeoutMs,
	): array
	{
		try
		{
			if(function_exists('curl_init'))
			{
				$curl = curl_init();
				curl_setopt_array($curl, [
					CURLOPT_URL => $url,
					CURLOPT_RETURNTRANSFER => true,
					CURLOPT_HEADER => true,
					CURLOPT_HTTPHEADER => $headers,
					CURLOPT_USERAGENT => self::USER_AGENT,
					CURLOPT_CONNECTTIMEOUT_MS => $timeoutMs,
					CURLOPT_TIMEOUT_MS => $timeoutMs,
					CURLOPT_NOSIGNAL => true,
				]);
				$raw = curl_exec($curl);
				// no curl_close(): a no-op since PHP 8.0 and deprecated from 8.5, so a
				// host that throws on deprecations would turn every pull into status 0
				$status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
				if(is_string($raw) === false)
				{
					return ['status' => 0, 'headers' => [], 'body' => ''];
				}
				
				return ['status' => $status] + self::split($raw);
			}
			$context = stream_context_create(['http' => [
				'method' => 'GET',
				'header' => implode("\r\n", $headers) . "\r\nUser-Agent: " . self::USER_AGENT,
				'timeout' => $timeoutMs / 1000,
				// a non-2xx answer (a 304 too) is still read, its status taken from the headers
				'ignore_errors' => true,
			]]);
			$body = @file_get_contents($url, false, $context);
			$status = 0;
			$parsed = [];
			// http_get_last_response_headers() from 8.4; the predefined
			// $http_response_header, deprecated from 8.5 and gone in 9, before it
			$lines = function_exists('http_get_last_response_headers')
				? (http_get_last_response_headers() ?? [])
				: ($http_response_header ?? []);
			foreach($lines as $line)
			{
				if(preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m) === 1)
				{
					$status = (int)$m[1];
				}
				elseif(str_contains($line, ':'))
				{
					[$name, $value] = explode(':', $line, 2);
					$parsed[strtolower(trim($name))] = trim($value);
				}
			}
			
			return ['status' => $status, 'headers' => $parsed, 'body' => is_string($body) ? $body : ''];
		}
		catch(Throwable)
		{
			return ['status' => 0, 'headers' => [], 'body' => ''];
		}
	}
	
	/** a raw HTTP response (with CURLOPT_HEADER) into headers (lowercase names) and body, past any 1xx block */
	public static function split(
		string $raw,
	): array
	{
		$headers = [];
		while(true)
		{
			$at = strpos($raw, "\r\n\r\n");
			if($at === false)
			{
				return ['headers' => $headers, 'body' => $raw];
			}
			$block = substr($raw, 0, $at);
			$raw = substr($raw, $at + 4);
			$lines = explode("\r\n", $block);
			$statusLine = $lines[0] ?? '';
			foreach($lines as $line)
			{
				if(str_contains($line, ':'))
				{
					[$name, $value] = explode(':', $line, 2);
					$headers[strtolower(trim($name))] = trim($value);
				}
			}
			// a 1xx block (100 Continue) is followed by the real one
			if(preg_match('~^HTTP/\S+\s+1\d\d~', $statusLine) !== 1)
			{
				return ['headers' => $headers, 'body' => $raw];
			}
		}
	}
	
	protected function log(
		string $line,
	): void
	{
		if($this->log !== null)
		{
			try
			{
				($this->log)('[shield] ' . $line);
			}
			catch(Throwable)
			{
				// the host's log never fails the request
			}
		}
	}
}
