<?php
declare(strict_types=1);

/**
 * ovos/codesafe Shield kernel — zero dependencies, vendor this file.
 *
 *   require_once __DIR__ . '/Shield.php';
 *   require_once __DIR__ . '/Shield/Wordpress.php';     // a WordPress host only, always after this file
 *   use Ovos\Codesafe\Shield\{Kernel, Store, Facts, Consent, Verdict, Wordpress};
 *
 *   $kernel = new Kernel(
 *       'https://codesafe.example',                 // codesafe instance base URL
 *       $apiKey,                                   // the project api_key the sender already holds (secret!)
 *       new Store('/var/cache/app/shield.json', 'myapp:shield'),   // file tier + APCu prefix
 *       report: fn(string $kind, string $message, array $extra) => $sender->reportRefusal($kind, $message, $extra),
 *       platforms: [new Wordpress()],              // the platform modules loaded; none on a host that is no WordPress
 *   );
 *   $consent = new Consent(detect: $config['shield_detect'], enforce: $config['shield_enforce'], kill: $config['shield_kill']);
 *   $verdict = $kernel->handle(Facts::fromServer($_SERVER, $_POST, fn() => file_get_contents('php://input'),
 *       platforms: $kernel->platforms()), $consent);
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
 * reads what the kernel could not (an upload, a WordPress batch not read
 * in full, a JSON body past Facts::JSON_CAP on a handler none of its other
 * entries pins), is held with the reason `unanswered`
 * (Verdict::REASON_UNANSWERED), never blocked. A JSON body past the cap on
 * the handler its other entries pin is taken to carry what its json:
 * conditions look for: the app decodes it whole, and an honest client sends
 * no such body to a patched handler.
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
 * Platform modules (Platform): what one platform's app makes of a request —
 * WordPress's REST routes and batches, its shortcode and block attributes,
 * the JSON types it reads — lives in a module of its own (Shield/Wordpress.php),
 * which the adapter loads after this file and hands the kernel and Facts.
 * A kernel drops a rule naming a module's words it was not given at the
 * pull, as it drops a kind it does not know, and Facts read none of them:
 * nothing is guessed. It reads every request with at least the modules it
 * pulled for, whatever its Facts name, and logs an entry of `platforms` that
 * is no module. The pull names the modules in X-Shield-Platforms, `core`
 * always first.
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
 * fatal error (the classes bind at compile time, so no guard can help). A
 * module is loaded the same way and after this file: it implements the
 * Platform interface declared here, which is no file a PSR-4 autoloader finds.
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
use function array_diff;
use function array_filter;
use function array_is_list;
use function array_key_exists;
use function array_keys;
use function array_map;
use function array_pop;
use function array_slice;
use function array_unique;
use function array_values;
use function base64_decode;
use function bin2hex;
use function ceil;
use function chr;
use function class_exists;
use function count;
use function ctype_digit;
use function curl_exec;
use function curl_getinfo;
use function curl_init;
use function curl_setopt_array;
use function explode;
use function fclose;
use function file_get_contents;
use function file_put_contents;
use function filter_var;
use function fopen;
use function fstat;
use function function_exists;
use function fwrite;
use function get_debug_type;
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
use function is_link;
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
use function random_bytes;
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
use function stripos;
use function strlen;
use function strncasecmp;
use function strpbrk;
use function strpos;
use function strrpos;
use function strtolower;
use function strtoupper;
use function substr;
use function time;
use function trim;
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
use const FILTER_VALIDATE_IP;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

/**
 * A platform's kernel module: the vocabulary only its app gives a request a
 * meaning in — frame targets, decode steps, the requests a request carries
 * inside it, the JSON types it reads. Given to Kernel and Facts (their
 * `platforms`), it is asked where the core's own reading ends; a kernel
 * without it drops its rules at the pull and reads none of its words
 */
interface Platform
{
	/** the word X-Shield-Platforms names it by */
	public function name(): string;
	
	/**
	 * Its frame targets (`rest`): named, no prefix; each selects the handler a
	 * request reaches whatever its test, and stands in as the frame value
	 *
	 * @return list<string>
	 */
	public function targets(): array;
	
	/**
	 * One of its targets' values over the request; [] when the request has none
	 *
	 * @return list<string>
	 */
	public function values(
		string $target,
		Facts $facts,
	): array;
	
	/** whether a decode step is one of its own and well formed */
	public function decodes(
		mixed $step,
	): bool;
	
	/**
	 * One of its steps over one value: the values it yields — none when it
	 * cannot read the value — and whether it read only part of it
	 *
	 * @return array{list<string>, bool}
	 */
	public function decode(
		string $step,
		string $value,
	): array;
	
	/**
	 * The requests inside this one that reach handlers of their own (a
	 * batch), and whether some of them could not be read
	 *
	 * @return array{list<Facts>, bool}
	 */
	public function subRequests(
		Facts $facts,
	): array;
	
	/** whether requests inside this one that could not be read (subRequests()) may have reached a vpatch */
	public function reaches(
		array $rule,
		Facts $facts,
	): bool;
	
	/** whether its app reads a body of this content type as JSON where the core does not */
	public function jsonType(
		string $contentType,
	): bool;
}

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
	
	/**
	 * a JSON body past this is not decoded (jsonUnread()): its json: conditions
	 * hold as answered where the rule's other entries pin the handler, else
	 * unanswered (Kernel::patched()) — padding never hides one
	 */
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
	
	/** the request a sub-request came in, whose superglobals its handler reads too (derived()) */
	protected ?Facts $outer = null;
	
	/** @var ?Closure(list<Platform>): ?Closure fromServer()'s JSON reader for a list of modules: a copy read with others builds its own (withPlatforms()) */
	protected ?Closure $jsonFor = null;
	
	/** @var list<Platform> the platform modules the request is read with */
	public readonly array $platforms;
	
	/**
	 * @param array<string, mixed> $query the query as the platform parsed it ($_GET)
	 * @param array<string, mixed> $form the form fields as the platform parsed them ($_POST)
	 * @param array<string, string> $headers lowercase names
	 * @param array<string, mixed> $files field => the uploaded file's name (or names)
	 * @param ?Closure(): mixed $jsonReader a JSON body, decoded; it throws a LengthException for a body too large to read
	 * @param ?Closure(string): ?bool $can whether the signed-in user has a capability; null when the host cannot say
	 * @param ?Closure(string, string): ?bool $nonce whether a nonce is valid for an action; null when the host cannot say
	 * @param bool $callerKnown whether the host could tell who the caller is: false leaves `authed` a guess,
	 *     and what depends on it — a vpatch's anonymous or lacks:, a threat address — only observes
	 * @param ?Closure(string): ?bool $kses whether the host's HTML filter would change a value (WordPress:
	 *     wp_kses_post()); null when the host cannot say
	 * @param array<string, mixed> $uploads field => the upload's temp path (or paths), nested as $files nests the names
	 * @param ?Closure(string): ?string $fileReader an upload's bytes by its temp path; null when the host cannot read it
	 * @param list<Platform> $platforms the platform modules the kernel was given (Kernel::platforms()); anything else is ignored
	 * @param array<string, scalar> $options what a platform module reads of the host, by the module's own key (WordPress's REST prefix)
	 * @param ?array<string, mixed> $request the host's request bag ($_REQUEST), whose values a request: target reads beside the
	 *     query's and the form's; null where the host has none
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
		public readonly bool $callerKnown = true,
		protected ?Closure $kses = null,
		public readonly array $uploads = [],
		protected ?Closure $fileReader = null,
		array $platforms = [],
		public readonly array $options = [],
		public readonly ?array $request = null,
	)
	{
		$this->platforms = array_values(array_filter($platforms, static fn(mixed $platform): bool => $platform instanceof Platform));
	}
	
	/**
	 * A request inside this one as the handler it reaches sees it — a
	 * platform module shapes it (a WordPress batch's sub-request): its method,
	 * URI, query, form, JSON body and headers, and this request's caller,
	 * host answers, platforms and options, whom the platform runs it as. Its
	 * handler also reads the superglobals, which stay this request's: its
	 * cookies, uploads, query, form and headers count beside the
	 * sub-request's own (Kernel::values()), and its host is this request's
	 *
	 * @param array<string, string> $headers lowercase names
	 */
	public function derived(
		string $method,
		string $uri,
		array $query,
		array $form,
		mixed $json,
		array $headers,
	): self
	{
		$sub = new self($method, $uri, $this->ua, $this->ip, $this->authed, null, $this->user, $query, $form, [], $headers, [], static fn(): mixed => $json,
			$this->can, $this->nonce, $this->callerKnown, $this->kses, platforms: $this->platforms, options: $this->options);
		$sub->outer = $this;
		
		return $sub;
	}
	
	/**
	 * This request read with other platform modules — a kernel's, when the
	 * adapter handed Facts fewer (Kernel::judge(), tally()). Every read goes
	 * through this request, so its body, uploads and the host's answers are
	 * read once whichever asks, and what a report says of the body holds for
	 * both. A JSON body is decoded anew only by fromServer()'s reader, off the
	 * input's one read, and then takes the modules' JSON types too; a reader
	 * the adapter built stays its own
	 *
	 * @param list<Platform> $platforms
	 */
	public function withPlatforms(
		array $platforms,
	): self
	{
		$copy = new self($this->method, $this->uri, $this->ua, $this->ip, $this->authed, fn(): array => [$this->body(), $this->bodyWasCapped()], $this->user,
			$this->query, $this->form, $this->cookies, $this->headers, $this->files, $this->jsonFor === null ? $this->jsonThrough(...) : ($this->jsonFor)($platforms),
			fn(string $capability): ?bool => $this->can($capability), fn(string $action, string $value): ?bool => $this->nonceValid($action, $value),
			$this->callerKnown, fn(string $value): ?bool => $this->htmlUnsafe($value), $this->uploads, fn(string $path): ?string => $this->fileContent($path),
			$platforms, $this->options, $this->request);
		$copy->outer = $this->outer;
		$copy->jsonFor = $this->jsonFor;
		
		return $copy;
	}
	
	/** this request's JSON body as a copy's reader hands it over (withPlatforms()): past the cap it is unread there too */
	protected function jsonThrough(): mixed
	{
		$json = $this->json();
		if($this->jsonUnread())
		{
			throw new LengthException('a JSON body past the cap');
		}
		
		return $json;
	}
	
	/** the request this sub-request came in; null for a request of its own */
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
	
	/**
	 * @param array<string, mixed> $server the request's server parameters ($_SERVER or a PSR-7 equivalent)
	 * @param array<string, mixed> $post the parsed form fields ($_POST) — files never
	 * @param ?callable(): string $input the raw body reader (fn() => file_get_contents('php://input')), called once at most
	 * @param string $user who a `user`-keyed rate rule counts: the signed-in identity, or the name a login POST tries ('' = none, the rule is skipped)
	 * @param ?array<string, mixed> $get the parsed query ($_GET); null = the raw URI's query through parse_str
	 * @param array<string, mixed> $cookies the parsed cookies ($_COOKIE)
	 * @param array<string, mixed> $files the uploads ($_FILES): their names, and their temp files for a file-content condition
	 * @param ?callable(string): ?bool $can whether the signed-in user has a capability (a vpatch's `lacks:`)
	 * @param ?callable(string, string): ?bool $nonce whether a nonce is valid for an action (a vpatch's nonce test)
	 * @param bool $callerKnown whether the host could tell who the caller is (Facts::$callerKnown)
	 * @param ?callable(string): ?bool $kses whether the host's HTML filter would change a value (a vpatch's unsafe_html)
	 * @param ?callable(string): ?string $fileReader an upload's bytes by its temp path; null reads PHP's own (uploadReader())
	 * @param list<Platform> $platforms the platform modules the kernel was given (Kernel::platforms())
	 * @param array<string, scalar> $options what a platform module reads of the host (Facts::$options)
	 * @param ?array<string, mixed> $request the host's request bag ($_REQUEST), read by a request: target beside the query and the form
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
		bool $callerKnown = true,
		?callable $kses = null,
		?callable $fileReader = null,
		array $platforms = [],
		array $options = [],
		?array $request = null,
	): self
	{
		$uri = is_string($server['REQUEST_URI'] ?? null) ? $server['REQUEST_URI'] : '/';
		if($get === null)
		{
			// the RAW query, as PHP would have parsed it — the URI is decoded once below
			parse_str(explode('?', $uri, 2)[1] ?? '', $get);
		}
		$contentType = is_string($server['CONTENT_TYPE'] ?? null) ? $server['CONTENT_TYPE'] : '';
		// the body's reader, the JSON readers and every copy's share one read: an input that cannot be rewound hands a second read nothing
		$input = $input === null ? null : self::readOnce($input);
		
		$facts = new self(
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
			self::jsonReader($contentType, $input, platforms: $platforms),
			$can === null ? null : Closure::fromCallable($can),
			$nonce === null ? null : Closure::fromCallable($nonce),
			$callerKnown,
			$kses === null ? null : Closure::fromCallable($kses),
			self::uploadPaths($files),
			$fileReader === null ? self::uploadReader() : Closure::fromCallable($fileReader),
			$platforms,
			$options,
			$request,
		);
		$facts->jsonFor = static fn(array $platforms): ?Closure => self::jsonReader($contentType, $input, platforms: $platforms);
		
		return $facts;
	}
	
	/**
	 * The raw input read once, whichever reader asks: what it returned, or
	 * what it threw, is every later read's answer. Of a body past both caps
	 * only the part a reader looks at is kept: it still reads as capped, and
	 * as JSON too large to decode
	 */
	protected static function readOnce(
		callable $input,
	): Closure
	{
		$read = false;
		$raw = null;
		$failure = null;
		// a byte past the larger cap: every reader still sees the body run past its own
		$keep = max(self::BODY_CAP, self::JSON_CAP) + 1;
		
		return static function() use ($input, $keep, &$read, &$raw, &$failure): mixed
		{
			if($read === false)
			{
				$read = true;
				try
				{
					$raw = $input();
					// held while the request is read: the rest of a large body would cost its size for nothing
					if(is_string($raw) && strlen($raw) > $keep)
					{
						$raw = substr($raw, 0, $keep);
					}
				}
				catch(Throwable $thrown)
				{
					$failure = $thrown;
				}
			}
			if($failure !== null)
			{
				throw $failure;
			}
			
			return $raw;
		};
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
	
	/**
	 * A JSON body, decoded — read only when a json: target asks; past the cap
	 * it throws, and json() says the body went unread
	 *
	 * @param list<Platform> $platforms the modules whose JSON types count too (jsonType())
	 */
	public static function jsonReader(
		string $contentType,
		?callable $input,
		int $cap = self::JSON_CAP,
		array $platforms = [],
	): ?Closure
	{
		if($input === null || self::jsonType($contentType, $platforms) === false)
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
	
	/**
	 * Whether a body of this content type is JSON to a rule: `application/json`,
	 * a `+json` type, or one a platform module given reads as JSON (Platform::jsonType())
	 *
	 * @param list<Platform> $platforms
	 */
	public static function jsonType(
		string $contentType,
		array $platforms = [],
	): bool
	{
		$type = strtolower(trim(explode(';', $contentType, 2)[0]));
		if($type === 'application/json' || str_ends_with($type, '+json'))
		{
			return true;
		}
		foreach($platforms as $platform)
		{
			if($platform instanceof Platform && $platform->jsonType($contentType))
			{
				return true;
			}
		}
		
		return false;
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
	
	/**
	 * The path alone, as a server maps it to a file (normalPath()) — what a
	 * `path` condition and a report line read; the query may carry what the
	 * body may not
	 */
	public function path(): string
	{
		return self::normalPath(explode('?', $this->uri, 2)[0]);
	}
	
	/**
	 * The script a PHP server runs for this path: the path cut after its
	 * first `.php` segment — /wp-admin/admin-ajax.php/x runs admin-ajax.php
	 * with /x as PATH_INFO under mod_php and the usual fastcgi_split_path_info
	 * — the path itself when it names none
	 */
	public function scriptPath(): string
	{
		$path = $this->path();
		
		return preg_match('~^.*?\.php(?=/)~i', $path, $match) === 1 ? $match[0] : $path;
	}
	
	/**
	 * A path as a server maps it to a resource: a run of slashes as one, the
	 * dot segments resolved (RFC 3986 §5.2.4) — Apache and nginx serve
	 * /wp-admin//admin-ajax.php, /wp-admin/./admin-ajax.php and
	 * /wp-admin/../wp-admin/admin-ajax.php all as /wp-admin/admin-ajax.php,
	 * so a rule naming that path must read every one of them so. A `..` never
	 * climbs above the root; a trailing dot segment leaves a directory
	 */
	public static function normalPath(
		string $path,
	): string
	{
		$segments = explode('/', (string)preg_replace('~/{2,}~', '/', $path));
		$last = count($segments) - 1;
		$kept = [];
		foreach($segments as $index => $segment)
		{
			if($segment === '.' || $segment === '..')
			{
				// the leading '' is the root: a `..` stops there
				if($segment === '..' && count($kept) > 1)
				{
					array_pop($kept);
				}
				if($index === $last)
				{
					$kept[] = '';
				}
				
				continue;
			}
			$kept[] = $segment;
		}
		$normal = implode('/', $kept);
		
		return $normal === '' ? '/' : $normal;
	}
	
	/**
	 * The subjects a field reads: field()'s, and for the uri its query as
	 * $_GET reads it too, every `+` a space, where that differs — a rule on
	 * `union select` meets `union+select`, and one spelled with the `+`
	 * still meets it; none when the request has none
	 *
	 * @return list<string>
	 */
	public function subjects(
		string $field,
	): array
	{
		$subject = $this->field($field);
		if($subject === null)
		{
			return [];
		}
		$spaced = $field === Ruleset::FIELD_URI ? self::querySpaced($subject) : $subject;
		
		return $spaced === $subject ? [$subject] : [$subject, $spaced];
	}
	
	/** a decoded URI with every `+` of its query read as a space, as PHP parses the query into $_GET */
	public static function querySpaced(
		string $uri,
	): string
	{
		$at = strpos($uri, '?');
		
		return $at === false ? $uri : substr($uri, 0, $at + 1) . str_replace('+', ' ', substr($uri, $at + 1));
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
	
	/** a vpatch's frame targets, without a name — a platform module names its own (Platform::targets()) — and the prefixes that take one (`query:file`) */
	public const TARGETS = ['method', 'path'];
	
	/** `request:` is $_REQUEST's reading: the query's values and the body's; `file:` an upload's name, `file-content:` its bytes */
	public const TARGET_PREFIXES = ['query', 'body', 'request', 'json', 'cookie', 'header', 'file', 'file-content', 'query-keys', 'body-keys'];
	
	/** the decode steps; `json:<dot.path>` is json walked to a path, as the json: target walks a body; a platform module decodes its own (Platform::decodes()) */
	public const DECODES = ['url', 'base64', 'json'];
	
	/** the values a condition's decode steps yield that are read at most: past them the condition holds unanswered */
	public const DECODED_MAX = 256;
	
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
	
	/**
	 * The most match and rate rules a kernel keeps, and the most virtual
	 * patches — the door's own caps per project; past them the rest of the
	 * door's order is dropped, so no door serves a kernel more work per
	 * request than codesafe's would
	 */
	public const RULES_MAX = 25;
	
	public const VPATCHES_MAX = 100;
	
	/**
	 * An ordinary visitor's request as a match rule's field reads it: the
	 * home page, a current browser, no body. A match rule that holds on it
	 * would refuse everyone (reachesEverything())
	 */
	public const ORDINARY = ['uri' => '/', 'ua' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 'body' => ''];
	
	/** the widest address range a match rule may name: a /8 of IPv4, a /32 of IPv6 */
	public const CIDR_V4_MIN = 8;
	
	public const CIDR_V6_MIN = 32;
	
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
	 * kept only whole — a mode, pass paths, addresses PHP can read (threats()).
	 * A rule in the words of a platform module not given is left out too
	 *
	 * @param list<Platform> $platforms the modules whose words a rule may use
	 */
	public static function fromPayload(
		array $payload,
		int $fetchedAt,
		string $digest = '',
		string $version = '',
		array $platforms = [],
	): self
	{
		$usable = ($payload['contract'] ?? null) === self::CONTRACT
			&& ($payload['dialect'] ?? null) === self::DIALECT
			&& is_array($payload['rules'] ?? null);
		// the store keeps only these: fromRecord() checks nothing, and a malformed rate rule would throw in judge() on every request (the Node twin checks on read)
		$rules = [];
		if($usable)
		{
			// the door's caps, in the door's order: what is past them is dropped
			$kept = ['match' => 0, 'vpatch' => 0];
			foreach($payload['rules'] as $rule)
			{
				// a match rule that would refuse every visitor is no door's to serve
				if(self::wellFormed($rule, $platforms) === false
					|| (self::isVpatch($rule) === false && self::isRate($rule) === false && self::reachesEverything($rule)))
				{
					continue;
				}
				$slot = self::isVpatch($rule) ? 'vpatch' : 'match';
				if($kept[$slot] >= ($slot === 'vpatch' ? self::VPATCHES_MAX : self::RULES_MAX))
				{
					continue;
				}
				$kept[$slot]++;
				$rules[] = $rule;
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
	
	/** @param list<Platform> $platforms the modules whose words a vpatch may use */
	public static function wellFormed(
		mixed $rule,
		array $platforms = [],
	): bool
	{
		if(is_array($rule) && self::isVpatch($rule))
		{
			return self::vpatchWellFormed($rule, $platforms);
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
	
	/**
	 * Whether a match rule would refuse every visitor: it holds on an
	 * ordinary request (ORDINARY) or names an address range wider than a /8
	 * (a /32 of IPv6). Such a rule is no patch but the site down, whoever set
	 * it or served it, and a kernel keeps none. A rate rule over every
	 * request is a site's ceiling and is not asked
	 */
	public static function reachesEverything(
		array $rule,
	): bool
	{
		$value = trim((string)$rule['value']);
		if($rule['op'] === self::OP_CIDR)
		{
			[$address, $bits] = explode('/', $value, 2) + [1 => null];
			$packed = filter_var($address, FILTER_VALIDATE_IP) === false ? false : inet_pton($address);
			
			// a bare address, or no address at all, is no range
			return $packed !== false && is_string($bits) && ctype_digit($bits)
				&& (int)$bits < (strlen($packed) === 4 ? self::CIDR_V4_MIN : self::CIDR_V6_MIN);
		}
		$ordinary = self::ORDINARY[$rule['field']] ?? null;
		
		return $ordinary !== null && Kernel::match($rule, $ordinary) !== null;
	}
	
	public static function isVpatch(
		array $rule,
	): bool
	{
		return ($rule['kind'] ?? self::KIND_MATCH) === self::KIND_VPATCH;
	}
	
	/**
	 * Whether a vpatch entry selects the handler a request reaches — its
	 * entry point: a platform module's target (a route), or an ENTRY_TESTS
	 * test on a value as sent (no decode steps) of any target but an
	 * upload's contents; a group when every member does. A negation, a
	 * payload test, a nonce or exists says what the exploit carries
	 *
	 * @param list<Platform> $platforms
	 */
	public static function selects(
		array $entry,
		array $platforms = [],
	): bool
	{
		if(isset($entry[self::GROUP_ANY]))
		{
			foreach((array)$entry[self::GROUP_ANY] as $member)
			{
				if(self::selects((array)$member, $platforms) === false)
				{
					return false;
				}
			}
			
			return true;
		}
		$target = (string)($entry['target'] ?? '');
		
		return self::targetOf($target, $platforms) !== null || (in_array($entry['test'] ?? null, self::ENTRY_TESTS, true) && ($entry['decode'] ?? []) === []
			&& str_starts_with($target, 'file-content:') === false);
	}
	
	/**
	 * The module among $platforms whose targets() names a target; null when
	 * none does — a target no module given names is never read
	 *
	 * @param list<Platform> $platforms
	 */
	public static function targetOf(
		string $target,
		array $platforms,
	): ?Platform
	{
		foreach($platforms as $platform)
		{
			if($platform instanceof Platform && in_array($target, $platform->targets(), true))
			{
				return $platform;
			}
		}
		
		return null;
	}
	
	/**
	 * The module among $platforms whose decodes() takes a step; null when
	 * none does — a step no module given decodes yields nothing
	 *
	 * @param list<Platform> $platforms
	 */
	public static function decoderOf(
		mixed $step,
		array $platforms,
	): ?Platform
	{
		foreach($platforms as $platform)
		{
			if($platform instanceof Platform && $platform->decodes($step))
			{
				return $platform;
			}
		}
		
		return null;
	}
	
	/**
	 * Whether a target is a frame target — one of TARGETS or a module's:
	 * it names no parameter, so its value stands in only when no parameter's matched
	 *
	 * @param list<Platform> $platforms
	 */
	public static function isFrame(
		string $target,
		array $platforms,
	): bool
	{
		return in_array($target, self::TARGETS, true) || self::targetOf($target, $platforms) !== null;
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
	
	/**
	 * A vpatch: an int id, a mode, a `who` off the vocabulary, 1 to
	 * CONDITIONS_MAX entries each well formed
	 *
	 * @param list<Platform> $platforms the modules whose words it may use
	 */
	public static function vpatchWellFormed(
		array $rule,
		array $platforms = [],
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
			if(self::entryWellFormed($condition, $platforms) === false)
			{
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * A vpatch's entry: a plain condition, or a group of GROUP_MIN to
	 * GROUP_MAX plain conditions under `any` and nothing else
	 *
	 * @param list<Platform> $platforms
	 */
	public static function entryWellFormed(
		mixed $entry,
		array $platforms = [],
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
					|| self::conditionWellFormed($member, $platforms) === false)
				{
					return false;
				}
			}
			
			return true;
		}
		
		return self::conditionWellFormed($entry, $platforms);
	}
	
	public static function whoWellFormed(
		mixed $who,
	): bool
	{
		return $who === self::WHO_ANYONE || $who === self::WHO_ANONYMOUS
			|| (is_string($who) && preg_match('~^lacks:[a-z0-9_]{1,64}$~D', $who) === 1);
	}
	
	/**
	 * A target off the vocabulary; a decode list off its own; a value the
	 * test can read — a list, a count, or a bounded string
	 *
	 * @param list<Platform> $platforms the modules whose targets and steps count too
	 */
	public static function conditionWellFormed(
		mixed $condition,
		array $platforms = [],
	): bool
	{
		if(is_array($condition) === false || self::targetWellFormed($condition['target'] ?? null, $platforms) === false
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
			if(self::decodeWellFormed($step, $platforms) === false)
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
	
	/**
	 * A decode step: one of DECODES, `json:` and a path the json: target
	 * would take, or one of a module's own (Platform::decodes())
	 *
	 * @param list<Platform> $platforms
	 */
	public static function decodeWellFormed(
		mixed $step,
		array $platforms = [],
	): bool
	{
		return in_array($step, self::DECODES, true)
			|| (is_string($step) && str_starts_with($step, 'json:') && $step !== 'json:' && self::targetWellFormed($step))
			|| self::decoderOf($step, $platforms) !== null;
	}
	
	/**
	 * `method`, `path`, a module's own (`rest`), or a prefix and a name
	 * (`query:file`); the keys targets may name the top level ('')
	 *
	 * @param list<Platform> $platforms
	 */
	public static function targetWellFormed(
		mixed $target,
		array $platforms = [],
	): bool
	{
		if(is_string($target) === false || strlen($target) > 200)
		{
			return false;
		}
		if(self::isFrame($target, $platforms))
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
				return self::clamped($hit);
			}
		}
		// a link planted at the path is no store: the next pull writes a real one
		if($this->file === '' || is_link($this->file) || is_file($this->file) === false)
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
		$record = self::clamped($record);
		if($this->apcu)
		{
			apcu_store($this->key('rules'), $record);
		}
		
		return $record;
	}
	
	/**
	 * A record whose fetched_at lies in the future (a clock that ran ahead, a
	 * file written by hand) as fetched now: the pull would skip it for as
	 * long as it lies ahead, and the ceiling would never lift it
	 */
	protected static function clamped(
		array $record,
	): array
	{
		$now = time();
		if(is_int($record['fetched_at'] ?? null) && $record['fetched_at'] > $now)
		{
			$record['fetched_at'] = $now;
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
			$temp = '';
			$created = false;
			try
			{
				// a temp file of its own, unguessable: concurrent writers never share one, and rename() swaps the file whole
				$temp = $this->file . '.' . bin2hex(random_bytes(12)) . '.tmp';
				$json = (string)json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
				// created exclusively: a file or a link planted at the name fails the open instead of being written through
				$handle = @fopen($temp, 'xb');
				if($handle !== false)
				{
					$created = true;
					$whole = fwrite($handle, $json) === strlen($json);
					fclose($handle);
					// a short write (a full disk) never replaces the good file
					$written = $whole && rename($temp, $this->file);
				}
			}
			catch(Throwable)
			{
				// not written: the temp goes below
			}
			// only a temp this call created: after a failed open the name is someone else's
			if($created && $written === false && is_file($temp))
			{
				@unlink($temp);
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
		// the key as its sha256, a fixed-width name no other key is given: two keys never share a count
		$head = 'rate:' . $ruleId . ':' . hash('sha256', $key) . ':';
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
	
	/** the most bytes of a pull's answer the kernel decodes */
	public const BODY_MAX = 2097152;
	
	/** `matched` is attacker-controlled: bounded here, scrubbed by the sender */
	public const MATCHED_MAX = 200;
	
	/**
	 * The names whose value a report never carries (shown()): a password, a
	 * token, a session, a CSRF or one-time code, a reset, API or private key,
	 * a card's security code — the senders' secret names, restated because
	 * the kernel loads nothing else. The short words a query parameter uses
	 * for a credential (`key`, `code`, `auth`, `sig`, `otp`, `pin`, `hash`)
	 * only as the whole name
	 */
	public const SECRET_NAME = '~pass(?:word|wd|phrase)?|pwd|token|secret|authori[sz]ation|cookie|session|sessid|csrf|xsrf|nonce|jwt|bearer'
		. '|signature|credential|api[-_]?key|(?:private|access|consumer|licen[cs]e|encryption|signing|rp)[-_]?key|auth[-_]?(?:code|key)'
		. '|backup[-_]?code|(?<![a-z0-9])(?:otp|totp|mfa|2fa)(?![a-z0-9])|card[-_]?(?:num|no|code|cvc|cvv|exp)|cc[-_]?(?:num|no)'
		. '|(?<![a-z])(?:cvv2?|cvc2?|csc|ccv|iban)(?![a-z])|security[-_]?code|^(?:key|auth|code|sig|otp|pin|hash)$~i';
	
	/** how deep shown() looks for a secret-named field in a parsed body before it assumes one */
	public const SECRET_DEPTH = 8;
	
	public const DOOR = '/api/v1/shield';
	
	public const USER_AGENT = 'ovos-codesafe-shield/1';
	
	/**
	 * what this kernel reads — the door serves rate rules only to a pull that
	 * names them, and says a blocking rule `block` only to one naming `mode-block`
	 */
	public const HEADER_KINDS = 'X-Shield-Kinds';
	
	public const KINDS = 'match,rate,threat,vpatch,mode-block';
	
	/**
	 * the platform modules this kernel reads — the door serves a rule in a
	 * module's words only to a pull that names the module; `core` always
	 * comes first, since a header with an empty value is dropped by libcurl
	 */
	public const HEADER_PLATFORMS = 'X-Shield-Platforms';
	
	public const PLATFORM_CORE = 'core';

	/** the rule the counting's heartbeat is an `entry` of, once per request it ran on: rule 0, the threat addresses', whose evidence nothing else counts */
	public const HEARTBEAT = Ruleset::THREAT_RULE;
	
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
	
	/** whether the host's log was told of a request read with more modules than its Facts named (readable()): once per kernel */
	protected bool $misread = false;
	
	/**
	 * @param string $url codesafe instance base URL
	 * @param string $key the project api_key
	 * @param ?callable(string $url, array<string> $headers, int $timeoutMs): array{status: int, headers: array<string, string>, body: string} $http the transport; null = curl or streams
	 * @param ?callable(string $kind, string $message, array<string, mixed> $extra): mixed $report the host's sender
	 * @param ?callable(string $line): mixed $log the host's log
	 * @param list<Platform> $platforms the platform modules loaded: the rules in their words are kept at the pull; anything else is
	 *     ignored, and the host's log names it
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
		protected array $platforms = [],
	)
	{
		$this->url = rtrim($url, '/');
		$this->http = $http === null ? null : Closure::fromCallable($http);
		$this->report = $report === null ? null : Closure::fromCallable($report);
		$this->log = $log === null ? null : Closure::fromCallable($log);
		foreach($platforms as $platform)
		{
			// a module named but not given (its word, say): its rules would be left out at the pull, and nothing else would tell
			if($platform instanceof Platform === false)
			{
				$this->log('platforms: ' . (is_string($platform) ? '"' . substr($platform, 0, 64) . '"' : get_debug_type($platform)) . ' is no platform module, ignored');
			}
		}
		$this->platforms = array_values(array_filter($platforms, static fn(mixed $platform): bool => $platform instanceof Platform));
	}
	
	public function store(): Store
	{
		return $this->store;
	}
	
	/**
	 * The platform modules this kernel reads — what the adapter hands Facts
	 * too, so that a request is read in the words its rules were kept in
	 *
	 * @return list<Platform>
	 */
	public function platforms(): array
	{
		return $this->platforms;
	}
	
	/**
	 * The request as this kernel reads it: never with fewer platform modules
	 * than it pulled for. Facts an adapter built without some of the
	 * kernel's — none given, or a module's word where the module was meant —
	 * are read with them too, else a rule kept for a module reads as
	 * unreadable and passes the request unreported; the host's log says so
	 * once per kernel
	 */
	protected function readable(
		Facts $facts,
	): Facts
	{
		$given = array_map(static fn(Platform $platform): string => $platform->name(), $facts->platforms);
		$missing = array_values(array_filter($this->platforms, static fn(Platform $platform): bool => in_array($platform->name(), $given, true) === false));
		if($missing === [])
		{
			return $facts;
		}
		if($this->misread === false)
		{
			$this->misread = true;
			$this->log('a request came without the platform modules ' . implode(',', array_map(static fn(Platform $platform): string => $platform->name(), $missing))
				. ', read with the kernel\'s: hand Facts Kernel::platforms()');
		}
		
		return $facts->withPlatforms([...$facts->platforms, ...$missing]);
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
			$facts = $this->readable($facts);
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
			[$subs, $unread] = self::subRequests($facts);
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
						// a sub-request (a batch's) reaches its route's handler as a request of its own; an answered hit wins
						$subHit = $hit !== null && $hit['resolved'] ? null : self::patched($rule, $sub);
						if($subHit !== null && ($hit === null || $subHit['resolved']))
						{
							$hit = $subHit;
						}
					}
					// sub-requests the kernel could not read may have reached it: held, never blocked, never passed in silence
					if($hit === null && self::reaches($rule, $facts, $unread))
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
	 * request is not signed in and the script it runs ends in none of the pass paths;
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
		// the script that runs: /xmlrpc.php/wp-login.php is xmlrpc.php, its PATH_INFO no pass
		$path = $facts->scriptPath();
		foreach((array)($threats['pass'] ?? []) as $pass)
		{
			if(str_ends_with($path, (string)$pass))
			{
				return null;
			}
		}
		
		return ['id' => Ruleset::THREAT_RULE, 'kind' => Ruleset::KIND_THREAT, 'mode' => (string)$threats['mode']];
	}
	
	/** a rule's predicate over the request: the fragment of the first of the field's subjects (Facts::subjects()) it matches, or null */
	protected function matched(
		array $rule,
		Facts $facts,
	): ?string
	{
		foreach($facts->subjects((string)$rule['field']) as $subject)
		{
			$matched = self::match($rule, $subject);
			if($matched !== null)
			{
				return $matched;
			}
		}
		
		return null;
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
			foreach(self::tallied($ruleset->rules, $this->readable($facts)) as $id => $counts)
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
	 * request counts once with its sub-requests (a batch's); sub-requests the
	 * kernel could not read match what they may have reached (reaches()),
	 * never as an entry
	 *
	 * @return array<int, array{entry: bool, match: bool, authed: bool}>
	 */
	public static function tallied(
		array $rules,
		Facts $facts,
	): array
	{
		$tally = [];
		[$subs, $unread] = self::subRequests($facts);
		$requests = [$facts, ...$subs];
		foreach($rules as $rule)
		{
			if(Ruleset::isVpatch($rule) === false)
			{
				continue;
			}
			$selecting = array_filter((array)($rule['conditions'] ?? []), static fn(mixed $entry): bool => Ruleset::selects((array)$entry, $facts->platforms));
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
			if($matched === null && self::reaches($rule, $facts, $unread))
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
	
	/**
	 * The requests inside this one that reach handlers of their own, as
	 * every platform module given reads them (a WordPress batch's), and the
	 * modules that could not read all of theirs
	 *
	 * @return array{list<Facts>, list<Platform>}
	 */
	public static function subRequests(
		Facts $facts,
	): array
	{
		$subs = [];
		$unread = [];
		foreach($facts->platforms as $platform)
		{
			[$found, $cut] = $platform->subRequests($facts);
			$subs = [...$subs, ...$found];
			if($cut)
			{
				$unread[] = $platform;
			}
		}
		
		return [$subs, $unread];
	}
	
	/**
	 * Whether sub-requests a module could not read (subRequests()) may have
	 * reached a vpatch — its own word, the one module that knows its handlers
	 *
	 * @param list<Platform> $unread
	 */
	public static function reaches(
		array $rule,
		Facts $facts,
		array $unread,
	): bool
	{
		foreach($unread as $platform)
		{
			if($platform->reaches($rule, $facts))
			{
				return true;
			}
		}
		
		return false;
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
				'matched' => self::shown($rule, $verdict->matched, $facts),
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
		if($this->store->once('rate:' . (int)$rule['id'] . ':' . hash('sha256', $key), max(1, $verdict->retryAfter)) === false)
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
			'matched' => self::shown($rule, $verdict->matched, $facts),
			'key' => (string)$rate['key'],
			'limit' => (int)$rate['limit'],
			'window' => $window,
			'count' => $verdict->count,
			'authed' => $facts->authed,
		]);
	}
	
	/**
	 * What a report says matched: the fragment, unless a secret could be
	 * it. Whoever serves the rules chooses what a rule reads, so a report is
	 * never how a request's secrets leave the site: a vpatch reading any
	 * cookie, a header or a parameter named like a secret, or a parameter by
	 * a wildcard name shows nothing; nor does a uri rule on a request whose
	 * query holds a secret-named parameter, nor a body rule on a body that
	 * holds one or that is read only raw. A name test alone would not do:
	 * a pattern cut to `wd=` reads the password behind `pwd=` all the same.
	 * The rule matched either way — only the report says less
	 */
	public static function shown(
		array $rule,
		string $matched,
		Facts $facts,
	): string
	{
		if($matched === '')
		{
			return '';
		}
		if(Ruleset::isVpatch($rule))
		{
			foreach((array)($rule['conditions'] ?? []) as $entry)
			{
				$members = is_array($entry) && isset($entry[Ruleset::GROUP_ANY]) ? (array)$entry[Ruleset::GROUP_ANY] : [$entry];
				foreach($members as $member)
				{
					if(is_array($member) && self::secretTarget((string)($member['target'] ?? '')))
					{
						return '';
					}
				}
			}
			
			return $matched;
		}
		
		return match((string)($rule['field'] ?? ''))
		{
			Ruleset::FIELD_URI => self::holdsSecret($facts->query) ? '' : $matched,
			Ruleset::FIELD_BODY => self::bodyShown($facts) ? $matched : '',
			default => $matched,
		};
	}
	
	/** whether a target reads a secret's value: any cookie, a header or a parameter named like a secret, a parameter by a wildcard name */
	public static function secretTarget(
		string $target,
	): bool
	{
		$at = strpos($target, ':');
		if($at === false)
		{
			return false;
		}
		$name = substr($target, $at + 1);
		
		return match(substr($target, 0, $at))
		{
			'cookie' => true,
			'header' => self::secretName($name),
			'query', 'body', 'request', 'json', 'file' => str_contains($name, '*') || self::secretName($name),
			default => false,
		};
	}
	
	/** whether a name, or one segment of it (`opts[api_key]`, `account.password`), is a secret's */
	public static function secretName(
		string $name,
	): bool
	{
		foreach([$name, ...preg_split('~[\[\].]+~', $name)] as $segment)
		{
			if(preg_match(self::SECRET_NAME, trim($segment)) === 1)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/** whether a parsed bag holds a secret-named field at any depth; past SECRET_DEPTH a nested array is assumed to */
	protected static function holdsSecret(
		mixed $bag,
		int $depth = 0,
	): bool
	{
		if(is_array($bag) === false)
		{
			return false;
		}
		if($depth > self::SECRET_DEPTH)
		{
			return true;
		}
		foreach($bag as $name => $value)
		{
			if((is_string($name) && self::secretName($name)) || self::holdsSecret($value, $depth + 1))
			{
				return true;
			}
		}
		
		return false;
	}
	
	/** whether a body rule's fragment may be shown: a form or a JSON document without a secret-named field, never a body read only raw */
	protected static function bodyShown(
		Facts $facts,
	): bool
	{
		if($facts->form !== [])
		{
			return self::holdsSecret($facts->form) === false;
		}
		$json = $facts->json();
		
		return is_array($json) && self::holdsSecret($json) === false;
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
		$platforms = implode(',', [self::PLATFORM_CORE, ...array_map(static fn(Platform $platform): string => $platform->name(), $this->platforms)]);
		$headers = ['X-Codesafe-Key: ' . $this->key, 'X-Console-Key: ' . $this->key, 'Accept: application/json',
			self::HEADER_KINDS . ': ' . self::KINDS, self::HEADER_PLATFORMS . ': ' . $platforms];
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
		// far past what RULES_MAX, VPATCHES_MAX and THREATS_MAX hold: a larger answer is no door's, and is never decoded
		if(strlen((string)($response['body'] ?? '')) > self::BODY_MAX)
		{
			$this->log('pull answered more than ' . self::BODY_MAX . ' bytes');
			
			return self::PULL_FAILED;
		}
		$payload = json_decode((string)($response['body'] ?? ''), true);
		if(is_array($payload) === false)
		{
			$this->log('pull answered no JSON');
			
			return self::PULL_FAILED;
		}
		$ruleset = Ruleset::fromPayload($payload, $now, self::header($response, 'X-Shield-Sha256'),
			self::header($response, self::HEADER_VERSION), $this->platforms);
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
	 * lacks every capability; a signed-in one asks Facts::can(). A json:
	 * condition over a body past Facts::JSON_CAP is answered as holding once
	 * an entry that held answered pins the handler (pins()): the app decodes
	 * the body whole, and padding must not turn a block into an observe
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
		// whether an entry the kernel read pins the handler, and whether a JSON body it did not read waits on that
		$pinned = false;
		$unread = false;
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
			if($hit['unread'] ?? false)
			{
				$unread = true;
			}
			else
			{
				$resolved = $resolved && $hit['resolved'];
			}
			$pinned = $pinned || ($hit['resolved'] && self::pins((array)$entry, $facts->platforms));
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
		
		return ['matched' => $matched !== '' ? $matched : $framed, 'resolved' => $resolved && ($unread === false || $pinned)];
	}
	
	/**
	 * Whether an entry pins the handler a request reaches: it selects
	 * (Ruleset::selects()) and none of its members reads the method, which
	 * every handler shares. A json: member pins only where the body was
	 * read, as patched() asks of an entry that held answered
	 *
	 * @param list<Platform> $platforms
	 */
	protected static function pins(
		array $entry,
		array $platforms,
	): bool
	{
		if(Ruleset::selects($entry, $platforms) === false)
		{
			return false;
		}
		foreach(isset($entry[Ruleset::GROUP_ANY]) ? (array)$entry[Ruleset::GROUP_ANY] : [$entry] as $member)
		{
			if((((array)$member)['target'] ?? '') === 'method')
			{
				return false;
			}
		}
		
		return true;
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
				$hit['frame'] = Ruleset::isFrame((string)($member['target'] ?? ''), $facts->platforms);
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
	 * unanswered and says so (`unread`), for patched() to answer
	 *
	 * @return ?array{matched: string, resolved: bool, unread?: true}
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
			return ['matched' => '', 'resolved' => false, 'unread' => true];
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
				[$decodedValues, $cut] = self::decoded($value, (array)($condition['decode'] ?? []), $facts->platforms);
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
			[$decodedValues, $cut] = self::decoded($value, (array)($condition['decode'] ?? []), $facts->platforms);
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
	 * A target's values over the request; over a sub-request (a batch's) its
	 * own, then its batch's: the handler reads the superglobals too, which
	 * stay the batch's — never the batch's JSON, which is the batch itself,
	 * and an upload's bytes contents() reads both of. A module's target is
	 * the module's to read, and none for a target no module given names
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
			// a script reached with PATH_INFO behind it is that script too
			return array_values(array_unique([$facts->path(), $facts->scriptPath()]));
		}
		$platform = Ruleset::targetOf($target, $facts->platforms);
		if($platform !== null)
		{
			return $platform->values($target, $facts);
		}
		[$prefix, $name] = explode(':', $target, 2) + [1 => ''];
		// Facts::$headers is keyed by lowercase name
		$header = strtolower($name);
		
		$values = match($prefix)
		{
			'query' => self::pick($facts->query, $name),
			'request' => self::requested($facts, $name),
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
	 * A request: target's own values: the query's and the form's, then what
	 * the host's request bag (Facts::$request) holds beside them — PHP's
	 * $_REQUEST takes the cookies in where request_order leaves them in, a
	 * cookie overriding the query's value there. A union, never the bag
	 * alone: WordPress rebuilds $_REQUEST from the query and the form after
	 * plugins_loaded, and its handlers read that one
	 *
	 * @return list<string>
	 */
	protected static function requested(
		Facts $facts,
		string $name,
	): array
	{
		$sent = [...self::pick($facts->query, $name), ...self::pick($facts->form, $name)];
		if($facts->request === null)
		{
			return $sent;
		}
		
		return [...$sent, ...array_values(array_diff(self::pick($facts->request, $name), $sent))];
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
	 * @param list<Platform> $platforms the modules whose steps are read
	 * @return array{list<string>, bool}
	 */
	public static function decoded(
		string $value,
		array $steps,
		array $platforms = [],
	): array
	{
		$values = [$value];
		$cut = false;
		foreach($steps as $step)
		{
			$step = (string)$step;
			// the module that reads the step, found once for every value
			$platform = Ruleset::decoderOf($step, $platforms);
			$next = [];
			foreach($values as $one)
			{
				[$out, $short] = self::step($step, $one, $platform);
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
	 * cannot read the value — and whether it read only part of it (a
	 * module's step past its own bounds). A step none of the core's is the
	 * module's that decodes it; one no module given reads yields nothing
	 *
	 * @return array{list<string>, bool}
	 */
	protected static function step(
		string $step,
		string $value,
		?Platform $platform = null,
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
		
		return $platform === null ? [[], false] : $platform->decode($step, $value);
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
				// a redirect is answered, never followed: the key header would go to wherever it points
				'follow_location' => 0,
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
