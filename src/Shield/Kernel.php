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
 * runs on the file alone; the record is sealed under a key derived from the
 * project key (Kernel::sealKey()), so what another writer of the file or
 * the pool puts there is no record, and a layer that holds the seal key
 * alone reads the store without the key that opens the door). It
 * does three things: pull() — a conditional GET
 * of the project's live rules under the store's lock, on the host's tick,
 * every INTERVAL seconds, a 304 costs nothing, a failure leaves the cache
 * alone; judge() — pure over the cached ruleset, returns pass | observe |
 * block and never a response; report() — hands the match to a callable the
 * adapter supplied (the host's sender) as a `shield_observe` /
 * `shield_block` security event, `matched` capped at 200 bytes.
 *
 * Fails open on everything: a missing store, a stored record not sealed
 * under the seal key or pulled by another kernel (read as a missing store;
 * the next pull puts a sealed unusable record in its place until the door
 * answers), an unknown contract, a rule the engine cannot run, a thrown
 * anything — the request passes. A
 * missing store also forces the very next pull. A ruleset older than CEILING (24 h,
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
 * `u` — the two semantics codesafe's conformance corpus pins. A pulled
 * regex is held to the dialect's gate first (RegexGate): a rule whose
 * pattern it refuses never enters the ruleset, whoever served it.
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
 * tail when a condition names its contents; a form PHP left out of $_POST
 * on PUT, PATCH or DELETE the kernel parses as WordPress's REST server
 * does, Facts::formReader()). `who` is anyone,
 * anonymous or lacks:<capability>, and a nonce test asks the platform: a
 * blocking vpatch whose who or nonce the adapter cannot answer, or that
 * reads what the kernel could not (an upload; a JSON body past
 * Facts::JSON_CAP or a decode step's values past Facts::DECODED_BUDGET on a
 * handler none of its other entries pins; a WordPress batch whose body it
 * could not read), is held with the reason `unanswered`
 * (Verdict::REASON_UNANSWERED), never blocked. On the handler its other
 * entries pin, what the kernel did not read whole is taken to carry what the
 * condition looks for, and the verdict says `unread` (Verdict::REASON_UNREAD):
 * the app reads it whole, padding must never turn a block into an observe,
 * and an honest heavy save refused there is reported as not read, never as
 * an exploit. A WordPress batch of more requests than the kernel reads
 * (Wordpress::BATCH_MAX) is taken to reach the REST handler a vpatch's `rest`
 * entry names, for the caller `who` names: WordPress refuses a batch past
 * its own count regardless.
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
use function array_merge;
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
use function filter_var;
use function fopen;
use function fstat;
use function function_exists;
use function fwrite;
use function get_debug_type;
use function hash;
use function hash_equals;
use function hash_hmac;
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
use function min;
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
use function sort;
use function sprintf;
use function str_contains;
use function str_ends_with;
use function str_ireplace;
use function str_repeat;
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
use function strtr;
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
use const PHP_INT_MAX;

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
	
	/**
	 * whether the requests inside this one run past the count the kernel reads,
	 * which the platform itself refuses to run: a vpatch they may reach fails
	 * closed, where a body the kernel could not read only holds unanswered
	 */
	public function overflows(
		Facts $facts,
	): bool;
	
	/** whether its app reads a body of this content type as JSON where the core does not */
	public function jsonType(
		string $contentType,
	): bool;
	
	/**
	 * The method its app runs the request as, where that differs from the
	 * one sent (WordPress's REST method override); null = the one sent
	 */
	public function appMethod(
		Facts $facts,
	): ?string;
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
	
	/**
	 * a form body the kernel parses itself (formReader(): PUT, PATCH, DELETE)
	 * is parsed up to this and cut at the last whole pair; the app parses it
	 * whole, so what lies past holds as a JSON body past JSON_CAP does
	 * (formUnread(), Kernel::condition())
	 */
	public const FORM_CAP = 1048576;
	
	/** an upload is read as its first FILE_HEAD bytes and its last FILE_TAIL, one value: a payload hides at either end */
	public const FILE_HEAD = 65536;
	
	public const FILE_TAIL = 4096;
	
	protected ?string $body = null;
	
	protected bool $bodyRead = false;
	
	protected bool $bodyCapped = false;
	
	protected mixed $json = null;
	
	protected bool $jsonRead = false;
	
	protected bool $jsonUnread = false;
	
	/** @var ?array<string, mixed> the form the kernel parsed itself (form()), once a rule asked */
	protected ?array $formParsed = null;
	
	/** whether the form the kernel parsed itself ran past FORM_CAP: what lies past is unread */
	protected bool $formCut = false;
	
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
	 * the decoded values a request's conditions test at most, every condition
	 * of every rule together, judge and tally alike (Kernel::condition()): a
	 * literal test costs about a microsecond per value whatever its bytes, so
	 * the budget bounds a request at under 200 ms whatever the rule count
	 * (half of it measured at 50 ms for `contains`, 68 ms a regex, 88 ms
	 * `has_markup`), and a 30000-leaf page-builder save passes four blocking
	 * decode-bearing vpatches at one handler; past it a decode-bearing
	 * condition is cut (Kernel::patched())
	 */
	public const DECODED_BUDGET = 131072;
	
	/** what a value the host's filter judges (unsafe_html) costs the budget: wp_kses_post() takes 2 to 33 µs where a literal test takes one */
	public const HOST_TEST_WEIGHT = 32;
	
	/** the budget spent so far (spend()); a sub-request's and a copy's is its request's */
	protected int $spent = 0;
	
	/** @var array<string, mixed> what was computed once for this request (kept()): what judge() read, tally() reads again for free */
	protected array $kept = [];
	
	/** the request whose budget and decoded values this one shares — the batch a sub-request came in, the request a copy was made of; null for a request of its own */
	protected ?Facts $root = null;
	
	/**
	 * @param array<string, mixed> $query the query as the platform parsed it ($_GET)
	 * @param array<string, mixed> $form the form fields as the platform parsed them ($_POST); form() is what a rule reads
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
	 * @param ?Closure(): array{array<string, mixed>, bool} $formReader the form a rule reads where the platform parsed none
	 *     (formReader()), and whether it ran past FORM_CAP; null = $form is the form
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
		protected ?Closure $formReader = null,
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
		// a batch's thousand sub-requests spend their request's one budget
		$sub->root = $this->root ?? $this;
		
		return $sub;
	}
	
	/**
	 * This request read with other platform modules — a kernel's, when the
	 * adapter handed Facts fewer (Kernel::judge(), tally()). Every read goes
	 * through this request, so its body, uploads and the host's answers are
	 * read once whichever asks, and what a report says of the body holds for
	 * both. A JSON body is decoded anew only by fromServer()'s reader, off the
	 * input's one read, and then takes the modules' JSON types too; a reader
	 * the adapter built stays its own. One copy per module set: judge() and
	 * tally() read the same one, so what the first read the second has; a
	 * form the kernel parses itself is parsed once, through this request
	 *
	 * @param list<Platform> $platforms
	 */
	public function withPlatforms(
		array $platforms,
	): self
	{
		$names = implode(',', array_map(static fn(mixed $platform): string => $platform instanceof Platform ? $platform->name() : '', $platforms));
		
		return $this->kept('with:' . $names, function() use ($platforms): self
		{
			$copy = new self($this->method, $this->uri, $this->ua, $this->ip, $this->authed, fn(): array => [$this->body(), $this->bodyWasCapped()], $this->user,
				$this->query, $this->form, $this->cookies, $this->headers, $this->files, $this->jsonFor === null ? $this->jsonThrough(...) : ($this->jsonFor)($platforms),
				fn(string $capability): ?bool => $this->can($capability), fn(string $action, string $value): ?bool => $this->nonceValid($action, $value),
				$this->callerKnown, fn(string $value): ?bool => $this->htmlUnsafe($value), $this->uploads, fn(string $path): ?string => $this->fileContent($path),
				$platforms, $this->options, $this->request, $this->formReader === null ? null : fn(): array => [$this->form(), $this->formUnread()]);
			$copy->outer = $this->outer;
			$copy->jsonFor = $this->jsonFor;
			$copy->root = $this->root ?? $this;
			
			return $copy;
		});
	}
	
	/**
	 * Whether the request's budget still covers a test of this cost, which is
	 * spent: false past DECODED_BUDGET, where the rest goes unread
	 */
	public function spend(
		int $cost = 1,
	): bool
	{
		$root = $this->root ?? $this;
		$root->spent+= $cost;
		
		return $root->spent <= self::DECODED_BUDGET;
	}
	
	/** the budget left: what a decode step need still build */
	public function remaining(): int
	{
		return max(0, self::DECODED_BUDGET - ($this->root ?? $this)->spent);
	}
	
	/** what was computed once for this request under a key: what judge() read, tally() reads again for free */
	public function kept(
		string $key,
		Closure $compute,
	): mixed
	{
		if(array_key_exists($key, $this->kept) === false)
		{
			$this->kept[$key] = $compute();
		}
		
		return $this->kept[$key];
	}
	
	/** the same, shared with the request this one derives from (its batch, the request it copies): a value decoded once whichever reads it */
	public function keptShared(
		string $key,
		Closure $compute,
	): mixed
	{
		return ($this->root ?? $this)->kept($key, $compute);
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
		$method = is_string($server['REQUEST_METHOD'] ?? null) ? $server['REQUEST_METHOD'] : 'GET';
		if($get === null)
		{
			// the RAW query, as PHP would have parsed it — the URI is decoded once below
			parse_str(explode('?', $uri, 2)[1] ?? '', $get);
		}
		$contentType = is_string($server['CONTENT_TYPE'] ?? null) ? $server['CONTENT_TYPE'] : '';
		// the body's reader, the JSON readers and every copy's share one read: an input that cannot be rewound hands a second read nothing
		$input = $input === null ? null : self::readOnce($input);
		// a form PHP left out of $_POST (PUT, PATCH, DELETE) is the kernel's to parse, as the app parses it, once a rule asks
		$formReader = self::formReader($contentType, $post, $input);
		
		$facts = new self(
			$method,
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
			$formReader,
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
		// a byte past the largest cap: every reader still sees the body run past its own
		$keep = max(self::BODY_CAP, self::JSON_CAP, self::FORM_CAP) + 1;
		
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
	 * The form a rule reads where PHP parsed none: PHP fills $_POST on POST
	 * alone, and WordPress's REST server parses the raw input itself on PUT,
	 * PATCH and DELETE (WP_REST_Request::parse_body_params()) when the
	 * Content-Type is application/x-www-form-urlencoded or names no type at
	 * all — none, or one without a slash — never multipart or any other
	 * type, and never a GET's body. The same here, with parse_str: the body
	 * up to $cap, cut at the last whole pair so no value is read in part, the
	 * host's fields over the parsed ones as WordPress merges them. The type
	 * is decided here, the method by form() — the one the app runs the
	 * request as (appMethod()), known once the modules read it — and the
	 * parse runs there, lazily: nothing until a rule asks
	 *
	 * @return ?Closure(): array{array<string, mixed>, bool} the form and whether the body ran past the cap; null = no form body to parse
	 */
	public static function formReader(
		string $contentType,
		array $post,
		?callable $input,
		int $cap = self::FORM_CAP,
	): ?Closure
	{
		$type = strtolower(trim(explode(';', $contentType, 2)[0]));
		if($input === null || ($type !== 'application/x-www-form-urlencoded' && str_contains($type, '/')))
		{
			return null;
		}
		
		return static function() use ($post, $input, $cap): array
		{
			$raw = $input();
			$raw = is_string($raw) ? $raw : '';
			$cut = strlen($raw) > $cap;
			if($cut)
			{
				// the pair the cap falls in goes whole: a value read in part would answer for one never sent
				$raw = substr($raw, 0, (int)strrpos(substr($raw, 0, $cap), '&'));
			}
			// past max_input_vars PHP keeps the first pairs and warns, for WordPress's parse_str as for this one: the same fields, the warning spared
			@parse_str($raw, $fields);
			
			return [array_merge($fields, $post), $cut];
		};
	}
	
	/** whether a form body on this method is the kernel's to parse (formReader()): PUT, PATCH and DELETE, where PHP fills no $_POST and WordPress parses the input itself */
	public static function formMethod(
		string $method,
	): bool
	{
		return in_array(strtoupper($method), ['PUT', 'PATCH', 'DELETE'], true);
	}
	
	/** whether a body of this content type is a form to a rule: its fields flattened, never the raw bytes */
	public static function formType(
		string $contentType,
	): bool
	{
		$type = strtolower(trim(explode(';', $contentType, 2)[0]));
		
		return $type === 'application/x-www-form-urlencoded' || $type === 'multipart/form-data';
	}
	
	/**
	 * What the body IS to a rule: for a form (urlencoded, multipart) the
	 * parsed fields flattened to `name=value` lines — PHP has parsed them and
	 * multipart's raw stream is gone by then; a form the kernel parses itself
	 * body() flattens off form() instead; for JSON, XML and anything else the
	 * raw input, capped at BODY_CAP, decoded once like the URI. Read lazily:
	 * nothing is touched until a body rule asks
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
		if(self::formType($contentType))
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
			try
			{
				// a form the kernel may parse itself is the body too, flattened off the one parse, cut where that was
				if($this->formReader !== null && self::formType((string)($this->headers['content-type'] ?? '')))
				{
					[$this->body, $this->bodyCapped] = [self::flatten($this->form()), $this->formUnread()];
				}
				elseif($this->bodyReader !== null)
				{
					[$this->body, $this->bodyCapped] = ($this->bodyReader)();
				}
			}
			catch(Throwable)
			{
				$this->body = null;
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
	
	/**
	 * The method the app runs the request as: the one sent ($method) unless
	 * a platform module names another (Platform::appMethod() — WordPress's
	 * REST override), upper-cased; what the `method` target reads and a form
	 * body is parsed for (form()). Asked once per request; a copy read with
	 * other modules asks its own
	 */
	public function appMethod(): string
	{
		return $this->kept('appMethod', function(): string
		{
			foreach($this->platforms as $platform)
			{
				$named = $platform->appMethod($this);
				if(is_string($named) && $named !== '')
				{
					return strtoupper($named);
				}
			}
			
			return strtoupper($this->method);
		});
	}
	
	/**
	 * The form a rule reads: the host's parsed fields ($form), or where the
	 * host parsed none the body the kernel parses itself (formReader()) for
	 * the method the app runs the request as (formMethod()), once when first
	 * asked
	 */
	public function form(): array
	{
		if($this->formReader === null || self::formMethod($this->appMethod()) === false)
		{
			return $this->form;
		}
		if($this->formParsed === null)
		{
			try
			{
				[$this->formParsed, $this->formCut] = ($this->formReader)();
			}
			catch(Throwable)
			{
				// an input that cannot be read leaves the host's fields
				$this->formParsed = $this->form;
			}
		}
		
		return $this->formParsed;
	}
	
	/** whether the form the kernel parsed itself ran past FORM_CAP: what its body: conditions ask of the rest is not known */
	public function formUnread(): bool
	{
		$this->form();
		
		return $this->formCut;
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
	 * A verdict decided on what the kernel did not read whole — a JSON body
	 * past Facts::JSON_CAP, a decode step's values past Facts::DECODED_BUDGET,
	 * a batch past the count it reads — on the handler the rule pins: a padded
	 * exploit, or an honest heavy save at a patched handler, which codesafe
	 * must not read as an exploit (the report says so)
	 */
	public const REASON_UNREAD = 'unread';
	
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
	
	/**
	 * the values one condition's decode steps yield that are built at most;
	 * the request's budget for every condition together is Facts::DECODED_BUDGET,
	 * twice this: a literal test costs about a microsecond per value
	 * whatever its bytes, a host's filter 2 to 33 µs, so the counts bound the
	 * CPU, and the largest page-builder save yields a fraction of them; past
	 * them the condition holds as a JSON body past Facts::JSON_CAP does
	 * (Kernel::patched())
	 */
	public const DECODED_MAX = 65536;
	
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
	 * @param list<string> $platforms the names of the platform modules the ruleset was pulled with: sealed into the record, and a
	 *   kernel reads back only a record pulled with its own (fromRecord())
	 */
	public function __construct(
		public readonly array $rules,
		public readonly string $digest,
		public readonly int $fetchedAt,
		public readonly bool $usable,
		public readonly string $project = '',
		public readonly string $version = '',
		public readonly ?array $threats = null,
		public readonly array $platforms = [],
	)
	{
	}
	
	/**
	 * What takes a refused record's place in the store (Kernel::pull()):
	 * unusable, without a digest, fetched now — so the interval and the lock
	 * apply until the door answers, and every request passes with
	 * `refused store` (isRefused())
	 *
	 * @param list<string> $platforms
	 */
	public static function refused(
		int $now,
		array $platforms,
	): self
	{
		return new self([], '', $now, false, '', '', null, $platforms);
	}
	
	/** the stand-in for a refused record: the one unusable ruleset without a digest, so no 304 is asked for it or renews it */
	public function isRefused(): bool
	{
		return $this->usable === false && $this->digest === '';
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
		// the store keeps only these: fromRecord() checks the seal, not the rules, and a malformed rate rule would throw in judge() on every request (the Node twin checks on read)
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
			self::isVersion($version) ? $version : '', $usable ? self::threats($payload['threats'] ?? null) : null,
			// an entry that is no module names nothing, as it keeps no rule (targetOf())
			array_values(array_map(static fn(Platform $platform): string => $platform->name(),
				array_filter($platforms, static fn(mixed $platform): bool => $platform instanceof Platform))));
	}
	
	/**
	 * The stored record back into a ruleset; null when the record is not
	 * one, is not sealed under this key (seal()) — planted by another
	 * writer of the store, changed after the write, an earlier kernel's —
	 * or was pulled by another kernel: of another contract or dialect, or
	 * with other platform modules than $platforms names, whose rules this
	 * kernel would have kept differently. Null also for an empty key: a
	 * kernel without one reads no store. Read as no store, so the request
	 * passes and the next pull asks for the whole ruleset, never with the
	 * record's digest
	 *
	 * @param list<string> $platforms the names of the kernel's platform modules
	 */
	public static function fromRecord(
		mixed $record,
		string $key,
		array $platforms = [],
	): ?self
	{
		if($key === '' || is_array($record) === false || is_array($record['rules'] ?? null) === false || is_int($record['fetched_at'] ?? null) === false
			|| is_string($record['seal'] ?? null) === false || hash_equals(self::seal($record, $key), $record['seal']) === false)
		{
			return null;
		}
		// the writing kernel's own contract, dialect and modules, so a record it derived under other rules never comes back as this kernel's
		$pulledWith = $record['platforms'] ?? null;
		if(($record['contract'] ?? null) !== self::CONTRACT || ($record['dialect'] ?? null) !== self::DIALECT || is_array($pulledWith) === false)
		{
			return null;
		}
		sort($pulledWith);
		sort($platforms);
		if(array_values($pulledWith) !== array_values($platforms))
		{
			return null;
		}
		
		return new self(
			$record['rules'],
			is_string($record['sha256'] ?? null) ? $record['sha256'] : '',
			// a fetched_at ahead of the clock (the clock ran ahead at the write) reads as now: the pull would skip the record for as long as it lies ahead, and the ceiling would never lift it
			min($record['fetched_at'], time()),
			($record['usable'] ?? false) === true,
			is_string($record['project'] ?? null) ? $record['project'] : '',
			is_string($record['version'] ?? null) && self::isVersion($record['version']) ? $record['version'] : '',
			// stored as checked (a lookup map): read per request, never checked again
			is_array($record['threats']['addresses'] ?? null) ? $record['threats'] : null,
			$record['platforms'],
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
	
	/** what the store keeps — JSON, never PHP — sealed under the project key (seal()) */
	public function toRecord(
		string $key,
	): array
	{
		$record = [
			'contract' => self::CONTRACT,
			'dialect' => self::DIALECT,
			'project' => $this->project,
			'fetched_at' => $this->fetchedAt,
			'sha256' => $this->digest,
			'version' => $this->version,
			'platforms' => $this->platforms,
			'threats' => $this->threats,
			'usable' => $this->usable,
			'rules' => $this->rules,
		];
		$record['seal'] = self::seal($record, $key);
		
		return $record;
	}
	
	/**
	 * A record's seal: an HMAC-SHA256 under the project key over every other
	 * field as the store's JSON. The store — a file, an APCu pool — can be
	 * written by more than this kernel, and the key is the one secret such
	 * a writer lacks: only a record a holder of the key wrote, and nobody
	 * changed since, is read back (fromRecord()). The bytes are this
	 * kernel's own encoding, so the check is exact wherever the record was
	 * kept
	 */
	public static function seal(
		array $record,
		string $key,
	): string
	{
		unset($record['seal']);
		
		return hash_hmac('sha256', (string)json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), $key);
	}
	
	/** renewed by a 304 — with the version it said, when it said one */
	public function withFetchedAt(
		int $fetchedAt,
		string $version = '',
	): self
	{
		return new self($this->rules, $this->digest, $fetchedAt, $this->usable, $this->project,
			self::isVersion($version) ? $version : $this->version, $this->threats, $this->platforms);
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
			&& (self::isRate($rule) === false || self::rateWellFormed($rule['rate'] ?? null))
			// a pattern the dialect's gate refuses never reaches the engine, whoever served it
			&& ($rule['op'] !== self::OP_REGEX || RegexGate::refusal($rule['value'], ($rule['ci'] ?? true) === true) === null);
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
		
		if(is_string($value) === false || trim($value) === '' || strlen($value) > self::VALUE_MAX)
		{
			return false;
		}
		
		// a pattern the dialect's gate refuses never reaches the engine, whoever served it
		return ($test !== 'regex' && $test !== 'not_regex') || RegexGate::refusal($value, ($condition['ci'] ?? true) === true) === null;
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
 * The regex gate of the rule dialect: the RE2-safe subset both engines read
 * alike, and nothing a backtracking engine runs in more than polynomial
 * time: no nested quantifier, no alternation inside a repeated group, at
 * most UNBOUNDED_MAX unbounded quantifiers, none that overlap. codesafe's
 * gate (Codesafe\Shield\Dialect::checkRegex()) answers with this class, and
 * a kernel holds every pulled regex to it (Ruleset::wellFormed(),
 * Ruleset::conditionWellFormed()), so a pattern an outdated, mistaken or
 * hostile codesafe serves never runs here: in PHP it fails open at
 * pcre.backtrack_limit, and in the Node twin (client-node/shield.mjs) it
 * would hold the event loop. Pure; asked at a pull, never per request
 */
final class RegexGate
{
	/**
	 * Unbounded quantifiers (`*`, `+`, `{n,}`) one regex may carry. Each
	 * one beside another that can match the same text multiplies the work a
	 * backtracking engine does on a near-miss: `.*.*.*.*.*.*.*.*z` is
	 * O(n^8), and V8 has no backtracking limit to stop it. Two keep the
	 * shapes the catalog uses (`\bon\w+\s*=`, a `\s*` either side of an
	 * optional slash) at O(n^2) at worst
	 */
	public const UNBOUNDED_MAX = 2;
	
	/**
	 * A count `{n,m}` (lazy or not) with m at least this many is unbounded to
	 * the gate — in the UNBOUNDED_MAX count and in the overlap check alike:
	 * `\w{0,300}\w{0,300}\w{0,300}x` carries no `*` or `+` and backtracks as
	 * badly in V8. An exact `{n}` has no choice to backtrack over and stays
	 * bounded whatever its n
	 */
	public const LARGE_COUNT = 16;
	
	/**
	 * The most choices a run of overlapping small counts may multiply to:
	 * `\w{1,8}\w{1,8}` (64) and `\w{1,15}\w{1,15}` (225) pass, three
	 * `\w{1,8}` (512) do not
	 */
	public const BOUNDED_CHOICES_MAX = 256;
	
	/** a POSIX class's opening: read where the classes still stand, as it is a class's own spelling */
	protected const POSIX_CLASS = '~\[\[:~';

	/** a character class, read as one atom by the construct checks: `[*+]` and `[(?]` are sets of characters, no quantifier and no group */
	protected const CLASS_ATOM = '~\[\^?\]?[^\]]*\]~';

	/**
	 * What the regex gate refuses — on the pattern with every escaped pair
	 * replaced by a plain atom, so `\(?=` (a literal) is not read as a
	 * lookahead and `\s*` keeps its quantifier on something, and every class
	 * one atom more (CLASS_ATOM), the POSIX class aside — each with the
	 * words a log line and a redraft carry
	 */
	protected const REFUSED_CONSTRUCTS = [
		'~\(\?[=!]~' => 'lookahead',
		'~\(\?<[=!]~' => 'lookbehind',
		'~\(\?>~' => 'atomic group',
		'~\(\?[imsxUXJn^-]+[:)]~' => 'inline flag',
		'~\(\?P[<=>]~' => 'Python-style named group',
		'~\(\?\'~' => 'quoted named group',
		'~\(\?\|~' => 'branch reset',
		'~\(\?[R0-9&+-]~' => 'recursion or subroutine call',
		'~\(\?\(~' => 'conditional',
		'~\(\?#~' => 'comment',
		'~\(\*~' => 'verb',
		self::POSIX_CLASS => 'POSIX class',
		'~[*+?}]\+~' => 'possessive quantifier',
	];
	
	/**
	 * What the regex gate refuses among the escapes — on the pattern with its
	 * escaped BACKSLASHES removed, so `\\A` (a backslash then an A) passes.
	 * `\g` and `\k` go whole: any spelling PCRE takes is a backreference
	 * (`\g-1` too), and to V8 a plain letter
	 */
	protected const REFUSED_ESCAPES = [
		'~\\\\[1-9]~' => 'backreference',
		'~\\\\[gk]~' => 'backreference',
		'~\\\\[AzZGKhHRXCNaeEQpPo]~' => 'PCRE-only escape',
		'~\\\\[uU]~' => 'JavaScript-only escape',
		'~\\\\x\{~' => 'PCRE-only \x{…} escape',
		// PCRE reads `\x` before fewer than two hex digits as a byte, V8 as the letter x
		'~\\\\x(?![0-9a-fA-F]{2})~' => '\x without two hex digits',
		'~\\\\x[89a-fA-F][0-9a-fA-F]~' => 'non-ASCII byte escape',
		'~\\\\[vV]~' => '\v or \V escape (a class in PCRE, one byte or a letter in JavaScript)',
		'~\\\\c~' => 'control escape',
	];
	
	/**
	 * Null when a rule's regex is in the dialect, else the reason, in the words
	 * a log line and a redraft carry: the RE2-safe subset, nested quantifiers
	 * refused, it compiles here and the overlap walk reads it whole
	 */
	public static function refusal(
		string $value,
		bool $ci = true,
	): ?string
	{
		if($value === '' || strlen($value) > Ruleset::VALUE_MAX)
		{
			return $value === '' ? 'the pattern is empty' : 'the pattern is longer than ' . Ruleset::VALUE_MAX . ' bytes';
		}
		if(self::isAscii($value) === false)
		{
			return 'the pattern is not ASCII';
		}
		// every escaped pair as a plain atom: `\(` opens no group, `\*` is no quantifier
		$bare = (string)preg_replace('~\\\\.~s', 'a', $value);
		// and every class one more: `[*+]` holds no possessive quantifier, `[(?=]` no lookahead
		$atoms = (string)preg_replace(self::CLASS_ATOM, 'a', $bare);
		foreach(self::REFUSED_CONSTRUCTS as $pattern => $reason)
		{
			if(preg_match($pattern, $pattern === self::POSIX_CLASS ? $bare : $atoms) === 1)
			{
				return $reason . ' is not in the ' . Ruleset::DIALECT . ' dialect';
			}
		}
		// escaped backslashes dropped: `\\A` is a backslash and an A, not `\A`
		$escapes = strtr($value, ['\\\\' => '']);
		foreach(self::REFUSED_ESCAPES as $pattern => $reason)
		{
			if(preg_match($pattern, $escapes) === 1)
			{
				return $reason . ' is not in the ' . Ruleset::DIALECT . ' dialect';
			}
		}
		if(self::hasBracketLedClass($bare))
		{
			return 'a class that opens with `]` (`[]a]`, `[^]a]`) is a literal `]` to PCRE and an empty or any-byte class to JavaScript — write `\]`';
		}
		if(self::hasLooseCount($bare))
		{
			return 'a count only PCRE reads as one (`{,n}`, a blank inside the braces) is text to JavaScript — write `{0,n}`';
		}
		if(self::hasNestedQuantifier($bare))
		{
			return 'a nested quantifier is valid RE2 and catastrophic in a backtracking engine';
		}
		if(self::hasQuantifiedAlternation($bare))
		{
			return 'an alternation inside a repeated group (`(a|aa)+`) is valid RE2 and catastrophic in a backtracking engine — repeat a class instead';
		}
		if(self::unboundedQuantifiers($bare) > self::UNBOUNDED_MAX)
		{
			return 'more than ' . self::UNBOUNDED_MAX . ' unbounded quantifiers (`* + {n,}`, and a `{n,m}` with m of ' . self::LARGE_COUNT . ' or more) backtrack polynomially in a backtracking engine';
		}
		// on the value itself: the parser reads each escape as its byte set; null when it cannot read the pattern
		$overlapping = self::hasOverlappingQuantifiers($value, $ci);
		if($overlapping === true)
		{
			return 'quantifiers that can match the same character back to back (`.*.*`, `\w+\w+`, a run of `\w{1,8}` past ' . self::BOUNDED_CHOICES_MAX . ' choices) backtrack polynomially in a backtracking engine — make their sets disjoint or bound them';
		}
		// run on an empty subject: a pattern that does not compile is no rule
		if(self::compiles($value, $ci) === false)
		{
			return 'the pattern does not compile';
		}
		// compiled, yet unread by the walk: a group PCRE alone knows (`(?C)`, `(?*…)`, `(?a)`), a SyntaxError or another meaning in V8
		if($overlapping === null)
		{
			return 'a construct the gate cannot read is not in the ' . Ruleset::DIALECT . ' dialect — a group opens with `(`, `(?:` or `(?<name>`';
		}
		
		return null;
	}
	
	/** printable ASCII and the tab: no other control byte, nothing past 0x7E */
	public static function isAscii(
		string $value,
	): bool
	{
		return preg_match('~^[\x20-\x7e\t]*$~D', $value) === 1;
	}
	
	/**
	 * Whether PCRE compiles a rule's pattern as Kernel::match() runs it, on an
	 * empty subject: one it refuses warns (a host's error handler may throw
	 * that) and answers false
	 */
	protected static function compiles(
		string $value,
		bool $ci,
	): bool
	{
		try
		{
			return @preg_match(Kernel::regexPattern($value, $ci), '') !== false;
		}
		catch(Throwable)
		{
			return false;
		}
	}
	
	/**
	 * A quantified group whose body carries a quantifier of its own — on the
	 * pattern with escapes removed and character classes skipped. `(a+)+`,
	 * `(\w*)*`, `(?:x{0,5})+`, `(a?)+` are all refused: RE2 runs them in
	 * linear time, PCRE and JavaScript may not
	 */
	protected static function hasNestedQuantifier(
		string $bare,
	): bool
	{
		$stack = [];
		$n = strlen($bare);
		for($i = 0; $i < $n; $i++)
		{
			$char = $bare[$i];
			if($char === '[')
			{
				// a class is a literal set: skip to its close, honouring a
				// leading `]` or `^]`
				$j = $i + 1;
				if($j < $n && $bare[$j] === '^')
				{
					$j++;
				}
				if($j < $n && $bare[$j] === ']')
				{
					$j++;
				}
				while($j < $n && $bare[$j] !== ']')
				{
					$j++;
				}
				$i = $j;
				
				continue;
			}
			if($char === '(')
			{
				$stack[] = false;
				// the `?` of `(?:` and `(?<name>` is syntax, not a quantifier
				if(($bare[$i + 1] ?? '') === '?')
				{
					$i++;
				}
				
				continue;
			}
			if($char === ')')
			{
				// the group closes: quantified itself while carrying a quantifier is the nesting
				$quantifiedInside = array_pop($stack) ?? false;
				$next = $bare[$i + 1] ?? '';
				if($quantifiedInside && ($next === '*' || $next === '+' || $next === '{'))
				{
					return true;
				}
				// either way the enclosing group now carries a quantifier
				if($stack !== [] && ($quantifiedInside || $next === '*' || $next === '+' || $next === '{' || $next === '?'))
				{
					$stack[count($stack) - 1] = true;
				}
				
				continue;
			}
			if(($char === '*' || $char === '+' || $char === '?' || $char === '{') && $stack !== [])
			{
				$stack[count($stack) - 1] = true;
			}
		}
		
		return false;
	}
	
	/**
	 * A group holding an alternation — at its own depth or in a group inside
	 * it — repeated by `*`, `+` or `{…}`: `(a|a)*b`, `(a|aa)+$`, `(\w|\d)*x`,
	 * `((a|b)c)+`. Branches that can match the same text give a backtracking
	 * engine two ways through every repetition, 2^n on a near-miss. The rule
	 * is the simple safe one — it refuses the harmless `(?:a|b)+` too, which
	 * is `[ab]+`. `?` stays allowed here: one optional group cannot
	 * multiply, and a run of them is the overlap walk's (counted()). On the
	 * pattern with escapes removed and character classes skipped — a `|`
	 * inside `[…]` is a literal
	 */
	protected static function hasQuantifiedAlternation(
		string $bare,
	): bool
	{
		$stack = [];
		$n = strlen($bare);
		for($i = 0; $i < $n; $i++)
		{
			$char = $bare[$i];
			if($char === '[')
			{
				$i = self::classEnd($bare, $i);
				
				continue;
			}
			if($char === '(')
			{
				$stack[] = false;
				
				continue;
			}
			if($char === '|' && $stack !== [])
			{
				$stack[count($stack) - 1] = true;
				
				continue;
			}
			if($char === ')')
			{
				// a group holding an alternation trips when repeated, else passes it up to the group around it
				$alternates = array_pop($stack) ?? false;
				$next = $bare[$i + 1] ?? '';
				if($alternates && ($next === '*' || $next === '+' || $next === '{'))
				{
					return true;
				}
				if($alternates && $stack !== [])
				{
					$stack[count($stack) - 1] = true;
				}
			}
		}
		
		return false;
	}
	
	/**
	 * How many `*`, `+`, `{n,}` and large counts (`{n,m}` with m at least
	 * LARGE_COUNT) the pattern carries — on the pattern with escapes removed
	 * and character classes skipped. A lazy `*?` is one quantifier; the `?`
	 * of `(?:` is syntax; a small count or a `{` that opens no count is not
	 * counted
	 */
	protected static function unboundedQuantifiers(
		string $bare,
	): int
	{
		$count = 0;
		$n = strlen($bare);
		for($i = 0; $i < $n; $i++)
		{
			$char = $bare[$i];
			if($char === '[')
			{
				$i = self::classEnd($bare, $i);
				
				continue;
			}
			if($char === '*' || $char === '+')
			{
				$count++;
				
				continue;
			}
			// `{n,}` or `{n,m}` with a large m; an exact `{n}` (no comma) never counts
			if($char === '{' && preg_match('~\G\{\d+(,(\d*))?\}~', $bare, $match, 0, $i) === 1
				&& isset($match[1]) && self::isUnboundedMax(($match[2] ?? '') === '' ? null : (int)$match[2]))
			{
				$count++;
			}
		}
		
		return $count;
	}
	
	/**
	 * A `{…}` of digits, commas and blanks that PCRE reads as a count and
	 * JavaScript as the text it is: `{,5}`, `{ 2}`, `{2, 5}` — on the pattern
	 * with escapes removed and character classes skipped. The strict `{n}`,
	 * `{n,}` and `{n,m}` mean the same in both, braces without a digit
	 * (`{,}`) are text in both
	 */
	protected static function hasLooseCount(
		string $bare,
	): bool
	{
		$n = strlen($bare);
		for($i = 0; $i < $n; $i++)
		{
			if($bare[$i] === '[')
			{
				$i = self::classEnd($bare, $i);
				
				continue;
			}
			if($bare[$i] === '{' && preg_match('~\G\{[\d, \t]*\}~', $bare, $match, 0, $i) === 1
				&& preg_match('~\d~', $match[0]) === 1 && preg_match('~^\{\d+(,\d*)?\}$~D', $match[0]) !== 1)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * A class whose first member (after a `^`) is a bare `]`: `[]a]` is the
	 * class of `]` and `a` to PCRE, an empty class and the text `a]` to
	 * JavaScript, and `[^]a]` any byte there — on the pattern with escapes
	 * removed, so `[\]a]` passes, and with classes skipped, so the `[` of
	 * `[[]` opens nothing
	 */
	protected static function hasBracketLedClass(
		string $bare,
	): bool
	{
		$n = strlen($bare);
		for($i = 0; $i < $n; $i++)
		{
			if($bare[$i] !== '[')
			{
				continue;
			}
			$first = ($bare[$i + 1] ?? '') === '^' ? $i + 2 : $i + 1;
			if(($bare[$first] ?? '') === ']')
			{
				return true;
			}
			$i = self::classEnd($bare, $i);
		}
		
		return false;
	}
	
	/**
	 * The index of the `]` closing the class opened at $i, honouring a
	 * leading `]` or `^]` — the last index when the class never closes
	 */
	protected static function classEnd(
		string $bare,
		int $i,
	): int
	{
		$n = strlen($bare);
		$j = $i + 1;
		if($j < $n && $bare[$j] === '^')
		{
			$j++;
		}
		if($j < $n && $bare[$j] === ']')
		{
			$j++;
		}
		while($j < $n && $bare[$j] !== ']')
		{
			$j++;
		}
		
		return $j;
	}
	
	/**
	 * Two unbounded quantifiers (`*`, `+`, `{n,}`, or a count of LARGE_COUNT
	 * and more) that can match the same byte back to back — adjacent
	 * (`\w+\w+`, `.*.*`, `\d+\w*`), with only optional or zero-width parts
	 * between them (`\s*\/?\s*`, `\w+\b\w+`), or with a required part between
	 * them that the first can swallow too (`.*a.*`). Each is a second way to
	 * split the same run, and an unanchored exec in V8 pays for it
	 * cubically on a near-miss (`\w+\w+=` over a few KiB of word bytes).
	 * Disjoint neighbours (`\d+[a-z]+`, `[a-z]+=\d+`) cost nothing extra.
	 *
	 * Small counts chain the same way and multiply: the choices of the
	 * overlapping ones in a row (`\w{1,8}\w{1,8}` is 8 × 8) may not pass
	 * BOUNDED_CHOICES_MAX, or forty `\w{1,15}` in 600 bytes would be the
	 * same hang without a single large count.
	 *
	 * Conservative: a set the parser cannot read exactly is every byte, a
	 * repeated group is the union of everything inside it, `ci` folds the
	 * letters. A pattern the parser cannot follow at all answers null, never
	 * "no conflict": checkRegex() lets the compile check name a broken one
	 * and refuses one that compiles.
	 */
	protected static function hasOverlappingQuantifiers(
		string $value,
		bool $ci,
	): ?bool
	{
		$at = 0;
		$tree = self::parseAlternation($value, $at, $ci);
		if($tree === null || $at !== strlen($value))
		{
			return null;
		}
		
		$conflict = false;
		self::walkAlternation($tree, self::emptyChain(), $conflict);
		
		return $conflict;
	}
	
	/**
	 * What flows along a sequence: `open`, every byte an unbounded
	 * quantifier still in reach could swallow; `chain`, the bytes of the
	 * small counts in the current overlapping run, and `choices`, the
	 * product of their choices
	 *
	 * @return array{open: string, chain: string, choices: int}
	 */
	protected static function emptyChain(): array
	{
		return ['open' => str_repeat("\0", 256), 'chain' => str_repeat("\0", 256), 'choices' => 1];
	}
	
	/**
	 * Each branch from the same entry; the exit is the union of the
	 * branches' sets and the worst of their choices
	 *
	 * @param list<list<array>> $branches
	 * @param array{open: string, chain: string, choices: int} $state
	 * @return array{open: string, chain: string, choices: int}
	 */
	protected static function walkAlternation(
		array $branches,
		array $state,
		bool &$conflict,
	): array
	{
		$out = ['open' => str_repeat("\0", 256), 'chain' => str_repeat("\0", 256), 'choices' => 1];
		foreach($branches as $sequence)
		{
			$exit = self::walkSequence($sequence, $state, $conflict);
			$out['open'] |= $exit['open'];
			$out['chain'] |= $exit['chain'];
			$out['choices'] = max($out['choices'], $exit['choices']);
		}
		
		return $out;
	}
	
	/**
	 * An unbounded item meeting `open` is the conflict, and so is a run of
	 * overlapping small counts past BOUNDED_CHOICES_MAX. An optional or
	 * zero-width item leaves both runs open; a required item ends a run
	 * only when that run cannot swallow the item's bytes
	 *
	 * @param list<array> $sequence
	 * @param array{open: string, chain: string, choices: int} $state
	 * @return array{open: string, chain: string, choices: int}
	 */
	protected static function walkSequence(
		array $sequence,
		array $state,
		bool &$conflict,
	): array
	{
		foreach($sequence as $item)
		{
			if($item['type'] === 'zero')
			{
				continue;
			}
			
			// a group that runs once (or not at all) is followed inside
			if($item['type'] === 'group' && $item['max'] !== null && $item['max'] <= 1)
			{
				$inner = self::walkAlternation($item['branches'], $state, $conflict);
				if($item['min'] === 0 || $item['nullable'])
				{
					$inner['open'] |= $state['open'];
					$inner['chain'] |= $state['chain'];
					$inner['choices'] = max($inner['choices'], $state['choices']);
				}
				// and is a choice itself: one way per branch, one more when it may
				// be skipped — forty `(?:x)?` before a `y` are 2^40 ways on a near-miss
				$ways = count($item['branches']) + ($item['min'] === 0 ? 1 : 0);
				if($ways > 1)
				{
					$inner = self::counted($inner, $item['set'], $ways, $item['min'] > 0 && $item['nullable'] === false, $conflict);
				}
				$state = $inner;
				
				continue;
			}
			
			$set = $item['set'];
			$required = $item['min'] > 0 && $item['nullable'] === false;
			$overlapsOpen = self::intersects($state['open'], $set);
			
			if($item['max'] === null)
			{
				if($overlapsOpen)
				{
					$conflict = true;
				}
				// an optional one keeps the earlier runs in reach; a required one is the only run left
				$state['open'] = $item['min'] === 0 ? $state['open'] | $set : $set;
			}
			elseif($required && $overlapsOpen === false)
			{
				// a required byte the open run cannot swallow ends it
				$state['open'] = str_repeat("\0", 256);
			}
			
			// an unbounded one weighs LARGE_COUNT in the counts' run, so
			// `\w{1,15}\w{1,15}\w+` (225 × 16) is a conflict while `\w+\d{0,3}`
			// (16 × 4) is not — the two unbounded ones meeting each other are
			// `open`'s business
			$state = self::counted($state, $set, $item['max'] === null ? self::LARGE_COUNT : $item['max'] - $item['min'] + 1, $required, $conflict);
		}
		
		return $state;
	}
	
	/**
	 * The counts' run after one more item with $choices ways through it: an
	 * item with a choice multiplies the run it overlaps or starts one, past
	 * BOUNDED_CHOICES_MAX the conflict; a required item the run cannot
	 * swallow ends it
	 *
	 * @param array{open: string, chain: string, choices: int} $state
	 * @return array{open: string, chain: string, choices: int}
	 */
	protected static function counted(
		array $state,
		string $set,
		int $choices,
		bool $required,
		bool &$conflict,
	): array
	{
		$overlapsChain = self::intersects($state['chain'], $set);
		if($choices > 1)
		{
			if($overlapsChain)
			{
				$state['choices']*= $choices;
				$state['chain'] |= $set;
			}
			elseif($required)
			{
				$state['chain'] = $set;
				$state['choices'] = $choices;
			}
			else
			{
				$state['chain'] |= $set;
				$state['choices'] = max($state['choices'], $choices);
			}
			if($state['choices'] > self::BOUNDED_CHOICES_MAX)
			{
				$conflict = true;
			}
		}
		elseif($required && $overlapsChain === false)
		{
			$state['chain'] = str_repeat("\0", 256);
			$state['choices'] = 1;
		}
		
		return $state;
	}
	
	/** whether two byte sets (256 bytes of "\0" or "\1") share a byte */
	protected static function intersects(
		string $a,
		string $b,
	): bool
	{
		return str_contains($a & $b, "\1");
	}
	
	/**
	 * branches := sequence ('|' sequence)* — null when the pattern is not
	 * one this parser follows
	 *
	 * @return list<list<array>>|null
	 */
	protected static function parseAlternation(
		string $value,
		int &$at,
		bool $ci,
	): ?array
	{
		$branches = [];
		while(true)
		{
			$sequence = self::parseSequence($value, $at, $ci);
			if($sequence === null)
			{
				return null;
			}
			$branches[] = $sequence;
			if(($value[$at] ?? '') !== '|')
			{
				return $branches;
			}
			$at++;
		}
	}
	
	/**
	 * Items up to a `|`, a `)` or the end: each a byte set (or a group, or a
	 * zero-width assertion) with its quantifier's min and max (null = no max)
	 *
	 * @return list<array>|null
	 */
	protected static function parseSequence(
		string $value,
		int &$at,
		bool $ci,
	): ?array
	{
		$items = [];
		$n = strlen($value);
		while($at < $n && $value[$at] !== '|' && $value[$at] !== ')')
		{
			$char = $value[$at];
			if($char === '^' || $char === '$')
			{
				$items[] = ['type' => 'zero'];
				$at++;
				
				continue;
			}
			if($char === '(')
			{
				$at++;
				// only `(?:` and `(?<name>` are followed; any other `(?` construct is not
				if(($value[$at] ?? '') === '?')
				{
					if(($value[$at + 1] ?? '') === ':')
					{
						$at+= 2;
					}
					elseif(preg_match('~\G\?<[A-Za-z_]\w*>~', $value, $match, 0, $at) === 1)
					{
						$at+= strlen($match[0]);
					}
					else
					{
						return null;
					}
				}
				$branches = self::parseAlternation($value, $at, $ci);
				if($branches === null || ($value[$at] ?? '') !== ')')
				{
					return null;
				}
				$at++;
				$item = ['type' => 'group', 'branches' => $branches, 'set' => self::unionOf($branches), 'nullable' => self::nullableOf($branches)];
			}
			else
			{
				$set = self::parseAtom($value, $at, $ci);
				// `\b`, `\B`: zero-width, and no quantifier is read after them
				if($set === null)
				{
					$items[] = ['type' => 'zero'];
					
					continue;
				}
				$item = ['type' => 'set', 'set' => $set, 'nullable' => false];
			}
			
			[$min, $max] = self::parseQuantifier($value, $at);
			$item['min'] = $min;
			$item['max'] = $max;
			$item['nullable'] = $item['nullable'] || $min === 0;
			$items[] = $item;
		}
		
		return $items;
	}
	
	/**
	 * Whether a count's max makes it unbounded for the dialect's purposes:
	 * none at all, or LARGE_COUNT and above
	 */
	protected static function isUnboundedMax(
		?int $max,
	): bool
	{
		return $max === null || $max >= self::LARGE_COUNT;
	}
	
	/**
	 * `* + ? {n} {n,} {n,m}`, a lazy `?` after any of them; [1, 1] when
	 * none follows (a `{` that is no count is a literal, read as an atom)
	 *
	 * @return array{0: int, 1: int|null}
	 */
	protected static function parseQuantifier(
		string $value,
		int &$at,
	): array
	{
		$char = $value[$at] ?? '';
		$quantifier = match($char)
		{
			'*' => [0, null],
			'+' => [1, null],
			'?' => [0, 1],
			default => null,
		};
		if($quantifier !== null)
		{
			$at++;
		}
		elseif($char === '{' && preg_match('~\G\{(\d+)(,(\d*))?\}~', $value, $match, 0, $at) === 1)
		{
			$at+= strlen($match[0]);
			$min = (int)$match[1];
			$max = ($match[3] ?? '') === '' ? null : (int)$match[3];
			// a large count backtracks like an unbounded one: read as one
			$quantifier = isset($match[2]) === false
				? [$min, $min]
				: [$min, self::isUnboundedMax($max) ? null : $max];
		}
		else
		{
			return [1, 1];
		}
		if(($value[$at] ?? '') === '?')
		{
			$at++;
		}
		
		return $quantifier;
	}
	
	/**
	 * One atom's byte set: a literal, `.`, an escape or a class. Null for a
	 * zero-width escape (`\b`, `\B`)
	 */
	protected static function parseAtom(
		string $value,
		int &$at,
		bool $ci,
	): ?string
	{
		$char = $value[$at];
		if($char === '.')
		{
			$at++;
			// every byte but the newline: no `s` flag
			$set = str_repeat("\1", 256);
			$set[10] = "\0";
			
			return $set;
		}
		if($char === '[')
		{
			return self::fold(self::parseClass($value, $at), $ci);
		}
		if($char === '\\')
		{
			$escape = $value[$at + 1] ?? '';
			if($escape === 'b' || $escape === 'B')
			{
				$at+= 2;
				
				return null;
			}
			
			return self::fold(self::parseEscape($value, $at), $ci);
		}
		$at++;
		
		return self::fold(self::setOf([ord($char)]), $ci);
	}
	
	/**
	 * An escape at $at (the backslash) as its byte set; a shorthand class
	 * is ASCII as the dialect pins it, plus 0xA0 for `\s` (JavaScript's
	 * reading — the wider set is the conservative one)
	 */
	protected static function parseEscape(
		string $value,
		int &$at,
	): string
	{
		$escape = $value[$at + 1] ?? '';
		$at+= 2;
		$all = str_repeat("\1", 256);
		
		$digits = self::setOf(self::range(48, 57));
		$word = self::setOf([...self::range(48, 57), ...self::range(65, 90), ...self::range(97, 122), 95]);
		$space = self::setOf([9, 10, 11, 12, 13, 32, 160]);
		
		switch($escape)
		{
			case 'd':
				return $digits;
			case 'D':
				return $all ^ $digits;
			case 'w':
				return $word;
			case 'W':
				return $all ^ $word;
			case 's':
				return $space;
			case 'S':
				// the complement of PCRE's \s: 0xA0 stays in, the wider reading
				return $all ^ self::setOf([9, 10, 11, 12, 13, 32]);
			case 'n':
				return self::setOf([10]);
			case 'r':
				return self::setOf([13]);
			case 't':
				return self::setOf([9]);
			case 'f':
				return self::setOf([12]);
			case 'v':
				return self::setOf([11]);
			case '0':
				return self::setOf([0]);
			case 'x':
				if(preg_match('~\G[0-9A-Fa-f]{2}~', $value, $match, 0, $at) === 1)
				{
					$at+= 2;
					
					return self::setOf([(int)hexdec($match[0])]);
				}
				
				return $all;
			case '':
				return $all;
		}
		
		// an escaped punctuation mark is itself; any other letter is read
		// as every byte rather than guessed at
		return preg_match('~[A-Za-z0-9]~', $escape) === 1 ? $all : self::setOf([ord($escape)]);
	}
	
	/**
	 * A class at $at (the `[`) as its byte set — negation, ranges, escapes
	 * and shorthands inside. A range with an escape at either end is read
	 * as every byte rather than guessed at; $at always lands past the `]`
	 */
	protected static function parseClass(
		string $value,
		int &$at,
	): string
	{
		$all = str_repeat("\1", 256);
		$n = strlen($value);
		$i = $at + 1;
		$negated = ($value[$i] ?? '') === '^';
		if($negated)
		{
			$i++;
		}
		$set = str_repeat("\0", 256);
		$odd = false;
		$first = true;
		// a `]` first in the class is a literal, not its end
		while($i < $n && ($value[$i] !== ']' || $first))
		{
			$first = false;
			if($value[$i] === '\\')
			{
				$set |= self::parseEscape($value, $i);
				// `\x00-\x1f`: a range from an escape
				if(($value[$i] ?? '') === '-' && ($value[$i + 1] ?? ']') !== ']')
				{
					$odd = true;
				}
				
				continue;
			}
			if(($value[$i + 1] ?? '') === '-' && ($value[$i + 2] ?? ']') !== ']')
			{
				$low = ord($value[$i]);
				if($value[$i + 2] === '\\')
				{
					$odd = true;
					$i+= 2;
					
					continue;
				}
				$high = ord($value[$i + 2]);
				// a reversed range does not compile anyway; read as every byte
				$set |= $high < $low ? $all : self::setOf(self::range($low, $high));
				$i+= 3;
				
				continue;
			}
			$set |= self::setOf([ord($value[$i])]);
			$i++;
		}
		$at = $i + 1;
		if($odd)
		{
			return $all;
		}
		
		return $negated ? $all ^ $set : $set;
	}
	
	/** a group's bytes: everything any item in any branch could match */
	protected static function unionOf(
		array $branches,
	): string
	{
		$set = str_repeat("\0", 256);
		foreach($branches as $sequence)
		{
			foreach($sequence as $item)
			{
				if($item['type'] !== 'zero')
				{
					$set |= $item['set'];
				}
			}
		}
		
		return $set;
	}
	
	/** whether a group can match the empty string — one branch of nullable items is enough */
	protected static function nullableOf(
		array $branches,
	): bool
	{
		foreach($branches as $sequence)
		{
			$nullable = true;
			foreach($sequence as $item)
			{
				if($item['type'] !== 'zero' && $item['nullable'] === false)
				{
					$nullable = false;
				}
			}
			if($nullable)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/** a set with both cases of every letter in it, when the rule folds case */
	protected static function fold(
		string $set,
		bool $ci,
	): string
	{
		if($ci === false)
		{
			return $set;
		}
		for($byte = 65; $byte <= 90; $byte++)
		{
			if($set[$byte] === "\1" || $set[$byte + 32] === "\1")
			{
				$set[$byte] = "\1";
				$set[$byte + 32] = "\1";
			}
		}
		
		return $set;
	}
	
	/**
	 * @param list<int> $bytes
	 */
	protected static function setOf(
		array $bytes,
	): string
	{
		$set = str_repeat("\0", 256);
		foreach($bytes as $byte)
		{
			$set[$byte & 0xFF] = "\1";
		}
		
		return $set;
	}
	
	/**
	 * @return list<int>
	 */
	protected static function range(
		int $low,
		int $high,
	): array
	{
		$bytes = [];
		for($byte = $low; $byte <= $high; $byte++)
		{
			$bytes[] = $byte;
		}
		
		return $bytes;
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
	
	/** the record as stored, from APCu, else from the file (re-priming APCu); null = no store. Ruleset::fromRecord() holds it to its seal */
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
	
	/** the key the stored record is sealed under (Ruleset::seal()): given, or derived from the API key (sealKey()) */
	protected string $sealKey;
	
	/**
	 * @param string $url codesafe instance base URL
	 * @param string $key the project api_key
	 * @param ?callable(string $url, array<string> $headers, int $timeoutMs): array{status: int, headers: array<string, string>, body: string} $http the transport; null = curl or streams
	 * @param ?callable(string $kind, string $message, array<string, mixed> $extra): mixed $report the host's sender
	 * @param ?callable(string $line): mixed $log the host's log
	 * @param list<Platform> $platforms the platform modules loaded: the rules in their words are kept at the pull; anything else is
	 *     ignored, and the host's log names it
	 * @param ?string $sealKey the key the stored record is sealed under, for a layer that holds it without the API key (the
	 *     plugin's prepend, from its consent file); null derives it from the API key (sealKey()), which gives '' for none —
	 *     and a kernel with '' reads no store
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
		?string $sealKey = null,
	)
	{
		$this->sealKey = $sealKey ?? self::sealKey($key);
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
	 * The seal key of an API key: an HMAC under the key over a fixed word,
	 * so a layer that holds it alone (the plugin's prepend, from its
	 * consent file) reads and verifies the store without the key that
	 * opens the door; '' for no key, which seals nothing a kernel reads
	 */
	public static function sealKey(
		string $apiKey,
	): string
	{
		return $apiKey === '' ? '' : hash_hmac('sha256', 'codesafe-shield-seal', $apiKey);
	}
	
	/** @return list<string> the names of the platform modules this kernel pulls with, in their order */
	protected function platformNames(): array
	{
		return array_values(array_map(static fn(Platform $platform): string => $platform->name(), $this->platforms));
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
				$this->ruleset = Ruleset::fromRecord($this->store->read(), $this->sealKey, $this->platformNames());
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
	 * the ruleset is past the ceiling; a listed threat address the section
	 * blocks is refused before any rule (held, as an unanswered vpatch is,
	 * when the host cannot tell the caller); else the first MATCH or VPATCH rule
	 * that matches — in the door's order, blocking first — as block (set to
	 * block AND enforce, a vpatch's who and nonce answered) or observe; a vpatch that
	 * could not be answered observes unless a later rule blocks; else the
	 * first RATE rule whose predicate matches and whose key
	 * is over its limit, the same way; else a listed address the section
	 * only observes, observed under its pseudo-rule — the rules judge it
	 * first, so a blocking rule still blocks it and a rule's match is the
	 * rule's. A rule the engine cannot run matches
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
				return Verdict::pass($ruleset->isRefused() ? 'refused store' : 'unknown contract');
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
			// a listed address the section only observes: the verdict when no rule decides
			$observed = null;
			// a listed address the section blocks is refused before any rule
			$threat = $this->threatened($ruleset, $facts);
			if($threat !== null)
			{
				$blocks = Ruleset::blocks($threat['mode']) && $consent->blocks();
				if($blocks && $facts->callerKnown)
				{
					return new Verdict(Verdict::BLOCK, $threat, $facts->ip);
				}
				// observed only: the rules judge it first, or a blocking vpatch would never block the address most likely to attack
				if($blocks === false)
				{
					$observed = new Verdict(Verdict::OBSERVE, $threat, $facts->ip);
				}
				else
				{
					// a caller the host cannot tell may be signed in: held, and a rule after it may still block
					$held = new Verdict(Verdict::OBSERVE, $threat, $facts->ip, Verdict::REASON_UNANSWERED);
				}
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
					// sub-requests the kernel could not read may have reached the handler the rule names (Platform::reaches()): past the
					// count the platform itself refuses (overflows()) the rule fails closed for this caller, the padded exploit refused
					// and not only logged; a body the kernel could not read holds unanswered
					if($hit === null && self::reaches($rule, $facts, $unread))
					{
						$overflow = self::overflows($facts, $unread);
						$who = $overflow ? self::patched(['who' => $rule['who'] ?? '', 'conditions' => []], $facts) : null;
						$hit = ['matched' => '', 'resolved' => $who !== null && $who['resolved'], 'unread' => $overflow];
					}
					if($hit === null)
					{
						continue;
					}
					$blocks = Ruleset::blocks($rule['mode'] ?? '') && $consent->blocks();
					// decided on what was not read whole: the verdict says so, and the report after it
					$verdict = new Verdict($blocks && $hit['resolved'] ? Verdict::BLOCK : Verdict::OBSERVE, $rule,
						substr($hit['matched'], 0, self::MATCHED_MAX), ($hit['unread'] ?? false) ? Verdict::REASON_UNREAD : '');
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

			return $observed ?? Verdict::pass('no match');
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
		// read once per request: judge() and tally() share the sub-requests, and so what each of them read
		return $facts->kept('subs', static function() use ($facts): array
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
		});
	}
	
	/**
	 * Whether the sub-requests a module could not read run past the count the
	 * module's platform itself refuses (Platform::overflows()), so a vpatch
	 * they may reach fails closed
	 *
	 * @param list<Platform> $unread
	 */
	public static function overflows(
		Facts $facts,
		array $unread,
	): bool
	{
		foreach($unread as $platform)
		{
			if($platform->overflows($facts))
			{
				return true;
			}
		}
		
		return false;
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
			// a verdict on what was not read whole says so — `reason`, the tag codesafe's grid filters by — and names no match: the
			// value that pinned the handler is no payload, and an honest heavy save refused there must not read as an exploit
			$unread = $verdict->reason === Verdict::REASON_UNREAD;
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
				'matched' => $unread ? '' : self::shown($rule, $verdict->matched, $facts),
				'reason' => $verdict->reason,
				'authed' => $facts->authed,
				'body_capped' => $facts->bodyWasCapped(),
			] + ($unread ? ['tags' => [Verdict::REASON_UNREAD]] : []) + (Ruleset::isVpatch($rule) ? ['who' => (string)($rule['who'] ?? '')] : []));
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
		$form = $facts->form();
		if($form !== [])
		{
			return self::holdsSecret($form) === false;
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
			$record = $this->store->read();
			$current = Ruleset::fromRecord($record, $this->sealKey, $this->platformNames());
			// a record that is not this kernel's: the door is asked for the whole ruleset now (no If-None-Match), and a sealed
			// unusable record fetched now takes its place, so while the door is down the interval and the lock apply as to any
			// record — one request and one log line per interval, not per tick
			$refused = $current === null && is_array($record);
			if($refused)
			{
				$this->log('stored ruleset refused (seal, contract or modules not this kernel\'s): pulling whole');
				$current = Ruleset::refused($now, $this->platformNames());
				$this->store->write($current->toRecord($this->sealKey));
				$this->rulesetRead = false;
			}
			if($force === false && $refused === false && $current !== null && $this->store->pullForced() === false && $current->fetchedAt + $this->interval > $now)
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
		// never the stand-in for a refused record: no If-None-Match went out for it, so a 304 is no answer to this pull
		if($status === 304 && $current !== null && $current->isRefused() === false)
		{
			// only a record that read back sealed is renewed, and it is sealed again
			$this->store->write($current->withFetchedAt($now, self::header($response, self::HEADER_VERSION))->toRecord($this->sealKey));
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
		$this->store->write($ruleset->toRecord($this->sealKey));
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
	 * lacks every capability; a signed-in one asks Facts::can(). A condition
	 * over what the kernel did not read whole — a JSON body past
	 * Facts::JSON_CAP, a form it parsed itself past Facts::FORM_CAP, a decode
	 * step's values past Ruleset::DECODED_MAX or a module's own bound — is
	 * answered as holding once an entry that held
	 * answered pins the handler (pins()): the app reads it whole, and padding
	 * must not turn a block into an observe; `unread` says the answer rests
	 * on that. A rule's answer is kept for the request: tally() reads what
	 * judge() read
	 *
	 * @return ?array{matched: string, resolved: bool, unread: bool}
	 */
	public static function patched(
		array $rule,
		Facts $facts,
	): ?array
	{
		$id = $rule['id'] ?? null;
		if(is_int($id) === false)
		{
			return self::patchedNow($rule, $facts);
		}
		// by id and by what the rule reads: a rule served again with other conditions is another rule
		$key = 'patched:' . $id . ':' . hash('xxh3', (string)json_encode([$rule['who'] ?? '', $rule['conditions'] ?? []]));
		
		return $facts->kept($key, static fn(): ?array => self::patchedNow($rule, $facts));
	}
	
	/**
	 * patched(), computed
	 *
	 * @return ?array{matched: string, resolved: bool, unread: bool}
	 */
	protected static function patchedNow(
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
		// whether an entry the kernel read pins the handler, and whether a condition it could not read whole waits on that
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
		
		return ['matched' => $matched !== '' ? $matched : $framed, 'resolved' => $resolved && ($unread === false || $pinned), 'unread' => $unread];
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
	 * passes; what the kernel did not read whole — a JSON body past the cap,
	 * a form it parsed itself past Facts::FORM_CAP, a decode step's values
	 * past DECODED_MAX or a module's own bound — holds the condition
	 * unanswered where no value read passes and says so (`unread`), for
	 * patched() to answer
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
		// what the kernel did not read — the decode steps' values past the request's budget (Facts::DECODED_BUDGET) or a step's own
		// bound, a form's pairs past Facts::FORM_CAP — may hold what no value read did: the condition holds unanswered and says so,
		// for patched() to answer on a pinned handler
		$cut = ['matched' => '', 'resolved' => false, 'unread' => true];
		$formCut = self::readsForm($target) && $facts->formUnread();
		// unreadable: an upload the host could not read — the host's failure, never a cap
		[$values, $unreadable] = str_starts_with($target, 'file-content:')
			? self::contents($facts, substr($target, strlen('file-content:'))) : [self::values($target, $facts), false];
		$test = (string)$condition['test'];
		if($test === 'exists')
		{
			// an upload that could not be read is there all the same
			return $values === [] && $unreadable === false ? ($formCut ? $cut : null) : ['matched' => $values[0] ?? '', 'resolved' => true];
		}
		if($test === 'nonce_invalid')
		{
			// no nonce sent is an invalid one, unless the form it would be in was cut
			if($values === [])
			{
				return $formCut ? $cut : ['matched' => '', 'resolved' => true];
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
		$steps = (array)($condition['decode'] ?? []);
		$short = false;
		if($test === 'unsafe_html')
		{
			// the first value the filter changes; a value it cannot judge keeps the match unanswered
			$pending = null;
			foreach($values as $value)
			{
				[$decodedValues, $partly] = $steps === [] ? [[$value], false] : self::decodedOnce($value, $steps, $facts);
				$short = $short || $partly;
				foreach($decodedValues as $decoded)
				{
					// the host's filter costs the budget its weight
					if($steps !== [] && $facts->spend(Facts::HOST_TEST_WEIGHT) === false)
					{
						return $cut;
					}
					$unsafe = $facts->htmlUnsafe($decoded);
					if($unsafe === true)
					{
						return ['matched' => $decoded, 'resolved' => true];
					}
					$pending ??= $unsafe === null ? $decoded : null;
				}
			}
			// what a step left unread may hold
			if($short)
			{
				return $cut;
			}
			
			// an upload the host could not read is a value the filter could not judge
			return $pending === null && $unreadable === false ? ($formCut ? $cut : null) : ['matched' => $pending ?? '', 'resolved' => false];
		}
		foreach($values as $value)
		{
			[$decodedValues, $partly] = $steps === [] ? [[$value], false] : self::decodedOnce($value, $steps, $facts);
			$short = $short || $partly;
			foreach($decodedValues as $decoded)
			{
				if($steps !== [] && $facts->spend() === false)
				{
					return $cut;
				}
				if(self::passes($test, $decoded, $condition, $facts->host()))
				{
					return ['matched' => $decoded, 'resolved' => true];
				}
			}
		}
		// what a step left unread may hold
		if($short)
		{
			return $cut;
		}
		
		// an upload the host could not read may hold what no value read did
		return $unreadable ? ['matched' => '', 'resolved' => false] : ($formCut ? $cut : null);
	}
	
	/** whether a target reads the form: `body:`, `body-keys:`, and `request:`, which reads it beside the query */
	protected static function readsForm(
		string $target,
	): bool
	{
		return str_starts_with($target, 'body:') || str_starts_with($target, 'body-keys:') || str_starts_with($target, 'request:');
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
			// the method the app runs the request as: WordPress's REST override, where a module reads one
			return [$facts->appMethod()];
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
			'body' => self::pick($facts->form(), $name),
			'json' => self::pickJson($facts->json(), $name),
			'cookie' => self::pick($facts->cookies, $name),
			'header' => isset($facts->headers[$header]) ? [(string)$facts->headers[$header]] : [],
			'file' => self::pick($facts->files, $name),
			'file-content' => self::contents($facts, $name)[0],
			'query-keys' => self::keys($facts->query, $name),
			'body-keys' => self::keys($facts->form(), $name),
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
		$sent = [...self::pick($facts->query, $name), ...self::pick($facts->form(), $name)];
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
	 * A JSON body's values at a dot path, `*` for any key or element; at most
	 * $limit of them
	 *
	 * @return list<string>
	 */
	public static function pickJson(
		mixed $json,
		string $path,
		int $limit = PHP_INT_MAX,
	): array
	{
		if(is_array($json) === false || $path === '')
		{
			return [];
		}
		$values = [];
		foreach(self::walk([$json], explode('.', $path)) as $node)
		{
			self::leaves($node, $values, $limit);
			if(count($values) >= $limit)
			{
				break;
			}
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
	
	/** every scalar under a node, as the string a test reads, until $values holds $limit of them: the rest is never built */
	protected static function leaves(
		mixed $node,
		array &$values,
		int $limit = PHP_INT_MAX,
	): void
	{
		if(count($values) >= $limit)
		{
			return;
		}
		if(is_array($node))
		{
			foreach($node as $child)
			{
				self::leaves($child, $values, $limit);
				if(count($values) >= $limit)
				{
					return;
				}
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
	 * decoded() once per request for a value and its steps, whichever rule
	 * reads them — a batch's thousand sub-requests carrying one value decode
	 * it once — built no further than the budget left, and no more of it
	 * handed over than the condition may test: the one value built past the
	 * limit is the sign of the cut, never a value read
	 *
	 * @return array{list<string>, bool}
	 */
	protected static function decodedOnce(
		string $value,
		array $steps,
		Facts $facts,
	): array
	{
		$names = implode(',', array_map(static fn(Platform $platform): string => $platform->name(), $facts->platforms));
		$key = 'decoded:' . hash('xxh3', $names . "\0" . implode("\0", $steps) . "\0" . $value);
		
		return $facts->keptShared($key, static function() use ($value, $steps, $facts): array
		{
			$limit = min(Ruleset::DECODED_MAX, $facts->remaining());
			[$values, $cut] = self::decoded($value, $steps, $facts->platforms, $limit);
			
			return [array_slice($values, 0, $limit), $cut];
		});
	}
	
	/**
	 * A value through the decode steps: every value the last step yields,
	 * and whether a step read only part of what it was given. url and
	 * base64 yield one or none; a step's values past $limit are not built
	 * — one past it is, so the condition still sees there were more
	 *
	 * @param list<Platform> $platforms the modules whose steps are read
	 * @return array{list<string>, bool}
	 */
	public static function decoded(
		string $value,
		array $steps,
		array $platforms = [],
		int $limit = Ruleset::DECODED_MAX,
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
				$room = $limit + 1 - count($next);
				[$out, $short] = self::step($step, $one, $platform, $room);
				$cut = $cut || $short || count($out) > $room;
				foreach(array_slice($out, 0, $room) as $decoded)
				{
					$next[] = $decoded;
				}
				// the one past the limit is built, nothing beyond it
				if(count($next) > $limit)
				{
					$cut = true;
					
					break;
				}
			}
			$values = $next;
		}
		
		return [$values, $cut];
	}
	
	/**
	 * One decode step over one value: the values it yields — none when it
	 * cannot read the value, at most $room of a JSON document's — and whether
	 * it read only part of it (a module's step past its own bounds, a json
	 * step over a value past Facts::JSON_CAP). A step none of the core's is
	 * the module's that decodes it; one no module given reads yields nothing
	 *
	 * @return array{list<string>, bool}
	 */
	protected static function step(
		string $step,
		string $value,
		?Platform $platform = null,
		int $room = PHP_INT_MAX,
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
			// not decoded past the cap, as a JSON body is not: a megabyte costs the request its decoding, not a 9 MB value
			if(strlen($value) > Facts::JSON_CAP)
			{
				return [[], true];
			}
			// an object or an array read as the json: target reads a body: a scalar or invalid JSON yields nothing
			$json = json_decode($value, true, Facts::JSON_DEPTH);
			if(is_array($json) === false)
			{
				return [[], false];
			}
			$values = [];
			if($step === 'json')
			{
				self::leaves($json, $values, $room);
				
				return [$values, false];
			}
			
			return [self::pickJson($json, substr($step, strlen('json:')), $room), false];
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
	public static function regexPattern(
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
