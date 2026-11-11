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
 * missing store also forces the very next pull. Past CEILING (24 h since the last
 * good fetch: codesafe gone silent, or the site kept from it) the kernel keeps its
 * blocking rules, each until its own expires_at, and lets the rest lapse — what
 * only observes, and the threat section; it keeps judging, forcing a pull on every
 * request, a failed pull holding the next off for RETRY, until one — 200 or 304 —
 * renews the ruleset. The door's own 401 is codesafe refusing the key (rotated,
 * its project switched off or deleted), not a site cut off: every rule lifts at
 * once. The verdict is `block` only when the rule is set to block AND
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
 * query, form, JSON, cookies, headers, file names, and an upload's bytes,
 * read whole within Facts::FILE_BUDGET, when a condition names its
 * contents; a form PHP left out of $_POST on PUT, PATCH or DELETE the
 * kernel parses as WordPress's REST server does, Facts::formReader()).
 * `who` is anyone,
 * anonymous or lacks:<capability>, and a nonce test asks the platform: a
 * blocking vpatch whose who or nonce the adapter cannot answer, or that
 * reads what the kernel could not (an upload the host cannot read; an
 * upload past Facts::FILE_BUDGET, a JSON body past Facts::JSON_CAP or a
 * decode step's values past Facts::DECODED_BUDGET on a handler none of its
 * other entries pins; a WordPress batch whose body it could not read), is
 * held with the reason `unanswered`
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
use function array_diff_key;
use function array_fill;
use function array_filter;
use function array_is_list;
use function array_key_exists;
use function array_keys;
use function array_map;
use function array_merge;
use function array_pop;
use function array_reduce;
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
use function gmmktime;
use function ini_get;
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
use function method_exists;
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
use function serialize;
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
use const FILTER_VALIDATE_BOOLEAN;
use const FILTER_VALIDATE_IP;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;
use const LOCK_EX;
use const PCRE_JIT_SUPPORT;
use const PHP_INT_MAX;
use const PREG_OFFSET_CAPTURE;

/**
 * A platform's kernel module: the vocabulary only its app gives a request a
 * meaning in — frame targets, decode steps, the requests a request carries
 * inside it, the JSON types it reads. Given to Kernel and Facts (their
 * `platforms`), it is asked where the core's own reading ends; a kernel
 * without it drops its rules at the pull and reads none of its words.
 *
 * Three members are optional, asked only of a module that has them, so a
 * module written before them still loads: `prefixes(): list<string>`, its
 * targets that take a name (`xmlrpc:<path>`), read like a core parameter
 * and never a frame; `unread(string $target, Facts $facts): bool`, whether
 * it did not read one of its targets whole for this request, which then
 * holds as a JSON body past its cap does; `words(): list<string>`, what
 * X-Shield-Platforms names beside its name, the words it reads beyond its
 * first release, so a door serves a rule in them only to a kernel that
 * reads them
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
	
	/**
	 * the body as sent that a platform module parses as its app does
	 * (raw(): WordPress's XML-RPC server) is read up to this, PHP's default
	 * post_max_size, so a host on PHP's defaults receives none larger; past
	 * it the module's targets are unread, held on the handler the rule's
	 * other entries pin, observed elsewhere
	 */
	public const RAW_CAP = 8388608;
	
	/**
	 * the upload bytes a request's file-content tests read in all, every
	 * condition of every rule together, judge and tally alike
	 * (Kernel::contents()): an upload is read whole, once, by the first test
	 * that can afford it, and each test spends its size times its weight
	 * (FILE_WEIGHTS), so a request holds at most this much of its uploads and
	 * stays under 200 ms whatever the rule count (a literal test 3.3 ms a MiB
	 * at worst); past it a condition is cut (Kernel::patched())
	 */
	public const FILE_BUDGET = 16777216;
	
	/** the least one test over one upload spends, as opening a small file costs more than its bytes: a request reads 256 small uploads at most */
	public const FILE_TEST_MIN = 65536;
	
	/**
	 * what a test over an upload's bytes weighs against a literal one where
	 * PCRE runs with its JIT, as PHP does by default: the markup and URL tests
	 * run up to 46 ms a MiB and copy the value twice, the host's HTML filter
	 * (wp_kses_post()) up to 6 s; every other test weighs 1, a regex too: the
	 * JIT runs `+` in a line, and a pattern at the gate's ceiling
	 * (`\w{0,1023}x`) costs 0.57 s a MiB, so one such test over a 16 MiB
	 * upload takes 9 s. A regex the JIT runs without its early exit
	 * (RegexGate::loops()) weighs as without the JIT (fileWeight())
	 */
	public const FILE_WEIGHTS = ['has_markup' => 4, 'offsite' => 4, 'unsafe_html' => 512];
	
	/**
	 * the weights where PCRE runs without its JIT (pcre.jit off, or a PHP
	 * built without it): the interpreter backtracks the shapes the gate
	 * admits quadratically — `[a-z]+[0-9]*x` over 16 KiB of `a` takes 3.9 s,
	 * over 1 KiB 15 ms — so a regex with `+` reads 2 KiB of a request's
	 * uploads, one of counts alone weighs this times its cost over
	 * RegexGate::RUN_COST_MAX (Kernel::weighted()); has_markup's own
	 * patterns run 340 ms over 4 MiB there
	 */
	public const FILE_WEIGHTS_INTERPRETED = ['regex' => 8192, 'not_regex' => 8192, 'has_markup' => 8];
	
	/**
	 * without PCRE's JIT, a quantified regex reads at most this many bytes
	 * of a longer value that is no upload and that it may not read whole
	 * (REGEX_WHOLE_MAX_INTERPRETED, REGEX_WHOLE_BYTES_INTERPRETED,
	 * REGEX_WHOLE_BUDGET_INTERPRETED), as the
	 * Node twin does: the interpreter backtracks the shapes the gate admits
	 * quadratically and pcre.backtrack_limit counts a start at a time, so it
	 * never stops them (`\w+x` over 64 KiB: 27 s). Past the cut a vpatch's
	 * condition that matched nothing is unread (the pinned handler refuses,
	 * any other observes), a match rule matches nothing; a pattern without a
	 * quantifier reads any value whole, and with the JIT every pattern does
	 * but one it runs without its early exit (RegexGate::loops())
	 */
	public const REGEX_SUBJECT_CAP = 1024;
	
	/**
	 * the longest value a quantified regex reads whole without the JIT, its
	 * bytes weighted by the pattern's cost (Kernel::weighted()): `\w+x` and
	 * `\w{1,4}\w{0,255}x` over 2 KiB 23 ms, the 1 KiB cut at most 28 ms
	 */
	public const REGEX_WHOLE_MAX_INTERPRETED = 2048;
	
	/**
	 * the most bytes a quantified regex reads whole without the JIT,
	 * whatever its cost: the cost is a model, and this bounds what its error
	 * can cost. It meets REGEX_WHOLE_MAX_INTERPRETED at a cost of 128, where
	 * `\w{0,127}x` takes the interpreter 24 ms over it; a pattern at the
	 * gate's ceiling would take 190 ms
	 */
	public const REGEX_WHOLE_BYTES_INTERPRETED = 16384;
	
	/** the weighted bytes a request's quantified regexes read whole past REGEX_SUBJECT_CAP without the JIT, every condition and match rule together: about 100 ms */
	public const REGEX_WHOLE_BUDGET_INTERPRETED = 8192;
	
	/**
	 * what each atom of a regex without a quantifier weighs where PCRE runs
	 * without its JIT (RegexGate::width()): every start compares its atoms
	 * in turn, up to 9 ms a MiB an atom, so `<\?(?:php|=)` (5) reads 800 KiB
	 * of a request's uploads and a 600-byte pattern 7 KiB
	 */
	public const LINEAR_ATOM_WEIGHT = 4;
	
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
	
	/** @var array<string, string|int|null> the uploads asked for, by temp path: the bytes, the length of one not read, null where the host cannot read it */
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
	
	/** the upload bytes spent so far (spendFile()); a sub-request's and a copy's is its request's */
	protected int $fileSpent = 0;
	
	/** the weighted bytes quantified regexes read whole so far without the JIT (spendRegex()); a sub-request's and a copy's is its request's */
	protected int $regexSpent = 0;
	
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
	 * @param ?Closure(string, int): (string|int|null) $fileReader an upload's bytes by its temp path when it is at most the int long,
	 *     else its length, unread; null when the host cannot read it
	 * @param list<Platform> $platforms the platform modules the kernel was given (Kernel::platforms()); anything else is ignored
	 * @param array<string, scalar> $options what a platform module reads of the host, by the module's own key (WordPress's REST prefix)
	 * @param ?array<string, mixed> $request the host's request bag ($_REQUEST), whose values a request: target reads beside the
	 *     query's and the form's; null where the host has none
	 * @param ?Closure(): array{array<string, mixed>, bool} $formReader the form a rule reads where the platform parsed none
	 *     (formReader()), and whether it ran past FORM_CAP; null = $form is the form
	 * @param ?Closure(): ?string $rawReader the body as sent, whatever its type (raw()); null where the host hands none
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
		protected ?Closure $rawReader = null,
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
				$this->callerKnown, fn(string $value): ?bool => $this->htmlUnsafe($value), $this->uploads, fn(string $path, int $max): string|int|null => $this->fileContent($path, $max),
				$platforms, $this->options, $this->request, $this->formReader === null ? null : fn(): array => [$this->form(), $this->formUnread()],
				$this->rawReader === null ? null : fn(): ?string => $this->raw());
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
	
	/** whether the request's upload budget still covers a test of this cost, which is spent only then: an upload cut leaves the rest to the next */
	public function spendFile(
		int $cost,
	): bool
	{
		$root = $this->root ?? $this;
		if($cost > self::FILE_BUDGET - $root->fileSpent)
		{
			return false;
		}
		$root->fileSpent+= $cost;
		
		return true;
	}
	
	/** the upload budget left: the most a test of weight 1 may still read */
	public function fileRemaining(): int
	{
		return self::FILE_BUDGET - ($this->root ?? $this)->fileSpent;
	}
	
	/**
	 * Whether a quantified regex may read a value of these weighted bytes
	 * whole without the JIT, which are spent only then: against
	 * REGEX_WHOLE_BUDGET_INTERPRETED
	 */
	public function spendRegex(
		int $bytes,
	): bool
	{
		$root = $this->root ?? $this;
		if($bytes > self::REGEX_WHOLE_BUDGET_INTERPRETED - $root->regexSpent)
		{
			return false;
		}
		$root->regexSpent+= $bytes;
		
		return true;
	}
	
	/** whether PCRE runs with its JIT here: built in and pcre.jit on */
	public static function jit(): bool
	{
		return PCRE_JIT_SUPPORT && filter_var(ini_get('pcre.jit'), FILTER_VALIDATE_BOOLEAN);
	}
	
	/**
	 * What a test over an upload's bytes weighs on the engine that runs it:
	 * PCRE's interpreter where its JIT is off or not built in, a regex there
	 * by its $pattern (Kernel::weighs()) — its atoms when it holds no
	 * quantifier, else FILE_WEIGHTS_INTERPRETED weighted by its cost; a
	 * regex test without a pattern weighs as one with `+`
	 */
	public static function fileWeight(
		string $test,
		?string $pattern = null,
		bool $ci = true,
	): int
	{
		// the JIT runs a pattern without its early exit as slowly as the interpreter does (RegexGate::loops())
		$loops = $pattern !== null && ($test === 'regex' || $test === 'not_regex') && Kernel::weighs($pattern, $ci)['loops'];
		if((self::jit() === false || $loops) && isset(self::FILE_WEIGHTS_INTERPRETED[$test]))
		{
			if(($test !== 'regex' && $test !== 'not_regex') || $pattern === null)
			{
				return self::FILE_WEIGHTS_INTERPRETED[$test];
			}
			$width = Kernel::weighs($pattern, $ci)['width'];
			
			// a pattern without a quantifier reads each start once over: its atoms set its cost, never past a quantified one's
			return $width !== null
				? min(self::FILE_WEIGHTS_INTERPRETED[$test], max(1, self::LINEAR_ATOM_WEIGHT * $width))
				: Kernel::weighted(self::FILE_WEIGHTS_INTERPRETED[$test], $pattern, $ci);
		}
		
		return self::FILE_WEIGHTS[$test] ?? 1;
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
	 * @param ?callable(string, int): (string|int|null) $fileReader an upload's bytes by its temp path, its length past the int;
	 *     null reads PHP's own (uploadReader())
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
			$input === null ? null : static function() use ($input): ?string
			{
				$raw = $input();
				
				return is_string($raw) ? $raw : null;
			},
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
		$keep = max(self::BODY_CAP, self::JSON_CAP, self::FORM_CAP, self::RAW_CAP) + 1;
		
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
	
	/** PHP's own temp files, read by fileBytes(): a path PHP did not write for this request's upload is never opened */
	public static function uploadReader(): Closure
	{
		return static fn(string $path, int $max = self::FILE_BUDGET): string|int|null => is_uploaded_file($path) ? self::fileBytes($path, $max) : null;
	}
	
	/** a file's bytes when it is at most $max long, else its length, unread; null when it cannot be read */
	public static function fileBytes(
		string $path,
		int $max = self::FILE_BUDGET,
	): string|int|null
	{
		$handle = is_file($path) && is_readable($path) ? fopen($path, 'rb') : false;
		if($handle === false)
		{
			return null;
		}
		try
		{
			$stat = fstat($handle);
			$size = $stat === false ? 0 : (int)$stat['size'];
			// longer than the test may read: the length answers, the bytes stay on disk
			if($size > $max)
			{
				return $size;
			}
			// a byte more than asked: a file grown since the stat still reads as past
			$bytes = stream_get_contents($handle, $max < PHP_INT_MAX ? $max + 1 : null);
		}
		finally
		{
			fclose($handle);
		}
		if($bytes === false)
		{
			return null;
		}
		
		return strlen($bytes) > $max ? strlen($bytes) : $bytes;
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
	
	/**
	 * The body as sent, whatever its type — what a platform module parses
	 * the way its app does (WordPress's XML-RPC server reads php://input
	 * whatever the Content-Type says) — read once when first asked, up to
	 * what the input keeps (fromServer(): a byte past the largest cap); null
	 * where the host hands none or it cannot be read
	 */
	public function raw(): ?string
	{
		return $this->kept('raw', function(): ?string
		{
			try
			{
				$raw = $this->rawReader === null ? null : ($this->rawReader)();
			}
			catch(Throwable)
			{
				$raw = null;
			}
			
			return is_string($raw) ? $raw : null;
		});
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
	 * An upload's contents, read whole and once: its bytes, or the length of
	 * one longer than $max, read only when a test may read that much; null
	 * when the host cannot read it. A host's reader may hand more than it was
	 * asked for: the bytes are kept, and their length tells the caller
	 */
	public function fileContent(
		string $path,
		int $max = self::FILE_BUDGET,
	): string|int|null
	{
		$known = $this->fileContents[$path] ?? null;
		// not asked yet, or a length this test may read now: the bytes, the host's failure and a length still past stand
		if(array_key_exists($path, $this->fileContents) === false || (is_int($known) && $known <= $max))
		{
			try
			{
				$bytes = $this->fileReader === null ? null : ($this->fileReader)($path, $max);
			}
			catch(Throwable)
			{
				$bytes = null;
			}
			// a length is an upload left on disk; anything else is no answer
			$this->fileContents[$path] = is_string($bytes) || (is_int($bytes) && $bytes >= 0) ? $bytes : null;
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
	 * the tag of a report a kernel sends past its ceiling: it judged on rules
	 * it last pulled at the report's `pulled_at`, which codesafe can neither
	 * lift nor change while the site does not reach it
	 */
	public const TAG_STALE = 'stale';
	
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
	
	/** the ids of rules a pull left out (dropped) a ruleset keeps and the next pull names (Kernel::HEADER_DROPPED) at most */
	public const DROPPED_MAX = 100;
	
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
	 * @param list<int> $dropped the ids of the rules the door served that this kernel left out: past RULES_MAX or VPATCHES_MAX,
	 *   or refused by its own checks (wellFormed(), reachesEverything()) — at most DROPPED_MAX, in the door's order
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
		public readonly array $dropped = [],
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
	 * A rule in the words of a platform module not given is left out too, and
	 * every rule left out is named by its id (dropped)
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
		$dropped = [];
		if($usable)
		{
			// the door's caps, in the door's order: what is past them is dropped
			$kept = ['match' => 0, 'vpatch' => 0];
			foreach($payload['rules'] as $rule)
			{
				// a match rule that would refuse every visitor is no door's to serve
				$left = self::wellFormed($rule, $platforms) === false
					|| (self::isVpatch($rule) === false && self::isRate($rule) === false && self::reachesEverything($rule));
				$slot = $left === false && self::isVpatch($rule) ? 'vpatch' : 'match';
				if($left || $kept[$slot] >= ($slot === 'vpatch' ? self::VPATCHES_MAX : self::RULES_MAX))
				{
					// said at the next pull, so the door's count of what a site holds is the site's
					if(is_array($rule) && is_int($rule['id'] ?? null) && count($dropped) < self::DROPPED_MAX)
					{
						$dropped[] = $rule['id'];
					}
					
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
				array_filter($platforms, static fn(mixed $platform): bool => $platform instanceof Platform))), $dropped);
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
			// a record from before the field drops nothing
			array_values(array_filter(is_array($record['dropped'] ?? null) ? $record['dropped'] : [], is_int(...))),
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
			'dropped' => $this->dropped,
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
			self::isVersion($version) ? $version : $this->version, $this->threats, $this->platforms, $this->dropped);
	}
	
	/** a version is the door's sha256, lowercase hex */
	public static function isVersion(
		string $version,
	): bool
	{
		return preg_match('~^[0-9a-f]{64}$~', $version) === 1;
	}
	
	/** past the ceiling: codesafe gone silent, or the site kept from it, for longer than it */
	public function isStale(
		int $now,
		int $ceiling,
	): bool
	{
		return $this->fetchedAt + $ceiling <= $now;
	}
	
	/**
	 * What a kernel holds past its ceiling: the rules whose mode blocks —
	 * match, rate and vpatch alike — each until its own expires_at, the
	 * door's UTC `Y-m-d H:i:s`, none for good. A rule that only observes
	 * lapses, so does one past its expiry or with an expiry this kernel
	 * cannot read, and the threat section with them: its addresses are a
	 * score that decays over days, and a dynamic address changes hands
	 */
	public function pastCeiling(
		int $now,
	): self
	{
		$held = array_values(array_filter($this->rules, static fn(array $rule): bool => self::blocks($rule['mode'] ?? '')
			&& self::holdsAt($rule['expires_at'] ?? null, $now)));
		
		return new self($held, $this->digest, $this->fetchedAt, $this->usable, $this->project, $this->version, null, $this->platforms, $this->dropped);
	}
	
	/** whether a rule's expires_at lies ahead of $now: null never expires; anything but the door's UTC `Y-m-d H:i:s` has */
	protected static function holdsAt(
		mixed $expires,
		int $now,
	): bool
	{
		if($expires === null)
		{
			return true;
		}
		if(is_string($expires) === false || preg_match('~^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$~D', $expires, $at) !== 1)
		{
			return false;
		}
		
		return $now < gmmktime((int)$at[4], (int)$at[5], (int)$at[6], (int)$at[2], (int)$at[3], (int)$at[1]);
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
	 * entry point: a platform module's frame target (a route), or an
	 * ENTRY_TESTS test on a value as sent (no decode steps) of any target but
	 * an upload's contents, a module's named one (`xmlrpc:0`) as a core
	 * parameter; a group when every member does. A negation, a payload
	 * test, a nonce or exists says what the exploit carries
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
		
		return self::frameOf($target, $platforms) !== null || (in_array($entry['test'] ?? null, self::ENTRY_TESTS, true) && ($entry['decode'] ?? []) === []
			&& str_starts_with($target, 'file-content:') === false);
	}
	
	/**
	 * The module among $platforms that reads a target: one whose targets()
	 * names it, or whose optional prefixes() names its prefix and a name
	 * follows (`xmlrpc:0`); null when none does — a target no module given
	 * names is never read
	 *
	 * @param list<Platform> $platforms
	 */
	public static function targetOf(
		string $target,
		array $platforms,
	): ?Platform
	{
		$frame = self::frameOf($target, $platforms);
		if($frame !== null)
		{
			return $frame;
		}
		$at = strpos($target, ':');
		if($at === false || $at === strlen($target) - 1)
		{
			return null;
		}
		foreach($platforms as $platform)
		{
			if($platform instanceof Platform && method_exists($platform, 'prefixes') && in_array(substr($target, 0, $at), (array)$platform->prefixes(), true))
			{
				return $platform;
			}
		}
		
		return null;
	}
	
	/**
	 * The module among $platforms whose targets() names a target, a frame
	 * target of its own; null when none does
	 *
	 * @param list<Platform> $platforms
	 */
	public static function frameOf(
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
		return in_array($target, self::TARGETS, true) || self::frameOf($target, $platforms) !== null;
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
	 * `method`, `path`, a module's own (`rest`, `xmlrpc:0`), or a prefix and
	 * a name (`query:file`); the keys targets may name the top level ('')
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
		if(self::isFrame($target, $platforms) || self::targetOf($target, $platforms) !== null)
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
 * most UNBOUNDED_MAX unbounded quantifiers, none that overlap, none of
 * the shapes the cost cannot weigh (shape()) or PCRE's JIT runs without
 * its early exit behind a group of varying count (behindVarying()), and
 * no start that costs more than RUN_COST_MAX (cost()). codesafe's
 * gate (Codesafe\Shield\Dialect::checkRegex()) answers with this class, and
 * a kernel holds every pulled regex to it (Ruleset::wellFormed(),
 * Ruleset::conditionWellFormed()), so a pattern an outdated, mistaken or
 * hostile codesafe serves never runs here: in PHP it fails open at
 * pcre.backtrack_limit, and in the Node twin (client-node/shield.mjs) it
 * would hold the event loop. Pure; the gate is asked at a pull, width()
 * and cost() by the byte budgets too, once per pattern (Kernel::weighs())
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
	 * badly in V8. An exact `{n}` has no choice to backtrack over and is
	 * never unbounded here, whatever its n; cost() weighs both by what they
	 * read: `\w{1,8}\w{0,500}x` and `\w{1,8}\w{500}x` read 4000 ways a start
	 */
	public const LARGE_COUNT = 16;
	
	/**
	 * The most choices a run of overlapping items may multiply to, an
	 * alternation's branches and an unbounded item's LARGE_COUNT among them:
	 * `\w+(?:a|b)(?:a|b)(?:a|b)(?:a|b)` (256) passes, `\w{1,8}` three times
	 * over (512) does not
	 */
	public const BOUNDED_CHOICES_MAX = 256;
	
	/**
	 * The most choices the counts in an overlapping run may multiply to on
	 * their own — a small count's m-n+1, an optional item or group 2, an
	 * alternation's branches and an unbounded item none: a near-miss tries
	 * every split of the run at every byte, so `\w{1,4}\w{1,4}` (16) costs
	 * 18 ms a MiB under PCRE's JIT, `\w{1,15}\w{1,15}` (225) 220 ms and V8
	 * the same. A large count is RUN_COST_MAX's to weigh
	 */
	public const COUNT_CHOICES_MAX = 16;
	
	/**
	 * The most one start of a pattern may cost (cost()): a near-miss pays it
	 * at every byte. At 1024, the weights calibrated on each engine timed
	 * alone, a MiB costs PCRE's JIT about 0.47 s (up to 0.8 s in a worker
	 * where the compiled code lands badly) and V8 3.6 s, PCRE's
	 * interpreter 21 ms over its 2 KiB read; the live rules reach 716 (rule
	 * 109, its `=src=` prefix credited). 512 would refuse two of them
	 */
	public const RUN_COST_MAX = 1024;
	
	/**
	 * What an unbounded quantifier (`*`, `+`, `{n,}`) weighs in the gate's
	 * cost: four ways may share its run (`\w+\d{0,3}=`), five may not
	 * (`\w{1,5}\w+x`). The byte budgets weigh it RUN_COST_MAX, as it reads
	 * the rest of the subject
	 */
	public const UNBOUNDED_REACH = 256;
	
	/**
	 * What a count right behind a separator its set cannot match multiplies
	 * its run by, whatever the count: the separator fixes where it starts,
	 * so `[\w.]{0,200}\.\w{1,8}x` costs about four times `[\w.]{0,200}`
	 * (3.6 under PCRE's JIT, the worst measured), not eight
	 */
	public const SEPARATED_WAYS = 4;
	
	/**
	 * The most atoms the body of a repeated group (`(…){n}`, `{n,m}`, `*`,
	 * `+`) may hold: each repetition reads them all again, so the body
	 * multiplies what one start reads. The live rules repeat three
	 * (`(\.\.[/\\]){3}`), the drafts none
	 */
	public const REPEATED_GROUP_ATOMS_MAX = 4;
	
	/**
	 * What one unit of a count's reach weighs in cost(), in eighths: a
	 * multiple of the unit, a count over a shorthand, `.` or a negated byte
	 * whose backtrack compares one byte or nothing it holds (`\w{0,1023}x`,
	 * `[^/]{0,1023}=`; per unit and MiB of a near-miss PCRE's JIT 0.45 ms,
	 * V8 3.5, the interpreter 11.7). Each is the slowest engine's multiple
	 * behind seven count sets at 255 and 1023, every engine timed alone —
	 * PCRE's JIT throughout: V8 stays under 2.3, the interpreter under 7
	 */
	protected const WEIGHTS = [
		'unit' => 8,
		// the count's set is a class of two or more members (`[a-z]`, `[\w.]`): 1.1-1.6
		'class' => 14,
		// a repeated group (`(?:\w)*`): the interpreter 1.3-1.7 a count's time
		'repeat' => 14,
		// a lazy count: 1.5-2.7, whatever it tests
		'lazy' => 23,
		// each step of the backtrack tests `$`: 1.0-3.0
		'end' => 25,
		// a class, a shorthand or a negated byte it holds (`[xy]`, `\d`, `[^a]`): 2.1-3.6; behind a count, a byte it holds
		// with more of the pattern behind, which each step passes where a near-miss repeats it: 2.5-3.4 a way, whatever the
		// row's length (`a#`, `ax`, `aax`, `abcx`), so shared over the compares the row counts
		'test' => 28,
		// `\b`: 4.9-6.1
		'boundary' => 52,
		// an optional byte, then what follows it (`x?=`, `-?x`): 2.7-3.6, half of it the row's second way
		'optional' => 20,
		// a count it holds, exact or not (`x{2}`, `[a-z]{1,2}`): 2.3-3.5 a way it makes
		'count' => 32,
		// an alternation of 2, 4, 8 branches: 3.3-4.6, 4.3-5.2, 6.8-8.9, so 4 and 0.75 a way into it
		'group' => 32,
		'way' => 6,
	];
	
	/**
	 * What one start of a branch anchored at `^` is spread over in cost(): a
	 * kernel runs a rule's regex once from the subject's start, without the
	 * `m` flag (Kernel::regexPattern()), so the branch starts there alone. Its
	 * unbounded quantifiers read this many bytes, and its cost grows with
	 * them at most once over (two multiplied pass COST_SATURATION), so a
	 * longer subject costs no more a byte
	 */
	protected const ANCHORED_BYTES = 1024;
	
	/**
	 * The most atoms and texts of a branch's literal prefix period() reads:
	 * the first atoms of a prefix are one too, and no period passes the
	 * shortest text. The live rules open with up to 10 texts
	 * (`=["']?(?:href|src|action|extsrc|asyncsrc)=`)
	 */
	protected const PREFIX_ATOMS_MAX = 16;
	
	protected const PREFIX_TEXTS_MAX = 16;
	
	/** a class of one member, `^` captured: its byte, or every byte but it */
	protected const ONE_MEMBER = '~\G\[(\^?)(?:\\\\x[0-9a-fA-F]{2}|\\\\[^dDwWsS]|[^\\\\\]])\]~';
	
	/** where a cost stops growing: far past RUN_COST_MAX, and an integer in both twins */
	protected const COST_SATURATION = 1048576;
	
	/** the overlap walk's conflicts: two unbounded quantifiers meeting, or a run past BOUNDED_CHOICES_MAX; a run of counts past COUNT_CHOICES_MAX */
	protected const CONFLICT_OVERLAP = 'overlap';
	
	protected const CONFLICT_COUNTS = 'counts';
	
	/**
	 * a POSIX class's opening, or a `[` that PCRE reads as one (`[=a=]`, `[.a.]`, `[:a:]`, inside a class or not), which
	 * it refuses to compile and JavaScript takes as plain members: read where the classes still stand, as it is a class's own spelling
	 */
	protected const POSIX_CLASS = '~\[\[:|\[([:.=])[^\]]*?\1\]~';

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
		if(self::hasRepeatedName($bare))
		{
			return 'a group name used twice compiles in JavaScript and not in PCRE — name each group once';
		}
		if(self::hasBracketLedClass($bare))
		{
			return 'a class that opens with `]` (`[]a]`, `[^]a]`) is a literal `]` to PCRE and an empty or any-byte class to JavaScript — write `\]`';
		}
		if(self::hasShorthandRange($value))
		{
			return 'a class range from a shorthand (`[\w-z]`) does not compile in PCRE and is three members to JavaScript — escape the `-` (`[\w\-z]`)';
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
		$shape = self::shape($value, $ci);
		if($shape !== null)
		{
			return $shape;
		}
		// on the value itself: the parser reads each escape as its byte set; null when it cannot read the pattern
		$overlapping = self::hasOverlappingQuantifiers($value, $ci);
		if($overlapping === self::CONFLICT_OVERLAP)
		{
			return 'quantifiers that can match the same character back to back (`.*.*`, `\w+\w+`, a run of `\w{1,8}` past ' . self::BOUNDED_CHOICES_MAX . ' choices) backtrack polynomially in a backtracking engine — make their sets disjoint or bound them';
		}
		if($overlapping === self::CONFLICT_COUNTS)
		{
			return 'counts that can match the same character back to back (`\w{1,8}\w{1,8}`, three `\w{1,4}`) multiply past ' . self::COUNT_CHOICES_MAX . ' choices, every one of them tried at every byte of a near-miss — fewer choices, or sets that do not overlap';
		}
		if(self::behindVarying($value, $ci))
		{
			return 'an unbounded quantifier behind or inside a group of varying count (`(?:a)?\w+`, `(?:\w+=)?`) is quadratic under PCRE\'s JIT — anchor the pattern with `^`, give the group one count, or bound the quantifier';
		}
		if((self::cost($value, $ci) ?? 0) > self::RUN_COST_MAX)
		{
			return 'one start can read more than ' . self::RUN_COST_MAX . ' bytes of work: a count beside another that can match the same character multiplies (`\w{1,8}\w{0,200}`, `\w+\w{16}`), and one over a class or before `\b`, `$` or an alternation weighs more — shorten a count, put a character between them the next one cannot match, or open the pattern with fixed text (`src=`) or `^`';
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
	 * Whether two groups carry one name: PCRE refuses to compile it, and V8
	 * takes it across alternatives (`(?<n>a)|(?<n>b)`)
	 */
	protected static function hasRepeatedName(
		string $bare,
	): bool
	{
		preg_match_all('~\(\?<([A-Za-z_]\w*)>~', $bare, $names);
		
		return count($names[1]) !== count(array_unique($names[1]));
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
	 * A class range with a shorthand (`\d \D \w \W \s \S`) at either end:
	 * `[\w-z]`, `[a-\d]` — PCRE refuses to compile it, JavaScript reads the
	 * shorthand, a `-` and the other end. On the value itself, an escape
	 * read whole; a `-` first or last in the class is a literal
	 */
	protected static function hasShorthandRange(
		string $value,
	): bool
	{
		$n = strlen($value);
		for($i = 0; $i < $n; $i++)
		{
			if($value[$i] === '\\')
			{
				$i++;
				
				continue;
			}
			if($value[$i] !== '[')
			{
				continue;
			}
			$j = $i + 1;
			if(($value[$j] ?? '') === '^')
			{
				$j++;
			}
			// whether the member before is a shorthand; null where no member may start a range
			$previous = null;
			$first = true;
			while($j < $n && ($value[$j] !== ']' || $first))
			{
				$first = false;
				if($value[$j] === '-' && $previous !== null && ($value[$j + 1] ?? ']') !== ']')
				{
					if($previous || ($value[$j + 1] === '\\' && self::isShorthand($value[$j + 2] ?? '')))
					{
						return true;
					}
					// past the range's other end, which starts no range itself
					$j+= $value[$j + 1] !== '\\' ? 2 : (($value[$j + 2] ?? '') === 'x' ? 5 : 3);
					$previous = null;
					
					continue;
				}
				if($value[$j] === '\\')
				{
					$previous = self::isShorthand($value[$j + 1] ?? '');
					$j+= ($value[$j + 1] ?? '') === 'x' ? 4 : 2;
					
					continue;
				}
				$previous = false;
				$j++;
			}
			$i = $j;
		}
		
		return false;
	}
	
	/** whether the letter after a backslash names a shorthand class */
	protected static function isShorthand(
		string $letter,
	): bool
	{
		return $letter !== '' && str_contains('dDwWsS', $letter);
	}
	
	/**
	 * The shapes the gate refuses on the parsed pattern, each with its
	 * reason: two branches of one alternation that read the same text, an
	 * empty group, a `{0}` count, a group that can match nothing yet is not
	 * optional itself, a group repeated a varying number of times up to
	 * LARGE_COUNT or more, a repeated group of more than
	 * REPEATED_GROUP_ATOMS_MAX atoms. Null when none is there, or when the
	 * parser cannot read the pattern (refusal() names that later)
	 */
	protected static function shape(
		string $value,
		bool $ci,
	): ?string
	{
		$at = 0;
		$tree = self::parseAlternation($value, $at, $ci);
		if($tree === null || $at !== strlen($value))
		{
			return null;
		}
		
		return self::shapeOf($tree);
	}
	
	/**
	 * Whether a branch not anchored at the subject's start holds an
	 * unbounded quantifier behind a group of varying count (varied()); one
	 * anchored is tried at one position only. False when the parser cannot
	 * read the pattern
	 */
	protected static function behindVarying(
		string $value,
		bool $ci,
	): bool
	{
		$at = 0;
		$tree = self::parseAlternation($value, $at, $ci);
		if($tree === null || $at !== strlen($value))
		{
			return false;
		}
		foreach($tree as $sequence)
		{
			$anchored = ($sequence[0]['type'] ?? '') === 'zero' && $sequence[0]['anchor'] === '^';
			if($anchored === false && self::varied($sequence, false)[0])
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Whether an unbounded quantifier (`*`, `+`, `{n,}`) follows a group
	 * whose count varies (`?`, `{1,2}`) in a sequence, or stands inside one,
	 * $varying saying one stood before it already: PCRE's JIT gives up its
	 * early exit from a failed start past such a group, so the quantifier
	 * reads to the end of its run from every start (`(?:a)?\S+=` over
	 * 256 KiB of `a`: 15 s; `(?:[a-z]*?\t|\s)??\s` over 64 KiB 1 s). Also
	 * whether the sequence holds such a group, for what follows it
	 *
	 * @param list<array> $sequence
	 * @return array{bool, bool}
	 */
	protected static function varied(
		array $sequence,
		bool $varying,
	): array
	{
		foreach($sequence as $item)
		{
			if($item['type'] === 'zero')
			{
				continue;
			}
			if($item['type'] === 'set')
			{
				if($varying && $item['reach'] === null)
				{
					return [true, true];
				}
				
				continue;
			}
			$inside = false;
			foreach($item['branches'] as $branch)
			{
				[$found, $holds] = self::varied($branch, $varying || $item['min'] !== $item['max']);
				if($found)
				{
					return [true, true];
				}
				$inside = $inside || $holds;
			}
			$varying = $varying || $inside || $item['min'] !== $item['max'];
		}
		
		return [false, $varying];
	}
	
	/**
	 * shape() over a parsed alternation, the groups inside it included
	 *
	 * @param list<list<array>> $branches
	 */
	protected static function shapeOf(
		array $branches,
	): ?string
	{
		if(self::repeats($branches))
		{
			return 'two branches that can read the same text (`(?:a|a)`, `(?:ab|a[bc])`) are tried at every way into them — drop the one the other covers';
		}
		foreach($branches as $sequence)
		{
			foreach($sequence as $item)
			{
				if($item['type'] === 'zero')
				{
					continue;
				}
				if($item['type'] === 'group' && array_filter($item['branches']) === [])
				{
					return 'an empty group (`()`, `(?:)`) matches nothing — drop it';
				}
				if($item['max'] === 0)
				{
					return 'a `{0}` count matches nothing — drop the item it counts';
				}
				if($item['type'] !== 'group')
				{
					continue;
				}
				// its skip is then plain to see: the cost model weighs every way past an optional item
				if($item['min'] > 0 && self::matchesNothing($item['branches']))
				{
					return 'a group that can match nothing (`(a|)`, `(a?)`) must be optional itself — write `(a)?`';
				}
				if($item['reach'] !== null && $item['reach'] >= self::LARGE_COUNT && $item['min'] !== $item['reach'])
				{
					return 'a group repeated up to ' . self::LARGE_COUNT . ' times or more (`(?:ab){0,100}`) is tried again at every repetition by PCRE — repeat a class, or count to ' . (self::LARGE_COUNT - 1) . ' at most';
				}
				if(($item['max'] === null || $item['max'] > 1) && self::atomsOf($item['branches']) > self::REPEATED_GROUP_ATOMS_MAX)
				{
					return 'a repeated group (`(…){n}`, `(…)+`) of more than ' . self::REPEATED_GROUP_ATOMS_MAX . ' atoms reads them all again at every repetition — repeat a class, or write the atoms out';
				}
				$inner = self::shapeOf($item['branches']);
				if($inner !== null)
				{
					return $inner;
				}
			}
		}
		
		return null;
	}
	
	/**
	 * Whether two branches of an alternation can read the same text
	 * (texts()): each is a way into what follows, so `(?:,|,|,)` makes every
	 * way that reaches it three. Branches with a count or a group inside are
	 * left to the cost model
	 *
	 * @param list<list<array>> $branches
	 */
	protected static function repeats(
		array $branches,
	): bool
	{
		$texts = array_values(array_filter(array_map(self::texts(...), $branches), static fn(?array $text): bool => $text !== null));
		foreach($texts as $i => $text)
		{
			foreach(array_slice($texts, $i + 1) as $other)
			{
				if(self::alike($text, $other))
				{
					return true;
				}
			}
		}
		
		return false;
	}
	
	/**
	 * Whether a branch of a group matches the empty string with no anchor
	 * in it: every item optional, `\b` or a group that does. A branch
	 * holding `^` or `$` (`(?:^|/)`, `(?:[:/]|$)`) only matches where the
	 * subject starts or ends, which the drafts use and the cost model weighs
	 *
	 * @param list<list<array>> $branches
	 */
	protected static function matchesNothing(
		array $branches,
	): bool
	{
		foreach($branches as $sequence)
		{
			$nothing = true;
			foreach($sequence as $item)
			{
				// an anchor, or an item that must read a byte, keeps the branch from matching nothing anywhere
				$holds = $item['type'] === 'zero'
					? $item['anchor'] !== ''
					: $item['min'] > 0 && ($item['type'] !== 'group' || self::matchesNothing($item['branches']) === false);
				if($holds)
				{
					$nothing = false;
					
					break;
				}
			}
			if($nothing)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * The atoms of a group's widest branch: an item its count's own max, 1
	 * when it has none or no count, a group inside its own widest branch, a
	 * zero-width item none
	 *
	 * @param list<list<array>> $branches
	 */
	protected static function atomsOf(
		array $branches,
	): int
	{
		$widest = 0;
		foreach($branches as $sequence)
		{
			$atoms = 0;
			foreach($sequence as $item)
			{
				// a count past the saturation stops there, so the product stays an integer
				$count = min(max(1, $item['reach'] ?? 1), self::COST_SATURATION);
				$atoms = min($atoms + match($item['type'])
				{
					'zero' => 0,
					'group' => self::atomsOf($item['branches']) * $count,
					default => $count,
				}, self::COST_SATURATION);
			}
			$widest = max($widest, $atoms);
		}
		
		return $widest;
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
	 * same hang without a single large count; and the counts' own choices
	 * in such a run, an alternation's branches and an unbounded item aside,
	 * may not pass COUNT_CHOICES_MAX. One start's cost (cost()) is asked
	 * only where these found nothing, so each keeps its own reason.
	 *
	 * Conservative: a set the parser cannot read exactly is every byte, a
	 * repeated group is the union of everything inside it, `ci` folds the
	 * letters. A pattern the parser cannot follow at all answers null, never
	 * "no conflict": checkRegex() lets the compile check name a broken one
	 * and refuses one that compiles. '' is no conflict, else the first one
	 * met (CONFLICT_OVERLAP, CONFLICT_COUNTS)
	 */
	protected static function hasOverlappingQuantifiers(
		string $value,
		bool $ci,
	): ?string
	{
		$at = 0;
		$tree = self::parseAlternation($value, $at, $ci);
		if($tree === null || $at !== strlen($value))
		{
			return null;
		}
		
		$seen = ['conflict' => '', 'cost' => 1, 'total' => 1, 'unbounded' => self::UNBOUNDED_REACH];
		self::walkAlternation($tree, self::emptyChain(), $seen);
		
		return $seen['conflict'];
	}
	
	/**
	 * What a near-miss costs a byte of the subject: the most one start of a
	 * pattern can be made to read, the runs it reads one after another added
	 * up (`\w{0,15}-` sixty times: 961). A run is items that can match the
	 * same byte (the overlap walk's run), and costs the product of what each
	 * reads — a count its max, one more when it may read nothing (`?` 2,
	 * `{0,200}` 201, `{1,8}` 8, an exact `{32}` 32), an unbounded one
	 * $unbounded, a group run once its inside walked, a repeated group its
	 * count times its widest branch's atoms — times the row the run's ways
	 * read after it (row()): its single atoms, and every optional byte or
	 * group they pass over. A count's reach is weighed (weight()): a class
	 * reads slower than a shorthand, and each step of its backtrack tests
	 * what follows it. Past a byte the run cannot swallow only the ways that
	 * stood at one position go on (`\w{1,4}\w{1,4}-` leaves four); an
	 * optional count the run cannot swallow adds its ways for the way at the
	 * run's end, every way there comparing it (`a{0,15}b{0,15}…z{0,15}!`
	 * 5291). An alternation pays what every branch adds (walkAlternation()),
	 * its ways out those of the branches that can match from one start
	 * (fanned()). A count right behind a required, exactly counted byte set
	 * it cannot match (`\.`, `=`) takes its run times SEPARATED_WAYS, or its
	 * own reach where that is more. Conservative: two exact counts in a row
	 * multiply (`\w{40}\w{40}` 1600) though they only add.
	 *
	 * Two credits, both sound on a subject an attacker writes: a top-level
	 * branch anchored at `^` starts once (ANCHORED_BYTES), so it costs its
	 * one start over a KiB; a branch that must open with a literal prefix
	 * (`src=`, `(?:href|src)=`) starts past it at most once every period()
	 * bytes, every other start failing inside it, so it costs its start over
	 * the period plus the prefix's atoms (rule 109: 2818 a start, 716 a
	 * byte). The branches neither applies to are walked together and added.
	 * Null for a pattern the parser cannot follow
	 */
	public static function cost(
		string $value,
		bool $ci = true,
		int $unbounded = self::UNBOUNDED_REACH,
	): ?int
	{
		$at = 0;
		$tree = $value === '' ? null : self::parseAlternation($value, $at, $ci);
		if($tree === null || $at !== strlen($value))
		{
			return null;
		}
		// the branches no credit applies to, walked as one alternation: what those that start on one byte add adds up
		$plain = [];
		$total = 0;
		foreach($tree as $sequence)
		{
			if(($sequence[0]['type'] ?? '') === 'zero' && $sequence[0]['anchor'] === '^')
			{
				$cost = self::walked([$sequence], self::ANCHORED_BYTES);
				$total+= $cost >= self::COST_SATURATION ? self::COST_SATURATION : intdiv($cost + self::ANCHORED_BYTES - 1, self::ANCHORED_BYTES);
				
				continue;
			}
			// weighed as the budgets weigh it, an unbounded quantifier reads to the subject's end from every start past the prefix
			[$period, $width] = $unbounded >= self::RUN_COST_MAX && self::holdsUnbounded($sequence) ? [1, 0] : self::period($sequence);
			if($period > 1)
			{
				$cost = self::walked([$sequence], $unbounded);
				$total+= $cost >= self::COST_SATURATION ? self::COST_SATURATION : min($cost, intdiv($cost + $period - 1, $period) + $width);
				
				continue;
			}
			$plain[] = $sequence;
		}
		
		return min($total + ($plain === [] ? 0 : self::walked($plain, $unbounded)), self::COST_SATURATION);
	}
	
	/**
	 * What one start of an alternation reads, the runs one after another
	 * added up, an unbounded quantifier weighing $unbounded (cost())
	 *
	 * @param list<list<array>> $branches
	 */
	protected static function walked(
		array $branches,
		int $unbounded,
	): int
	{
		$seen = ['conflict' => '', 'cost' => 1, 'total' => 1, 'unbounded' => $unbounded];
		self::walkAlternation($branches, self::emptyChain(), $seen);
		
		return $seen['total'];
	}
	
	/**
	 * How far apart two starts of a branch that pass its required literal
	 * prefix must be, and the most atoms of it a start compares, as
	 * [period, width]. The prefix is the branch's opening atoms, a byte set
	 * each (`\b` reads none): one text per way an optional atom or a group of
	 * literal branches (texts()) makes, cut at PREFIX_ATOMS_MAX atoms and
	 * PREFIX_TEXTS_MAX texts. Two starts d bytes apart both pass only where a
	 * text shifted by d agrees with one at every byte they share, `ci`
	 * folding the sets: `src=` never does (4), `aa` does at 1. [1, 0] for a
	 * branch that may open with no atom
	 *
	 * @param list<array> $sequence
	 * @return array{int, int}
	 */
	protected static function period(
		array $sequence,
	): array
	{
		$texts = [[]];
		foreach($sequence as $item)
		{
			if($item['type'] === 'zero')
			{
				// an anchor ends the prefix
				if($item['anchor'] !== '')
				{
					break;
				}
				
				continue;
			}
			$ways = match(true)
			{
				$item['type'] === 'set' && $item['max'] === 1 => $item['min'] === 0 ? [[], [$item['set']]] : [[$item['set']]],
				$item['type'] === 'group' && $item['min'] === 1 && $item['max'] === 1 => self::branchTexts($item['branches']),
				default => null,
			};
			if($ways === null || count($texts) * count($ways) > self::PREFIX_TEXTS_MAX)
			{
				break;
			}
			$longer = [];
			foreach($texts as $text)
			{
				foreach($ways as $way)
				{
					$longer[] = array_slice([...$text, ...$way], 0, self::PREFIX_ATOMS_MAX);
				}
			}
			$texts = $longer;
		}
		$lengths = array_map(count(...), $texts);
		$period = min($lengths);
		foreach($texts as $text)
		{
			foreach($texts as $other)
			{
				// the nearest $other can start behind $text with both passing; past $text's end it always can
				for($shift = 1; $shift < $period && $shift < count($text); $shift++)
				{
					if(self::shifted($text, $other, $shift))
					{
						$period = $shift;
						
						break;
					}
				}
			}
		}
		
		return $period === 0 ? [1, 0] : [$period, max($lengths)];
	}
	
	/**
	 * Every text the branches of a group of literal branches can read
	 * (texts()); null when one branch is no such branch
	 *
	 * @param list<list<array>> $branches
	 * @return list<list<string>>|null
	 */
	protected static function branchTexts(
		array $branches,
	): ?array
	{
		$all = [];
		foreach($branches as $sequence)
		{
			$texts = self::texts($sequence);
			if($texts === null)
			{
				return null;
			}
			$all = [...$all, ...$texts];
		}
		
		return $all;
	}
	
	/**
	 * Whether $other can be read $shift bytes after $text begins: every byte
	 * set of it that overlaps $text shares a byte with $text's there
	 *
	 * @param list<string> $text
	 * @param list<string> $other
	 */
	protected static function shifted(
		array $text,
		array $other,
		int $shift,
	): bool
	{
		for($at = 0; $at + $shift < count($text) && $at < count($other); $at++)
		{
			if(self::intersects($text[$at + $shift], $other[$at]) === false)
			{
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * Whether PCRE's JIT runs a pattern without its early exit from a
	 * failed start, so a quantifier reads to the end of its run from every
	 * start: a group repeated without a bound (`(?:ab)+`; `(?:aaa)*y` over
	 * 64 KiB of `a`: 1.1 s, past that its stack gives out) or a count of two
	 * or more without a max (`[a-f0-9]{3,}!` over 64 KiB: 0.9 s). A kernel
	 * reads such a pattern as without the JIT (Kernel::weighs()). False for a
	 * pattern the parser cannot follow
	 */
	public static function loops(
		string $value,
		bool $ci = true,
	): bool
	{
		$at = 0;
		$tree = $value === '' ? null : self::parseAlternation($value, $at, $ci);
		
		return $tree !== null && $at === strlen($value) && self::loopsIn($tree);
	}
	
	/**
	 * loops() over a parsed alternation, the groups inside it included
	 *
	 * @param list<list<array>> $branches
	 */
	protected static function loopsIn(
		array $branches,
	): bool
	{
		foreach($branches as $sequence)
		{
			foreach($sequence as $item)
			{
				$unbounded = $item['type'] !== 'zero' && $item['reach'] === null;
				if($unbounded && ($item['type'] === 'group' || $item['min'] >= 2))
				{
					return true;
				}
				if($item['type'] === 'group' && self::loopsIn($item['branches']))
				{
					return true;
				}
			}
		}
		
		return false;
	}
	
	/**
	 * The atoms one attempt of a pattern without a quantifier reads at one
	 * start: an escape, a class or a byte is one, a zero-width assertion
	 * none, a group its widest branch. Null for a pattern with any quantifier
	 * — `* + ?` or a count, `{n}` too, which multiplies what one start reads
	 * (`\w{2000}`) — and for one the parser cannot follow. Such a pattern
	 * runs in a line on every engine, each start costing its atoms
	 */
	public static function width(
		string $value,
		bool $ci = true,
	): ?int
	{
		$at = 0;
		$tree = $value === '' ? null : self::parseAlternation($value, $at, $ci);
		
		return $tree === null || $at !== strlen($value) ? null : self::widthOf($tree);
	}
	
	/**
	 * width() over a parsed alternation: its widest branch, null once an item is quantified
	 *
	 * @param list<list<array>> $branches
	 */
	protected static function widthOf(
		array $branches,
	): ?int
	{
		$widest = 0;
		foreach($branches as $sequence)
		{
			$width = 0;
			foreach($sequence as $item)
			{
				if($item['type'] === 'zero')
				{
					continue;
				}
				if($item['min'] !== 1 || $item['max'] !== 1)
				{
					return null;
				}
				$inner = $item['type'] === 'group' ? self::widthOf($item['branches']) : 1;
				if($inner === null)
				{
					return null;
				}
				$width+= $inner;
			}
			$widest = max($widest, $width);
		}
		
		return $widest;
	}
	
	/**
	 * What flows along a sequence: `open`, every byte an unbounded
	 * quantifier still in reach could swallow; `chain`, the bytes of the
	 * small counts in the current overlapping run, and `choices`, the
	 * product of their choices; `countSet` and `counts`, the same run read
	 * for its counts' own choices alone; `costSet` and `cost`, the same run
	 * read for what one start of it reads (cost()), `spent`, what the runs
	 * it ended read, and `sep`, the bytes of the separator right before,
	 * null when none is. The row the cost run reads since its ways last
	 * changed (row()): `atoms`, its required single atoms, `first` the first
	 * one's bytes, `like` how many of them share a byte with it, `extra` the
	 * items every way passed over without a choice, and `base` the ways.
	 * `ways`, the ways the cost run's choices make, and `dup`, the most of
	 * them that can end at one position: past a byte the run cannot swallow
	 * only those go on, each reading all that follows; `start`, the cost the
	 * run had when it began, which it has read only once it grows past
	 *
	 * @return array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int}
	 */
	protected static function emptyChain(): array
	{
		return ['open' => str_repeat("\0", 256), 'chain' => str_repeat("\0", 256), 'choices' => 1, 'countSet' => str_repeat("\0", 256), 'counts' => 1,
			'costSet' => str_repeat("\0", 256), 'cost' => 1, 'spent' => 0, 'sep' => null, 'atoms' => 0, 'first' => null, 'like' => 0, 'extra' => 0, 'base' => 1, 'ways' => 1, 'dup' => 1, 'start' => 1];
	}
	
	/**
	 * Each branch from the same entry; the exit is the union of the
	 * branches' sets and the worst of their choices. $seen carries the
	 * first conflict met, the highest cost of one run (`cost`) and of the
	 * runs one after another (`total`), and what an unbounded item weighs.
	 * A start tries every branch, so what the branches that can start on the
	 * same byte add to the entry's cost adds up (`\w{1000}!|\w{1000}#` 1999),
	 * and so do their ways out; branches that cannot (`\.\./|%2e%2e`) never
	 * both go past their first byte at one position. A row (row()) goes on
	 * past the alternation where any branch ends on one, read by the ways
	 * out of all of them: `(?:a|b)` or `(?:a|-)` 250 times behind
	 * `\w{0,1023}` is a row of 250. $after, the items that follow the
	 * alternation, for what a count's backtrack tests (weight())
	 *
	 * @param list<list<array>> $branches
	 * @param array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int} $state
	 * @param array{conflict: string, cost: int, total: int, unbounded: int} $seen
	 * @param list<array> $after
	 * @return array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int}
	 */
	protected static function walkAlternation(
		array $branches,
		array $state,
		array &$seen,
		array $after = [],
	): array
	{
		$out = self::emptyChain();
		[$peak, $peakTotal] = [$seen['cost'], $seen['total']];
		$entry = self::total($state);
		// by each byte a branch can start on: what the branches add to the entry's cost and to its total
		$grown = array_fill(0, 256, 0);
		$grownTotal = array_fill(0, 256, 0);
		// per branch its first bytes, the texts it can read, its ways out, the ways a row after it is read by, the ways its
		// runs make and the most of them it leaves at one position
		$exits = [];
		// what every branch's runs ended read, and whether each left its ways where its last run began
		[$spent, $fresh] = [null, true];
		foreach($branches as $sequence)
		{
			// each branch's own highest cost and total, counted from the entry's
			[$seen['cost'], $seen['total']] = [$state['cost'], $entry];
			$exit = self::walkSequence($sequence, $state, $seen, $after);
			$first = self::firstOf($sequence);
			$rowed = $exit['atoms'] + $exit['extra'] > 0;
			$spent = min($spent ?? $exit['spent'], $exit['spent']);
			$fresh = $fresh && $exit['cost'] === $exit['start'];
			for($byte = 0; $byte < 256; $byte++)
			{
				if($first[$byte] === "\1")
				{
					$grown[$byte]+= $seen['cost'] - $state['cost'];
					$grownTotal[$byte]+= $seen['total'] - $entry;
				}
			}
			$exits[] = [$first, self::texts($sequence), $exit['cost'], $rowed ? $exit['base'] : $exit['cost'], $exit['ways'], $exit['dup']];
			$out['open'] |= $exit['open'];
			$out['chain'] |= $exit['chain'];
			$out['choices'] = max($out['choices'], $exit['choices']);
			$out['countSet'] |= $exit['countSet'];
			$out['counts'] = max($out['counts'], $exit['counts']);
			$out['costSet'] |= $exit['costSet'];
			// a separator holds only where every way ends on it: one branch
			$out['sep'] = count($branches) === 1 ? $exit['sep'] : null;
			if($rowed)
			{
				[$out['atoms'], $out['like'], $out['extra']] = [max($out['atoms'], $exit['atoms']), max($out['like'], $exit['like']), max($out['extra'], $exit['extra'])];
				$out['first'] = self::union($out['first'], $exit['first']);
			}
		}
		$seen['cost'] = max($peak, min($state['cost'] + max($grown), self::COST_SATURATION));
		$seen['total'] = max($peakTotal, min($entry + max($grownTotal), self::COST_SATURATION));
		[$out['cost'], $bases, $paths, $out['dup']] = self::fanned($exits);
		// what the branches read stays spent, but for the ways out that go on reading, and never less than every branch ended
		$out['start'] = $fresh ? $out['cost'] : 1;
		$out['spent'] = min(max($spent, $entry + max($grownTotal) - ($out['cost'] > $out['start'] ? $out['cost'] : 0)), self::COST_SATURATION);
		$out['base'] = $out['atoms'] + $out['extra'] > 0 ? $bases : 1;
		$out['ways'] = $paths;
		
		return $out;
	}
	
	/**
	 * What an alternation's branches hand on, as [its ways out, the ways a
	 * row after it is read by, the ways its runs make, the most of them at
	 * one position]: a branch's own and those of every branch that can
	 * match from the same start — for the ways the same text (`,|,` twice as
	 * many), else a text the one begins the other with (`aa|aaa`). Branches
	 * of single atoms read only their texts, so `action|asyncsrc` never
	 * both match at one start; any other branch goes with every branch that
	 * starts on a byte it starts on
	 *
	 * @param list<array{string, ?list<list<string>>, int, int, int, int}> $exits
	 * @return array{int, int, int, int}
	 */
	protected static function fanned(
		array $exits,
	): array
	{
		$most = [1, 1, 1, 1];
		foreach($exits as [$first, $texts])
		{
			$sums = [0, 0, 0, 0];
			foreach($exits as [$otherFirst, $otherTexts, $cost, $base, $ways, $dup])
			{
				if(self::intersects($first, $otherFirst) === false)
				{
					continue;
				}
				$either = $texts === null || $otherTexts === null;
				if($either || self::alike($texts, $otherTexts, true))
				{
					$sums = [$sums[0] + $cost, $sums[1] + $base, $sums[2] + $ways, $sums[3]];
				}
				if($either || self::alike($texts, $otherTexts))
				{
					$sums[3]+= $dup;
				}
			}
			$most = array_map(static fn(int $a, int $b): int => max($a, min($b, self::COST_SATURATION)), $most, $sums);
		}
		
		return $most;
	}
	
	/**
	 * The texts a branch of single atoms can read, each a list of byte
	 * sets: one per way its optional atoms (`?`, at most three) are taken
	 * or skipped. Null for any other branch
	 *
	 * @param list<array> $sequence
	 * @return list<list<string>>|null
	 */
	protected static function texts(
		array $sequence,
	): ?array
	{
		$texts = [[]];
		foreach($sequence as $item)
		{
			if($item['type'] === 'zero')
			{
				continue;
			}
			if($item['type'] !== 'set' || $item['max'] !== 1 || count($texts) > 4)
			{
				return null;
			}
			$taken = array_map(static fn(array $text): array => [...$text, $item['set']], $texts);
			$texts = $item['min'] === 0 ? [...$texts, ...$taken] : $taken;
		}
		
		return $texts;
	}
	
	/**
	 * Whether two branches can read the same text: a text of each as long
	 * as the other whose sets share a byte at every place — or, with
	 * $begins, a text of one the other's begins with
	 *
	 * @param list<list<string>> $a
	 * @param list<list<string>> $b
	 */
	protected static function alike(
		array $a,
		array $b,
		bool $begins = false,
	): bool
	{
		foreach($a as $text)
		{
			foreach($b as $other)
			{
				if(count($text) !== count($other) && $begins === false)
				{
					continue;
				}
				[$shorter, $longer] = count($text) <= count($other) ? [$text, $other] : [$other, $text];
				$same = true;
				foreach($shorter as $at => $set)
				{
					$same = $same && self::intersects($set, $longer[$at]);
				}
				if($same)
				{
					return true;
				}
			}
		}
		
		return false;
	}
	
	/**
	 * The bytes a sequence can start on: its items' up to the first that
	 * cannot be skipped, every byte where all of them can (a group's whole
	 * set stands for its first bytes)
	 *
	 * @param list<array> $sequence
	 */
	protected static function firstOf(
		array $sequence,
	): string
	{
		$first = str_repeat("\0", 256);
		foreach($sequence as $item)
		{
			if($item['type'] === 'zero')
			{
				continue;
			}
			$first |= $item['set'];
			if($item['nullable'] === false)
			{
				return $first;
			}
		}
		
		return str_repeat("\1", 256);
	}
	
	/**
	 * An unbounded item meeting `open` is the conflict, and so is a run of
	 * overlapping small counts past BOUNDED_CHOICES_MAX, or its counts past
	 * COUNT_CHOICES_MAX. An optional or zero-width item leaves the runs
	 * open; a required item ends a run only when that run cannot swallow
	 * the item's bytes. $after, the items that follow the sequence
	 *
	 * @param list<array> $sequence
	 * @param array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int} $state
	 * @param array{conflict: string, cost: int, total: int, unbounded: int} $seen
	 * @param list<array> $after
	 * @return array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int}
	 */
	protected static function walkSequence(
		array $sequence,
		array $state,
		array &$seen,
		array $after = [],
	): array
	{
		foreach($sequence as $index => $item)
		{
			if($item['type'] === 'zero')
			{
				continue;
			}
			$follows = [...array_slice($sequence, $index + 1), ...$after];
			
			// a group that runs once (or not at all) is followed inside
			if($item['type'] === 'group' && $item['max'] !== null && $item['max'] <= 1)
			{
				$inner = self::walkAlternation($item['branches'], $state, $seen, $follows);
				if($item['min'] === 0 || $item['nullable'])
				{
					$inner = self::skipped($inner, $state, $item['min'] === 0, $seen);
				}
				// and is a choice itself: one way per branch, one more when it may
				// be skipped — forty `(?:x)?` before a `y` are 2^40 ways on a near-miss;
				// to the counts' run only the skip is a choice, and the cost's ways out are the walk's above
				$ways = count($item['branches']) + ($item['min'] === 0 ? 1 : 0);
				if($ways > 1)
				{
					// the group's own work is its alternation's peak; the ways out only weigh with what follows,
					// as `%2f|%5c` both start on `%` but never both end
					[$peak, $total] = [$seen['cost'], $seen['total']];
					$inner = self::counted($inner, $item['set'], $ways, $item['min'] === 0 ? 2 : 1, $item['min'] > 0 && $item['nullable'] === false, $seen);
					[$seen['cost'], $seen['total']] = [$peak, $total];
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
					$seen['conflict'] = $seen['conflict'] === '' ? self::CONFLICT_OVERLAP : $seen['conflict'];
				}
				// an optional one keeps the earlier runs in reach; a required one is the only run left
				$state['open'] = $item['min'] === 0 ? $state['open'] | $set : $set;
			}
			elseif($required && $overlapsOpen === false)
			{
				// a required byte the open run cannot swallow ends it
				$state['open'] = str_repeat("\0", 256);
			}
			
			// an unbounded one weighs LARGE_COUNT in the run, so `\w{1,15}\w{1,15}\w+`
			// (225 × 16) is a conflict while `\w+\d{0,3}` (16 × 4) is not — the two
			// unbounded ones meeting each other are `open`'s business — and nothing
			// among the counts' own choices
			$choices = $item['max'] === null ? 1 : $item['max'] - $item['min'] + 1;
			// what one start reads through it: a count its max, a repeated group that many times its widest branch's
			// atoms, one more when it may read nothing; an unbounded one what $seen weighs it
			$width = $item['type'] === 'group' ? max(1, self::atomsOf($item['branches'])) : 1;
			$reach = $item['reach'] === null
				? $seen['unbounded']
				: min(min($item['reach'], self::COST_SATURATION) * $width + ($item['min'] === 0 ? 1 : 0), self::COST_SATURATION);
			// as one start pays it: its set, its laziness or what each step of its backtrack tests (weight()); a reach of two
			// (`?`, `{1,2}`) gives back one byte at most, which the count before it pays for
			$reach = $reach > 2 ? min(intdiv($reach * self::weight($item, $follows) + 7, 8), self::COST_SATURATION) : $reach;
			// right behind a separator it cannot match, a count only moves where its run goes on
			$separated = $state['sep'] !== null && self::intersects($state['sep'], $set) === false;
			// a required single atom the cost run can swallow is compared by every way of the run (row())
			$atom = $item['type'] === 'set' && $item['min'] === 1 && $item['reach'] === 1 && self::intersects($state['costSet'], $set);
			[$before, $ways] = [$state['cost'], $state['ways']];
			// with no run going on there is no row, and nothing to end
			$open = str_contains($state['costSet'], "\1");
			$ends = $required && $open && self::intersects($state['costSet'], $set) === false;
			$beside = $open && $required === false && $reach > 1 && self::intersects($state['costSet'], $set) === false;
			// the ways it makes: a count's choices, a large one's too; an unbounded one what $seen weighs it
			$spread = $item['reach'] === null ? $seen['unbounded'] : max(1, min($item['reach'], self::COST_SATURATION) - $item['min'] + 1);
			$state = self::counted($state, $set, $item['max'] === null ? self::LARGE_COUNT : $choices, $choices, $required, $seen, $reach, $separated, $spread);
			if($atom)
			{
				$state = self::row($state, $set, $seen);
			}
			elseif($open && $ends === false && $state['cost'] === $before)
			{
				// every way of the run compares it and goes on as it was: one more item of the row
				$state = self::row($state, null, $seen);
			}
			elseif($beside)
			{
				// an optional count beside the run adds ways where it ended, and every way there compared it:
				// `a{0,15}b{0,15}c{0,15}…` reads each count with every way the ones before it made
				$state['spent'] = min($state['spent'] + $ways, self::COST_SATURATION);
				$seen['total'] = max($seen['total'], self::total($state));
			}
			// a required byte set counted exactly (`\.`, `=`, `-{2}`) is the next count's separator
			$state['sep'] = $item['type'] === 'set' && $item['min'] >= 1 && $item['reach'] === $item['min'] ? $set : null;
		}
		
		return $state;
	}
	
	/**
	 * What one unit of a count's reach weighs, in eighths (WEIGHTS): the
	 * most of its own set's, its laziness's and what each step of its
	 * backtrack tests on the byte it gave back — the items that follow it
	 * ($after) up to the first that must read a byte, the costliest of them;
	 * each test's weight holds behind a class's count too. Where none of
	 * those items can start on a byte its set holds, it gives back nothing
	 * they could take and weighs its set alone. A count behind it is entered
	 * at every step, which a small one's few ways do not dwarf
	 * (`\w{0,255}[a-z]{1,2}x` 5 to 7 times the unit, `\w{1,4}\w{0,255}x`
	 * once). Behind an unbounded quantifier, whose run PCRE's JIT leaves
	 * early, a count weighs its ways alone, as UNBOUNDED_REACH allows four
	 * (`\w+\d{0,3}=`), and so does a byte (`.*\.phar` 1 ms a MiB)
	 *
	 * @param list<array> $after
	 */
	protected static function weight(
		array $item,
		array $after,
	): int
	{
		$tests = self::WEIGHTS['unit'];
		$first = str_repeat("\0", 256);
		foreach($after as $index => $next)
		{
			if($next['type'] === 'zero')
			{
				// `\b` and `$` fail at every step of a near-miss, whatever follows them
				$tests = max($tests, $next['anchor'] === '' ? self::WEIGHTS['boundary'] : self::WEIGHTS['end']);
				$first = str_repeat("\1", 256);
				
				break;
			}
			// the bytes it can start on: a group's are its branches' first ones
			$first |= $next['type'] === 'group' ? array_reduce($next['branches'], static fn(string $bytes, array $branch): string => $bytes | self::firstOf($branch), str_repeat("\0", 256)) : $next['set'];
			$tests = max($tests, match(true)
			{
				// each way into an alternation
				$next['type'] === 'group' && $next['max'] !== null && $next['max'] <= 1
					=> self::WEIGHTS['group'] + self::WEIGHTS['way'] * (count($next['branches']) + ($next['min'] === 0 ? 1 : 0)),
				// a small count it enters at every step; a large one, or one behind `+`, weighs its own reach
				$next['reach'] === null || $next['reach'] > 1
					=> $item['reach'] !== null && $next['reach'] !== null && $next['reach'] < self::LARGE_COUNT ? self::WEIGHTS['count'] : self::WEIGHTS['unit'],
				$next['min'] === 0 && $next['kind'] === 'byte' => self::WEIGHTS['optional'],
				// a byte the pattern ends on is only scanned for, matching it being a match
				$next['kind'] === 'byte' => $item['reach'] !== null && self::reads(array_slice($after, $index + 1))
					? self::shared(self::WEIGHTS['test'], self::rowLength($item['set'], array_slice($after, $index))) : self::WEIGHTS['unit'],
				default => self::WEIGHTS['test'],
			});
			if($next['nullable'] === false)
			{
				break;
			}
		}
		$own = match($item['kind'])
		{
			'class' => self::WEIGHTS['class'],
			'group' => self::WEIGHTS['repeat'],
			default => self::WEIGHTS['unit'],
		};
		$weight = self::intersects($item['set'], $first) ? max($own, $tests) : $own;
		
		return max($weight, $item['lazy'] ? self::WEIGHTS['lazy'] : 0);
	}
	
	/**
	 * The compares a row of single atoms at the head of $items costs a way of
	 * a count over $set, as row() counts them: the atoms the count holds, at
	 * most one more than those that share a byte with the first
	 *
	 * @param list<array> $items
	 */
	protected static function rowLength(
		string $set,
		array $items,
	): int
	{
		[$atoms, $like, $first] = [0, 0, null];
		foreach($items as $item)
		{
			if($item['type'] !== 'set' || $item['min'] !== 1 || $item['reach'] !== 1 || self::intersects($set, $item['set']) === false)
			{
				break;
			}
			$first ??= $item['set'];
			$atoms++;
			$like+= self::intersects($first, $item['set']) ? 1 : 0;
		}
		
		return max(1, min($atoms, $like + 1));
	}
	
	/** a weight shared over $compares, rounded up and never under the unit */
	protected static function shared(
		int $weight,
		int $compares,
	): int
	{
		return max(self::WEIGHTS['unit'], intdiv($weight + $compares - 1, $compares));
	}
	
	/**
	 * Whether items must still match something: a zero-width assertion, or
	 * an item that must read a byte
	 *
	 * @param list<array> $items
	 */
	protected static function reads(
		array $items,
	): bool
	{
		foreach($items as $item)
		{
			if($item['type'] === 'zero' || $item['nullable'] === false)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Whether a sequence holds an unbounded quantifier (`*`, `+`, `{n,}`), in
	 * a group inside it too
	 *
	 * @param list<array> $sequence
	 */
	protected static function holdsUnbounded(
		array $sequence,
	): bool
	{
		foreach($sequence as $item)
		{
			if($item['type'] === 'zero')
			{
				continue;
			}
			if($item['reach'] === null)
			{
				return true;
			}
			foreach($item['type'] === 'group' ? $item['branches'] : [] as $branch)
			{
				if(self::holdsUnbounded($branch))
				{
					return true;
				}
			}
		}
		
		return false;
	}
	
	/**
	 * The ways out of a group that may match nothing: the ones through it
	 * ($inner) and, past a group marked optional, the one that skips it
	 * ($state); a branch that matches nothing is already one of the ways
	 * through. Each set keeps both ways' bytes. Both ways read what follows:
	 * a row goes on, read by the ways of both, every one of which compared
	 * the group — one more item of it. What the two have read is the larger,
	 * and what the runs they ended read no less than either keeps
	 *
	 * @param array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int} $inner
	 * @param array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int} $state
	 * @param array{conflict: string, cost: int, total: int, unbounded: int} $seen
	 * @return array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int}
	 */
	protected static function skipped(
		array $inner,
		array $state,
		bool $optional,
		array &$seen,
	): array
	{
		$through = $inner['atoms'] + $inner['extra'] > 0 ? $inner['base'] : $inner['cost'];
		$skip = $state['atoms'] + $state['extra'] > 0 ? $state['base'] : $state['cost'];
		$read = max(self::total($inner), self::total($state));
		$spent = min($inner['spent'], $state['spent']);
		$inner['open'] |= $state['open'];
		$inner['chain'] |= $state['chain'];
		$inner['choices'] = max($inner['choices'], $state['choices']);
		$inner['countSet'] |= $state['countSet'];
		$inner['counts'] = max($inner['counts'], $state['counts']);
		$inner['costSet'] |= $state['costSet'];
		// the way that skips it ends on no separator
		$inner['sep'] = null;
		if($optional === false)
		{
			$inner['cost'] = max($inner['cost'], $state['cost']);
			$inner['spent'] = max($inner['spent'], $state['spent']);
			[$inner['ways'], $inner['dup']] = [max($inner['ways'], $state['ways']), max($inner['dup'], $state['dup'])];
			$inner['start'] = min($inner['cost'], max($inner['start'], $state['start']));
			
			return $inner;
		}
		[$inner['ways'], $inner['dup']] = [min($inner['ways'] + $state['ways'], self::COST_SATURATION), min($inner['dup'] + $state['dup'], self::COST_SATURATION)];
		$inner['first'] = self::union($inner['first'], $state['first']);
		[$inner['atoms'], $inner['like'], $inner['extra']] = [max($inner['atoms'], $state['atoms']), max($inner['like'], $state['like']), max($inner['extra'], $state['extra']) + 1];
		[$inner['base'], $inner['spent'], $inner['start']] = [min($through + $skip, self::COST_SATURATION), $spent, 1];
		$inner = self::read($inner, $seen);
		$inner['spent'] = max($spent, $read - $inner['cost']);
		$seen['total'] = max($seen['total'], self::total($inner));
		
		return $inner;
	}
	
	/**
	 * The cost run after one more item of its row: a required single atom
	 * the run can swallow ($set), or an item every way of it compares and
	 * goes on past without a choice (null). Each way reads the row from
	 * where it ends, so 250 `\w` behind `\w{0,1023}` cost 1024 × 250, as
	 * `\w{250}` does (JIT 68 s a MiB). A position goes past the first atom
	 * only where its byte matches it, so the atoms count at most one more
	 * than those that share a byte with the first (`\.php` behind `[^/]+`
	 * counts 2, not 4); every other item counts one, an optional byte or
	 * group the run skips included. The row starts where the run's ways last
	 * changed, its ways then the cost (`base`)
	 *
	 * @param array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int} $state
	 * @param array{conflict: string, cost: int, total: int, unbounded: int} $seen
	 * @return array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int}
	 */
	protected static function row(
		array $state,
		?string $set,
		array &$seen,
	): array
	{
		if($state['atoms'] + $state['extra'] === 0)
		{
			[$state['first'], $state['like'], $state['base']] = [null, 0, $state['cost']];
		}
		if($set === null)
		{
			$state['extra']++;
		}
		else
		{
			$state['first'] ??= $set;
			$state['atoms']++;
			$state['like']+= self::intersects($state['first'], $set) ? 1 : 0;
		}
		
		return self::read($state, $seen);
	}
	
	/**
	 * The cost run as its row has it: the row's ways times its atoms, at
	 * most one more than those like the first, and its other items
	 *
	 * @param array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int} $state
	 * @param array{conflict: string, cost: int, total: int, unbounded: int} $seen
	 * @return array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int}
	 */
	protected static function read(
		array $state,
		array &$seen,
	): array
	{
		$state['cost'] = min($state['base'] * (min($state['atoms'], $state['like'] + 1) + $state['extra']), self::COST_SATURATION);
		$seen['cost'] = max($seen['cost'], $state['cost']);
		$seen['total'] = max($seen['total'], self::total($state));
		
		return $state;
	}
	
	/**
	 * The runs after one more item with $choices ways through it, $counts
	 * of them its counts' own, $reach what one start reads through it
	 * (run()); $separated, whether it stands right behind a separator its
	 * set cannot match, $spread the ways it makes. A required item the cost
	 * run cannot swallow ends it, what it read then spent; a row ends with
	 * the run or where its ways change
	 *
	 * @param array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int} $state
	 * @param array{conflict: string, cost: int, total: int, unbounded: int} $seen
	 * @return array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int}
	 */
	protected static function counted(
		array $state,
		string $set,
		int $choices,
		int $counts,
		bool $required,
		array &$seen,
		int $reach = 1,
		bool $separated = false,
		int $spread = 1,
	): array
	{
		[$state['chain'], $state['choices']] = self::run($state['chain'], $state['choices'], $set, $choices, $required);
		[$state['countSet'], $state['counts']] = self::run($state['countSet'], $state['counts'], $set, $counts, $required);
		$cost = $state['cost'];
		$open = str_contains($state['costSet'], "\1");
		$overlaps = self::intersects($state['costSet'], $set);
		$ends = $required && $open && $overlaps === false;
		[$state['costSet'], $state['cost']] = self::costRun($state['costSet'], $state['cost'], $set, $reach, $required, $separated, $state['dup']);
		// past a byte that ends the run only the ways that stood at one position go on; a count the run overlaps, or
		// one with no run going on, stacks at most its choices of them on one position, one behind a separator none;
		// one the run cannot reach spreads only the ways at the run's end
		[$state['ways'], $state['dup']] = match(true)
		{
			$ends => [min($state['dup'] * $spread, self::COST_SATURATION), $state['dup']],
			$spread === 1 => [$state['ways'], $state['dup']],
			$overlaps || $open === false => [min($state['ways'] * $spread, self::COST_SATURATION), $separated ? $state['dup'] : min($state['dup'] * $spread, $state['ways'])],
			default => [min($state['ways'] + $state['dup'] * ($spread - 1), self::COST_SATURATION), $state['dup']],
		};
		if($ends || $state['cost'] !== $cost)
		{
			$state['spent'] = $ends && $cost > 1 ? min($state['spent'] + $cost, self::COST_SATURATION) : $state['spent'];
			[$state['atoms'], $state['extra'], $state['like'], $state['first']] = [0, 0, 0, null];
		}
		if($ends)
		{
			// the ways that go on have read nothing past the byte yet; a count that ends the run reads at once
			$state['start'] = $reach > 1 ? 1 : $state['cost'];
		}
		$seen['cost'] = max($seen['cost'], $state['cost']);
		$seen['total'] = max($seen['total'], self::total($state));
		if($seen['conflict'] === '' && $state['choices'] > self::BOUNDED_CHOICES_MAX)
		{
			$seen['conflict'] = self::CONFLICT_OVERLAP;
		}
		if($seen['conflict'] === '' && $state['counts'] > self::COUNT_CHOICES_MAX)
		{
			$seen['conflict'] = self::CONFLICT_COUNTS;
		}
		
		return $state;
	}
	
	/**
	 * One run — its bytes and the product of its choices — after one more
	 * item with $choices ways through it: an item with a choice multiplies
	 * the run it overlaps or starts one; a required item the run cannot
	 * swallow ends it. The product stops one past BOUNDED_CHOICES_MAX, which
	 * both runs' limits already refuse: forty `(?:x|xx|xxx)` would pass what
	 * an integer holds
	 *
	 * @return array{string, int}
	 */
	protected static function run(
		string $bytes,
		int $product,
		string $set,
		int $choices,
		bool $required,
	): array
	{
		$overlaps = self::intersects($bytes, $set);
		if($choices > 1)
		{
			if($overlaps)
			{
				return [$bytes | $set, min($product * $choices, self::BOUNDED_CHOICES_MAX + 1)];
			}
			
			return $required ? [$set, $choices] : [$bytes | $set, max($product, $choices)];
		}
		
		return $required && $overlaps === false ? [str_repeat("\0", 256), 1] : [$bytes, $product];
	}
	
	/**
	 * The cost run — its bytes and what one start reads — after one more
	 * item reading $reach: one the run overlaps multiplies it (behind a
	 * separator ($separated) by SEPARATED_WAYS, or the item's own where that
	 * is more); with no run going on, every way goes on into it. A required
	 * item the run cannot swallow ends it, the $dup ways that stood at one
	 * position going on; an optional one adds its reach for those ways
	 *
	 * @return array{string, int}
	 */
	protected static function costRun(
		string $bytes,
		int $product,
		string $set,
		int $reach,
		bool $required,
		bool $separated,
		int $dup,
	): array
	{
		if($reach <= 1)
		{
			$ends = $required && str_contains($bytes, "\1") && self::intersects($bytes, $set) === false;
			
			return $ends ? [str_repeat("\0", 256), $dup] : [$bytes, $product];
		}
		if(self::intersects($bytes, $set) || str_contains($bytes, "\1") === false)
		{
			$product = $separated && self::intersects($bytes, $set) ? max($product * self::SEPARATED_WAYS, $reach) : $product * $reach;
			
			return [$bytes | $set, min($product, self::COST_SATURATION)];
		}
		
		return $required ? [$set, min($dup * $reach, self::COST_SATURATION)] : [$bytes | $set, min($product + $dup * ($reach - 1), self::COST_SATURATION)];
	}
	
	/**
	 * What one start has read so far: the runs ended and the one going on,
	 * once it read past what it began with — a run without a choice
	 * nothing (the items it passes are dwarfed by the runs with one), nor
	 * the ways a run that ended left at the end of the pattern
	 *
	 * @param array{open: string, chain: string, choices: int, countSet: string, counts: int, costSet: string, cost: int, spent: int, sep: ?string, atoms: int, first: ?string, like: int, extra: int, base: int, ways: int, dup: int, start: int} $state
	 */
	protected static function total(
		array $state,
	): int
	{
		return min($state['spent'] + ($state['cost'] > $state['start'] ? $state['cost'] : 0), self::COST_SATURATION);
	}
	
	/** two rows' first atoms as one: either one where the other is none */
	protected static function union(
		?string $a,
		?string $b,
	): ?string
	{
		return $a === null || $b === null ? $a ?? $b : $a | $b;
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
	 * zero-width assertion) with its quantifier's min and max (null = no max,
	 * a large count's too), its reach, the count's own max (null = none),
	 * whether it is lazy, and its kind: how a set was written — `byte` one
	 * byte (`a`, `\.`, `[a]`), `short` a shorthand, `.` or every byte but one
	 * (`[^/]`), `class` any other class — or `group`
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
				$items[] = ['type' => 'zero', 'anchor' => $char];
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
				$item = ['type' => 'group', 'branches' => $branches, 'set' => self::unionOf($branches), 'nullable' => self::nullableOf($branches), 'kind' => 'group'];
			}
			else
			{
				$kind = match(true)
				{
					$char === '[' => preg_match(self::ONE_MEMBER, $value, $member, 0, $at) === 1 ? ($member[1] === '^' ? 'short' : 'byte') : 'class',
					$char === '.' || ($char === '\\' && self::isShorthand($value[$at + 1] ?? '')) => 'short',
					default => 'byte',
				};
				$set = self::parseAtom($value, $at, $ci);
				// `\b`, `\B`: zero-width, and no quantifier is read after them
				if($set === null)
				{
					$items[] = ['type' => 'zero', 'anchor' => ''];
					
					continue;
				}
				$item = ['type' => 'set', 'set' => $set, 'nullable' => false, 'kind' => $kind];
			}
			
			[$min, $max, $reach, $lazy] = self::parseQuantifier($value, $at);
			$item['min'] = $min;
			$item['max'] = $max;
			$item['reach'] = $reach;
			$item['lazy'] = $lazy;
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
	 * `* + ? {n} {n,} {n,m}`, a lazy `?` after any of them, as [min, max,
	 * reach, lazy]: max null for none and for a large count, reach the
	 * count's own max (null for none); [1, 1, 1, false] when none follows (a
	 * `{` that is no count is a literal, read as an atom)
	 *
	 * @return array{0: int, 1: int|null, 2: int|null, 3: bool}
	 */
	protected static function parseQuantifier(
		string $value,
		int &$at,
	): array
	{
		$char = $value[$at] ?? '';
		$quantifier = match($char)
		{
			'*' => [0, null, null],
			'+' => [1, null, null],
			'?' => [0, 1, 1],
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
				? [$min, $min, $min]
				: [$min, self::isUnboundedMax($max) ? null : $max, $max];
		}
		else
		{
			return [1, 1, 1, false];
		}
		$lazy = ($value[$at] ?? '') === '?';
		$at+= $lazy ? 1 : 0;
		
		return [...$quantifier, $lazy];
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
	
	/** this instance's word on the last failed pull (pullFailed()); null until it read or wrote one */
	protected ?int $failedAt = null;
	
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
	
	/**
	 * A pull that failed at $at (Kernel::RETRY holds the next off), 0 for one
	 * that did not: in APCu, and beside the file (`<file>.failed`), so a host
	 * without APCu does not pull on every request either; an eviction costs
	 * one more attempt
	 */
	public function pullFailed(
		int $at,
	): void
	{
		if($at === 0 && $this->pullFailedAt() === 0)
		{
			return;
		}
		$this->failedAt = $at;
		if($this->apcu)
		{
			if($at === 0)
			{
				apcu_delete($this->key('failed'));
			}
			else
			{
				apcu_store($this->key('failed'), $at, 3600);
			}
		}
		$path = $this->file === '' ? '' : $this->file . '.failed';
		if($path === '' || is_link($path))
		{
			return;
		}
		if($at === 0)
		{
			@unlink($path);
			
			return;
		}
		@file_put_contents($path, (string)$at, LOCK_EX);
	}
	
	/** when the last pull failed, 0 when it did not: this instance's word, else APCu's, else the file's */
	public function pullFailedAt(): int
	{
		if($this->failedAt !== null)
		{
			return $this->failedAt;
		}
		$at = $this->apcu ? apcu_fetch($this->key('failed')) : false;
		if(is_int($at))
		{
			return $at;
		}
		$path = $this->file === '' ? '' : $this->file . '.failed';
		if($path === '' || is_link($path) || is_file($path) === false)
		{
			return 0;
		}
		
		return (int)@file_get_contents($path);
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
	
	/**
	 * the ceiling — a ruleset not renewed this long keeps only its blocking
	 * rules (Ruleset::pastCeiling()): a site kept from codesafe stays
	 * protected, and a codesafe incident neither disarms the fleet nor leaves
	 * it observing what codesafe would have dropped
	 */
	public const CEILING = 86400;
	
	/** a pull that failed holds the next off this long, forced or not: a door that is down is asked once a minute, never on every request */
	public const RETRY = 60;
	
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
	
	/**
	 * the ids of the rules the last pull left out (Ruleset::$dropped), a
	 * comma list each pull sends while the stored ruleset names any: a door
	 * that knows it keeps what the site holds, any other ignores it
	 */
	public const HEADER_DROPPED = 'X-Shield-Dropped';
	
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
	
	/** @var array<string, array{width: ?int, cost: int}> what each pattern weighs (weighs()), by its `ci` and value */
	protected static array $weights = [];
	
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
	 * What X-Shield-Platforms names beside the core: each module's name, then
	 * the words it reads beyond its first release (a module's optional
	 * words(): WordPress's XML-RPC), so a door serves a rule in those words
	 * only to a kernel that reads them
	 *
	 * @return list<string>
	 */
	protected function platformWords(): array
	{
		$words = [];
		foreach($this->platforms as $platform)
		{
			$words[] = $platform->name();
			foreach(method_exists($platform, 'words') ? (array)$platform->words() : [] as $word)
			{
				if(is_string($word) && $word !== '')
				{
					$words[] = $word;
				}
			}
		}
		
		return $words;
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
	 * rule's. A regex PCRE gives up on over a value is what the kernel did
	 * not read whole: a vpatch's condition holds `unread` (patched()), a
	 * match rule, which nothing pins, observes `unread`, held where it would
	 * block; a rate rule's counts nothing. The one side effect: a rate rule's
	 * predicate that matches counts the request
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
			$now ??= time();
			// past the ceiling the blocking rules hold, each until its expiry, and every request asks for a pull until one renews them
			if($ruleset->isStale($now, $this->ceiling))
			{
				$this->store->forcePull();
				$ruleset = $ruleset->pastCeiling($now);
				if($ruleset->rules === [])
				{
					return Verdict::pass('ceiling');
				}
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
			[$subs, $unread, $failed] = self::subRequests($facts);
			// the blocking rules first, whatever order they were served in: their tests read an upload before an observing one spends the budget
			foreach(self::blockingFirst($ruleset->rules) as $rule)
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
						$overflow = self::overflows($facts, $unread, $failed);
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
				// its own name: $unread holds the modules whose sub-requests went unread, which every vpatch after it asks
				$gaveUp = false;
				$matched = $this->matched($rule, $facts, $gaveUp);
				if($matched === null && $gaveUp === false)
				{
					continue;
				}
				$blocks = Ruleset::blocks($rule['mode'] ?? '') && $consent->blocks();
				// a pattern the engine gave up on: no entry point pins a match rule, so it observes as an unpinned vpatch does, held
				// where it would block (a later blocking rule still blocks), and says it read nothing whole
				if($matched === null)
				{
					$unreadVerdict = new Verdict(Verdict::OBSERVE, $rule, '', Verdict::REASON_UNREAD);
					if($blocks)
					{
						$held ??= $unreadVerdict;
						
						continue;
					}
					
					return $held ?? $unreadVerdict;
				}
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
	
	/**
	 * A rule's predicate over the request: the fragment of the first of the
	 * field's subjects (Facts::subjects()) it matches, or null; $unread says
	 * whether PCRE gave up on a subject that matched nothing (its JIT stack,
	 * its backtrack or recursion limit) — never the subject cut without the
	 * JIT, which a match rule reads as no match (Facts::REGEX_SUBJECT_CAP)
	 */
	protected function matched(
		array $rule,
		Facts $facts,
		bool &$unread = false,
	): ?string
	{
		$unread = false;
		foreach($facts->subjects((string)$rule['field']) as $subject)
		{
			if(($rule['op'] ?? '') === Ruleset::OP_REGEX)
			{
				// the request's budget lets a long subject be read whole without the JIT
				$found = self::regexFind((string)($rule['value'] ?? ''), ($rule['ci'] ?? true) === true, $subject, false, $facts);
				if($found['found'] !== null)
				{
					return $found['found'];
				}
				$unread = $unread || $found['error'];
				
				continue;
			}
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
			$this->report($verdict, $facts, $now);
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
			if($ruleset === null || $ruleset->usable === false)
			{
				return;
			}
			// past the ceiling the counting runs on what judge() holds and stops with the last rule held: the heartbeat says
			// the kernel still judges; under it a ruleset without a rule counts as any other
			if($ruleset->isStale($now, $this->ceiling))
			{
				$ruleset = $ruleset->pastCeiling($now);
				if($ruleset->rules === [])
				{
					return;
				}
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
				$hit = self::patched($rule, $request);
				// held on what was not read whole: neither honest traffic at the entry point nor a match as far as anyone knows
				if($hit !== null && ($hit['unread'] ?? false))
				{
					continue;
				}
				$entry = $entry || $selecting !== [];
				$matched ??= $hit === null ? null : $request;
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
	 * every platform module given reads them (a WordPress batch's), the
	 * modules that could not read all of theirs, and those that threw
	 * reading them: a module's fault costs the vpatches its sub-requests may
	 * reach, which fail closed (overflows()), never the request
	 *
	 * @return array{list<Facts>, list<Platform>, list<Platform>}
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
			$failed = [];
			foreach($facts->platforms as $platform)
			{
				try
				{
					[$found, $cut] = $platform->subRequests($facts);
				}
				catch(Throwable)
				{
					[$found, $cut] = [[], true];
					$failed[] = $platform;
				}
				$subs = [...$subs, ...$found];
				if($cut)
				{
					$unread[] = $platform;
				}
			}
			
			return [$subs, $unread, $failed];
		});
	}
	
	/**
	 * Whether the sub-requests a module could not read run past the count the
	 * module's platform itself refuses (Platform::overflows()), so a vpatch
	 * they may reach fails closed — as it does where a module threw reading
	 * them ($failed) or asked how many there were
	 *
	 * @param list<Platform> $unread
	 * @param list<Platform> $failed
	 */
	public static function overflows(
		Facts $facts,
		array $unread,
		array $failed = [],
	): bool
	{
		if($failed !== [])
		{
			return true;
		}
		foreach($unread as $platform)
		{
			try
			{
				if($platform->overflows($facts))
				{
					return true;
				}
			}
			catch(Throwable)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Whether sub-requests a module could not read (subRequests()) may have
	 * reached a vpatch — its own word, the one module that knows its
	 * handlers; one that throws answering may have
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
			try
			{
				if($platform->reaches($rule, $facts))
				{
					return true;
				}
			}
			catch(Throwable)
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
		?int $now = null,
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
			$stale = $this->staleness($now ?? time());
			if($verdict->isRate())
			{
				$this->reportRate($verdict, $facts, $stale);
				
				return;
			}
			// a verdict on what was not read whole says so — `reason`, the tag codesafe's grid filters by — and names no match: the
			// value that pinned the handler is no payload, and an honest heavy save refused there must not read as an exploit
			$unread = $verdict->reason === Verdict::REASON_UNREAD;
			$tags = [...($unread ? [Verdict::REASON_UNREAD] : []), ...($stale === [] ? [] : [Verdict::TAG_STALE])];
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
			] + ($tags === [] ? [] : ['tags' => $tags]) + $stale + (Ruleset::isVpatch($rule) ? ['who' => (string)($rule['who'] ?? '')] : []));
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
		array $stale = [],
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
		] + ($stale === [] ? [] : ['tags' => [Verdict::TAG_STALE]] + $stale));
	}
	
	/**
	 * What a report says of a ruleset past its ceiling: `pulled_at`, the
	 * second of its last good pull — the report is tagged `stale` beside it;
	 * nothing under the ceiling
	 *
	 * @return array{pulled_at?: int}
	 */
	protected function staleness(
		int $now,
	): array
	{
		$ruleset = $this->ruleset();
		
		return $ruleset !== null && $ruleset->usable && $ruleset->isStale($now, $this->ceiling) ? ['pulled_at' => $ruleset->fetchedAt] : [];
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
	
	/** whether a target reads a secret's value: any cookie, a header or a parameter named like a secret, a parameter by a wildcard name, any module's named one */
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
		
		$prefix = substr($target, 0, $at);
		
		return match($prefix)
		{
			'cookie' => true,
			'header' => self::secretName($name),
			'query', 'body', 'request', 'json', 'file' => str_contains($name, '*') || self::secretName($name),
			// a module's named target (`xmlrpc:2`) may be a password by its place alone
			default => in_array($prefix, Ruleset::TARGET_PREFIXES, true) === false,
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
	 * detect (no network); skipped inside the interval unless forced, and
	 * within RETRY of a pull that failed unless forced by the caller ($force);
	 * locked when another request of the pool is pulling; fresh (200,
	 * stored), unchanged (304, the ceiling renewed), refused (a contract this
	 * kernel does not know, or the door's 401 for this key — stored unusable,
	 * so every rule lifts and the door is not hammered), failed (anything
	 * else — the cache is left alone, the next pull waits RETRY)
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
			// a pull that failed less than RETRY ago holds this one off, forced by a request or not; a failure that lies ahead (the clock
			// set back) holds nothing
			$failedAt = $this->store->pullFailedAt();
			if($force === false && $failedAt !== 0 && $failedAt <= $now && $now < $failedAt + self::RETRY)
			{
				return self::PULL_SKIPPED;
			}
			if($this->store->lock('pull') === false)
			{
				return self::PULL_LOCKED;
			}
			try
			{
				$pulled = $this->fetch($current, $now);
			}
			finally
			{
				$this->store->unlock('pull');
			}
			$this->store->pullFailed($pulled === self::PULL_FAILED ? $now : 0);
			
			return $pulled;
		}
		catch(Throwable $e)
		{
			$this->log('pull failed: ' . $e->getMessage());
			$this->store->pullFailed($now);
			
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
		$platforms = implode(',', [self::PLATFORM_CORE, ...$this->platformWords()]);
		$headers = ['X-Codesafe-Key: ' . $this->key, 'X-Console-Key: ' . $this->key, 'Accept: application/json',
			self::HEADER_KINDS . ': ' . self::KINDS, self::HEADER_PLATFORMS . ': ' . $platforms];
		// what the last pull left out, so the door knows the site does not hold it
		if($current !== null && $current->dropped !== [])
		{
			$headers[] = self::HEADER_DROPPED . ': ' . implode(',', $current->dropped);
		}
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
		// codesafe refusing this key (rotated, its project switched off or deleted) over the connection the site trusts, not a
		// site cut off: every rule lifts, as on a contract this kernel does not know, and the interval applies
		if($status === 401 && self::refusesKey($response))
		{
			$this->log('pull answered 401: the door refuses this key, every rule lifted until it answers');
			$this->store->write(Ruleset::refused($now, $this->platformNames())->toRecord($this->sealKey));
			$this->rulesetRead = false;
			
			return self::PULL_REFUSED;
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
		if($ruleset->dropped !== [])
		{
			$this->log('pull kept ' . count($ruleset->rules) . ' rules and left out rule ' . implode(', ', $ruleset->dropped) . ': past the '
				. Ruleset::RULES_MAX . ' match and rate rules or ' . Ruleset::VPATCHES_MAX . ' vpatches a kernel keeps, or refused by its own checks');
		}
		if($ruleset->usable === false)
		{
			$this->log('pull refused: contract ' . json_encode($payload['contract'] ?? null) . ' dialect ' . json_encode($payload['dialect'] ?? null));
			
			return self::PULL_REFUSED;
		}
		
		return self::PULL_FRESH;
	}
	
	/**
	 * Whether a 401 is the door's own refusal of the key — its JSON, `success`
	 * false — and no page a proxy or an HTTP login in front of the instance
	 * answers, which is a failed pull
	 */
	protected static function refusesKey(
		array $response,
	): bool
	{
		$body = (string)($response['body'] ?? '');
		// a door's refusal is a few bytes; anything longer is no door's, and is never decoded
		$payload = strlen($body) > 4096 ? null : json_decode($body, true);
		
		return is_array($payload) && ($payload['success'] ?? null) === false;
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
	 * A ruleset's rules with those whose mode blocks first, each part in its
	 * own order
	 *
	 * @param list<array<string, mixed>> $rules
	 * @return list<array<string, mixed>>
	 */
	protected static function blockingFirst(
		array $rules,
	): array
	{
		$blocking = array_filter($rules, static fn(array $rule): bool => Ruleset::blocks($rule['mode'] ?? ''));
		
		return [...$blocking, ...array_diff_key($rules, $blocking)];
	}
	
	/**
	 * A vpatch over the request: the value that passed (a parameter's, else
	 * the frame's) and whether all of it was answered — `who` and any nonce
	 * test — or null when it does not hold. A request that is not signed in
	 * lacks every capability; a signed-in one asks Facts::can(). A condition
	 * over what the kernel did not read whole — a JSON body past
	 * Facts::JSON_CAP, a form it parsed itself past Facts::FORM_CAP, an
	 * upload past what Facts::FILE_BUDGET left, a value a regex could not
	 * run over, a decode step's values past Ruleset::DECODED_MAX or a
	 * module's own bound — is answered as holding once an entry that held
	 * answered pins the handler (pins()), or a module's frame entry the
	 * kernel could not read does — an XML-RPC call past Facts::RAW_CAP is
	 * still xmlrpc.php's: the app reads it whole, and padding must not turn
	 * a block into an observe; `unread` says the answer rests on that. An
	 * entry that throws is unread and pins nothing, so a module's fault costs
	 * the rule judged, never the request. A rule's answer is kept for the
	 * request: tally() reads what judge() read
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
			try
			{
				$hit = self::held((array)$entry, $facts);
			}
			catch(Throwable)
			{
				// a module or a test that throws costs this entry alone: unread, and it pins nothing
				$hit = ['matched' => '', 'resolved' => false, 'unread' => true, 'frame' => false];
			}
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
			// a module's frame it could not read still names the handler family (an XML-RPC call is xmlrpc.php's whatever it holds)
			$pinned = $pinned || (($hit['resolved'] || (($hit['unread'] ?? false) && $hit['frame'])) && self::pins((array)$entry, $facts->platforms));
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
	 * never being in one), a frame member's before any other, as an unread
	 * frame still names the handler — with `frame` saying whether the
	 * holding target is a frame target
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
				// an unread branch never answers for one that holds answered; of the unread, a frame names the handler (patchedNow())
				if($hit['resolved'])
				{
					return $hit;
				}
				if($pending === null || ($hit['frame'] && $pending['frame'] === false))
				{
					$pending = $hit;
				}
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
	 * a form it parsed itself past Facts::FORM_CAP, an upload past what
	 * Facts::FILE_BUDGET left, any value a regex could not run over, a decode
	 * step's values past DECODED_MAX or a module's own bound — holds the
	 * condition unanswered where no value read passes and says so
	 * (`unread`), for patched() to answer. One over the request's uploads is
	 * answered once, whichever rule asks it
	 *
	 * @return ?array{matched: string, resolved: bool, unread?: true}
	 */
	public static function condition(
		array $condition,
		Facts $facts,
	): ?array
	{
		if(str_starts_with((string)$condition['target'], 'file-content:') === false)
		{
			return self::conditionNow($condition, $facts);
		}
		$names = implode(',', array_map(static fn(Platform $platform): string => $platform->name(), $facts->platforms));
		
		// read and paid for once: three vpatches asking it at one handler spend the upload budget once
		return $facts->keptShared('upload:' . hash('xxh3', $names . "\0" . serialize($condition)), static fn(): ?array => self::conditionNow($condition, $facts));
	}
	
	/**
	 * condition(), computed
	 *
	 * @return ?array{matched: string, resolved: bool, unread?: true}
	 */
	protected static function conditionNow(
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
		// a module's target over what the module did not read whole (WordPress's XML-RPC call past its bounds): the same
		if(self::moduleUnread($target, $facts))
		{
			return ['matched' => '', 'resolved' => false, 'unread' => true];
		}
		// what the kernel did not read — the decode steps' values past the request's budget (Facts::DECODED_BUDGET) or a step's own
		// bound, a form's pairs past Facts::FORM_CAP — may hold what no value read did: the condition holds unanswered and says so,
		// for patched() to answer on a pinned handler
		$cut = ['matched' => '', 'resolved' => false, 'unread' => true];
		$formCut = self::readsForm($target) && $facts->formUnread();
		$test = (string)$condition['test'];
		$upload = str_starts_with($target, 'file-content:') ? substr($target, strlen('file-content:')) : null;
		if($upload !== null && $test === 'exists')
		{
			// an upload is there whether or not it is read: its bytes are never needed
			return self::uploaded($facts, $upload) ? ['matched' => '', 'resolved' => true] : null;
		}
		// unreadable: an upload the host could not read — the host's failure, never a cap; $fileCut: one past the upload budget
		[$values, $unreadable, $fileCut] = $upload !== null
			? self::contents($facts, $upload, Facts::fileWeight($test, self::patternOf($condition), ($condition['ci'] ?? true) === true))
			: [self::values($target, $facts), false, false];
		if($test === 'exists')
		{
			return $values === [] ? ($formCut ? $cut : null) : ['matched' => $values[0], 'resolved' => true];
		}
		if($test === 'nonce_invalid')
		{
			// no nonce sent is an invalid one, unless the form or the upload it would be in was cut
			if($values === [])
			{
				return $formCut || $fileCut ? $cut : ['matched' => '', 'resolved' => true];
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
			// what a step left unread, or an upload past the budget, may hold
			if($short || $fileCut)
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
				// an upload's regex runs over all of it, which its weight keeps short; any other value's past Facts::REGEX_SUBJECT_CAP may go unread without the JIT
				$passed = $test === 'regex' || $test === 'not_regex'
					? self::regexAnswer($test, $decoded, $condition, $upload !== null, $facts) : self::passes($test, $decoded, $condition, $facts->host());
				if($passed === true)
				{
					return ['matched' => $decoded, 'resolved' => true];
				}
				// a pattern PCRE gave up on (its JIT stack, its backtrack or recursion limit) answered neither yes nor no, whatever it read:
				// `(ab)+c` does on 16 KiB of `ab` under the JIT; so did one that read only the first KiB of a value without the JIT
				$short = $short || $passed === null;
			}
		}
		// what a step left unread, an upload past the budget or a value past a pattern's reach may hold
		if($short || $fileCut)
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
	 * Whether the module that reads a target did not read it whole for this
	 * request: its optional unread(), which a module without bounds of its
	 * own does not have
	 */
	protected static function moduleUnread(
		string $target,
		Facts $facts,
	): bool
	{
		$platform = Ruleset::targetOf($target, $facts->platforms);
		
		return $platform !== null && method_exists($platform, 'unread') && $platform->unread($target, $facts) === true;
	}
	
	/** a regex test's pattern, what Facts::fileWeight() weighs it by; null for any other test */
	protected static function patternOf(
		array $condition,
	): ?string
	{
		$test = (string)($condition['test'] ?? '');
		
		return ($test === 'regex' || $test === 'not_regex') && is_string($condition['value'] ?? null) ? $condition['value'] : null;
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
	 * An upload field's contents (Facts::fileContent()) as a test of this
	 * weight reads them within Facts::FILE_BUDGET, each costing its size
	 * times the weight, Facts::FILE_TEST_MIN at least; whether the host
	 * could not read one; and whether one was past what the budget left. A
	 * failed upload, with no temp path, never reached the app and is not
	 * there. A batch's sub-request has none of its own: its handler reads
	 * its batch's, through the batch's own reads
	 *
	 * @return array{list<string>, bool, bool}
	 */
	public static function contents(
		Facts $facts,
		string $name,
		int $weight = 1,
	): array
	{
		$contents = [];
		$unread = false;
		$cut = false;
		foreach(self::pick($facts->uploads, $name) as $path)
		{
			if($path === '')
			{
				continue;
			}
			// past what the budget left for the least test: not even opened
			if(Facts::FILE_TEST_MIN > $facts->fileRemaining())
			{
				$cut = true;
				
				continue;
			}
			// asked for no more than this test may still read: a longer upload answers its length and stays on disk
			$content = $facts->fileContent($path, intdiv($facts->fileRemaining(), $weight));
			$unread = $unread || $content === null;
			// checked before it is spent: an upload cut leaves the budget to a smaller one after it
			if(is_int($content) || (is_string($content) && $facts->spendFile(max(strlen($content) * $weight, Facts::FILE_TEST_MIN)) === false))
			{
				$cut = true;
			}
			else if($content !== null)
			{
				$contents[] = $content;
			}
		}
		$outer = $facts->outer();
		if($outer === null)
		{
			return [$contents, $unread, $cut];
		}
		// read once per request, however many sub-requests reach the rule
		[$outers, $outerUnread, $outerCut] = self::contents($outer, $name, $weight);
		
		return [[...$contents, ...$outers], $unread || $outerUnread, $cut || $outerCut];
	}
	
	/** whether an upload field holds an upload with a temp path, its own or the batch's a sub-request came in */
	protected static function uploaded(
		Facts $facts,
		string $name,
	): bool
	{
		foreach(self::pick($facts->uploads, $name) as $path)
		{
			if($path !== '')
			{
				return true;
			}
		}
		$outer = $facts->outer();
		
		return $outer !== null && self::uploaded($outer, $name);
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
	
	/**
	 * Whether a regex matches, as match() runs it: null when the engine
	 * refuses the pattern or gives up, or when no match in a subject cut at
	 * Facts::REGEX_SUBJECT_CAP says nothing of the rest
	 */
	protected static function regexes(
		string $pattern,
		string $subject,
		bool $ci,
	): ?bool
	{
		$found = self::regexFind($pattern, $ci, $subject, false);
		
		return $found['unread'] ? null : $found['found'] !== null;
	}
	
	/**
	 * A regex or not_regex test over a value as a condition reads it
	 * (regexFind()): true or false, null where the answer is not known,
	 * which leaves the condition unread; an upload's whole ($whole), within
	 * its weight
	 */
	protected static function regexAnswer(
		string $test,
		string $subject,
		array $condition,
		bool $whole,
		Facts $facts,
	): ?bool
	{
		$value = $condition['value'] ?? '';
		$found = self::regexFind(is_string($value) ? $value : '', ($condition['ci'] ?? true) === true, $subject, $whole, $facts);
		if($found['unread'])
		{
			return null;
		}
		
		return $test === 'regex' ? $found['found'] !== null : $found['found'] === null;
	}
	
	/**
	 * A regex over a subject: `found`, the fragment it matched, null for
	 * none; `unread`, whether that answer is not known — PCRE refused the
	 * pattern or gave up on it (`error` says so), or, without the JIT or for
	 * a pattern it runs without its early exit (RegexGate::loops()), one with a
	 * quantifier read only Facts::REGEX_SUBJECT_CAP bytes of a longer
	 * subject and found nothing there, or a match the cut ended that reads
	 * the subject's end. `whole` reads all of it, as an upload is read
	 * within its weight; with the JIT any other pattern, and a pattern
	 * without a quantifier, reads all of it always; with the request's $facts, a
	 * pattern with one reads all of it within what the request may still
	 * spend (Facts::spendRegex()), its bytes weighted by the pattern's cost,
	 * up to Facts::REGEX_WHOLE_MAX_INTERPRETED, and up to
	 * Facts::REGEX_WHOLE_BYTES_INTERPRETED bytes whatever the cost
	 *
	 * @return array{found: ?string, unread: bool, error: bool}
	 */
	protected static function regexFind(
		string $value,
		bool $ci,
		string $subject,
		bool $whole,
		?Facts $facts = null,
	): array
	{
		// cut BEFORE the engine sees it: the interpreter's backtracking runs within pcre.backtrack_limit at every start,
		// and the JIT's too where it has no early exit (RegexGate::loops())
		$weighs = self::weighs($value, $ci);
		$cut = $whole === false && strlen($subject) > Facts::REGEX_SUBJECT_CAP && (Facts::jit() === false || $weighs['loops']) && $weighs['width'] === null;
		if($cut && $facts !== null)
		{
			$weighted = self::weighted(strlen($subject), $value, $ci);
			$cut = strlen($subject) > Facts::REGEX_WHOLE_BYTES_INTERPRETED || $weighted > Facts::REGEX_WHOLE_MAX_INTERPRETED || $facts->spendRegex($weighted) === false;
		}
		$pattern = self::regexPattern($value, $ci);
		// @: a pattern PCRE refuses warns and returns false, as does one it gives up on
		$found = @preg_match($pattern, $cut ? substr($subject, 0, Facts::REGEX_SUBJECT_CAP) : $subject, $match, PREG_OFFSET_CAPTURE);
		if($found === false)
		{
			return ['found' => null, 'unread' => true, 'error' => true];
		}
		if($found !== 1)
		{
			return ['found' => null, 'unread' => $cut, 'error' => false];
		}
		// the cut is not the subject's end: a match that reaches it stands only for a pattern that never reads the end —
		// `\.php$` must not match a value whose first KiB happens to end in .php
		if($cut && $match[0][1] + strlen($match[0][0]) >= Facts::REGEX_SUBJECT_CAP && self::readsTheEnd($value))
		{
			return ['found' => null, 'unread' => true, 'error' => false];
		}
		
		return ['found' => $match[0][0], 'unread' => false, 'error' => false];
	}
	
	/**
	 * Whether a pattern reads the subject's end — an unescaped `$`, or `\b`
	 * or `\B`, outside a class (the dialect has no lookarounds): only such a
	 * pattern can match at the cut where it would not on the whole subject
	 */
	protected static function readsTheEnd(
		string $pattern,
	): bool
	{
		$inClass = false;
		$n = strlen($pattern);
		for($i = 0; $i < $n; $i++)
		{
			$char = $pattern[$i];
			if($char === '\\')
			{
				$next = $pattern[$i + 1] ?? '';
				if($inClass === false && ($next === 'b' || $next === 'B'))
				{
					return true;
				}
				$i++;
			}
			elseif($inClass)
			{
				$inClass = $char !== ']';
			}
			elseif($char === '[')
			{
				$inClass = true;
			}
			elseif($char === '$')
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * What a pattern weighs, asked once per pattern: `width`, its atoms where
	 * it holds no quantifier (RegexGate::width()); `cost`, what one start of
	 * it costs with an unbounded quantifier as RegexGate::RUN_COST_MAX, as a
	 * byte budget weighs it (RegexGate::cost()); `loops`, whether PCRE's JIT
	 * runs it as slowly as its interpreter does (RegexGate::loops()). A
	 * pattern the gate cannot read
	 * costs RUN_COST_MAX; the cache is dropped past 200
	 *
	 * @return array{width: ?int, cost: int, loops: bool}
	 */
	public static function weighs(
		string $value,
		bool $ci,
	): array
	{
		$name = ($ci ? 'i:' : ':') . $value;
		if(isset(self::$weights[$name]) === false)
		{
			if(count(self::$weights) > 200)
			{
				self::$weights = [];
			}
			self::$weights[$name] = [
				'width' => RegexGate::width($value, $ci),
				'cost' => RegexGate::cost($value, $ci, RegexGate::RUN_COST_MAX) ?? RegexGate::RUN_COST_MAX,
				'loops' => RegexGate::loops($value, $ci),
			];
		}
		
		return self::$weights[$name];
	}
	
	/**
	 * Bytes a pattern reads weighted by what one start of it costs, over
	 * RegexGate::RUN_COST_MAX and rounded up: one with `+` weighs them at
	 * least once (`\w+x` 1, `\w{1,4}\w+x` 4), one of counts alone by its cost
	 * (`\w{1,4}\w{1,4}x` 1/64)
	 */
	public static function weighted(
		int $bytes,
		string $value,
		bool $ci,
	): int
	{
		return intdiv($bytes * self::weighs($value, $ci)['cost'] + RegexGate::RUN_COST_MAX - 1, RegexGate::RUN_COST_MAX);
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
				// a pattern PCRE refuses matches nothing, as does one past the cut without the JIT
				return self::regexFind($value, $ci, $subject, false)['found'];
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
