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
 * enforce = block proven rules, kill = nothing and no network) and the Store
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
 * renews it. The verdict is `block` only when the rule is `proven` AND
 * consent.enforce is on; an `observe` rule never blocks whatever the
 * switches say — the per-rule safety lives here.
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
 * observes or answers 429 with Retry-After. The match rules are judged
 * first; a rate rule counts only a request no match rule decided. Counting
 * needs APCu (the file tier cannot count): without it rate rules are
 * skipped, and the limit is per POOL — one server's APCu, not the site's.
 * The pull names `X-Shield-Kinds: match,rate`, and the door serves rate
 * rules only to a kernel that does, so a kernel older than them never reads
 * a rate rule as a match rule.
 *
 * PHP 8.3 floor (the WordPress plugin's, since 0.7.0 — MG 2026-09-23: 8.1 need
 * not be supported). codesafe's own suite tests this
 * file; consumers keep it byte-identical (sha1-compare after sync) and load
 * it with require_once — like any PHP class file, a second include is a
 * fatal error (the classes bind at compile time, so no guard can help).
 *
 * @author Marcin Gil <mg@ovos.at>
 */

namespace Ovos\Codesafe\Shield;

use APCUIterator;
use Closure;
use Throwable;

use function apcu_add;
use function apcu_delete;
use function apcu_enabled;
use function apcu_fetch;
use function apcu_inc;
use function apcu_store;
use function ceil;
use function class_exists;
use function crc32;
use function curl_exec;
use function curl_getinfo;
use function curl_init;
use function curl_setopt_array;
use function explode;
use function file_get_contents;
use function file_put_contents;
use function function_exists;
use function hash;
use function http_get_last_response_headers;
use function implode;
use function in_array;
use function inet_pton;
use function intdiv;
use function is_array;
use function is_bool;
use function is_file;
use function is_int;
use function is_string;
use function json_decode;
use function json_encode;
use function max;
use function ord;
use function preg_match;
use function preg_quote;
use function preg_replace;
use function rawurldecode;
use function rename;
use function rtrim;
use function sprintf;
use function str_contains;
use function str_starts_with;
use function strcasecmp;
use function stream_context_create;
use function stripos;
use function strlen;
use function strncasecmp;
use function strpos;
use function strtolower;
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
	
	protected ?string $body = null;
	
	protected bool $bodyRead = false;
	
	protected bool $bodyCapped = false;
	
	public function __construct(
		public readonly string $method,
		public readonly string $uri,
		public readonly string $ua,
		public readonly string $ip,
		public readonly bool $authed = false,
		protected ?Closure $bodyReader = null,
		public readonly string $user = '',
	)
	{
	}
	
	/**
	 * @param array<string, mixed> $server the request's server parameters ($_SERVER or a PSR-7 equivalent)
	 * @param array<string, mixed> $post the parsed form fields ($_POST) — files never
	 * @param ?callable(): string $input the raw body reader (fn() => file_get_contents('php://input'))
	 * @param string $user who a `user`-keyed rate rule counts: the signed-in identity, or the name a login POST tries ('' = none, the rule is skipped)
	 */
	public static function fromServer(
		array $server,
		array $post = [],
		?callable $input = null,
		bool $authed = false,
		?string $ip = null,
		string $user = '',
	): self
	{
		$uri = is_string($server['REQUEST_URI'] ?? null) ? $server['REQUEST_URI'] : '/';
		
		return new self(
			is_string($server['REQUEST_METHOD'] ?? null) ? $server['REQUEST_METHOD'] : 'GET',
			self::decodeOnce($uri),
			is_string($server['HTTP_USER_AGENT'] ?? null) ? $server['HTTP_USER_AGENT'] : '',
			$ip ?? (is_string($server['REMOTE_ADDR'] ?? null) ? $server['REMOTE_ADDR'] : ''),
			$authed,
			self::bodyReader(is_string($server['CONTENT_TYPE'] ?? null) ? $server['CONTENT_TYPE'] : '', $post, $input),
			$user,
		);
	}
	
	/**
	 * What the body IS to a rule: for a form (urlencoded, multipart) the
	 * parsed fields flattened to `name=value` lines — PHP has parsed them and
	 * multipart's raw stream is gone by then; for JSON, XML and anything
	 * else the raw input, capped at BODY_CAP, decoded once like the URI. Read
	 * lazily: nothing is touched until a body rule asks
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
 * proven rule (inert without detect); kill = nothing, and no network
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
	
	public const MODE_PROVEN = 'proven';
	
	public const VALUE_MAX = 600;
	
	public const KIND_MATCH = 'match';
	
	public const KIND_RATE = 'rate';
	
	public const KINDS = [self::KIND_MATCH, self::KIND_RATE];
	
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
	)
	{
	}
	
	/**
	 * The door's payload, checked: contract and dialect this kernel knows,
	 * every rule with an int id, a field and an op off the lists, a
	 * non-empty value under VALUE_MAX, a mode — anything else is left out.
	 * The digest is the door's (X-Shield-Sha256) or, absent, the sha256 of
	 * the rules as received — the same bytes the door hashes
	 */
	public static function fromPayload(
		array $payload,
		int $fetchedAt,
		string $digest = '',
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
			$digest = hash('sha256', (string)json_encode(is_array($payload['rules'] ?? null) ? $payload['rules'] : [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
		}
		
		return new self($rules, $digest, $fetchedAt, $usable, is_string($payload['project'] ?? null) ? $payload['project'] : '');
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
		);
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
			'usable' => $this->usable,
			'rules' => $this->rules,
		];
	}
	
	public function withFetchedAt(
		int $fetchedAt,
	): self
	{
		return new self($this->rules, $this->digest, $fetchedAt, $this->usable, $this->project);
	}
	
	/** past the ceiling: a codesafe instance gone silent lifts its shield */
	public function isStale(
		int $now,
		int $ceiling,
	): bool
	{
		return $this->fetchedAt + $ceiling <= $now;
	}
	
	/** whether any rule reads this field — the body is touched only when one does */
	public function reads(
		string $field,
	): bool
	{
		foreach($this->rules as $rule)
		{
			if(($rule['field'] ?? null) === $field)
			{
				return true;
			}
		}
		
		return false;
	}
	
	public static function wellFormed(
		mixed $rule,
	): bool
	{
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
 * Two tiers. Fast: APCu under a per-install prefix ('' = none). Durable:
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
			$temp = $this->file . '.' . uniqid('', true) . '.tmp';
			try
			{
				$json = (string)json_encode($record, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
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
			$written = apcu_store($this->key('rules'), $record) || $written;
		}
		if($written)
		{
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
		$head = 'rate:' . $ruleId . ':' . crc32($key) . ':';
		$ttl = 2 * $window + 1;
		$name = $this->key($head . $bucket);
		$current = apcu_inc($name, 1, $success, $ttl);
		if($current === false || $success === false)
		{
			$current = apcu_add($name, 1, $ttl) ? 1 : (int)apcu_inc($name, 1, $success, $ttl);
		}
		$previous = apcu_fetch($this->key($head . ($bucket - 1)));
		$covered = 1 - ($now - $bucket * $window) / $window;
		
		return (float)$current + (is_int($previous) ? $previous * $covered : 0.0);
	}
	
	/** true the first time a name is claimed within its ttl — the report-once gate; false without APCu */
	public function once(
		string $name,
		int $ttl,
	): bool
	{
		return $this->apcu && apcu_add($this->key('once:' . $name), 1, max(1, $ttl));
	}
	
	/**
	 * A minute's counters, taken (fetched and deleted) for the fragment that
	 * ships them: [rule id => ['observe' => n, 'block' => n]]
	 *
	 * @return array<int, array{observe: int, block: int}>
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
			[$ruleId, $outcome] = explode(':', substr($key, strlen($head)), 2) + [1 => ''];
			$id = (int)$ruleId;
			$hits[$id] ??= ['observe' => 0, 'block' => 0];
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
	
	/** what this kernel reads — the door serves rate rules only to a pull that names them */
	public const HEADER_KINDS = 'X-Shield-Kinds';
	
	public const KINDS = 'match,rate';
	
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
	 * the ruleset is past the ceiling; else the first MATCH rule that matches
	 * — in the door's order, proven first — as block (proven AND enforce) or
	 * observe; else the first RATE rule whose predicate matches and whose key
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
			if($ruleset === null)
			{
				$this->store->forcePull();
				
				return Verdict::pass('no ruleset');
			}
			if($ruleset->usable === false)
			{
				return Verdict::pass('unknown contract');
			}
			if($ruleset->isStale($now ?? time(), $this->ceiling))
			{
				$this->store->forcePull();
				
				return Verdict::pass('ceiling');
			}
			$rates = [];
			foreach($ruleset->rules as $rule)
			{
				if(Ruleset::isRate($rule))
				{
					$rates[] = $rule;
					
					continue;
				}
				$matched = $this->matched($rule, $facts);
				if($matched === null)
				{
					continue;
				}
				$blocks = ($rule['mode'] ?? '') === Ruleset::MODE_PROVEN && $consent->blocks();
				
				return new Verdict($blocks ? Verdict::BLOCK : Verdict::OBSERVE, $rule, substr($matched, 0, self::MATCHED_MAX));
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
		$key = match($rate['key'])
		{
			Ruleset::RATE_KEY_IP => $facts->ip,
			Ruleset::RATE_KEY_USER => $facts->user,
			default => '*',
		};
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
		$blocks = ($rule['mode'] ?? '') === Ruleset::MODE_PROVEN && $consent->blocks();
		
		return new Verdict($blocks ? Verdict::BLOCK : Verdict::OBSERVE, $rule, substr($matched, 0, self::MATCHED_MAX),
			'over limit', (int)ceil($count), $window - ($now % $window));
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
		
		return $verdict;
	}
	
	/** the match through the adapter's sender as a security event; never throws */
	public function report(
		Verdict $verdict,
		Facts $facts,
	): void
	{
		if($this->report === null || $verdict->isPass() || $verdict->rule === null)
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
			($this->report)($verdict->kind(), sprintf('shield rule %d %s %s %s', (int)$rule['id'],
				$verdict->isBlock() ? 'refused' : 'observed', $facts->method, substr($facts->path(), 0, 200)), [
				'rule' => (int)$rule['id'],
				'finding' => is_string($rule['finding'] ?? null) ? $rule['finding'] : '',
				'cve' => is_string($rule['cve'] ?? null) ? $rule['cve'] : '',
				'origin' => is_string($rule['origin'] ?? null) ? $rule['origin'] : '',
				'field' => (string)$rule['field'],
				'op' => (string)$rule['op'],
				'mode' => (string)$rule['mode'],
				'matched' => $verdict->matched,
				'authed' => $facts->authed,
				'body_capped' => $facts->bodyWasCapped(),
			]);
		}
		catch(Throwable $e)
		{
			$this->log('report failed: ' . $e->getMessage());
		}
	}
	
	/**
	 * A rate verdict, ONCE per rule, key and window — the hits count every
	 * request past the limit, the event says it started. Never "refused": the
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
		$key = match($rate['key'])
		{
			Ruleset::RATE_KEY_IP => $facts->ip,
			Ruleset::RATE_KEY_USER => $facts->user,
			default => '*',
		};
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
		// both names of the key header: X-Console-Key is what an instance from
		// before the rename (2026-09-24) reads, X-Codesafe-Key every one since
		$headers = ['X-Codesafe-Key: ' . $this->key, 'X-Console-Key: ' . $this->key, 'Accept: application/json',
			self::HEADER_KINDS . ': ' . self::KINDS];
		if($current !== null && $current->digest !== '')
		{
			$headers[] = 'If-None-Match: "' . $current->digest . '"';
		}
		$response = ($this->http ?? Closure::fromCallable([$this, 'transport']))($this->url . self::DOOR, $headers, $this->timeoutMs);
		$status = (int)($response['status'] ?? 0);
		if($status === 304 && $current !== null)
		{
			$this->store->write($current->withFetchedAt($now)->toRecord());
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
		$digest = '';
		foreach((array)($response['headers'] ?? []) as $name => $value)
		{
			if(strtolower((string)$name) === 'x-shield-sha256' && is_string($value))
			{
				$digest = trim($value);
			}
		}
		$ruleset = Ruleset::fromPayload($payload, $now, $digest);
		$this->store->write($ruleset->toRecord());
		$this->rulesetRead = false;
		if($ruleset->usable === false)
		{
			$this->log('pull refused: contract ' . json_encode($payload['contract'] ?? null) . ' dialect ' . json_encode($payload['dialect'] ?? null));
			
			return self::PULL_REFUSED;
		}
		
		return self::PULL_FRESH;
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
				$pattern = '~' . (string)preg_replace('#(?<!\\\\)((?:\\\\\\\\)*)~#', '$1\\~', $value) . '~D' . ($ci ? 'i' : '');
				
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
		if($prefix === false || $packed === false || strlen($packed) !== strlen($prefix))
		{
			return false;
		}
		$max = strlen($prefix) * 8;
		$bits = $max;
		if($slash !== false)
		{
			$given = substr($cidr, $slash + 1);
			if(preg_match('~^\d{1,3}$~', $given) !== 1 || (int)$given > $max)
			{
				return false;
			}
			$bits = (int)$given;
		}
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
				// no curl_close(): a no-op since PHP 8.0 and deprecated from 8.5, where
				// a host that throws on deprecations turned every pull into status 0
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
			}
		}
	}
}
