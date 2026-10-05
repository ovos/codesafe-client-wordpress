<?php
declare(strict_types=1);
// phpcs:disable WordPress.WP.AlternativeFunctions.curl_curl_init, WordPress.WP.AlternativeFunctions.curl_curl_setopt_array, WordPress.WP.AlternativeFunctions.curl_curl_exec -- the fire-and-forget rollup call needs millisecond timeouts (300 ms connect / 1 s total) the WP HTTP API cannot express; without curl the fragment is dropped rather than riding a blocking call at shutdown

namespace Ovos\Codesafe;

use APCUIterator;
use Throwable;

use function apcu_add;
use function apcu_delete;
use function apcu_enabled;
use function apcu_entry;
use function apcu_fetch;
use function apcu_inc;
use function apcu_store;
use function array_fill;
use function array_intersect_key;
use function base_convert;
use function curl_exec;
use function curl_init;
use function curl_setopt_array;
use function defined;
use function function_exists;
use function gethostname;
use function getmypid;
use function headers_list;
use function http_response_code;
use function in_array;
use function intdiv;
use function is_array;
use function is_int;
use function json_encode;
use function ksort;
use function md5;
use function microtime;
use function preg_match;
use function preg_quote;
use function preg_replace;
use function register_shutdown_function;
use function reset;
use function strrpos;
use function substr;
use function time;

use const PHP_SAPI;

/**
 * Per-minute traffic rollup accumulator — the console's DENOMINATOR layer,
 * WordPress port of the php-library Console\Rollup. The error reports tell
 * the console what broke; this tells it how much traffic there was, so
 * "379 requests for nothing we serve" can be read as a rate instead of a
 * raw count.
 *
 * One apcu_inc() set per request (sub-microsecond, no I/O), and a single
 * POST to /api/v1/ingest/rollup by whichever request first crosses a minute
 * boundary — guarded by an APCu add()-lock so only one flushes.
 *
 * APCu ONLY, by decision: WordPress hosting is too varied to trust any
 * other shared per-pool memory (a per-request object cache would count a
 * denominator of one), and an undercounted denominator silently deflates
 * every rate computed from it. NO APCu, NO ROLLUPS — the whole class
 * degrades to a silent no-op, never to wrong numbers. APCu is per FPM
 * POOL: pools flush their own fragments, the console SUMS them and dedups
 * retries by (instance, seq) — both APCu-held, regenerated together on an
 * APCu restart so a recycled pid can never collide with a seq history it
 * does not own. The key prefix carries a site marker, because shared
 * hosting can run several WordPress sites in ONE pool.
 *
 * THE CLOSED-VOCABULARY RULE (the console refuses violations wholesale):
 * every dimension comes from the app, never from the request. WordPress
 * has no route table, so the route is the query the request RESOLVED to —
 * front-page, singular/{post_type}, archive/{taxonomy}, search, login,
 * rest, admin — all names WordPress itself defines; a request answered 404
 * counts only __unmatched, which is exactly the probe signal the console
 * wants. A raw URI must never reach a field name.
 *
 * Page-cache plugins that serve hits before WordPress boots bypass this
 * entirely (cached traffic is uncounted) — the same caveat every front
 * cache carries. Probe traffic is never a cache hit, so the signal stays.
 *
 * Opt-in twice: the rollups setting here (default off), rollups_enabled on
 * the console project there. Either switch off keeps this inert.
 */
class Rollup
{
	/**
	 * Orphaned counters (a pool that stops receiving traffic mid-minute)
	 * age out on their own — well past the console's ±90min skew window,
	 * inside which they could still have shipped
	 */
	protected const COUNTER_TTL = 3600;
	
	/**
	 * POSTs per flush — a pool waking from a long idle ships its backlog
	 * over a few requests instead of stalling one on many sends
	 */
	protected const FLUSH_MAX = 5;
	
	/**
	 * The console rejects fragments older than its skew window — a minute
	 * this stale is deleted instead of shipped
	 */
	protected const SKEW_MINUTES = 90;
	
	/**
	 * The verbs worth a per-method counter (the console's vocabulary);
	 * anything else still counts into requests
	 */
	public const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
	
	/**
	 * Duration histogram bounds, MILLISECONDS — a WIRE CONTRACT shared
	 * verbatim with every sender and the console's Console\Stats\Durations:
	 * bucket i counts durations > bounds[i-1] and <= bounds[i]; the 12th
	 * bucket is everything past the last bound. Fixed for the life of the
	 * feature — changing it breaks additivity across time.
	 */
	public const DURATION_BOUNDS = [25, 50, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 30000];
	
	public const DURATION_BUCKETS = 12;
	
	/**
	 * Bucket 0's split (codesafe's D5): nearly every request lands in bucket
	 * 0, where a percentile reads 12.5 / 23.8 ms whatever the site does, so
	 * a duration there also counts into one of three parts — at most 5, at
	 * most 10, at most 25 ms — shipped as the optional durations_fine
	 * beside the coarse vectors. The coarse contract above stays as it is;
	 * a codesafe that predates the key ignores it.
	 */
	public const DURATION_SPLIT = [5, 10];
	
	public const DURATION_FINE_PARTS = 3;
	
	/**
	 * APCu key prefix, site-scoped lazily — see prefix()
	 */
	protected ?string $prefix = null;
	
	/**
	 * The Shield's per-minute hook (Shield\Adapter::hits): `so:<rule>` /
	 * `sb:<rule>` fields the flush merges into the minute's counters before
	 * the fragment is assembled; null = no shield
	 *
	 * @var ?callable(int): array<string, int>
	 */
	protected $extra;
	
	public function __construct(
		protected Config $config,
		?callable $extra = null,
	)
	{
		$this->extra = $extra;
	}
	
	/**
	 * Counting rides its own shutdown handler (registered after the
	 * Sender's, so it runs once error flushing is done): only there do the
	 * conditional tags see the fully-resolved query, and a page-cache
	 * plugin that already served and exited never reaches it
	 */
	public function register(): void
	{
		register_shutdown_function([$this, 'observe']);
	}
	
	/**
	 * Rollups need the plugin's master switch, the explicit rollups opt-in,
	 * the console transport — and APCu, without which nothing is ever
	 * counted or sent
	 */
	public function isEnabled(): bool
	{
		return $this->config->enabled()
			&& $this->config->rollups()
			&& $this->config->url() !== ''
			&& $this->config->apiKey() !== ''
			&& self::hasApcu();
	}
	
	/**
	 * Counts this request and flushes complete minutes when a boundary was
	 * crossed. WP-CLI runs are not HTTP traffic and count nothing.
	 */
	public function observe(): void
	{
		try
		{
			if($this->isEnabled() === false
				|| PHP_SAPI === 'cli'
				|| defined('WP_CLI'))
			{
				return;
			}
			
			$minute = intdiv(time(), 60);
			$status = http_response_code();
			
			// request wall time: SAPI start to this shutdown observer —
			// WordPress boot included, web server and network excluded. No
			// start marker means no histogram entry.
			$started = isset($_SERVER['REQUEST_TIME_FLOAT']) ? (float)$_SERVER['REQUEST_TIME_FLOAT'] : 0.0;
			$duration = $started > 0.0 ? (microtime(true) - $started) * 1000 : null;
			
			// a streaming response (server-sent events) is held open for as long
			// as the client listens: its wall time measures the subscription, not
			// the work. It still counts as a request - it just has no duration
			if(self::isStream(headers_list()))
			{
				$duration = null;
			}
			
			$this->count(
				$minute,
				$status,
				isset($_SERVER['REQUEST_METHOD']) ? (string)$_SERVER['REQUEST_METHOD'] : '',
				$this->routeFor($status),
				function_exists('is_user_logged_in') ? is_user_logged_in() : null,
				$duration !== null && $duration >= 0 ? $duration : null,
			);
			
			$this->maybeFlush($minute);
		}
		catch(Throwable)
		{
			// telemetry must never break the host site
		}
	}
	
	/**
	 * Whether the response being finished is a stream: a Content-Type of
	 * text/event-stream, whatever its case or charset suffix. A stream is held
	 * open for as long as the client listens, so its wall time measures the
	 * subscription, not the work - observe() counts it as a request and gives
	 * it no duration. Takes the header list (headers_list() at shutdown, empty
	 * on the CLI) so the rule is testable where no headers exist.
	 */
	public static function isStream(
		array $headers,
	): bool
	{
		foreach($headers as $header)
		{
			if(preg_match('~^content-type:\s*text/event-stream\b~i', (string)$header) === 1)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * The resolved query as a route name — WordPress's own vocabulary,
	 * never the URI. The response status is consulted FIRST: a 404 answer
	 * matched nothing this site serves (that counter IS the probe signal),
	 * and checking it costs no conditional-tag call — the tags trigger
	 * _doing_it_wrong before the main query exists, which our own error
	 * handler would dutifully report as self-noise.
	 */
	protected function routeFor(
		int|false $status,
	): string
	{
		if($status === 404)
		{
			return '__unmatched';
		}
		
		// surfaces resolved before (or without) the main query — each one a
		// name WordPress defines, and login/xmlrpc the classic brute-force
		// targets a method/route split makes visible
		if(defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)
		{
			return '/xmlrpc';
		}
		
		if(defined('REST_REQUEST') && REST_REQUEST)
		{
			return '/rest';
		}
		
		if(function_exists('wp_doing_ajax') && wp_doing_ajax())
		{
			return '/admin/ajax';
		}
		
		if(function_exists('wp_doing_cron') && wp_doing_cron())
		{
			return '/cron';
		}
		
		if(function_exists('is_login') && is_login())
		{
			return '/login';
		}
		
		if(function_exists('is_admin') && is_admin())
		{
			return '/admin';
		}
		
		// the conditional tags only answer truthfully once the main query
		// ran — a request that died before that resolved to nothing nameable
		if(function_exists('did_action') === false || did_action('wp') === 0)
		{
			return '__other';
		}
		
		// core's template-loader precedence: feed and search resolve before
		// the front-page/home flags they can carry alongside
		if(is_404())
		{
			return '__unmatched';
		}
		
		if(is_feed())
		{
			return '/feed';
		}
		
		if(is_search())
		{
			return '/search';
		}
		
		if(is_front_page())
		{
			return '/front-page';
		}
		
		if(is_home())
		{
			return '/home';
		}
		
		if(is_singular())
		{
			$type = $this->token((string)get_post_type());
			
			return '/singular/' . ($type !== '' ? $type : 'post');
		}
		
		if(is_category())
		{
			return '/archive/category';
		}
		
		if(is_tag())
		{
			return '/archive/tag';
		}
		
		if(is_author())
		{
			return '/archive/author';
		}
		
		if(is_date())
		{
			return '/archive/date';
		}
		
		if(is_post_type_archive())
		{
			$queried = get_query_var('post_type');
			$type = $this->token((string)(is_array($queried) ? reset($queried) : $queried));
			
			return '/archive/' . ($type !== '' ? $type : 'post');
		}
		
		if(is_tax())
		{
			$queried = get_queried_object();
			$taxonomy = $this->token((string)($queried->taxonomy ?? ''));
			
			return '/archive/' . ($taxonomy !== '' ? $taxonomy : 'term');
		}
		
		if(is_archive())
		{
			return '/archive';
		}
		
		return '__other';
	}
	
	/**
	 * A registered name (post type, taxonomy) reduced to the console's
	 * route-token shape. These come from code — register_post_type() keys
	 * are sanitized lowercase — but the shape is enforced anyway: anything
	 * doubtful becomes '' and the caller substitutes a generic word.
	 */
	protected function token(
		string $name,
	): string
	{
		return preg_match('~^[a-z0-9_-]{1,40}$~', $name) === 1 ? $name : '';
	}
	
	/**
	 * A minute's collected counters as the fragment body the console
	 * expects — requests plus the status/methods/routes/authed breakdowns.
	 * Pure, so the mapping is testable without APCu.
	 *
	 * @param array<string, int> $fields flattened counter fields
	 *   ('requests', 's:200', 'm:GET', 'r:/search', 'a:yes')
	 */
	/**
	 * The histogram bucket one duration falls into: first bound >= value,
	 * else the overflow bucket
	 */
	public static function bucketFor(
		float $ms,
	): int
	{
		foreach(self::DURATION_BOUNDS as $i => $bound)
		{
			if($ms <= $bound)
			{
				return $i;
			}
		}
		
		return self::DURATION_BUCKETS - 1;
	}
	
	/**
	 * The part of bucket 0's split one duration falls into — at most 5, at
	 * most 10, at most 25 ms — or null past bucket 0
	 */
	public static function splitFor(
		float $ms,
	): ?int
	{
		if($ms > self::DURATION_BOUNDS[0])
		{
			return null;
		}
		
		foreach(self::DURATION_SPLIT as $i => $bound)
		{
			if($ms <= $bound)
			{
				return $i;
			}
		}
		
		return self::DURATION_FINE_PARTS - 1;
	}
	
	/**
	 * The histogram fields one duration increments: the coarse bucket in the
	 * __total headline and in the route's own vector, always together, and
	 * within bucket 0 its part of the split, the same two ways
	 *
	 * @return list<string>
	 */
	public static function durationFields(
		string $route,
		float $ms,
	): array
	{
		$bucket = self::bucketFor($ms);
		$fields = ['dt:' . $bucket, 'd:' . $route . ':' . $bucket];
		
		$part = self::splitFor($ms);
		if($part !== null)
		{
			$fields[] = 'dtf:' . $part;
			$fields[] = 'df:' . $route . ':' . $part;
		}
		
		return $fields;
	}
	
	/**
	 * The minute's counters plus what the hook adds for it — the Shield's
	 * hits; a hook that throws adds nothing (the rollup never breaks the site)
	 *
	 * @param array<string, int> $fields
	 * @param ?callable(int): array<string, int> $extra
	 * @return array<string, int>
	 */
	public static function withExtra(
		array $fields,
		$extra,
		int $minute,
	): array
	{
		if($extra === null)
		{
			return $fields;
		}
		try
		{
			foreach($extra($minute) as $field => $count)
			{
				if((int)$count > 0)
				{
					$fields[(string)$field] = ($fields[(string)$field] ?? 0) + (int)$count;
				}
			}
		}
		catch(Throwable)
		{
			// never break the host site
		}
		
		return $fields;
	}
	
	public static function assemble(
		int $minute,
		array $fields,
	): array
	{
		$payload = [
			'minute' => $minute,
			'requests' => 0,
			'status' => [],
			'methods' => [],
			'routes' => [],
			'authed' => [],
		];
		
		ksort($fields);
		
		$durations = [];
		$fine = [];
		
		foreach($fields as $field => $count)
		{
			$field = (string)$field;
			$count = (int)$count;
			
			if($field === 'requests')
			{
				$payload['requests'] = $count;
			}
			elseif(substr($field, 0, 2) === 's:')
			{
				$payload['status'][substr($field, 2)] = $count;
			}
			elseif(substr($field, 0, 2) === 'm:')
			{
				$payload['methods'][substr($field, 2)] = $count;
			}
			elseif(substr($field, 0, 3) === 'dt:')
			{
				$durations['__total'] = isset($durations['__total'])
					? $durations['__total']
					: array_fill(0, self::DURATION_BUCKETS, 0);
				$durations['__total'][(int)substr($field, 3)] = $count;
			}
			elseif(substr($field, 0, 2) === 'd:')
			{
				// the bucket index is whatever follows the LAST colon — route
				// names may carry colons of their own
				$cut = strrpos($field, ':');
				$route = substr($field, 2, $cut - 2);
				$durations[$route] = isset($durations[$route])
					? $durations[$route]
					: array_fill(0, self::DURATION_BUCKETS, 0);
				$durations[$route][(int)substr($field, $cut + 1)] = $count;
			}
			elseif(substr($field, 0, 4) === 'dtf:')
			{
				$fine['__total'] = isset($fine['__total'])
					? $fine['__total']
					: array_fill(0, self::DURATION_FINE_PARTS, 0);
				$fine['__total'][(int)substr($field, 4)] = $count;
			}
			elseif(substr($field, 0, 3) === 'df:')
			{
				$cut = strrpos($field, ':');
				$route = substr($field, 3, $cut - 3);
				$fine[$route] = isset($fine[$route])
					? $fine[$route]
					: array_fill(0, self::DURATION_FINE_PARTS, 0);
				$fine[$route][(int)substr($field, $cut + 1)] = $count;
			}
			elseif(substr($field, 0, 2) === 'r:')
			{
				$payload['routes'][substr($field, 2)] = $count;
			}
			elseif(substr($field, 0, 2) === 'a:')
			{
				$payload['authed'][substr($field, 2)] = $count;
			}
			// the Shield's per-rule hits (the kernel store's counters, merged in
			// by the flush hook): two optional sections the console folds beside
			// the request counters — absent when no rule fired
			elseif(substr($field, 0, 3) === 'so:')
			{
				$payload['shield_observe'][substr($field, 3)] = $count;
			}
			elseif(substr($field, 0, 3) === 'sb:')
			{
				$payload['shield_block'][substr($field, 3)] = $count;
			}
		}
		
		// the console requires the __total headline whenever the map is
		// non-empty; a partial APCu eviction that lost the dt:* keys ships
		// NO histograms rather than a fragment the endpoint refuses whole
		if(isset($durations['__total']))
		{
			$payload['durations'] = $durations;
			
			// the split rides only beside the vector it splits; codesafe
			// drops one that does not add up to that bucket 0, so a counter
			// evicted between the two costs the split, never the fragment
			$fine = array_intersect_key($fine, $durations);
			if($fine !== [])
			{
				$payload['durations_fine'] = $fine;
			}
		}
		
		return $payload;
	}
	
	/**
	 * A hostname reduced to the console's identity shape ([A-Za-z0-9._-],
	 * max 64) — '' when nothing usable remains
	 */
	public static function hostName(
		string $raw,
	): string
	{
		$host = (string)preg_replace('~[^A-Za-z0-9._-]~', '-', $raw);
		
		return substr($host, 0, 64);
	}
	
	/**
	 * One field set per request. apcu_inc() creates absent keys at 1 with
	 * the TTL, so there is no init step and no race.
	 */
	protected function count(
		int $minute,
		int|false $status,
		string $method,
		string $route,
		?bool $authed,
		?float $durationMs = null,
	): void
	{
		$fields = ['requests'];
		
		if(is_int($status) && $status >= 100 && $status <= 599)
		{
			$fields[] = 's:' . $status;
		}
		
		if(in_array($method, self::METHODS, true))
		{
			$fields[] = 'm:' . $method;
		}
		
		$fields[] = 'r:' . $route;
		
		// null = the answer is not knowable here; no dimension at all is
		// better than a wrong split
		if($authed !== null)
		{
			$fields[] = 'a:' . ($authed ? 'yes' : 'no');
		}
		
		// the duration histogram (console perf-lite): one increment into the
		// fixed bucket vocabulary — the __total headline and the route's own
		// vector, always together, so counts and percentiles can never
		// describe different route sets — and bucket 0's split
		if($durationMs !== null)
		{
			$fields = [...$fields, ...self::durationFields($route, $durationMs)];
		}
		
		$ok = false;
		foreach($fields as $field)
		{
			apcu_inc($this->prefix() . $minute . ':' . $field, 1, $ok, self::COUNTER_TTL);
		}
	}
	
	/**
	 * Ships complete minutes once per boundary: the watermark keeps the
	 * common case (same minute as the last flush) to one apcu_fetch, the
	 * add()-lock keeps racing requests from shipping the same minute twice
	 * with two different seqs — which the server-side dedup could not
	 * catch, and additive counters never recover from.
	 */
	protected function maybeFlush(
		int $minute,
	): void
	{
		$flushed = apcu_fetch($this->prefix() . 'flushed');
		if(is_int($flushed) && $flushed >= $minute - 1)
		{
			return;
		}
		
		// fresh APCu epoch: nothing older than us exists — start the
		// watermark, ship nothing
		if($flushed === false && apcu_add($this->prefix() . 'flushed', $minute - 1))
		{
			return;
		}
		
		if(apcu_add($this->prefix() . 'lock', 1, 30) === false)
		{
			return; // someone else is flushing
		}
		
		try
		{
			$this->flush($minute);
		}
		finally
		{
			apcu_delete($this->prefix() . 'lock');
		}
	}
	
	/**
	 * Collect every complete minute's counters, ship the fresh ones (up to
	 * FLUSH_MAX per pass), drop the ones the console would refuse as stale,
	 * and advance the watermark when the backlog is drained.
	 */
	protected function flush(
		int $minute,
	): void
	{
		$byMinute = [];
		
		$pattern = '~^' . preg_quote($this->prefix(), '~') . '(\d+):(.+)$~';
		foreach(new APCUIterator($pattern) as $entry)
		{
			if(preg_match($pattern, (string)$entry['key'], $match) !== 1)
			{
				continue;
			}
			
			$entryMinute = (int)$match[1];
			if($entryMinute >= $minute)
			{
				continue; // still accumulating
			}
			
			$byMinute[$entryMinute][$match[2]] = (int)$entry['value'];
		}
		
		ksort($byMinute);
		
		$shipped = 0;
		$drained = true;
		
		foreach($byMinute as $entryMinute => $fields)
		{
			if($entryMinute >= $minute - self::SKEW_MINUTES && $shipped >= self::FLUSH_MAX)
			{
				$drained = false; // the next boundary crossing continues
				
				break;
			}
			
			foreach($fields as $field => $count)
			{
				apcu_delete($this->prefix() . $entryMinute . ':' . $field);
			}
			
			// too stale for the console's skew window — deleted, not shipped
			if($entryMinute < $minute - self::SKEW_MINUTES)
			{
				continue;
			}
			
			$this->send($this->payload($entryMinute, self::withExtra($fields, $this->extra, $entryMinute)));
			$shipped++;
		}
		
		if($drained)
		{
			apcu_store($this->prefix() . 'flushed', $minute - 1);
		}
	}
	
	/**
	 * The finished fragment: the assembled counters plus the APCu-held
	 * identity — host, the pool marker, and the monotonic seq the console
	 * dedups retries by
	 */
	protected function payload(
		int $minute,
		array $fields,
	): array
	{
		return [
			'v' => 1,
			'type' => 'rollup',
			'host' => self::hostName((string)gethostname()),
			'instance' => $this->instance(),
			'seq' => (int)apcu_inc($this->prefix() . 'seq'),
		] + self::assemble($minute, $fields);
	}
	
	/**
	 * The pool identity, minted once per APCu epoch: the first worker to
	 * ask stores its pid plus the epoch time, so a recycled pid after an
	 * APCu restart is still a NEW identity — the console's dedup set for
	 * the old one must never answer for the new one's fresh seq counter.
	 */
	protected function instance(): string
	{
		$instance = apcu_entry($this->prefix() . 'instance',
			static fn(): string => 'p' . (int)getmypid()
				. '-' . base_convert((string)time(), 10, 36));
		
		return (string)$instance;
	}
	
	/**
	 * The APCu key prefix, carrying a site marker: shared hosting can run
	 * several WordPress sites in ONE FPM pool, and without the marker their
	 * counters — and their seq/instance identities — would silently merge
	 */
	protected function prefix(): string
	{
		if($this->prefix === null)
		{
			$site = function_exists('get_option')
				? (string)get_option('home')
				: '';
			
			$this->prefix = 'ovos:codesafe:rollups:' . substr(md5($site), 0, 8) . ':';
		}
		
		return $this->prefix;
	}
	
	/** whether the web SAPI has APCu — the rollups' and the Shield hit counters' shared memory; the settings page says so */
	public static function hasApcu(): bool
	{
		return function_exists('apcu_enabled') && apcu_enabled();
	}
	
	/**
	 * TLS peer verification, same filter as the Sender's ingest call — a
	 * console behind a self-signed certificate opts out via
	 * add_filter('ovos_codesafe_sslverify', '__return_false')
	 */
	protected function verifyTls(): bool
	{
		return (bool)Legacy::filter('ovos_codesafe_sslverify', true);
	}
	
	/**
	 * Fire-and-forget POST, the Sender's transport contract: connection
	 * released first, NOSIGNAL for poll-based sub-second timeouts, hard
	 * bounds, no reading the answer — the console answers duplicates with
	 * a 2xx anyway. curl only: without the extension the fragment is
	 * dropped rather than riding a blocking wp_remote_post at shutdown.
	 */
	protected function send(
		array $payload,
	): void
	{
		if(function_exists('curl_init') === false)
		{
			return;
		}
		
		// the response is already sent — release the connection so the
		// HTTP call is invisible to the end user
		if(function_exists('fastcgi_finish_request'))
		{
			@fastcgi_finish_request();
		}
		
		$verify = $this->verifyTls();
		
		$handle = curl_init($this->config->url() . '/api/v1/ingest/rollup');
		
		curl_setopt_array($handle, [
			CURLOPT_POST => true,
			CURLOPT_POSTFIELDS => (string)json_encode($payload,
				JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR),
			CURLOPT_HTTPHEADER => [
				'Content-Type: application/json',
				'X-Codesafe-Key: ' . $this->config->apiKey(),
				'X-Console-Key: ' . $this->config->apiKey(),
			],
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_NOSIGNAL => true,
			CURLOPT_CONNECTTIMEOUT_MS => 300,
			CURLOPT_TIMEOUT_MS => 1000,
			CURLOPT_SSL_VERIFYPEER => $verify,
			CURLOPT_SSL_VERIFYHOST => $verify ? 2 : 0,
		]);
		
		curl_exec($handle);
	}
}
