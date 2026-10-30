<?php
declare(strict_types=1);

/**
 * ovos/codesafe Shield — WordPress's kernel module, vendored beside the
 * kernel (Shield.php): what WordPress makes of a request that the core does
 * not read alike for every platform. Its REST route (target `rest`, in either
 * spelling, under the site's REST prefix), its batch route (each request a
 * batch lists reaches its own route's handler), the shortcode and block
 * attributes a decode step reads (`shortcode:<tag>.<attribute>`,
 * `block:<namespace/name>.<dot.path>`) and the JSON types WordPress reads as
 * JSON. A kernel not given this module drops a rule that names these words
 * at the pull and reads none of them: nothing is guessed.
 *
 *   require_once __DIR__ . '/Shield.php';               // the core first: it declares Platform
 *   require_once __DIR__ . '/Shield/Wordpress.php';
 *   use Ovos\Codesafe\Shield\{Kernel, Facts, Wordpress};
 *
 *   $kernel = new Kernel($url, $apiKey, $store, platforms: [new Wordpress()]);
 *   $facts = Facts::fromServer($_SERVER, $_POST, $input, platforms: $kernel->platforms(),
 *       options: [Wordpress::OPTION_REST_PREFIX => rest_get_url_prefix()]);
 *
 * PHP 8.3 floor, zero dependencies. Byte-identical in every consumer, like
 * the kernel, and loaded with require_once after it: autoloaded before the
 * kernel's file, its interface is not found and the include is fatal.
 *
 * @author Marcin Gil <mg@ovos.at>
 */

namespace Ovos\Codesafe\Shield;

use function array_filter;
use function array_slice;
use function array_values;
use function count;
use function explode;
use function in_array;
use function is_array;
use function is_scalar;
use function is_string;
use function json_decode;
use function parse_str;
use function preg_match;
use function preg_match_all;
use function preg_replace;
use function rawurldecode;
use function rtrim;
use function str_contains;
use function str_ends_with;
use function str_starts_with;
use function strcasecmp;
use function stripcslashes;
use function strlen;
use function strpos;
use function strrpos;
use function strspn;
use function strtolower;
use function strtoupper;
use function strtr;
use function substr;
use function trim;

use const PREG_SET_ORDER;

final class Wordpress implements Platform
{
	/** the word X-Shield-Platforms names this module by */
	public const NAME = 'wordpress';
	
	/** the REST route in either spelling: a frame target with no name, which selects the handler a request reaches */
	public const TARGETS = ['rest'];
	
	/** Facts::$options' key for the REST API's path prefix — rest_get_url_prefix(); none is WordPress's default, wp-json */
	public const OPTION_REST_PREFIX = 'rest_prefix';
	
	/** WordPress's batch route: each request it lists reaches its own route's handler */
	public const BATCH_ROUTE = '/batch/v1';
	
	/**
	 * the batch's sub-requests judged at most — WordPress refuses a batch of
	 * more requests than rest_get_max_batch_size, 25 unless a site raises it,
	 * so one past this runs nothing honest, and a vpatch its unread requests
	 * may reach fails closed (overflows()). The count is WordPress's limit,
	 * not the bytes: a batch within it whose body runs past JSON_CAP holds
	 * unanswered, since an editor saving 25 large posts sends one
	 */
	public const BATCH_MAX = 1000;
	
	/**
	 * the shortcodes or blocks one decode step reads in a value at most: no
	 * post carries that many of one tag, and the read costs under 60 ms
	 * there; past them the value is not read in full and the condition holds
	 * as one past Ruleset::DECODED_MAX does (Kernel::patched())
	 */
	public const OCCURRENCES_MAX = 16384;
	
	/** a shortcode tag as add_shortcode() takes one, in printable ASCII: never `<>&/[]=` or a space */
	public const SHORTCODE_TAG = '~^[^<>&/\[\]\x00-\x20=\x7f-\xff]{1,100}$~D';
	
	/** a block's `namespace/name` as WordPress's block parser reads one */
	public const BLOCK_NAME = '~^[a-z][a-z0-9_-]*/[a-z][a-z0-9_-]*$~D';
	
	/** WordPress's shortcode_parse_atts() pattern (get_shortcode_atts_regex()), as it is */
	public const SHORTCODE_ATTRIBUTES = '/([\w-]+)\s*=\s*"([^"]*)"(?:\s|$)|([\w-]+)\s*=\s*\'([^\']*)\'(?:\s|$)|([\w-]+)\s*=\s*([^\s\'"]+)(?:\s|$)|"([^"]*)"(?:\s|$)|\'([^\']*)\'(?:\s|$)|(\S+)(?:\s|$)/';
	
	/** the bytes PCRE's `\w` and a hyphen are: what may not follow a shortcode's tag */
	public const WORD_BYTES = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-';
	
	/** the bytes PCRE's `\s` is */
	public const SPACE_BYTES = " \t\n\x0B\f\r";
	
	public function name(): string
	{
		return self::NAME;
	}
	
	public function targets(): array
	{
		return self::TARGETS;
	}
	
	public function values(
		string $target,
		Facts $facts,
	): array
	{
		return $target === 'rest' ? self::routes($facts) : [];
	}
	
	public function decodes(
		mixed $step,
	): bool
	{
		return self::shortcodeStep($step) !== null || self::blockStep($step) !== null;
	}
	
	public function decode(
		string $step,
		string $value,
	): array
	{
		$shortcode = self::shortcodeStep($step);
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
		$block = self::blockStep($step);
		if($block !== null)
		{
			[$found, $cut] = self::blocks($value, $block[0]);
			$values = [];
			foreach($found as $attributes)
			{
				foreach(Kernel::pickJson($attributes, $block[1]) as $one)
				{
					$values[] = $one;
				}
			}
			
			return [$values, $cut];
		}
		
		return [[], false];
	}
	
	/** a batch's sub-requests (batched()), and whether the kernel did not read them all (batchUnread()) */
	public function subRequests(
		Facts $facts,
	): array
	{
		return [self::batched($facts), self::batchUnread($facts)];
	}
	
	public function reaches(
		array $rule,
		Facts $facts,
	): bool
	{
		return self::batchReaches($rule, $facts);
	}
	
	/** whether the batch lists more requests than the kernel reads (batchOverflows()): WordPress refuses one past its own count, so nothing honest fails closed */
	public function overflows(
		Facts $facts,
	): bool
	{
		return self::batchOverflows($facts);
	}
	
	public function jsonType(
		string $contentType,
	): bool
	{
		return self::jsonMediaType($contentType);
	}
	
	/**
	 * The method WordPress runs a REST request as
	 * (WP_REST_Server::serve_request()): $_GET['_method'], else the
	 * X-HTTP-Method-Override header, upper-cased by set_method(). Null off a
	 * REST route (routes()), for a batch's sub-request — serve_batch_request_v1()
	 * takes the method the item names — and where neither is sent
	 */
	public function appMethod(
		Facts $facts,
	): ?string
	{
		if($facts->outer() !== null || self::routes($facts) === [])
		{
			return null;
		}
		$override = $facts->query['_method'] ?? ($facts->headers['x-http-method-override'] ?? null);
		
		return is_string($override) && $override !== '' ? strtoupper($override) : null;
	}
	
	/** a REST prefix without its slashes; none is WordPress's default, wp-json */
	public static function restPrefixOf(
		string $prefix,
	): string
	{
		$prefix = trim($prefix, '/');
		
		return $prefix === '' ? 'wp-json' : $prefix;
	}
	
	/** the REST prefix the host named in Facts::$options (OPTION_REST_PREFIX), without its slashes */
	public static function restPrefix(
		Facts $facts,
	): string
	{
		$prefix = $facts->options[self::OPTION_REST_PREFIX] ?? '';
		
		return self::restPrefixOf(is_scalar($prefix) ? (string)$prefix : '');
	}
	
	/**
	 * Whether WordPress reads a body of this content type as JSON:
	 * WP_REST_Request::get_content_type()'s value — cut at a `;` past the
	 * first byte, lower case, holding a `/`, trimmed — through
	 * wp_is_json_media_type()'s pattern
	 */
	public static function jsonMediaType(
		string $contentType,
	): bool
	{
		// WordPress tests strpos() for truth: a `;` as the first byte cuts nothing
		$value = strtolower(strpos($contentType, ';') ? explode(';', $contentType, 2)[0] : $contentType);
		
		return str_contains($value, '/') && preg_match('/(^|\s|,)application\/([\w!#\$&-\^\.\+]+\+)?json(\+oembed)?($|\s|;|,)/i', trim($value)) === 1;
	}
	
	/**
	 * A batch's sub-request as its route's handler sees it: its method, its
	 * path under this site's REST prefix with its query, its body as the
	 * form and the JSON, its headers — and the batch's caller, whom WordPress
	 * runs every sub-request as (Facts::derived())
	 *
	 * @param array<string, mixed> $headers
	 */
	public static function subRequest(
		Facts $facts,
		string $method,
		string $path,
		mixed $body,
		array $headers,
	): Facts
	{
		parse_str(explode('?', $path, 2)[1] ?? '', $query);
		$names = [];
		foreach($headers as $name => $value)
		{
			// WordPress keeps a header's values as a list: the first is the one read
			$names[strtolower((string)$name)] = is_array($value) ? (string)(array_values($value)[0] ?? '') : (is_scalar($value) ? (string)$value : '');
		}
		
		return $facts->derived(strtoupper($method), Facts::decodeOnce('/' . self::restPrefix($facts) . $path), $query, is_array($body) ? $body : [], $body,
			$names);
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
		$prefix = self::restPrefix($facts);
		foreach([$path, rawurldecode($path)] as $spelling)
		{
			$route = self::routeIn($spelling, $prefix);
			if($route !== null && in_array($route, $routes, true) === false)
			{
				$routes[] = $route;
			}
		}
		// rest_route is a query var WP::parse_request() reads, from $_POST then $_GET, and parse_request() runs through the front
		// controller alone (frontController()); PHP fills $_POST on POST alone, and a batch's sub-request has no query vars of its own
		$bags = $facts->outer() === null && self::frontController($facts) ? (strtoupper($facts->method) === 'POST' ? [$facts->query, $facts->form] : [$facts->query]) : [];
		foreach($bags as $bag)
		{
			foreach(Kernel::pick($bag, 'rest_route') as $value)
			{
				// WordPress's empty(): '' and '0' address no route, and an untrailed '0' is the index
				if($value !== '' && $value !== '0')
				{
					$route = self::untrailed($value);
					$routes[] = $route === '0' ? '/' : $route;
				}
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
	 * it (subRequest(): POST when it names no method); none for any other
	 * request, and none past BATCH_MAX (batchUnread())
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
				$subs[] = self::subRequest($facts, is_string($request['method'] ?? null) ? $request['method'] : 'POST', $request['path'], $request['body'] ?? null,
					is_array($request['headers'] ?? null) ? $request['headers'] : []);
			}
		}
		
		return $subs;
	}
	
	/**
	 * Whether a path reaches WordPress's front controller — index.php by
	 * name, or a pretty path a rewrite hands it — the one place wp() runs
	 * WP::parse_request() (wp-blog-header.php): wp-admin's scripts,
	 * wp-login.php, xmlrpc.php and a plugin's own file never do, so
	 * rest_route and the REST method override mean nothing there
	 */
	public static function frontController(
		Facts $facts,
	): bool
	{
		$script = $facts->scriptPath();
		
		return preg_match('~\.php$~i', $script) !== 1 || preg_match('~(^|/)index\.php$~i', $script) === 1;
	}
	
	/** whether a request addresses WordPress's batch route as the method it runs (appMethod()): the route answers POST alone */
	public static function isBatch(
		Facts $facts,
	): bool
	{
		return $facts->appMethod() === 'POST' && array_filter(self::routes($facts), static fn(string $route): bool => strcasecmp($route, self::BATCH_ROUTE) === 0) !== [];
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
		// the form as PHP parsed it: the batch route takes POST alone, so no body the kernel parses itself reaches it
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
	 * content type is one WordPress reads as JSON (jsonMediaType()), else
	 * whenever the adapter named no content type and handed a JSON body
	 */
	protected static function jsonFirst(
		Facts $facts,
	): bool
	{
		$type = $facts->headers['content-type'] ?? null;
		
		return is_string($type) === false || self::jsonMediaType($type);
	}
	
	/**
	 * Whether a request is a batch whose sub-requests the kernel did not
	 * read in full: the JSON body that comes first past JSON_CAP
	 * (Facts::jsonUnread()), or a list past BATCH_MAX (batchOverflows())
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
		
		return (self::jsonFirst($facts) && $facts->jsonUnread()) || self::batchOverflows($facts);
	}
	
	/**
	 * Whether a batch lists more requests than BATCH_MAX, which WordPress
	 * itself refuses to run: a vpatch the unread ones may reach fails closed
	 * at no honest cost, where a body past JSON_CAP, whose count WordPress
	 * would accept, only holds unanswered
	 */
	public static function batchOverflows(
		Facts $facts,
	): bool
	{
		$list = self::isBatch($facts) ? self::batchList($facts) : null;
		
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
		
		// who alone, as Kernel::patched() judges it for this caller
		return $routed && Kernel::patched(['who' => $rule['who'] ?? '', 'conditions' => []], $facts) !== null;
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
				if(count($found) === self::OCCURRENCES_MAX || $budget < 0)
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
			if(++$count > self::OCCURRENCES_MAX || $budget < 0)
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
}
