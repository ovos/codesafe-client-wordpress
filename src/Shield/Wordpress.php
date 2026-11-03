<?php
declare(strict_types=1);

/**
 * ovos/codesafe Shield — WordPress's kernel module, vendored beside the
 * kernel (Shield.php): what WordPress makes of a request that the core does
 * not read alike for every platform. Its REST route (target `rest`, in either
 * spelling, under the site's REST prefix), its batch route (each request a
 * batch lists reaches its own route's handler), its XML-RPC call (target
 * `xmlrpc`, the method; `xmlrpc:<dot.path>`, a parameter, base64 decoded as
 * the server decodes it), the shortcode and block attributes a decode step
 * reads (`shortcode:<tag>.<attribute>`, `block:<namespace/name>.<dot.path>`)
 * and the JSON types WordPress reads as JSON. A kernel not given this module
 * drops a rule that names these words at the pull and reads none of them:
 * nothing is guessed.
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

use Closure;

use function abs;
use function array_filter;
use function array_pop;
use function array_slice;
use function array_values;
use function base64_decode;
use function count;
use function explode;
use function html_entity_decode;
use function in_array;
use function is_array;
use function is_infinite;
use function is_scalar;
use function is_string;
use function json_decode;
use function parse_str;
use function preg_match;
use function preg_match_all;
use function preg_replace;
use function rawurldecode;
use function rtrim;
use function sprintf;
use function str_contains;
use function str_replace;
use function str_ends_with;
use function str_repeat;
use function str_starts_with;
use function strcasecmp;
use function strcspn;
use function stripcslashes;
use function strlen;
use function strpos;
use function strrpos;
use function strspn;
use function strtolower;
use function strtoupper;
use function strtr;
use function substr;
use function substr_compare;
use function substr_count;
use function substr_replace;
use function trim;

use const ENT_QUOTES;
use const ENT_XML1;
use const PREG_SET_ORDER;

final class Wordpress implements Platform
{
	/** the word X-Shield-Platforms names this module by */
	public const NAME = 'wordpress';
	
	/**
	 * the REST route in either spelling, and the XML-RPC method a call names:
	 * frame targets with no name, which select the handler a request reaches
	 */
	public const TARGETS = ['rest', 'xmlrpc'];
	
	/** the targets that take a name: `xmlrpc:<dot.path>`, a parameter of the XML-RPC call — positional from 0, a struct member by its name, `*` any */
	public const PREFIXES = ['xmlrpc'];
	
	/**
	 * what X-Shield-Platforms names beside `wordpress` for this module: it
	 * reads the XML-RPC targets, which a module before them drops at the pull
	 */
	public const WORD_XMLRPC = 'wordpress-xmlrpc';
	
	/** the bytes PHP's trim() takes off either end, as IXR_Message trims a message */
	public const TRIMMED_BYTES = " \t\n\r\0\x0B";
	
	/** the script WordPress's XML-RPC server runs as */
	public const XMLRPC_SCRIPT = '/xmlrpc.php';
	
	/**
	 * the elements a call holds at most, IXR_Message's own limit (the
	 * xmlrpc_element_limit filter's default): WordPress refuses a message
	 * with more than twice as many `<`, unless a site raised it, so past it a
	 * call is unread rather than refused
	 */
	public const XMLRPC_ELEMENTS_MAX = 30000;
	
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
	
	/** its targets that take a name (Platform's optional prefixes()) */
	public function prefixes(): array
	{
		return self::PREFIXES;
	}
	
	/** the words a door serves its XML-RPC targets to a kernel by (Platform's optional words()) */
	public function words(): array
	{
		return [self::WORD_XMLRPC];
	}
	
	public function values(
		string $target,
		Facts $facts,
	): array
	{
		if($target === 'rest')
		{
			return self::routes($facts);
		}
		$call = $target === 'xmlrpc' || str_starts_with($target, 'xmlrpc:') ? self::xmlrpcCall($facts) : null;
		if(is_array($call) === false)
		{
			return [];
		}
		if($target === 'xmlrpc')
		{
			return $call['methods'];
		}
		// a parameter of the call, and of each call system.multicall lists: any of them is enough
		$values = [];
		foreach($call['params'] as $params)
		{
			foreach(Kernel::pickJson($params, substr($target, strlen('xmlrpc:'))) as $value)
			{
				$values[] = $value;
			}
		}
		
		return $values;
	}
	
	/** whether an XML-RPC target was not read whole for this request (Platform's optional unread(), xmlrpcCall()) */
	public function unread(
		string $target,
		Facts $facts,
	): bool
	{
		return ($target === 'xmlrpc' || str_starts_with($target, 'xmlrpc:')) && self::xmlrpcCall($facts) === false;
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
			// WordPress keeps a header's values as a list: the first is the one read, a scalar as PHP writes it, anything else empty
			$first = is_array($value) ? (array_values($value)[0] ?? null) : $value;
			$names[strtolower((string)$name)] = is_scalar($first) ? (string)$first : '';
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
	
	/**
	 * The XML-RPC call a request carries, as WordPress's server reads it
	 * (xmlrpc.php, IXR_Server::serve()): on a POST to a script ending in
	 * /xmlrpc.php, the body as sent whatever its Content-Type, trimmed,
	 * through IXR_Message's reading (ixr()) — the method it names and each
	 * one system.multicall lists (IXR_Server::multiCall(), one level: a
	 * nested multicall runs nothing), and the parameters of the call and of
	 * each listed one. Null where no call runs: another script, another
	 * method, a body IXR_Message refuses or a message that is no
	 * methodCall; false where the kernel did not read it whole (unread()):
	 * past Facts::RAW_CAP, past XMLRPC_ELEMENTS_MAX, XML its reader does not
	 * follow, or no body to read. Read once per request
	 *
	 * @return array{methods: list<string>, params: list<list<mixed>>}|false|null
	 */
	public static function xmlrpcCall(
		Facts $facts,
	): array|false|null
	{
		return $facts->kept('xmlrpc', static function() use ($facts): array|false|null
		{
			if($facts->outer() !== null || strtoupper($facts->method) !== 'POST' || str_ends_with(strtolower($facts->scriptPath()), self::XMLRPC_SCRIPT) === false)
			{
				return null;
			}
			$raw = $facts->raw();
			// a call the kernel cannot see may be any call
			if($raw === null || strlen($raw) > Facts::RAW_CAP)
			{
				return false;
			}
			$message = self::ixr(trim($raw));
			if(is_array($message) === false)
			{
				return $message;
			}
			$methods = [$message['method']];
			$params = [$message['params']];
			// the calls system.multicall runs, each with its own parameters
			if($message['method'] === 'system.multicall' && is_array($message['params'][0] ?? null))
			{
				foreach($message['params'][0] as $call)
				{
					if(is_array($call) && is_scalar($call['methodName'] ?? null))
					{
						$methods[] = (string)$call['methodName'];
					}
					if(is_array($call) && is_array($call['params'] ?? null))
					{
						$params[] = $call['params'];
					}
				}
			}
			
			return ['methods' => $methods, 'params' => $params];
		});
	}
	
	/**
	 * A message as IXR_Message::parse() reads it: the XML declaration taken
	 * out of the first 100 bytes and a DOCTYPE without a subset out of the
	 * first 200, a root of methodCall, methodResponse or fault, at most
	 * XMLRPC_ELEMENTS_MAX elements, then each tag as tag_open(), cdata()
	 * and tag_close() read it (ixrClose()) over the XML (xmlEvents()). Null
	 * where IXR_Message refuses the message or it is no methodCall, false
	 * where the reader does not follow it. What IXR_Message takes off the
	 * front is read past, never copied off: a message of RAW_CAP bytes is
	 * held once, beside the text of its largest value
	 *
	 * @return array{method: string, params: list<mixed>}|false|null
	 */
	public static function ixr(
		string $message,
	): array|false|null
	{
		$window = substr($message, 0, 100);
		$head = (string)preg_replace('/<\?xml.*?\?>/s', '', $window, 1);
		// a declaration that begins the message leaves the rest of the window at its end: the message is read from there; one in
		// the window's middle, which no client writes, is taken out as IXR_Message takes it, at the cost of a copy
		if(str_ends_with($window, $head) === false)
		{
			$message = trim(substr_replace($message, $head, 0, 100));
			$window = '';
			$head = '';
		}
		$from = strlen($window) - strlen($head);
		$from+= strspn($message, self::TRIMMED_BYTES, $from);
		// a DOCTYPE is taken off the next 200 bytes' start alone: read past the same way
		$window = substr($message, $from, 200);
		$from+= strlen($window) - strlen((string)preg_replace('/^<!DOCTYPE[^>]*+>/i', '', $window, 1));
		$from+= strspn($message, self::TRIMMED_BYTES, $from);
		$root = substr($message, $from, strcspn($message, "> \t\r\n", $from, 20));
		if($from >= strlen($message) || in_array($root, ['<methodCall', '<methodResponse', '<fault'], true) === false)
		{
			return null;
		}
		// WordPress refuses more by default; the xmlrpc_element_limit filter may raise it, so the rest is unread, not refused
		if(2 * self::XMLRPC_ELEMENTS_MAX < substr_count($message, '<', $from))
		{
			return false;
		}
		$state = ['contents' => '', 'type' => '', 'stack' => [], 'kinds' => [], 'names' => [], 'params' => [], 'method' => ''];
		$read = self::xmlEvents($message, static function(string $event, string $data) use (&$state): void
		{
			if($event === 'text')
			{
				$state['contents'] .= $data;
			}
			elseif($event === 'open')
			{
				$state['contents'] = '';
				if($data === 'methodCall' || $data === 'methodResponse' || $data === 'fault')
				{
					$state['type'] = $data;
				}
				elseif($data === 'data' || $data === 'struct')
				{
					$state['kinds'][] = $data === 'data' ? 'array' : 'struct';
					$state['stack'][] = [];
				}
			}
			else
			{
				self::ixrClose($state, $data);
			}
		}, $from);
		
		return $read === false ? false : ($state['type'] === 'methodCall' ? ['method' => $state['method'], 'params' => $state['params']] : null);
	}
	
	/**
	 * IXR_Message::tag_close(): a typed value as WordPress gets it — an int
	 * as PHP's (int) reads its trimmed text, a double as PHP's (float) does
	 * (doubleOf()), a boolean '1' or '', a base64 decoded as base64_decode()
	 * does without strict, a string trimmed, an untyped value that is not
	 * blank as sent, a date as its trimmed text — added to the struct (under
	 * the open member's name) or the array open, else to the parameters; a
	 * name pushed, a member popped, the method name trimmed; the contents
	 * emptied whatever the tag
	 */
	protected static function ixrClose(
		array &$state,
		string $tag,
	): void
	{
		$contents = $state['contents'];
		$state['contents'] = '';
		$value = match($tag)
		{
			'int', 'i4' => (string)(int)trim($contents),
			'double' => self::doubleOf(trim($contents)),
			'dateTime.iso8601' => trim($contents),
			'string' => trim($contents),
			'value' => trim($contents) !== '' ? $contents : null,
			'boolean' => (bool)trim($contents) ? '1' : '',
			'base64' => (string)base64_decode($contents),
			'data', 'struct' => array_pop($state['stack']),
			default => null,
		};
		if($tag === 'data' || $tag === 'struct')
		{
			array_pop($state['kinds']);
		}
		elseif($tag === 'member')
		{
			array_pop($state['names']);
		}
		elseif($tag === 'name')
		{
			$state['names'][] = trim($contents);
		}
		elseif($tag === 'methodName')
		{
			$state['method'] = trim($contents);
		}
		if($value === null)
		{
			return;
		}
		$open = count($state['stack']) - 1;
		if($open < 0)
		{
			$state['params'][] = $value;
		}
		elseif($state['kinds'][count($state['kinds']) - 1] === 'struct')
		{
			// no member open: PHP reads the missing name as null, the key ''
			$state['stack'][$open][$state['names'] === [] ? '' : $state['names'][count($state['names']) - 1]] = $value;
		}
		else
		{
			$state['stack'][$open][] = $value;
		}
	}
	
	/**
	 * A double's text as the value a test reads: what PHP's (float) makes of
	 * it, as IXR_Message does — `1e3` is 1000, `500abc` 500 — in the fewest
	 * digits that read back as that double, written out up to 21 integer
	 * digits and down to 10^-6, past either as `1e+21`: the number a number
	 * test compares, the text a text test reads, the Node twin's alike; an
	 * infinite one INF or -INF
	 */
	public static function doubleOf(
		string $text,
	): string
	{
		$double = (float)$text;
		if(is_infinite($double))
		{
			return $double > 0 ? 'INF' : '-INF';
		}
		if($double === 0.0)
		{
			return '0';
		}
		// the fewest significant digits that read back as this double: seventeen always do
		$digits = 1;
		while((float)sprintf('%.' . ($digits - 1) . 'e', $double) !== $double)
		{
			$digits++;
		}
		preg_match('/^(-?)([0-9])(?:\.([0-9]+))?e([+-][0-9]+)$/', sprintf('%.' . ($digits - 1) . 'e', $double), $parts);
		$mantissa = rtrim($parts[2] . ($parts[3] ?? ''), '0');
		$length = strlen($mantissa);
		// how many of the digits stand before the decimal point
		$point = (int)$parts[4] + 1;
		
		return $parts[1] . match(true)
		{
			$point >= $length && $point <= 21 => $mantissa . str_repeat('0', $point - $length),
			$point > 0 && $point <= 21 => substr($mantissa, 0, $point) . '.' . substr($mantissa, $point),
			$point > -6 && $point <= 0 => '0.' . str_repeat('0', -$point) . $mantissa,
			default => $mantissa[0] . ($length > 1 ? '.' . substr($mantissa, 1) : '') . 'e' . ($point > 0 ? '+' : '-') . abs($point - 1),
		};
	}
	
	/**
	 * A document's elements as libxml2 (PHP's ext/xml, which IXR_Message
	 * parses with) hands them to a handler — `open` and `close` with the
	 * tag, `text` with the character data between two tags, one event a
	 * run, its line ends folded to one `\n` and its references decoded (the
	 * five XML ones, numeric ones of any length to UTF-8; references()),
	 * CDATA as it is, line ends and all; comments and processing
	 * instructions skipped. A name is read as XML 1.0's and wider: an ASCII
	 * one as it allows, any byte past ASCII in it (where libxml2 refuses
	 * such a name, WordPress runs nothing). False where the document is
	 * anything else or not well formed: no UTF-8, a DOCTYPE, an unknown
	 * entity, a control byte, a tag closed out of order. The document starts
	 * at $from, and the bytes before it are held to the same UTF-8 and
	 * control-byte checks: what a client puts in an XML declaration is
	 * ASCII. It is never copied whole: a text run is read where it stands,
	 * and a run of references costs a few passes in C, never a call each
	 */
	public static function xmlEvents(
		string $xml,
		Closure $handler,
		int $from = 0,
	): bool
	{
		// UTF-8 whole, no control byte but tab and line ends, no U+FFFE or U+FFFF
		if(preg_match('//u', $xml) !== 1 || preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F]|\xEF\xBF[\xBE\xBF]/', $xml) === 1)
		{
			return false;
		}
		$name = '[A-Za-z_:\x80-\xFF][A-Za-z0-9._:\x80-\xFF-]*';
		$length = strlen($xml);
		$open = [];
		$rooted = false;
		$at = $from;
		while($at < $length)
		{
			$run = strcspn($xml, '<', $at);
			if($run > 0)
			{
				$text = substr($xml, $at, $run);
				// outside the root only blanks, a reference no blank either; `]]>` is no text anywhere
				if(($open === [] && trim($text, " \t\r\n") !== '') || str_contains($text, ']]>'))
				{
					return false;
				}
				// the line ends folded first: a reference's `&#13;` is a carriage return as written
				$text = $open === [] ? null : self::references(self::lineEnds($text));
				if($open !== [] && $text === null)
				{
					return false;
				}
				if($text !== null)
				{
					$handler('text', $text);
				}
				// a value's text is held once, by the handler: a run of RAW_CAP bytes is not held twice while the next tag decodes it
				unset($text);
				$at+= $run;
				
				continue;
			}
			if(substr_compare($xml, '<!--', $at, 4) === 0)
			{
				$end = strpos($xml, '-->', $at + 4);
				$body = $end === false ? '' : substr($xml, $at + 4, $end - $at - 4);
				if($end === false || str_contains($body, '--') || str_ends_with($body, '-'))
				{
					return false;
				}
				$at = $end + 3;
				
				continue;
			}
			if(substr_compare($xml, '<![CDATA[', $at, 9) === 0)
			{
				$end = strpos($xml, ']]>', $at + 9);
				if($open === [] || $end === false)
				{
					return false;
				}
				// as it is, its line ends too: libxml2's push parser, which ext/xml runs, hands a CDATA section over unfolded
				$handler('text', substr($xml, $at + 9, $end - $at - 9));
				$at = $end + 3;
				
				continue;
			}
			if(substr_compare($xml, '<?', $at, 2) === 0)
			{
				$end = strpos($xml, '?>', $at + 2);
				// a declaration anywhere but the start is an error to libxml2
				if($end === false || preg_match('/\G<\?(' . $name . ')(?:[ \t\r\n]|\?>)/', $xml, $target, 0, $at) !== 1 || strtolower($target[1]) === 'xml')
				{
					return false;
				}
				$at = $end + 2;
				
				continue;
			}
			if(substr_compare($xml, '</', $at, 2) === 0)
			{
				if(preg_match('/\G<\/(' . $name . ')[ \t\r\n]*>/', $xml, $tag, 0, $at) !== 1 || $open === [] || array_pop($open) !== $tag[1])
				{
					return false;
				}
				$handler('close', $tag[1]);
				$at+= strlen($tag[0]);
				
				continue;
			}
			// a start tag: its name, attributes each after a blank and named once, `>` or `/>`
			if(($rooted && $open === []) || preg_match('/\G<(' . $name . ')((?:[ \t\r\n]+' . $name . '[ \t\r\n]*=[ \t\r\n]*(?:"[^<"]*"|\'[^<\']*\'))*)[ \t\r\n]*(\/?)>/',
					$xml, $tag, 0, $at) !== 1 || self::xmlAttributes($tag[2], $name) === false)
			{
				return false;
			}
			$rooted = true;
			$handler('open', $tag[1]);
			if($tag[3] === '/')
			{
				$handler('close', $tag[1]);
			}
			else
			{
				$open[] = $tag[1];
			}
			$at+= strlen($tag[0]);
		}
		
		return $rooted && $open === [];
	}
	
	/**
	 * a text's line ends as XML reads them, `\r\n` and a lone `\r` one `\n`:
	 * two passes that each build their text at its size, where strtr()'s
	 * growing buffer holds twice a long one
	 */
	protected static function lineEnds(
		string $text,
	): string
	{
		return str_contains($text, "\r") ? str_replace("\r", "\n", str_replace("\r\n", "\n", $text)) : $text;
	}
	
	/** whether a start tag's attributes are each named once and hold only references libxml2 reads */
	protected static function xmlAttributes(
		string $attributes,
		string $name,
	): bool
	{
		preg_match_all('/(' . $name . ')[ \t\r\n]*=[ \t\r\n]*(?:"([^"]*)"|\'([^\']*)\')/', $attributes, $pairs, PREG_SET_ORDER);
		$names = [];
		foreach($pairs as $pair)
		{
			$value = ($pair[2] ?? '') . ($pair[3] ?? '');
			if(isset($names[$pair[1]]) || preg_match('/&(?!(?:lt|gt|amp|quot|apos|#[0-9]+|#x[0-9a-fA-F]+);)/', $value) === 1)
			{
				return false;
			}
			$names[$pair[1]] = true;
		}
		
		return true;
	}
	
	/**
	 * A text's references as the text they stand for: the five XML
	 * entities, a numeric one as UTF-8, its digits as many as sent (leading
	 * zeros included, as libxml2 reads them); null where an `&` opens none
	 * of them (a bare one, an unknown entity, `&#X41;`) or one names a code
	 * point XML allows no document (`&#0;`, a surrogate, past U+10FFFF).
	 * html_entity_decode() under ENT_XML1 decodes exactly those and leaves
	 * the others as written, so an `&` left over is a refused one; the `&`
	 * a reference stands for is held apart (\x01, a control byte no
	 * document holds) until then
	 */
	protected static function references(
		string $text,
	): ?string
	{
		if(str_contains($text, '&') === false)
		{
			return $text;
		}
		if(preg_match('/&(?!(?:lt|gt|amp|quot|apos|#[0-9]+|#x[0-9a-fA-F]+);)/', $text) === 1)
		{
			return null;
		}
		$decoded = html_entity_decode((string)preg_replace('/&(?:amp|#0*38|#x0*26);/', "\x01", $text), ENT_QUOTES | ENT_XML1, 'UTF-8');
		
		return str_contains($decoded, '&') ? null : str_replace("\x01", '&', $decoded);
	}
}
