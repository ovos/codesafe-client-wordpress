<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function array_key_last;
use function http_build_query;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function json_last_error;
use function mb_check_encoding;
use function mb_strlen;
use function mb_substr;
use function parse_str;
use function preg_match;
use function preg_replace_callback;
use function str_contains;
use function stripos;
use function strlen;
use function strtolower;
use function trim;

use const JSON_ERROR_NONE;
use const JSON_UNESCAPED_SLASHES;
use const JSON_UNESCAPED_UNICODE;

/**
 * The raw request body, reduced before it leaves the site.
 *
 * Mirrors Console\Error\Body on the server (docs/plans in the console repo,
 * A2 of the sender round). The body is logged so the console can REPLAY the
 * request that failed — a REST or admin-ajax call carrying JSON has an EMPTY
 * $_POST, so without it a replay is a bare method and URL.
 *
 * Until 2026-09-21 the body was scrubbed by the same flat `<name> = <value>`
 * regex as free text, which is the mistake this class exists to end: a body is
 * a structured DOCUMENT. Six holes in that regex all came from reading one as
 * the other, and on WordPress two of them were the worst possible shapes —
 * `opts[api_key]` is how every settings form posts, and XML-RPC names its
 * credentials not at all.
 *
 * So: parse, hand the tree to the key walk (Redactor::scrub, which has never
 * had those holes because it walks KEYS), run the text scrubber over what is
 * left inside the string values, and re-encode. Anything that will not parse
 * is DROPPED rather than handed back to the regex.
 */
final class Body
{
	/** no body leaves the site at all */
	public const MODE_OFF = 'off';
	
	/** parsed, key-scrubbed, re-encoded — the default */
	public const MODE_STRUCTURE = 'structure';
	
	/** the raw body as text, cut at FULL_MAX */
	public const MODE_FULL = 'full';
	
	public const MODES = [self::MODE_OFF, self::MODE_STRUCTURE, self::MODE_FULL];
	
	/**
	 * What `structure` sends. Half of what this plugin used to send, and
	 * generous enough that a real WooCommerce order (2–6 KB) survives whole.
	 * A document over the cap is SHRUNK — trailing keys go and `_truncated`
	 * says so — never cut mid-token, because it has to keep parsing.
	 */
	public const STRUCTURE_MAX = 8192;
	
	/** what `full` sends — the cap this plugin has always applied */
	public const FULL_MAX = 16384;
	
	/** well under json_decode's 512 default: the key walk caps the depth anyway */
	public const JSON_DEPTH = 32;
	
	/**
	 * Endpoints that exist to RECEIVE credentials. Their body never leaves the
	 * site, whatever it parses as and whatever mode the site runs in.
	 *
	 * On WordPress this list is doing most of the work, because the two most
	 * brute-forced endpoints on the internet are both on it: wp-login.php,
	 * and xmlrpc.php, whose system.multicall packs hundreds of logins into one
	 * request and names none of them. A scanner hitting either produces errors
	 * all day, and every one of those reports used to carry the credentials it
	 * was trying.
	 */
	public const CREDENTIAL_ROUTES = [
		'wp-login.php',
		'xmlrpc.php',
		'/wp-json/jwt-auth/',
		'/oauth/token',
		'/oauth2/token',
		'/login',
		'/signin',
		'/sign-in',
		'/session',
		'/register',
		'/password/reset',
		'/password-reset',
		'/user/password',
		'/auth/token',
	];
	
	/**
	 * A `<string>` in an XML-RPC call, and the one form of it that is KEPT: the
	 * inner method name of a system.multicall, which is the attack signal
	 * rather than a credential. The alternation is ordered so the kept form
	 * wins, so this is one pass and needs no sentinel.
	 */
	protected const RPC_STRING = '/(<name>\s*methodName\s*<\/name>\s*<value>\s*<string>)'
		. '([^<]*)(<\/string>)|<string>([^<]*)<\/string>/i';
	
	/**
	 * The body, reduced per $mode, or null when nothing may be sent
	 */
	public static function redact(
		string $raw,
		string $contentType,
		string $mode = self::MODE_STRUCTURE,
		string $uri = '',
	): ?string
	{
		if($mode === self::MODE_OFF
			|| trim($raw) === ''
			|| self::isCredentialRoute($uri) === true)
		{
			return null;
		}
		
		$type = strtolower(trim($contentType));
		
		// an upload's body is megabytes of binary and $_POST already carries
		// its fields
		if(stripos($type, 'multipart/form-data') !== false)
		{
			return null;
		}
		
		// a body we cannot even read as text is one we cannot promise anything
		// about
		if(mb_check_encoding($raw, 'UTF-8') === false || str_contains($raw, "\0") === true)
		{
			return null;
		}
		
		if($mode === self::MODE_FULL)
		{
			return Redactor::scrubText(mb_substr($raw, 0, self::FULL_MAX), false);
		}
		
		return self::structure($raw, $type);
	}
	
	/**
	 * Whether a URI names an endpoint whose body never leaves. Matched as a
	 * substring on purpose: WordPress is mounted under a subdirectory as often
	 * as not, and a false positive costs one body while a miss costs a
	 * credential.
	 */
	public static function isCredentialRoute(
		string $uri,
	): bool
	{
		if($uri === '')
		{
			return false;
		}
		
		$path = strtolower($uri);
		
		foreach(self::CREDENTIAL_ROUTES as $route)
		{
			if(str_contains($path, $route) === true)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Whether $mode is one this class knows, so a stored option cannot turn
	 * into "no mode" and take the body decision with it
	 */
	public static function mode(
		string $mode,
	): string
	{
		$mode = trim($mode);
		
		return in_array($mode, self::MODES, true) === true ? $mode : self::MODE_STRUCTURE;
	}
	
	protected static function structure(
		string $raw,
		string $type,
	): ?string
	{
		if($type === '' || str_contains($type, 'json') === true)
		{
			return self::json($raw);
		}
		
		if(str_contains($type, 'x-www-form-urlencoded') === true)
		{
			return self::form($raw);
		}
		
		if(str_contains($type, 'xml') === true)
		{
			return self::xml($raw);
		}
		
		return self::fit(Redactor::scrubText(mb_substr($raw, 0, self::STRUCTURE_MAX), false));
	}
	
	protected static function json(
		string $raw,
	): ?string
	{
		$decoded = json_decode($raw, true, self::JSON_DEPTH);
		
		if(json_last_error() !== JSON_ERROR_NONE)
		{
			return null; // truncated, malformed, or not JSON after all
		}
		
		if(is_array($decoded) === true)
		{
			return self::encode(self::scrubStrings(Redactor::scrub($decoded, identities: false)));
		}
		
		// a bare JSON scalar: a string can hide a credential, a number cannot
		return is_string($decoded)
			? self::encode(Redactor::scrubText($decoded, false))
			: self::fit($raw);
	}
	
	/**
	 * parse_str gives the same nested array PHP would have put in $_POST, so
	 * `opts[api_key]` becomes a real key and the walk finds it — and the values
	 * are DECODED, which is the other half of why parsing matters: the text
	 * scrubber never decodes, so `note=password%3A%20hunter2` carries no
	 * separator for it to see and travelled whole.
	 */
	protected static function form(
		string $raw,
	): ?string
	{
		parse_str($raw, $fields);
		
		if($fields === [])
		{
			return null;
		}
		
		return self::shrink(
			self::scrubStrings(Redactor::scrub($fields, identities: false)),
			static fn(array $data): string => http_build_query($data),
		);
	}
	
	/**
	 * An XML body, deliberately NOT handed to a real parser: this string is
	 * attacker-controlled and runs inside someone's site, so pointing libxml
	 * at it buys entity expansion and a parser CVE surface in exchange for
	 * tidier output. The text scrubber's XML pass reads <password>x</password>
	 * including a namespace prefix, which is the whole of what a name-based
	 * rule can do for XML.
	 *
	 * XML-RPC is the exception that needs structure, because it NAMES nothing.
	 * Reduced to its shape: every <string> becomes its length while the method
	 * names stay. A system.multicall carrying two hundred wp.getUsersBlogs IS
	 * the signal, stated more plainly than the credentials stated it.
	 */
	protected static function xml(
		string $raw,
	): ?string
	{
		$body = mb_substr($raw, 0, self::STRUCTURE_MAX);
		
		if(preg_match('/<methodCall[\s>]/i', $body) === 1)
		{
			$body = (string)preg_replace_callback(
				self::RPC_STRING,
				static function(array $match): string
				{
					// the kept form: an inner method name, not a credential
					if(($match[1] ?? '') !== '')
					{
						return $match[0];
					}
					
					return '<string>[redacted:' . mb_strlen($match[4] ?? '') . ']</string>';
				},
				$body,
			);
		}
		
		return self::fit(Redactor::scrubText($body, false));
	}
	
	/**
	 * The text scrubber over every string VALUE in the tree, after the key walk
	 * has had it. Both are needed: the key walk answers a field NAMED like a
	 * credential, this answers one hiding inside an ordinary field's free text.
	 *
	 * @param array<array-key, mixed> $data
	 * @return array<array-key, mixed>
	 */
	protected static function scrubStrings(
		array $data,
	): array
	{
		foreach($data as $key => $value)
		{
			if(is_array($value) === true)
			{
				$data[$key] = self::scrubStrings($value);
				continue;
			}
			
			if(is_string($value) === true)
			{
				$data[$key] = Redactor::scrubText($value, false);
			}
		}
		
		return $data;
	}
	
	/**
	 * @param array<array-key, mixed>|string $data
	 */
	protected static function encode(
		array|string $data,
	): ?string
	{
		if(is_string($data) === true)
		{
			return self::fit($data);
		}
		
		return self::shrink($data, static function(array $data): ?string
		{
			$json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
			
			return $json === false ? null : $json;
		});
	}
	
	/**
	 * Serialise, and while the result is over the cap drop the last top-level
	 * key and say so. Shared with the form path, which cannot be cut as a
	 * string either: cut mid-token its last parameter is corrupt.
	 *
	 * @param array<array-key, mixed> $data
	 * @param callable(array<array-key, mixed>): ?string $serialise
	 */
	protected static function shrink(
		array $data,
		callable $serialise,
	): ?string
	{
		$out = $serialise($data);
		
		while($out !== null && strlen($out) > self::STRUCTURE_MAX)
		{
			// the marker is re-added each round, so take it off before asking
			// which key is last, or it would be the one dropped
			unset($data['_truncated']);
			$last = array_key_last($data);
			
			if($last === null)
			{
				return null;
			}
			
			unset($data[$last]);
			$data['_truncated'] = true;
			$out = $serialise($data);
		}
		
		return $out === null || trim($out) === '' ? null : $out;
	}
	
	protected static function fit(
		?string $body,
	): ?string
	{
		if($body === null || trim($body) === '')
		{
			return null;
		}
		
		return mb_substr($body, 0, self::STRUCTURE_MAX);
	}
}
