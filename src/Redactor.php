<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function count;
use function explode;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function ltrim;
use function max;
use function mb_strlen;
use function mb_substr;
use function min;
use function preg_match;
use function preg_replace;
use function preg_replace_callback;
use function preg_split;
use function rawurldecode;
use function rawurlencode;
use function strlen;
use function strpos;
use function strtolower;
use function strtr;
use function substr;
use function trim;

/**
 * Scrubs request variables and extras before they leave the site.
 *
 * Secret fields (per docs/API.V1.md plus WordPress's own login/profile field
 * names) are dropped entirely; username fields are anonymized to their first
 * character and e-mail addresses (in any value) are masked with the domain
 * kept. The console redacts again server-side as a backstop.
 */
final class Redactor
{
	/**
	 * The secret names, as a bare regex FRAGMENT, because the list is needed
	 * in three shapes: matched against a field name (REDACT_PATTERN, used by
	 * scrub() and scrubUrl()), against a header name (isSecretName()), and
	 * spliced into the "<name> = <value>" search scrubText() runs over a raw
	 * request body. All three derive from this one list on purpose — a name
	 * added here has to take effect in every one of them, or the redaction
	 * grows a hole exactly where someone believed they closed one.
	 *
	 * The group is NON-capturing deliberately: scrubText() splices this in
	 * beside numbered backreferences, and a capturing group here shifts every
	 * one of them so the search silently matches nothing.
	 *
	 * pass(?:word|wd)? also covers pass1/pass2/user_pass as a substring; pwd
	 * is wp-login's field.
	 */
	protected const SECRET_NAMES =
		'pass(?:word|wd)?|pwd|token|secret|authorization|cookie|api[-_]key'
		// promoted from the westbahn pipeline 2026-09-22: safe unanchored,
		// since no ordinary field name contains jwt or bearer
		. '|jwt|bearer|signature'
		// a CSRF nonce — _wpnonce, _ajax_nonce, woocommerce-process-checkout-nonce
		// (the G3 sanitizer test, 2026-09-23): no letter before it, or wp
		// before it — never unanchored, announce and pronounce contain it.
		// The console's list carries the same rule (Scrubber::NAMES)
		. '|(?<![a-z])nonce|wpnonce'
		// the payment and reset fields (security audit 2026-10-03 H3): wp-login's
		// rp_key beside the `key` of its link; the card number in every gateway's
		// spelling — card_number, ccnum, cc-number, wc-gateway-card-number,
		// x_card_num — with its code (x_card_code), expiry and the three names of
		// the security code; an account number and an IBAN. cvv, cvc, csc and
		// iban only as a WORD of the name (no letter beside them): Caribbean holds
		// no iban, but a bare substring rule is how the next one would
		. '|rp[-_]?key'
		. '|card[-_]?(?:num(?:ber)?|no(?![a-z])|code|cvc|cvv|exp(?:iry|iration|(?![a-z])))'
		. '|cc[-_]?(?:num(?:ber)?|no(?![a-z]))'
		. '|(?<![a-z])(?:cvv2?|cvc2?|csc|ccv)(?![a-z])|security[-_]?code'
		. '|(?:account|acct)[-_]?(?:num(?:ber)?|no(?![a-z]))|(?<![a-z])iban(?![a-z])';
	
	/** the names above, matched against a field name */
	protected const REDACT_PATTERN = '/' . self::SECRET_NAMES . '/i';
	
	/**
	 * What a language wraps a secret name in: the dots and dashes of a path
	 * (`config.api_key`), and the BRACKETS a form field uses — `opts[api_key]`,
	 * the WordPress house style, which walked straight past the pair search
	 * until 2026-09-21 because [ and ] were not in this class. Every WordPress
	 * settings form and every Gravity/CF7 field posts in that shape.
	 */
	protected const NAME_EDGE = '[A-Za-z0-9_.\-\[\]]{0,24}';
	
	/** the same, for an XML element or attribute name — namespaces carry a colon */
	protected const XML_NAME_EDGE = '[A-Za-z0-9_.:\-]{0,24}';
	
	/**
	 * An auth SCHEME counts as part of the value, so `Authorization: Bearer x`
	 * collapses to one mark rather than redacting the word Bearer and then the
	 * token behind it.
	 */
	protected const SCHEME = '(?:(?:bearer|basic|token|digest)\s+)?';
	
	/**
	 * What sits between a name and its value. `>` is excluded from the value
	 * classes below for this constant's sake: the unquoted pass has no
	 * value-quote group to absorb a quote, so the alternation backtracks — on
	 * `'secret' => 'x'` it gives up the `=>`, takes the bare `=` and matches
	 * the `>` as the value.
	 */
	protected const SEPARATOR = '(\s*(?:=>|[:=])\s*)';
	
	/**
	 * Username field names for the TEXT path. `log` is included, unlike the
	 * console's copy: here it is wp-login's own field and means nothing else,
	 * while on the server `extra.log` is routinely a log excerpt.
	 */
	protected const USERNAME_NAMES = 'user(?:[_-]?(?:name|login))?|log(?:in)?';
	
	/**
	 * Values that are a DIAGNOSTIC however secret-sounding the name in front of
	 * them. "Access denied for user 'x'@'y' (using password: YES)" is the
	 * canonical MySQL error and the YES is the entire diagnostic — it says
	 * whether a password was sent at all. Mirrors the console's HARMLESS_VALUES.
	 */
	protected const HARMLESS_VALUES = [
		'yes', 'no', 'true', 'false', 'null', 'nil', 'none',
		'on', 'off', 'set', 'unset', 'empty', '0', '1',
	];
	
	/**
	 * Field names whose value is masked to every MASK_GROUP-th character, the
	 * rest starred (e.g. "bob" -> "b**", "marcin" -> "m***i*"). Includes
	 * WordPress's own login field names —
	 * log (wp-login) and user_login (profile/registration) — beside the generic
	 * ones. Anchored, so identifier fields like userId / userAgent stay intact.
	 */
	protected const USERNAME_PATTERN = '/^(user([_-]?(name|login))?|log(in)?)$/i';
	
	/**
	 * maskName() keeps every MASK_GROUP-th character of a value and stars the
	 * rest, so the mask is exactly as long as what it replaced and a field
	 * finally says how much was there. MASK_MAX caps the stars, and past the
	 * cap the mask states the real length instead ("[200]") — a login field
	 * holding thousands of characters is someone trying something. Mirrors
	 * Logger::MASK_GROUP in ovos/php-library, the console's server-side
	 * Scrubber and the two JS clients — the answers must agree, or the same
	 * event means different things depending on which client sent it.
	 */
	protected const MASK_GROUP = 4;
	
	protected const MASK_MAX = 24;
	
	/**
	 * A cut maskName() result: whole revealed-character groups, then the
	 * bracketed length. Alone among the masks this form is not idempotent
	 * by construction — re-masking would measure the mask and report 29 for a
	 * value of 200 — so maskName() returns it untouched; the console scrubs
	 * the report again server-side.
	 */
	protected const MASKED_CUT_PATTERN = '~^(?:.\*{3})+\[\d+\]$~u';
	
	/**
	 * Names that are credentials ONLY as query parameters, kept apart from
	 * REDACT_PATTERN because they are too generic to drop as field names.
	 *
	 * `key` is WordPress's own password-reset token: wp-login.php?action=rp&
	 * key=<20 chars>&login=<user>. Nothing above touched it — api[-_]key needs
	 * the api — so a 404 or an error on a reset link sent a live key. `login`
	 * was already masked; the key beside it was not.
	 */
	// otp, pin and hash are promoted from westbahn's DENYLIST_EXACT, which
	// matches a WHOLE name. As field names they would over-redact — `hash`
	// eats content_hash and filehash, `pin` eats shipping and pinned — so
	// they are credentials as a query parameter only.
	//
	// Since 1.0.3 the same exact names drop the value of a REQUEST field too
	// (scrub(), request: true — get, post and the parsed body): the reset link's
	// `key` reached request.get whole while the uri beside it said [redacted]
	// (security audit 2026-10-03 H3). Exact names only, so content_hash, pinned
	// and coupon_code stay readable.
	public const QUERY_NAMES = ['key', 'auth', 'code', 'sig', 'signature',
		'otp', 'pin', 'hash'];
	
	/**
	 * A path segment is a secret, not a slug, when it has no word structure and
	 * carries the character mix a generated token does: a JWT, a uuid, a long
	 * hex string, or one long run of mixed case with digits. Single-use
	 * credentials travel in paths and are followed over GET — /reset/<token>,
	 * /invite/<token> — and this plugin had nothing between such a URL and the
	 * console.
	 *
	 * The rule is shared with the console's own Scrubber and the browser
	 * client; the corpus that pins all three lives in the console repo
	 * (project/application/tests/fixtures/looks-secret.json). Keep them equal:
	 * a length-only version of this once redacted every German slug.
	 */
	protected const PATH_CANDIDATE = '~(/)([A-Za-z0-9_.-]{20,})(?=[/?#]|$)~';
	
	/**
	 * An e-mail address inside a string value. The local part is masked to
	 * every MASK_GROUP-th character (maskName), the domain is left intact
	 * (john.doe@example.com -> j***.***@example.com) — the mask says how
	 * long the address was and the domain still tells providers/customers
	 * apart, while the identifying part is gone.
	 */
	protected const EMAIL_PATTERN =
		'/([a-z0-9._%+\-]+)@([a-z0-9.\-]+\.[a-z]{2,})/i';
	
	/**
	 * An address this class ALREADY masked. A mask's local part always holds
	 * a star (or a bracketed cut length) somewhere before the @ — a real
	 * local part never does — so this spots every mask shape: the legacy
	 * fixed form (j***@…), the length-aware form (j***.***@…, m***i@…) and
	 * the cut form (x***x***[47]@…).
	 */
	protected const MASKED_EMAIL_PATTERN =
		'/[*\]][a-z0-9._%+\-]*@[a-z0-9.\-]+\.[a-z]{2,}/i';
	
	protected const MAX_DEPTH = 8;
	
	/**
	 * A bag scrubbed: secret-named fields dropped wholesale; e-mail
	 * addresses and username fields masked — unless $identities is false,
	 * which is how the REQUEST data (get, post, the body) is scrubbed: the
	 * console masks those on arrival and keeps the original encrypted for an
	 * audited reveal and a replay (console docs/plans/reveal-everything.md).
	 *
	 * $request marks a bag of REQUEST fields (get, post, a parsed body): the
	 * QUERY_NAMES drop there too, by exact name — the reset link's `key` and
	 * an OAuth `code` are the same credential in $_GET as in the uri
	 */
	public static function scrub(
		array $values,
		int $depth = 0,
		bool $identities = true,
		bool $request = false,
	): array
	{
		if($depth >= self::MAX_DEPTH)
		{
			return ['[redacted]'];
		}
		
		$clean = [];
		
		foreach($values as $key => $value)
		{
			// secret fields are dropped wholesale — before recursing, so a
			// secret key whose value is an array cannot leak through its children
			if(preg_match(self::REDACT_PATTERN, (string)$key) === 1
				|| ($request && self::isQueryName((string)$key)))
			{
				$clean[$key] = '[redacted]';
				
				continue;
			}
			
			if(is_array($value))
			{
				$clean[$key] = self::scrub($value, $depth + 1, $identities, $request);
				
				continue;
			}
			
			if(is_string($value) === false || $identities === false)
			{
				$clean[$key] = $value;
				
				continue;
			}
			
			// an e-mail in ANY field (a login that is an e-mail, a "to"
			// address, ...) — masked to its length with the domain kept. A
			// one-character local part masks to ITSELF and an already-masked
			// address no longer looks like one: both still belong to this
			// rule, or the username mask below would chew them and drop the
			// domain kept on purpose.
			$masked = self::maskEmails($value);
			
			if($masked !== $value
				|| preg_match(self::EMAIL_PATTERN, $value) === 1
				|| preg_match(self::MASKED_EMAIL_PATTERN, $value) === 1)
			{
				$clean[$key] = $masked;
				
				continue;
			}
			
			if(preg_match(self::USERNAME_PATTERN, (string)$key) === 1)
			{
				$clean[$key] = self::maskName($value);
				
				continue;
			}
			
			$clean[$key] = $value;
		}
		
		return $clean;
	}
	
	/**
	 * Scrubs a URL the way scrub() scrubs request arrays: secret-named query
	 * parameters are dropped, e-mail values (in any parameter) are masked
	 * with the domain kept and username-named parameters are anonymized.
	 * The same data already leaves through request.get — this closes the
	 * uri/referer copy of it. Untouched parameters stay byte-for-byte
	 * identical; values are only re-encoded when changed.
	 */
	public static function scrubUrl(
		string $url,
	): string
	{
		// the PATH first — a token in a path is not a query parameter and had
		// no rule at all here
		$position = strpos($url, '?');
		$url = self::scrubPath(
			$position === false ? $url : substr($url, 0, $position),
		) . ($position === false ? '' : substr($url, $position));
		$position = strpos($url, '?');
		if($position !== false)
		{
			$query = (string)preg_replace_callback(
				'~(^|&)([^&=]+)=([^&]*)~',
				static function(array $match): string
				{
					$name = rawurldecode($match[2]);
					if(preg_match(self::REDACT_PATTERN, $name) === 1
						|| self::isQueryName($name))
					{
						return $match[1] . $match[2] . '=[redacted]';
					}
					
					$value = rawurldecode($match[3]);
					$masked = self::maskEmails($value);
					if($masked === $value
						// not an address in any form — raw (a one-character
						// local part masks to itself) or already masked — or
						// the username mask would drop the domain
						&& preg_match(self::EMAIL_PATTERN, $value) !== 1
						&& preg_match(self::MASKED_EMAIL_PATTERN, $value) !== 1
						&& preg_match(self::USERNAME_PATTERN, rawurldecode($match[2])) === 1)
					{
						$masked = self::maskName($value);
					}
					
					if($masked === $value)
					{
						return $match[0];
					}
					
					// keep the mask readable — @ and * are legal in a query, and
					// the [] of a stated length are what every reader expects
					return $match[1] . $match[2] . '='
						. strtr(rawurlencode($masked),
							['%40' => '@', '%2A' => '*', '%5B' => '[', '%5D' => ']']);
				},
				substr($url, $position + 1),
			);
			
			$url = substr($url, 0, $position + 1) . $query;
		}
		
		// a plain e-mail in the path (unsubscribe links and the like)
		return (string)preg_replace(self::EMAIL_PATTERN, '${1}***@${2}', $url);
	}
	
	/**
	 * Scrubs CLI argv (WP-CLI) the way scrub() scrubs request arrays. Both
	 * argument styles are covered: --password=x / password=x get the value
	 * dropped, and a bare secret-named token drops the FOLLOWING argument
	 * ("name value" pair style). E-mails in any argument are masked with
	 * the domain kept.
	 */
	public static function scrubArgs(
		array $args,
	): array
	{
		$removeNext = false;
		
		foreach($args as $key => $arg)
		{
			if(is_string($arg) === false)
			{
				continue;
			}
			
			if($removeNext)
			{
				$args[$key] = '[redacted]';
				$removeNext = false;
				
				continue;
			}
			
			if(preg_match('~^(--?)?([^=]+)=(.*)$~s', $arg, $match) === 1)
			{
				$args[$key] = preg_match(self::REDACT_PATTERN, $match[2]) === 1
					? $match[1] . $match[2] . '=[redacted]'
					: (string)preg_replace(self::EMAIL_PATTERN, '${1}***@${2}', $arg);
				
				continue;
			}
			
			if(preg_match(self::REDACT_PATTERN, ltrim($arg, '-')) === 1)
			{
				// the name stays, the value that follows is dropped
				$removeNext = true;
				
				continue;
			}
			
			$args[$key] = (string)preg_replace(self::EMAIL_PATTERN, '${1}***@${2}', $arg);
		}
		
		return $args;
	}
	
	/**
	 * Token-shaped PATH segments -> [redacted], leaving readable slugs alone.
	 */
	public static function scrubPath(
		string $path,
	): string
	{
		// a credential that FOLLOWS its name, which the shape rule below cannot
		// see: /token/abc, /api_key/xyz. Promoted from westbahn's UrlScrubber
		// 2026-09-22 and narrowed on the way — it matched the segment against
		// its query list too, so /code/at lost its country. Only the NAMES
		// list is read here: a path segment carrying token, password, secret,
		// jwt, bearer or api_key is naming a credential, where code, key, hash,
		// pin and otp are ordinary words in a route.
		$segments = explode('/', $path);
		$last = count($segments) - 1;
		
		for($i = 0; $i < $last; $i++)
		{
			if($segments[$i] !== ''
				&& $segments[$i + 1] !== ''
				&& preg_match(self::REDACT_PATTERN, $segments[$i]) === 1)
			{
				$segments[++$i] = '[redacted]';
			}
		}
		
		$path = implode('/', $segments);
		
		return (string)preg_replace_callback(
			self::PATH_CANDIDATE,
			static fn(array $match): string => self::looksSecret($match[2])
				? $match[1] . '[redacted]'
				: $match[0],
			$path,
		);
	}
	
	/**
	 * A path segment ending in one of these is a static asset, not a
	 * credential — see looksSecret().
	 *
	 * Build output and media only. `pdf`, `zip`, `csv`, `xlsx`, `json`, `xml`
	 * and friends are deliberately absent: a signed one-time download link ends
	 * in one of those, and none of them is ever emitted by a bundler.
	 */
	protected const ASSET_PATTERN = '~\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|less|map|wasm'
		. '|woff2?|ttf|otf|eot'
		. '|svg|png|jpe?g|gif|webp|avif|ico|bmp'
		. '|mp3|mp4|webm|ogg|wav)$~i';
	
	/**
	 * See PATH_CANDIDATE: a generated token, not a slug. Where it is genuinely
	 * ambiguous this errs towards redaction — an unreadable URI costs less than
	 * a leaked reset token.
	 *
	 * A cache-busted STATIC ASSET is the exception, and not an ambiguous one:
	 * every bundler names its output after a content hash (WordPress ships
	 * plenty — main.<md5>.js, index-DkL9mQxZ8vB2nR4tY7wA.js), and each trips a
	 * rule below on its 32-character or mixed-case run. Nothing was protected
	 * by that: the browser fetched the file with no credential. It cost `file`,
	 * which is the field a JS error is read from. A one-time credential in a
	 * path is a bare segment; it does not end in .js.
	 */
	public static function looksSecret(
		string $segment,
	): bool
	{
		// before the asset rule: a uuid and a bare hex run hold no dot, so only
		// a JWT could end in something that reads like an extension, and a JWT
		// stays a JWT
		if(preg_match('~^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$~', $segment) === 1
			|| preg_match('~^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$~i', $segment) === 1
			|| preg_match('~^[0-9a-f]{24,}$~i', $segment) === 1)
		{
			return true;
		}
		
		if(preg_match(self::ASSET_PATTERN, $segment) === 1)
		{
			return false;
		}
		
		if(strlen($segment) < 24)
		{
			return false;
		}
		
		$longest = 0;
		foreach(preg_split('~[-_.]+~', $segment) ?: [] as $run)
		{
			$longest = max($longest, strlen($run));
		}
		
		$digits = preg_match('~[0-9]~', $segment) === 1;
		
		// one long mixed-case run with digits, or a very long single run
		return ($digits && preg_match('~[A-Z]~', $segment) === 1 && $longest >= 16)
			|| ($digits && $longest >= 32);
	}
	
	/**
	 * Every MASK_GROUP-th character kept, the rest starred (bob -> b**,
	 * marcin -> m***i*) — the identity mask for usernames (same format the
	 * php-library sender uses), enough to tell accounts apart in a grouped
	 * issue while dropping the identifying part. The mask is as long as the
	 * value it replaced, so a line says how much was there — and past MASK_MAX
	 * the stars stop and the real length is stated instead ("[200]"), because
	 * a 4000-character login is an attempt, not a name. Masking a mask is a
	 * no-op, which is what lets the console scrub the report again.
	 */
	public static function maskName(
		string $value,
	): string
	{
		if($value === ''
			|| preg_match(self::MASKED_CUT_PATTERN, $value) === 1)
		{
			return $value;
		}
		
		$length = mb_strlen($value);
		$cut = min($length, self::MASK_MAX);
		$masked = '';
		for($index = 0; $index < $cut; $index++)
		{
			$masked.= $index % self::MASK_GROUP === 0
				? mb_substr($value, $index, 1)
				: '*';
		}
		
		return $length > $cut ? $masked . '[' . $length . ']' : $masked;
	}
	
	/**
	 * Masks e-mail addresses inside a plain string: the local part becomes a
	 * maskName() mask — as long as the address was, every MASK_GROUP-th
	 * character revealed — and the domain is kept
	 * (john.doe@example.com -> j***.***@example.com). Idempotent: a masked
	 * local part never ends in a run of address characters, so the pattern
	 * can at most re-find a single revealed character before the @, which
	 * maskName maps onto itself.
	 */
	public static function maskEmails(
		string $value,
	): string
	{
		return (string)preg_replace_callback(
			self::EMAIL_PATTERN,
			static fn(array $match): string
				=> self::maskName($match[1]) . '@' . $match[2],
			$value,
		);
	}
	
	/**
	 * Whether a NAME is one whose value never leaves the site — the same list
	 * scrub() drops by key, asked about a header name (docs/SENDER.md
	 * §context.request). One list, one answer.
	 */
	public static function isSecretName(
		string $name,
	): bool
	{
		return preg_match(self::REDACT_PATTERN, $name) === 1;
	}
	
	/**
	 * Whether a NAME is one of the QUERY_NAMES — exact, case and surrounding
	 * space aside: a credential as a query parameter or a request field, an
	 * ordinary word anywhere else
	 */
	public static function isQueryName(
		string $name,
	): bool
	{
		return in_array(strtolower(trim($name)), self::QUERY_NAMES, true);
	}
	
	/**
	 * Scrubs a raw TEXT body the way scrub() scrubs an array — by the same
	 * secret NAMES, but read out of the punctuation a body is written in
	 * rather than off an array key: `"password": "x"`, `password=x`,
	 * `'secret' => 'x'`, `<password>x</password>`.
	 *
	 * FOUR passes since 2026-09-21, where there was one. The single pass had
	 * six holes, all the same mistake — a structured document read as flat
	 * text — and all of them shipped (the corpus that pins them is the
	 * console's tests/fixtures/scrub-body.json):
	 *
	 *   1. a quoted value containing a SPACE did not redact partially, it did
	 *      not redact AT ALL: the value class excluded whitespace, so the
	 *      closing backreference could never reach the quote. Passwords
	 *      contain spaces.
	 *   2. `opts[api_key]` walked past — see NAME_EDGE.
	 *   3. no XML body was touched anywhere: the separators were `=>`, `:` and
	 *      `=`, and XML writes the name and value either side of a `>`. Every
	 *      SOAP <password> and every XML-RPC login travelled whole.
	 *   4. an escaped quote inside JSON was matched AS the value, leaking the
	 *      real one and writing a corrupted document into storage.
	 *   5. the username rule never ran on text, so `user=marcin` in a body
	 *      survived while $_POST['user'] was masked.
	 *
	 * Idempotent: [redacted] and a mask both survive a second pass, so the
	 * console scrubbing again server-side agrees with this.
	 */
	public static function scrubText(
		string $text,
		bool $identities = true,
	): string
	{
		if($text === '')
		{
			return $text;
		}
		
		$name = '(["\']?)(' . self::NAME_EDGE . '(?:' . self::SECRET_NAMES . ')'
			. self::NAME_EDGE . ')\1';
		
		// a QUOTED value, running to its own closing quote — whitespace and
		// escapes included
		$text = self::redactPairs($text,
			'/' . $name . self::SEPARATOR . '(["\'])' . self::SCHEME
				. '((?:\\\\.|(?!\4)[^\\\\])*)\4/i');
		
		// the same pair quoted with ESCAPED quotes — a string inside a JSON
		// string, which is how a GraphQL query arrives
		$text = self::redactPairs($text,
			'/' . $name . self::SEPARATOR . '(\\\\["\'])' . self::SCHEME
				. '((?:(?!\4).)*)\4/i');
		
		// an UNQUOTED value, ending at the punctuation around it. Its class can
		// begin with neither a quote nor a backslash, so a pair either pass
		// above answered is never matched twice. The empty group keeps the
		// numbering identical, so one callback serves all three.
		$text = self::redactPairs($text,
			'/' . $name . self::SEPARATOR . '()' . self::SCHEME
				. '([^"\'\s,;)&}>\\\\]{1,512})/i');
		
		// <password>x</password>, including a namespace prefix
		$text = (string)preg_replace_callback(
			'/<(' . self::XML_NAME_EDGE . '(?:' . self::SECRET_NAMES . ')'
				. self::XML_NAME_EDGE . ')((?:\s[^>]*)?)>([^<]*)<\/\1\s*>/i',
			static function(array $match): string
			{
				if(self::isHarmless($match[3]) === true)
				{
					return $match[0];
				}
				
				return '<' . $match[1] . $match[2] . '>[redacted]</' . $match[1] . '>';
			},
			$text,
		);
		
		// the request body keeps its people (see scrub()): secrets only
		if($identities === false)
		{
			return $text;
		}
		
		// the username rule, which never ran on text at all. The value class
		// excludes `@` so an address falls through to maskEmails() below, which
		// keeps the domain instead of chewing it.
		$text = (string)preg_replace_callback(
			'/(["\']?)(' . self::USERNAME_NAMES . ')\1' . self::SEPARATOR
				. '(["\']?)([^"\'\s,;)&}>@]{1,256})\4/i',
			static function(array $match): string
			{
				if($match[5] === '[redacted]' || self::isHarmless($match[5]) === true)
				{
					return $match[0];
				}
				
				return $match[1] . $match[2] . $match[1]
					. $match[3] . $match[4] . self::maskName($match[5]) . $match[4];
			},
			$text,
		);
		
		return self::maskEmails($text);
	}
	
	/**
	 * One "<name> = <value>" pass: the shared callback for the three patterns,
	 * which differ only in how the value ends.
	 */
	protected static function redactPairs(
		string $text,
		string $pattern,
	): string
	{
		return (string)preg_replace_callback(
			$pattern,
			static function(array $match): string
			{
				// an EMPTY value says a field was sent with nothing in it,
				// which carries nothing and is a diagnostic in itself
				if($match[5] === '' || self::isHarmless($match[5]) === true)
				{
					return $match[0];
				}
				
				return $match[1] . $match[2] . $match[1]
					. $match[3] . $match[4] . '[redacted]' . $match[4];
			},
			$text,
		);
	}
	
	/**
	 * Whether a VALUE carries nothing whatever the name in front of it says
	 */
	protected static function isHarmless(
		string $value,
	): bool
	{
		return in_array(strtolower(trim($value)), self::HARMLESS_VALUES, true);
	}
}
