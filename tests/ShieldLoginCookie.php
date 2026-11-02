<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;
use Ovos\Test;
use Ovos\Test\Exception\SkipException;
use Ovos\Test\Internal;

use function basename;
use function bin2hex;
use function copy;
use function count;
use function dirname;
use function escapeshellarg;
use function exec;
use function fclose;
use function file_put_contents;
use function getenv;
use function hash;
use function hash_hmac;
use function implode;
use function is_dir;
use function is_file;
use function is_resource;
use function json_encode;
use function md5;
use function mkdir;
use function proc_close;
use function proc_open;
use function random_bytes;
use function rawurlencode;
use function realpath;
use function rmdir;
use function scandir;
use function str_contains;
use function str_replace;
use function stream_get_contents;
use function substr;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;
use function var_export;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;
use const PHP_BINARY;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
// the kernel file holds Store, Ruleset and Verdict beside Kernel: the adapter's require brings it
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Adapter.php';

/**
 * The login cookie at the must-use stage, checked there as WordPress will
 * check it with the core code loaded before the must-use plugins: a cookie
 * that signs no one in leaves the request anonymous, judged whole before any
 * plugin's own code runs; a valid one waits for plugins_loaded, which judges
 * it as its user; what this stage cannot reproduce waits as before. Judged
 * against rule 41, a blocking virtual patch for anonymous callers on
 * ?action=fx_save, and rule 8, an observing uri rule.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class ShieldLoginCookie extends Test
{
	/** the API key the store is sealed under */
	protected const string KEY = 'login-cookie-key';
	
	/** the ruleset's name the consent carries */
	protected const string RULES_NAME = 'shield-cdcdcdcdcdcdcdcdcdcdcdcd.json';
	
	/** the site URL WordPress hashes into the cookie's name */
	protected const string SITE = 'https://shop.example';
	
	/** a session token as WP_Session_Tokens::create() draws one */
	protected const string TOKEN = 'jK3nP8qR2sT5vW9xZ1aB4cD7eF0gH6iL3mN8oQ2rS5u';
	
	/** a phpass hash: the fragment is Lm9K, its last four sAe/ */
	protected const string PHPASS = '$P$BqXw2Lm9KZ8vYt3RpNc5Hd0FgJ1sAe/';
	
	/** a 6.8 bcrypt hash behind WordPress's own prefix */
	protected const string WP_BCRYPT = '$wp$2y$10$Hq7cV0sKpL3mN6oR9tW2yOeA5dG8jB1nQ4uX7zC0fI3kM6pS9vY2a';
	
	/** a bcrypt hash a plugin stored before 6.8 */
	protected const string BCRYPT = '$2y$10$Tq4wE7rY0uI3oP6aS9dF2gHjK5lZ8xC1vB4nM7qW0eR3tY6uI9oPa';
	
	/** wp-config's salts as these tests define them, each its own */
	protected const array CONSTANTS = [
		'AUTH_KEY' => 'ak-Vb8!Zp2#Lr5$Qm9&Wt3*Xc6^Ny1@Hs4%Jd7(Kf0)Ge2_Bv5+',
		'SECURE_AUTH_KEY' => 'sk-Mn3!Pq6#Rs9$Tu2&Vw5*Xy8^Za1@Bc4%De7(Fg0)Hi3_Jk6+',
		'LOGGED_IN_KEY' => 'lk-Qa1!Ws2#Ed3$Rf4&Tg5*Yh6^Uj7@Ik8%Ol9(Pm0)Nb1_Vc2+',
		'NONCE_KEY' => 'nk-Zx9!Cv8#Bn7$Mq6&Wl5*Ek4^Rj3@Th2%Yg1(Uf0)Id9_Os8+',
		'AUTH_SALT' => 'as-Pl0!Ok9#Ij8$Uh7&Yg6*Tf5^Rd4@Es3%Wa2(Qz1)Xc0_Vb9+',
		'SECURE_AUTH_SALT' => 'ss-Gh5!Jk6#Lz7$Xc8&Vb9*Nm0^Qw1@Er2%Ty3(Ui4)Op5_As6+',
		'LOGGED_IN_SALT' => 'ls-Df7!Gh8#Jk9$Lq0&Wv1*Eb2^Rn3@Tm4%Yx5(Uc6)Iz7_Oa8+',
		'NONCE_SALT' => 'ns-Kj4!Hg5#Fd6$Sa7&Qw8*Er9^Ty0@Ui1%Op2(Az3)Sx4_Dc5+',
	];
	
	/** the logged_in salt the site options hold, where the constants do not give it */
	protected const array OPTIONS = ['logged_in_key' => 'lko-Rt6!Yu7#Io8$Pa9&Sd0*Fg1^Hj2@Kl3%', 'logged_in_salt' => 'lso-Zx4!Cv5#Bn6$Mq7&Wl8*Ek9^Rj0@Th1%'];
	
	/** the users table the check reads: login => [ID, user_pass] */
	protected const array USERS = [
		'editor' => [8, self::PHPASS],
		'modern' => [9, self::WP_BCRYPT],
		'vanilla' => [10, self::BCRYPT],
		"o'brien" => [11, self::PHPASS],
	];
	
	protected string $dir;
	
	protected string $root;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		$this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-cookie-' . uniqid();
		mkdir($this->dir . DIRECTORY_SEPARATOR . 'site', 0700, true);
		file_put_contents($this->dir . DIRECTORY_SEPARATOR . 'site' . DIRECTORY_SEPARATOR . 'index.php', "<?php\n");
		$this->root = str_replace('\\', '/', (string)realpath($this->dir . DIRECTORY_SEPARATOR . 'site'));
		$GLOBALS['wp']['options'] = ['siteurl' => self::SITE] + self::OPTIONS;
		$live = [hash('sha256', self::TOKEN) => ['expiration' => time() + 3600]];
		$GLOBALS['wp']['user_meta'] = [8 => ['session_tokens' => $live], 9 => ['session_tokens' => $live], 10 => ['session_tokens' => $live],
			11 => ['session_tokens' => $live]];
		$GLOBALS['wpdb'] = $this->users(self::USERS);
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => [
				['id' => 41, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'proven', 'expires_at' => null,
					'who' => 'anonymous', 'conditions' => [['target' => 'query:action', 'test' => 'equals', 'value' => 'fx_save']]],
				['id' => 8, 'origin' => 'finding', 'finding' => 'f', 'cve' => 'CVE-2099-0001', 'field' => 'uri', 'op' => 'regex', 'value' => '[?&]include=[^&]*\.\./',
					'ci' => true, 'mode' => 'observe', 'expires_at' => null],
			],
		], time(), platforms: Prepend::platforms())->toRecord(Kernel::sealKey(self::KEY)));
		Prepend::writeConsent($this->dir, $this->consent());
		unset($GLOBALS[Prepend::STASH]);
	}
	
	#[Internal]
	public function finalize(): void
	{
		wp_shim_reset();
		unset($GLOBALS['wpdb'], $GLOBALS[Prepend::STASH]);
		$this->remove($this->dir);
	}
	
	/**
	 * RULE: at the must-use stage a cookie by the site's login cookie name
	 * whose hmac WordPress rejects signs no one in: the request is judged
	 * whole there as anonymous — rule 41 refuses it, and its report counts no
	 * one signed in — before any plugin's own code runs, whether the judge is
	 * handed the check's answer or makes the check itself. Before WordPress
	 * the cookie cannot be checked and the request still waits. Falsify: judge
	 * without the check — a forged `wordpress_logged_in_<hash>` walks the
	 * exploit past both early layers to every plugin's include-time code.
	 */
	public function aForgedLoginCookieIsRefusedAtTheMustUseStage(): bool
	{
		$forged = [self::name() => 'editor|' . (time() + 3600) . '|' . self::TOKEN . '|' . bin2hex(random_bytes(32))];
		$signedIn = $this->check($forged);
		$ran = null;
		$refused = $this->judged($forged, $signedIn, $ran);
		$checkedHere = $this->judged($forged, null);
		$prepend = Prepend::judge($this->dir, $this->server(), [], $forged);
		
		return $signedIn === false
			&& ($refused['verdict'] ?? null)?->isBlock() === true && (int)$refused['verdict']->rule['id'] === 41 && $ran === true
			&& ($refused['report'][0] ?? '') === Verdict::KIND_BLOCK && ($refused['report'][2]['authed'] ?? null) === false
			&& ($checkedHere['verdict'] ?? null)?->isBlock() === true && (int)$checkedHere['verdict']->rule['id'] === 41
			&& $prepend === null;
	}
	
	/**
	 * RULE: the must-use stage reads the database for a login cookie only once
	 * the request has rules to be judged by: not with detection off or the
	 * kill constant set, not without a ruleset this layer can read. Falsify:
	 * check the cookie first — every signed-in page view on a site whose
	 * Shield is off pays a users query.
	 */
	public function theCookieIsCheckedOnlyWhenThereIsSomethingToJudge(): bool
	{
		$forged = [self::name() => 'editor|' . (time() + 3600) . '|' . self::TOKEN . '|' . bin2hex(random_bytes(32))];
		$asked = function(array $with) use ($forged): array
		{
			Prepend::writeConsent($this->dir, $with + $this->consent());
			$GLOBALS['wpdb']->asked = [];
			$judged = $this->judged($forged, null);
			
			return [$judged, count($GLOBALS['wpdb']->asked)];
		};
		[$off, $offAsked] = $asked(['detect' => false]);
		[$killed, $killedAsked] = $asked(['kill' => true]);
		[$unsealed, $unsealedAsked] = $asked(['seal' => Kernel::sealKey('another-key')]);
		[$judged, $judgedAsked] = $asked([]);
		
		return $off === null && $offAsked === 0
			&& $killed === null && $killedAsked === 0
			&& $unsealed === null && $unsealedAsked === 0
			&& ($judged['verdict'] ?? null)?->isBlock() === true && $judgedAsked === 1;
	}
	
	/**
	 * RULE: a cookie WordPress would turn away before or after its hmac signs
	 * no one in, and the request is refused: expired (its session still live),
	 * a login no user has, a session token destroyed, a value that is no
	 * `login|expiration|token|hmac`. Falsify: skip the session — a cookie
	 * stolen before its user logged out keeps deferring.
	 */
	public function aCookieWordPressTurnsAwaySignsNoOneIn(): bool
	{
		$now = time();
		$expired = [self::name() => $this->editor($now - 7200)];
		$unknown = [self::name() => $this->cookie('ghost', $now + 3600, substr(self::PHPASS, 8, 4))];
		$valid = [self::name() => $this->editor($now + 3600)];
		$malformed = [];
		foreach(['editor|' . ($now + 3600) . '|' . self::TOKEN, $this->editor($now + 3600) . '|x', '', '0'] as $value)
		{
			$malformed[] = $this->check([self::name() => $value]);
		}
		$malformed[] = $this->check([self::name() => ['x']]);
		$expiredSays = $this->check($expired);
		$unknownSays = $this->check($unknown);
		$validSays = $this->check($valid);
		$GLOBALS['wp']['user_meta'][8]['session_tokens'] = [hash('sha256', 'another-session') => ['expiration' => $now + 3600]];
		$destroyedSays = $this->check($valid);
		$refused = static fn(?array $judged): bool => ($judged['verdict'] ?? null)?->isBlock() === true && (int)$judged['verdict']->rule['id'] === 41;
		
		return $expiredSays === false && $refused($this->judged($expired, $expiredSays))
			&& $unknownSays === false && $refused($this->judged($unknown, $unknownSays))
			&& $validSays === true
			&& $destroyedSays === false && $refused($this->judged($valid, $destroyedSays))
			&& $malformed === [false, false, false, false, false];
	}
	
	/**
	 * RULE: a cookie WordPress will sign its user in with waits for
	 * plugins_loaded, unjudged here, and the adapter judges it as that user —
	 * rule 41 holds for anonymous callers, not for them. Falsify: answer true
	 * as false — every editor's save of a page an anonymous vpatch guards is
	 * refused before WordPress knows who they are.
	 */
	public function aValidCookieWaitsForTheAdapterWhichJudgesItsUser(): bool
	{
		$valid = [self::name() => $this->editor(time() + 3600)];
		$signedIn = $this->check($valid);
		$ran = null;
		$waits = $this->judged($valid, $signedIn, $ran);
		$reports = [];
		$adapter = $this->adapter($reports);
		$request = [$this->server(), ['action' => 'fx_save'], [], $valid, []];
		// WordPress's answer at plugins_loaded: the editor is signed in
		$asUser = $adapter->judgeRequest($request, Adapter::caller($request[0], $request[1], [], true, false), '203.0.113.9', 'wp-json');
		$asAnonymous = $adapter->judgeRequest($request, Adapter::caller($request[0], $request[1], [], false, false), '203.0.113.9', 'wp-json');
		
		return $signedIn === true && $waits === null && $ran === false
			&& $asUser?->isPass() === true
			&& $asAnonymous?->isBlock() === true && (int)$asAnonymous->rule['id'] === 41
			&& count($reports) === 1;
	}
	
	/**
	 * RULE: WordPress reads its login cookie by the site's name alone, and so
	 * does this check: a valid value under another `wordpress_logged_in_`
	 * name signs no one in, and junk beside the site's own cookie changes
	 * nothing. Falsify: read any name with the prefix — a forger copies a
	 * real cookie of another site on the server to defer again.
	 */
	public function aCookieUnderAnotherNameIsIgnoredAsWordPressIgnoresIt(): bool
	{
		$value = $this->editor(time() + 3600);
		$other = ['wordpress_logged_in_' . md5('https://other.example') => $value];
		$beside = [self::name() => $value, 'wordpress_logged_in_abc' => 'junk'];
		$otherSays = $this->check($other);
		
		return $otherSays === false
			&& ($this->judged($other, $otherSays)['verdict'] ?? null)?->isBlock() === true
			&& $this->check($beside) === true;
	}
	
	/**
	 * RULE: the salt is wp_salt('logged_in')'s: LOGGED_IN_KEY and
	 * LOGGED_IN_SALT, each taken only while it is set, not the sample's phrase
	 * and not a value another of the ten constants shares, SECRET_KEY before
	 * the key's site option, else the logged_in_key and logged_in_salt site
	 * options — the network's on a multisite network. The sample's phrase is
	 * the English one alone, whatever __() answers: the must-use stage runs
	 * before WordPress loads its translations, and the adapter vouches only
	 * where WordPress's own salt is this one. Falsify: drop the duplicate
	 * rule — a site whose wp-config repeats one phrase has every genuine
	 * cookie read as forged, its editors refused.
	 */
	public function theSaltIsWpSaltsConstantsThenTheSiteOptions(): bool
	{
		$constants = self::CONSTANTS;
		$byOptions = [self::name() => $this->editor(time() + 3600, self::OPTIONS['logged_in_key'] . self::OPTIONS['logged_in_salt'])];
		$byConstants = [self::name() => $this->editor(time() + 3600)];
		$withoutPair = $constants;
		unset($withoutPair['LOGGED_IN_KEY'], $withoutPair['LOGGED_IN_SALT']);
		$sample = ['LOGGED_IN_KEY' => 'put your unique phrase here'] + $constants;
		$sampleCookie = [self::name() => $this->editor(time() + 3600, self::OPTIONS['logged_in_key'] . $constants['LOGGED_IN_SALT'])];
		$shared = ['LOGGED_IN_SALT' => $constants['NONCE_SALT']] + $constants;
		$sharedCookie = [self::name() => $this->editor(time() + 3600, $constants['LOGGED_IN_KEY'] . self::OPTIONS['logged_in_salt'])];
		$empty = ['LOGGED_IN_KEY' => ''] + $constants;
		$secret = ['SECRET_KEY' => 'sec-Wq2!Er3#Ty4$'] + $withoutPair;
		$secretCookie = [self::name() => $this->editor(time() + 3600, 'sec-Wq2!Er3#Ty4$' . self::OPTIONS['logged_in_salt'])];
		$results = [
			$this->check($byConstants, $constants),
			$this->check($byOptions, $constants),
			$this->check($byOptions, $withoutPair),
			$this->check($byConstants, $withoutPair),
			$this->check($sampleCookie, $sample),
			$this->check($sharedCookie, $shared),
			$this->check($sampleCookie, $empty),
			$this->check($secretCookie, $secret),
			$this->check($byOptions, $secret),
		];
		// a translation loaded changes nothing: the localized placeholder is keyed as written, the English one never
		$GLOBALS['wp']['translations'] = ['put your unique phrase here' => 'hier einen eindeutigen Begriff eingeben'];
		$results[] = $this->check([self::name() => $this->editor(time() + 3600, 'hier einen eindeutigen Begriff eingeben' . $constants['LOGGED_IN_SALT'])],
			['LOGGED_IN_KEY' => 'hier einen eindeutigen Begriff eingeben'] + $constants);
		$results[] = $this->check($sampleCookie, $sample);
		// a network keeps them among its own options
		$GLOBALS['wp']['multisite'] = true;
		$GLOBALS['wp']['site_options'] = ['siteurl' => self::SITE, 'logged_in_key' => 'net-key', 'logged_in_salt' => 'net-salt'];
		$network = $this->check([self::name() => $this->editor(time() + 3600, 'net-keynet-salt')], $withoutPair);
		
		return $results === [true, false, true, false, true, true, true, true, false, true, true]
			&& $network === true;
	}
	
	/**
	 * RULE: what this stage cannot reproduce exactly leaves the request
	 * waiting, as before: no name from the adapter (it found WordPress's
	 * check replaced, or its init has not run yet), a name other than the
	 * one WordPress will define now, a filter on the salt or on the session
	 * store, a salt option not there yet, a salt constant that is no string,
	 * no database or one that failed. Falsify: read any of them as forged —
	 * a site whose sessions live in Redis has every editor refused.
	 */
	public function whatThisStageCannotReproduceKeepsTheRequestWaiting(): bool
	{
		$forged = [self::name() => 'editor|' . (time() + 3600) . '|' . self::TOKEN . '|' . bin2hex(random_bytes(32))];
		$consent = Prepend::consent($this->dir);
		$withoutPair = self::CONSTANTS;
		unset($withoutPair['LOGGED_IN_KEY'], $withoutPair['LOGGED_IN_SALT']);
		$results = [
			$this->check($forged, consent: ['login_cookie' => ''] + $consent),
			$this->check($forged, consent: ['login_cookie' => 'wordpress_logged_in_' . md5('https://old.example')] + $consent),
			$this->check($forged, ['AUTH_KEY' => true] + self::CONSTANTS),
			$this->check(['' => 'x'], ['LOGGED_IN_COOKIE' => ''] + self::CONSTANTS, consent: ['login_cookie' => ''] + $consent),
		];
		$GLOBALS['wp']['filters']['salt'] = [static fn(string $salt): string => $salt];
		$results[] = $this->check($forged);
		$GLOBALS['wp']['filters'] = ['session_token_manager' => [static fn(string $class): string => $class]];
		$results[] = $this->check($forged);
		$GLOBALS['wp']['filters'] = [];
		unset($GLOBALS['wp']['options']['logged_in_salt']);
		$results[] = $this->check($forged, $withoutPair);
		$GLOBALS['wpdb']->last_error = 'MySQL server has gone away';
		$results[] = $this->check($forged);
		unset($GLOBALS['wpdb']);
		$results[] = $this->check($forged);
		
		return $results === [null, null, null, null, null, null, null, null, null]
			&& $this->judged($forged, null) === null;
	}
	
	/**
	 * RULE: the site's cookie name is the one WordPress defines after the
	 * must-use plugins: LOGGED_IN_COOKIE where wp-config sets it, else the
	 * prefix and COOKIEHASH where set, else the md5 of the site URL — and it
	 * must be the one the adapter wrote. Falsify: always hash the site URL —
	 * a site naming its cookie in wp-config has every genuine one read as
	 * absent and its editors refused.
	 */
	public function theCookieNameIsTheOneWordPressDefines(): bool
	{
		$value = $this->editor(time() + 3600);
		$consent = Prepend::consent($this->dir);
		$named = $this->check(['shop_login' => $value], ['LOGGED_IN_COOKIE' => 'shop_login'] + self::CONSTANTS, consent: ['login_cookie' => 'shop_login'] + $consent);
		$hashed = $this->check(['wordpress_logged_in_abc' => $value], ['COOKIEHASH' => 'abc'] + self::CONSTANTS,
			consent: ['login_cookie' => 'wordpress_logged_in_abc'] + $consent);
		$GLOBALS['wp']['options']['siteurl'] = '';
		$unhashed = $this->check(['wordpress_logged_in_' => $value], consent: ['login_cookie' => 'wordpress_logged_in_'] + $consent);
		
		return $named === true && $hashed === true && $unhashed === true;
	}
	
	/**
	 * RULE: a cookie holds through the second it expires, as WordPress's
	 * `$expired < time()` holds it, and the hour of grace
	 * wp_validate_auth_cookie() gives a POST or an Ajax call past it is given
	 * here too, and no more. Falsify: give none — an editor's form posted in
	 * the last minute of the session is refused here and saved by WordPress.
	 */
	public function theGraceHourIsWordPresss(): bool
	{
		$now = time();
		$late = [self::name() => $this->editor($now - 1800)];
		$gone = [self::name() => $this->editor($now - 7200)];
		$edge = [self::name() => $this->editor($now)];
		$atEdge = $this->check($edge, now: $now);
		$pastEdge = $this->check($edge, now: $now + 1);
		$get = $this->check($late);
		$post = $this->check($late, server: ['REQUEST_METHOD' => 'POST']);
		$gonePost = $this->check($gone, server: ['REQUEST_METHOD' => 'POST']);
		$GLOBALS['wp']['doing_ajax'] = true;
		$ajax = $this->check($late);
		
		return $atEdge === true && $pastEdge === false
			&& $get === false && $post === true && $gonePost === false && $ajax === true;
	}
	
	/**
	 * RULE: the password hash's fragment in the key is WordPress's: 8..11 of a
	 * phpass or bcrypt hash, as every version takes it; of any other hash the
	 * last four, as 6.8 and later take it, or 8..11, as earlier versions did.
	 * Falsify: accept both for every hash — a phpass user's cookie is checked
	 * more loosely than WordPress checks it.
	 */
	public function theHashFragmentIsTheOneWordPressTakes(): bool
	{
		$at = time() + 3600;
		$cookie = fn(string $login, string $fragment): array => [self::name() => $this->cookie($login, $at, $fragment)];
		
		return $this->check($cookie('editor', substr(self::PHPASS, 8, 4))) === true
			&& $this->check($cookie('editor', substr(self::PHPASS, -4))) === false
			&& $this->check($cookie('vanilla', substr(self::BCRYPT, 8, 4))) === true
			&& $this->check($cookie('vanilla', substr(self::BCRYPT, -4))) === false
			&& $this->check($cookie('modern', substr(self::WP_BCRYPT, -4))) === true
			&& $this->check($cookie('modern', substr(self::WP_BCRYPT, 8, 4))) === true;
	}
	
	/**
	 * RULE: the user is read with one prepared query for ID and user_pass by
	 * the login as the cookie spells it, and only once the cookie is well
	 * formed and not expired, as WordPress orders its checks. Falsify: put the
	 * login into the SQL — `'` in a cookie is an injection before any plugin
	 * loads.
	 */
	public function theUserIsReadWithOnePreparedQuery(): bool
	{
		$this->check([self::name() => $this->editor(time() - 7200)]);
		$this->check([self::name() => 'x|y']);
		$early = $GLOBALS['wpdb']->asked;
		$quoted = $this->check([self::name() => $this->cookie("o'brien", time() + 3600, substr(self::PHPASS, 8, 4))]);
		
		return $early === []
			&& $quoted === true
			&& $GLOBALS['wpdb']->asked === [['SELECT ID, user_pass FROM wp_users WHERE user_login = %s LIMIT 1', ["o'brien"]]];
	}
	
	/**
	 * RULE: the consent carries the login cookie's name the adapter writes;
	 * the plugin's early write, which cannot know it, keeps it, and init
	 * rewrites it only when it changed — here to '', as the shim's
	 * pluggables are no core file; a name no browser can send reads as none.
	 * Falsify: drop it on the early write — the check stops on every other
	 * request.
	 */
	public function theConsentCarriesTheLoginCookieAndInitWritesItWhenItChanged(): bool
	{
		$consent = $this->consent();
		unset($consent['login_cookie']);
		$kept = Prepend::writeConsent($this->dir, $consent);
		$read = Prepend::consent($this->dir)['login_cookie'];
		$cleared = Adapter::syncLoginCookie($this->dir);
		$clearedTo = Prepend::consent($this->dir)['login_cookie'];
		$again = Adapter::syncLoginCookie($this->dir);
		$written = Prepend::writeLoginCookie($this->dir, self::name());
		$same = Prepend::writeLoginCookie($this->dir, self::name());
		$named = Prepend::consent($this->dir)['login_cookie'];
		$fresh = $this->dir . DIRECTORY_SEPARATOR . 'fresh';
		mkdir($fresh);
		$none = Prepend::writeLoginCookie($fresh, self::name());
		Prepend::writeLoginCookie($this->dir, "wordpress_logged_in_x\nSet-Cookie: y");
		$unprintable = Prepend::consent($this->dir)['login_cookie'];
		
		return $kept === false && $read === self::name()
			&& $cleared === true && $clearedTo === '' && $again === false
			&& $written === true && $same === false && $named === self::name()
			&& $none === false && is_file($fresh . DIRECTORY_SEPARATOR . Prepend::CONSENT) === false
			&& $unprintable === '';
	}
	
	/**
	 * RULE: the adapter vouches for WordPress's own check, by naming the
	 * cookie, only while the five pluggable functions on its path are core's
	 * own, no filter changes the salt or the session store, no salt
	 * wp_salt('logged_in') reads holds the sample's placeholder, in English or
	 * in the site's language — LOGGED_IN_KEY, LOGGED_IN_SALT, and SECRET_KEY
	 * where the key falls back to it — and the salt the must-use stage
	 * reproduces is the one wp_salt() answers, whatever makes them differ. WordPress tells a localized
	 * placeholder only once its translations are loaded, so a site keeping one
	 * is withheld whenever its salt was first asked for. In a process of its
	 * own: the constants and functions would reach every other class.
	 * Falsify: compare the salts alone — the site is named on every request
	 * whose salt was asked for before the translations, and its editors are
	 * refused as forged.
	 */
	public function theAdapterVouchesOnlyForWordPresssOwnCheck(): bool
	{
		$site = $this->dir . DIRECTORY_SEPARATOR . 'core';
		mkdir($site . DIRECTORY_SEPARATOR . 'wp-includes', 0700, true);
		$files = __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR;
		copy($files . 'pluggable.file.php', $site . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'pluggable.php');
		$answers = [];
		foreach(['core', 'localized-late', 'localized-early', 'secret-early', 'secret-shared', 'secret-unread', 'english', 'english-localized', 'diverged', 'salt',
			'session', 'replaced', 'unnamed'] as $variant)
		{
			$output = [];
			exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($files . 'vouch.file.php') . ' ' . escapeshellarg($site) . ' ' . $variant . ' 2>&1', $output);
			$answers[$variant] = implode('', $output);
		}
		
		return $answers === ['core' => '[wordpress_logged_in_0123]', 'localized-late' => '[]', 'localized-early' => '[]', 'secret-early' => '[]',
			'secret-shared' => '[]', 'secret-unread' => '[wordpress_logged_in_0123]', 'english' => '[]', 'english-localized' => '[]', 'diverged' => '[]',
			'salt' => '[]', 'session' => '[]', 'replaced' => '[]', 'unnamed' => '[]'];
	}
	
	/**
	 * RULE: through php-cgi, as a site runs it — the prepend stub, then
	 * WordPress up to its must-use plugins: the prepend leaves a request with
	 * a login cookie to WordPress, and the must-use stage checks the cookie.
	 * A forged one is refused there, 403 with the rule and the layer, the
	 * block queued as anonymous; passed, the request is marked judged, and
	 * observed its verdict is stashed — either way plugins_loaded only lends
	 * the Sender, never judges it again. A valid cookie leaves nothing marked:
	 * plugins_loaded judges it whole. Without the prepend the must-use stage
	 * refuses the forged cookie alone; without the adapter's word the cookie
	 * waits as before. With detection off, or no ruleset either layer can
	 * read, the users table is never read. Falsify: return at the must-use
	 * stage once the prepend ran — a forged cookie reaches every plugin
	 * unjudged.
	 */
	public function theMustUseStageDecidesWhatThePrependLeftIt(): bool
	{
		$cgi = $this->cgiBinary();
		$stub = Prepend::ensureStub($this->dir);
		$mu = Prepend::ensureMuPlugin($this->dir, $this->dir . DIRECTORY_SEPARATOR . 'mu-plugins');
		$entry = $this->root . '/index.php';
		file_put_contents($entry, "<?php\nrequire " . var_export(__DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'mu-stage.file.php', true) . ";\n");
		$state = $this->dir . DIRECTORY_SEPARATOR . 'state.json';
		$live = [hash('sha256', self::TOKEN) => ['expiration' => time() + 3600]];
		file_put_contents($state, json_encode([
			'options' => ['siteurl' => self::SITE],
			'user_meta' => ['8' => ['session_tokens' => $live]],
			'users' => self::USERS,
			'constants' => self::CONSTANTS,
			'root' => $this->root,
			'mu_plugin' => $mu,
		]));
		$forged = self::name() . '=' . rawurlencode('editor|' . (time() + 3600) . '|' . self::TOKEN . '|' . bin2hex(random_bytes(32)));
		$valid = self::name() . '=' . rawurlencode($this->editor(time() + 3600));
		$run = function(string $cookie, string $query, bool $prepend = true) use ($cgi, $stub, $entry, $state): array
		{
			$output = $this->runCgi($cgi, $prepend ? $stub : '', $entry, $query, $cookie, $state);
			$queued = [];
			Prepend::drain($this->dir, static function(string $kind, string $message, array $extra) use (&$queued): void
			{
				$queued[] = [$kind, $extra];
			});
			
			return [$output, $queued];
		};
		[$refused, $blocks] = $run($forged, 'action=fx_save');
		[$passed, $none] = $run($forged, 'x=1');
		[$observed] = $run($forged, 'include=../x');
		[$valued, $nothing] = $run($valid, 'action=fx_save');
		[$alone, $aloneBlocks] = $run($forged, 'action=fx_save', false);
		Prepend::writeConsent($this->dir, ['login_cookie' => ''] + $this->consent());
		[$unvouched] = $run($forged, 'action=fx_save');
		$quiet = [];
		foreach([['detect' => false], ['seal' => Kernel::sealKey('another-key')]] as $with)
		{
			Prepend::writeConsent($this->dir, $with + $this->consent());
			$quiet[] = $run($forged, 'action=fx_save')[0];
			$quiet[] = $run($forged, 'action=fx_save', false)[0];
		}
		$untouched = '{"plugins":true,"judged":false,"mark":false,"stash":null,"queries":0}';
		
		return str_contains($refused, 'Status: 403') && str_contains($refused, 'X-Shield-Rule: 41') && str_contains($refused, 'X-Shield-Layer: prepend')
			&& str_contains($refused, '"plugins"') === false
			&& count($blocks) === 1 && $blocks[0][0] === Verdict::KIND_BLOCK && ($blocks[0][1]['rule'] ?? 0) === 41 && ($blocks[0][1]['authed'] ?? null) === false
			&& str_contains($passed, '{"plugins":true,"judged":true,"mark":false,"stash":null,"queries":1}') && $none === []
			&& str_contains($observed, '{"plugins":true,"judged":false,"mark":true,"stash":"observe","queries":1}')
			&& str_contains($valued, '{"plugins":true,"judged":false,"mark":false,"stash":null,"queries":1}') && $nothing === []
			&& str_contains($alone, 'Status: 403') && str_contains($alone, 'X-Shield-Rule: 41') && count($aloneBlocks) === 1
			&& str_contains($unvouched, $untouched)
			&& count($quiet) === 4 && str_contains(implode('', $quiet), 'Status: 403') === false
			&& str_contains($quiet[0], $untouched) && str_contains($quiet[1], $untouched) && str_contains($quiet[2], $untouched) && str_contains($quiet[3], $untouched);
	}
	
	// ---- helpers --------------------------------------------------------------
	
	/** the site's login cookie name, as WordPress defines it from the site URL */
	protected static function name(): string
	{
		return 'wordpress_logged_in_' . md5(self::SITE);
	}
	
	/** the consent the adapter keeps for this site, the cookie's name with it */
	protected function consent(): array
	{
		return ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => '', 'root' => $this->root, 'rules' => self::RULES_NAME,
			'seal' => Kernel::sealKey(self::KEY), 'login_cookie' => self::name()];
	}
	
	/** a GET to the front end's index.php carrying ?action=fx_save, or the query given */
	protected function server(
		string $query = 'action=fx_save',
	): array
	{
		return [
			'REQUEST_METHOD' => 'GET',
			'REQUEST_URI' => '/?' . $query,
			'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'REMOTE_ADDR' => '203.0.113.9',
			'SCRIPT_FILENAME' => $this->root . '/index.php',
		];
	}
	
	/** the must-use stage's check of these cookies, with these wp-config constants */
	protected function check(
		array $cookies,
		array $constants = self::CONSTANTS,
		array $server = [],
		?array $consent = null,
		?int $now = null,
	): ?bool
	{
		return Prepend::loginCookieSignsIn($cookies, $server + $this->server(), $consent ?? (array)Prepend::consent($this->dir), $now, $constants);
	}
	
	/** the must-use stage's judge of the front-end request, given what the check said */
	protected function judged(
		array $cookies,
		?bool $signedIn,
		?bool &$ran = null,
	): ?array
	{
		return Prepend::judge($this->dir, $this->server(), [], $cookies, null, null, $ran, null, [], true, null, $signedIn);
	}
	
	/** a login cookie as wp_generate_auth_cookie() makes it, keyed by the salt and the password hash's fragment */
	protected function cookie(
		string $login,
		int $expiration,
		string $fragment,
		?string $salt = null,
	): string
	{
		$salt ??= self::CONSTANTS['LOGGED_IN_KEY'] . self::CONSTANTS['LOGGED_IN_SALT'];
		$key = hash_hmac('md5', $login . '|' . $fragment . '|' . $expiration . '|' . self::TOKEN, $salt);
		
		return $login . '|' . $expiration . '|' . self::TOKEN . '|' . hash_hmac('sha256', $login . '|' . $expiration . '|' . self::TOKEN, $key);
	}
	
	/** the editor's login cookie, under the constants' salt unless another is given */
	protected function editor(
		int $expiration,
		?string $salt = null,
	): string
	{
		return $this->cookie('editor', $expiration, substr(self::PHPASS, 8, 4), $salt);
	}
	
	/** a users table behind $wpdb that records every prepared lookup it answers */
	protected function users(
		array $rows,
	): object
	{
		return new class($rows)
		{
			public string $users = 'wp_users';
			
			public string $last_error = '';
			
			public array $asked = [];
			
			public function __construct(
				protected array $rows,
			)
			{
			}
			
			public function prepare(
				string $query,
				mixed ...$arguments,
			): array
			{
				return [$query, $arguments];
			}
			
			public function get_row(
				array $prepared,
			): ?object
			{
				$this->asked[] = $prepared;
				if($this->last_error !== '' || $prepared[0] !== 'SELECT ID, user_pass FROM wp_users WHERE user_login = %s LIMIT 1')
				{
					return null;
				}
				$row = $this->rows[$prepared[1][0] ?? ''] ?? null;
				
				return $row === null ? null : (object)['ID' => (string)$row[0], 'user_pass' => $row[1]];
			}
		};
	}
	
	/** an adapter judging with this test's rules, blocking on, its kernel's reports recorded into $reports */
	protected function adapter(
		array &$reports,
	): Adapter
	{
		$kernel = new Kernel('', '', new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES_NAME, ''),
			static fn(): array => ['status' => 0, 'headers' => [], 'body' => ''],
			static function(string $kind, string $message, array $extra) use (&$reports): void
			{
				$reports[] = [$kind, $message, $extra];
			}, platforms: Prepend::platforms(), sealKey: Kernel::sealKey(self::KEY));
		$config = new class extends Config
		{
			public function __construct()
			{
			}
			
			public function enabled(): bool
			{
				return true;
			}
			
			public function shieldDetect(): bool
			{
				return true;
			}
			
			public function shieldEnforce(): bool
			{
				return true;
			}
			
			public function shieldKill(): bool
			{
				return false;
			}
		};
		
		return new Adapter($config, new Sender(new Config), $kernel);
	}
	
	/** php-cgi beside this PHP — the SAPI a site's prepend runs in; the test is skipped without one */
	protected function cgiBinary(): string
	{
		$dir = dirname(PHP_BINARY);
		// Windows ships php-cgi.exe beside php.exe; Debian's packages name it php-cgi8.x beside php8.x
		foreach([$dir . DIRECTORY_SEPARATOR . 'php-cgi.exe', $dir . DIRECTORY_SEPARATOR . str_replace('php', 'php-cgi', basename(PHP_BINARY)),
			$dir . DIRECTORY_SEPARATOR . 'php-cgi'] as $candidate)
		{
			if(is_file($candidate))
			{
				return $candidate;
			}
		}
		
		throw new SkipException('No php-cgi beside ' . PHP_BINARY . '.');
	}
	
	/**
	 * One GET through php-cgi with no php.ini, the stub as auto_prepend_file
	 * unless $stub is '', the cookie and the query given, and the fake
	 * WordPress's state: what it printed, headers and body
	 */
	protected function runCgi(
		string $cgi,
		string $stub,
		string $script,
		string $query,
		string $cookie,
		string $state,
	): string
	{
		$environment = ['GATEWAY_INTERFACE' => 'CGI/1.1', 'SCRIPT_FILENAME' => $script, 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/?' . $query,
			'QUERY_STRING' => $query, 'HTTP_COOKIE' => $cookie, 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'CODESAFE_MU_STATE' => $state];
		// Windows' own libraries need it in any process
		if(getenv('SYSTEMROOT') !== false)
		{
			$environment['SYSTEMROOT'] = (string)getenv('SYSTEMROOT');
		}
		$command = [$cgi, '-n', '-d', 'cgi.force_redirect=0'];
		if($stub !== '')
		{
			$command[] = '-d';
			$command[] = 'auto_prepend_file=' . $stub;
		}
		$process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $this->dir, $environment);
		if(is_resource($process) === false)
		{
			return '';
		}
		$output = (string)stream_get_contents($pipes[1]) . (string)stream_get_contents($pipes[2]);
		fclose($pipes[1]);
		fclose($pipes[2]);
		proc_close($process);
		
		return $output;
	}
	
	/** a temp directory and everything under it */
	protected function remove(
		string $dir,
	): void
	{
		if(is_dir($dir) === false)
		{
			return;
		}
		foreach(scandir($dir) ?: [] as $name)
		{
			if($name === '.' || $name === '..')
			{
				continue;
			}
			$path = $dir . DIRECTORY_SEPARATOR . $name;
			is_dir($path) ? $this->remove($path) : unlink($path);
		}
		rmdir($dir);
	}
}
