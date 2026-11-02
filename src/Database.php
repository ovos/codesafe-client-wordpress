<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Closure;
use ReflectionClass;
use ReflectionFunction;
use ReflectionFunctionAbstract;
use ReflectionMethod;
use Throwable;
use WP_Application_Passwords;
use WP_Session_Tokens;

use function _get_cron_array;
use function array_fill;
use function array_filter;
use function array_key_exists;
use function array_map;
use function array_slice;
use function array_unique;
use function array_values;
use function basename;
use function class_exists;
use function constant;
use function count;
use function defined;
use function dirname;
use function explode;
use function file_get_contents;
use function filemtime;
use function function_exists;
use function get_option;
use function get_site_option;
use function get_users;
use function glob;
use function gmdate;
use function has_action;
use function home_url;
use function implode;
use function in_array;
use function is_array;
use function is_file;
use function is_multisite;
use function is_object;
use function is_string;
use function max;
use function method_exists;
use function min;
use function preg_match;
use function preg_match_all;
use function preg_replace;
use function rtrim;
use function str_contains;
use function str_ends_with;
use function str_replace;
use function str_starts_with;
use function strlen;
use function strpos;
use function strtolower;
use function strtotime;
use function substr;
use function wp_parse_url;

use const PHP_URL_HOST;
use const PREG_SET_ORDER;

/**
 * The database half of the integrity scan — the attacker's other
 * filesystem. Half of real WordPress malware never
 * touches disk in a way a file walk sees: it is the administrator created at
 * 03:12 during a wave, the application password minted for durability, the
 * cron hook that re-infects nightly, the option row holding the payload an
 * innocent three-line loader evals, the script tag injected into every post.
 *
 * READS ONLY, and NAMES NOTHING PRIVATE: every finding is an id, an option
 * name, a hook name or a host — never a login, an e-mail, a value or a post
 * body. The console correlates the `mtime` a finding carries (a user's
 * registration, a post's modification) against the project's attack waves;
 * that is where "admin #57 was created forty seconds after the wave" comes
 * from, and it needs no name to say it. A cron row carries none: its only
 * date is the hook's next run, which is no write.
 *
 * Every read is bounded (LIMITs, caps per detector) and wrapped: a failing
 * query costs the detector, never the pass.
 */
class Database
{
	public const AREA = 'database';
	
	protected const MAX_PER_DETECTOR = 20;
	
	/** the code markers that run a string as PHP */
	public const CODE_EXECUTORS = ['eval(', 'assert(', 'create_function('];
	
	/** the code markers that unwrap a payload kept unreadable */
	public const CODE_DECODERS = ['base64_decode(', 'gzinflate(', 'gzuncompress(', 'str_rot13('];
	
	/** option values that carry code — the loader's payload */
	protected const CODE_MARKERS = ['<?php', ...self::CODE_EXECUTORS, ...self::CODE_DECODERS];
	
	/** PHP's own functions that run a shell command: as a cron listener, or fed by request input */
	public const COMMANDS = ['system', 'exec', 'passthru', 'shell_exec', 'proc_open', 'popen', 'pcntl_exec'];
	
	/**
	 * PHP's own functions a cron listener has no honest reason to be: they
	 * call what they are handed, write a file, rebuild objects, or reset the
	 * request's own scope or the process's configuration — the arguments a
	 * scheduled event carries decide what they do
	 */
	protected const BUILTINS_HIGH = ['call_user_func', 'call_user_func_array', 'forward_static_call', 'forward_static_call_array',
		'array_map', 'array_walk', 'usort', 'register_shutdown_function', 'file_put_contents', 'fwrite', 'fputs', 'unserialize',
		'move_uploaded_file', 'copy', 'rename', 'symlink', 'extract', 'parse_str', 'ini_set', 'putenv'];
	
	/** a cron hook nobody listens to is common leftover; one of these names is not */
	protected const SUSPICIOUS_HOOK = '~(?:eval|base64|shell|exec|backdoor|payload|inject|cmd)|^[a-f0-9]{16,}$~i';
	
	/**
	 * Third-party script hosts a site embeds on purpose — analytics, fonts,
	 * players, CDNs. A `<script src>` to any other host in post content is
	 * the injection to look at.
	 */
	/**
	 * Where a theme's markup can live BESIDES its files. A block theme — the
	 * default for new sites, and all four bundled ones — is edited in the
	 * Site Editor, which writes rows, not files: the integrity scan's tree
	 * walk and wordpress.org's checksums can never see an injection there,
	 * and neither can a file-editor observer. Its synced patterns
	 * (`wp_block`) and navigation menus are rows too, rendered wherever
	 * they are placed. `custom_css` is the Customizer's Additional CSS, the
	 * oldest place to hide a `</style>` breakout.
	 */
	protected const CONTENT_TYPES = ['post', 'page',
		'wp_template', 'wp_template_part', 'wp_global_styles', 'custom_css', 'wp_block', 'wp_navigation'];
	
	/** the content rows read per pass: the newest, and as many onward from where the last pass stopped by id */
	protected const CONTENT_ROWS = 100;
	
	/**
	 * The statuses a person or a renderer reaches: published; a draft or a
	 * post pending review in the editor and its preview; a private one for
	 * every logged-in editor; a scheduled one on its date, with no further
	 * write. Trash renders nowhere and empties itself, a revision or an
	 * autosave is a copy of its parent no visitor is served, an auto-draft
	 * is an empty placeholder
	 */
	protected const CONTENT_STATUSES = ['publish', 'draft', 'pending', 'private', 'future'];
	
	/** what a finding calls a status other than published */
	protected const STATUS_LABELS = [
		'draft' => 'draft',
		'pending' => 'pending review',
		'private' => 'private',
		'future' => 'scheduled',
	];
	
	/** what to call the rows a person would not think of as a post */
	protected const CONTENT_LABELS = [
		'wp_template' => 'site-editor template',
		'wp_template_part' => 'site-editor template part',
		'wp_global_styles' => 'global styles',
		'custom_css' => 'additional CSS',
		'wp_block' => 'synced pattern',
		'wp_navigation' => 'navigation menu',
	];
	
	protected const KNOWN_SCRIPT_HOSTS = ['googleapis.com', 'gstatic.com', 'google.com', 'googletagmanager.com',
		'google-analytics.com', 'googlesyndication.com', 'doubleclick.net', 'facebook.net', 'facebook.com',
		'cloudflare.com', 'cloudflareinsights.com', 'jsdelivr.net', 'unpkg.com', 'jquery.com', 'bootstrapcdn.com',
		'youtube.com', 'youtube-nocookie.com', 'vimeo.com', 'twitter.com', 'x.com', 'instagram.com', 'linkedin.com',
		'hotjar.com', 'hs-scripts.com', 'hubspot.com', 'wp.com', 'gravatar.com', 'w.org', 'wordpress.com',
		'wordpress.org', 'typekit.net', 'adobe.com', 'stripe.com', 'paypal.com', 'paypalobjects.com',
		'recaptcha.net', 'matomo.cloud', 'plausible.io', 'usercentrics.eu', 'cookiebot.com', 'consentmanager.net',
		'mailchimp.com', 'list-manage.com', 'calendly.com', 'typeform.com', 'vimeocdn.com', 'ytimg.com',
		'openstreetmap.org', 'mapbox.com', 'maps.googleapis.com', 'ionos.com', 'siteground.com', 'kinsta.com'];
	
	protected string $host = '';
	
	/** @var list<int> the posts this pass's content findings name (content()), the next pass's `known` */
	protected array $found = [];
	
	/** @var array<string, int> the findings each tier lost to a detector's cap (overflow()), for the report's truncated */
	protected array $truncated = [Scan::TIER_URGENT => 0, Scan::TIER_HIGH => 0, Scan::TIER_INFO => 0];
	
	/**
	 * @param array<string, string> $roots the area roots Scan::roots() names, which a cron listener's file is held
	 *     against; empty reads them from WordPress when a listener needs them
	 * @param int $cursor the content row id the last pass stopped after (content())
	 * @param list<int> $known the posts the last pass's content findings named, read again first (content())
	 */
	public function __construct(
		protected array $roots = [],
		protected int $cursor = 0,
		protected array $known = [],
	)
	{
	}
	
	/**
	 * The database findings as the scan's finding shape — detector, tier,
	 * path (relative to the "database" area), detail, mtime — plus the
	 * counters the report's area block carries, the posts the content
	 * findings name and, by tier, the findings the caps left out
	 *
	 * @return array{findings: list<array<string, mixed>>, stats: array<string, int>, posts: list<int>, truncated: array<string, int>}
	 */
	public function scan(): array
	{
		$this->host = $this->siteHost();
		$this->found = [];
		$this->truncated = [Scan::TIER_URGENT => 0, Scan::TIER_HIGH => 0, Scan::TIER_INFO => 0];
		$findings = [];
		$stats = ['admins' => 0, 'app_passwords' => 0, 'cron_hooks' => 0, 'options_scanned' => 0, 'posts_scanned' => 0];
		
		foreach(['administrators', 'activePlugins', 'cron', 'uninstallers', 'optionCode', 'content', 'widgets', 'options'] as $detector)
		{
			try
			{
				foreach($this->$detector($stats) as $finding)
				{
					$findings[] = $finding;
				}
			}
			catch(Throwable)
			{
				// a failing query costs the detector, never the pass
			}
		}
		
		return ['findings' => $findings, 'stats' => $stats, 'posts' => $this->found, 'truncated' => $this->truncated];
	}
	
	/**
	 * Every administrator by id with the moment the account was
	 * REGISTERED (the mtime the console dates against the waves), its live
	 * sessions and the newest login; an admin holding application passwords
	 * is its own finding — the durable API access an intruder mints.
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function administrators(
		array &$stats,
	): array
	{
		$findings = [];
		$admins = get_users(['role' => 'administrator', 'fields' => ['ID', 'user_registered'], 'number' => 200]);
		
		foreach((array)$admins as $admin)
		{
			$id = (int)($admin->ID ?? 0);
			
			if($id <= 0)
			{
				continue;
			}
			
			$stats['admins']++;
			$registered = strtotime((string)($admin->user_registered ?? ''));
			$registered = $registered === false ? 0 : $registered;
			
			[$sessions, $newest] = $this->sessions($id);
			$detail = 'registered ' . ($registered > 0 ? gmdate('Y-m-d H:i', $registered) : '?')
				. ', ' . $sessions . ' live session' . ($sessions === 1 ? '' : 's')
				. ($newest > 0 ? ', last login ' . gmdate('Y-m-d H:i', $newest) : '');
			
			$findings[] = $this->finding('admin_account', Scan::TIER_INFO, 'users/' . $id, $detail, $registered);
			
			if(class_exists(WP_Application_Passwords::class))
			{
				$passwords = WP_Application_Passwords::get_user_application_passwords($id);
				
				if(is_array($passwords) && $passwords !== [])
				{
					$stats['app_passwords'] += count($passwords);
					$oldest = 0;
					
					foreach($passwords as $password)
					{
						$created = (int)($password['created'] ?? 0);
						$oldest = $oldest === 0 ? $created : min($oldest, $created);
					}
					
					$findings[] = $this->finding('admin_app_password', Scan::TIER_HIGH, 'users/' . $id . '/application-passwords',
						count($passwords) . ' application password' . (count($passwords) === 1 ? '' : 's') . ' on an administrator'
						. ($oldest > 0 ? ', oldest ' . gmdate('Y-m-d', $oldest) : ''), $oldest);
				}
			}
		}
		
		return $findings;
	}
	
	/**
	 * @return array{0: int, 1: int} live sessions, newest login (epoch)
	 */
	protected function sessions(
		int $userId,
	): array
	{
		if(class_exists(WP_Session_Tokens::class) === false)
		{
			return [0, 0];
		}
		
		$all = WP_Session_Tokens::get_instance($userId)->get_all();
		$newest = 0;
		
		foreach($all as $session)
		{
			$newest = max($newest, (int)($session['login'] ?? 0));
		}
		
		return [count($all), $newest];
	}
	
	/**
	 * An active plugin whose file is not on disk, or outside the plugins
	 * directory — the activated-then-hidden loader
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function activePlugins(
		array &$stats,
	): array
	{
		$findings = [];
		$root = defined('WP_PLUGIN_DIR') ? rtrim(str_replace('\\', '/', (string)WP_PLUGIN_DIR), '/') : '';
		$active = (array)get_option('active_plugins', []);
		
		// network-activated plugins live in sitemeta (update_site_option()), never in the site's options
		if(function_exists('is_multisite') && is_multisite())
		{
			foreach((array)get_site_option('active_sitewide_plugins', []) as $file => $time)
			{
				$active[] = $file;
			}
		}
		
		foreach($active as $file)
		{
			if(is_string($file) === false || $file === '')
			{
				continue;
			}
			
			$traversal = str_contains($file, '..') || str_starts_with($file, '/');
			
			if($traversal || ($root !== '' && is_file($root . '/' . $file) === false))
			{
				if($this->overflow(count($findings), Scan::TIER_HIGH))
				{
					continue;
				}
				
				$findings[] = $this->finding('active_plugin_missing', Scan::TIER_HIGH, 'options/active_plugins/' . $file,
					$traversal ? 'an active plugin path leaving the plugins directory' : 'an active plugin whose file is not on disk');
			}
		}
		
		return $findings;
	}
	
	/**
	 * Scheduled hooks nobody listens to — at scan time every active
	 * plugin has registered its actions, so a hook without one is a leftover
	 * (a deactivated plugin's, usually: info) or a stranger's (a name shaped
	 * like a payload: high). A hook WITH a listener is judged by the file
	 * that defined the listener (listenerFinding()): a backdoor schedules its
	 * own hook and listens to it. Each kind keeps its own cap, so leftovers
	 * never crowd a foreign listener out
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function cron(
		array &$stats,
	): array
	{
		$findings = [];
		$crons = function_exists('_get_cron_array') ? _get_cron_array() : [];
		$seen = [];
		$orphans = 0;
		$foreign = 0;
		
		foreach((array)$crons as $timestamp => $hooks)
		{
			if(is_array($hooks) === false)
			{
				continue;
			}
			
			foreach($hooks as $hook => $events)
			{
				if(is_string($hook) === false || isset($seen[$hook]))
				{
					continue;
				}
				
				$seen[$hook] = true;
				$stats['cron_hooks']++;
				
				if(has_action($hook))
				{
					$finding = $this->listenerFinding($hook);
					
					if($finding !== null && $this->overflow($foreign, (string)$finding['tier']) === false)
					{
						$findings[] = $finding;
						$foreign++;
					}
					
					continue;
				}
				
				$suspicious = preg_match(self::SUSPICIOUS_HOOK, $hook) === 1;
				
				if($this->overflow($orphans, $suspicious ? Scan::TIER_HIGH : Scan::TIER_INFO))
				{
					continue;
				}
				$schedule = '';
				
				foreach((array)$events as $event)
				{
					$schedule = is_array($event) && is_string($event['schedule'] ?? null) ? $event['schedule'] : $schedule;
				}
				
				$findings[] = $this->finding($suspicious ? 'cron_suspicious' : 'cron_orphan',
					$suspicious ? Scan::TIER_HIGH : Scan::TIER_INFO, 'options/cron/' . $hook,
					'scheduled hook no active plugin or theme listens to'
					. ($schedule !== '' ? ', ' . $schedule : '')
					. ', next ' . gmdate('Y-m-d H:i', (int)$timestamp));
				$orphans++;
			}
		}
		
		return $findings;
	}
	
	/**
	 * Whether a detector that has $listed findings is at its cap: the one it
	 * would add is then counted in $tier's truncated instead (scan()), so a
	 * report that carries fewer findings than the database holds says so
	 */
	protected function overflow(
		int $listed,
		string $tier,
	): bool
	{
		if($listed < self::MAX_PER_DETECTOR)
		{
			return false;
		}
		
		$this->truncated[$tier] = ($this->truncated[$tier] ?? 0) + 1;
		
		return true;
	}
	
	/**
	 * The hook's verdict from the first of its listeners whose code stands
	 * where nothing installed keeps code, is PHP's own, or names nothing PHP
	 * can find (cron_listener_unresolved, info: WordPress fails on it at the
	 * event's time, and the scan cannot say whose it is); dated by the file,
	 * since its modification is a write the console can hold against the waves
	 *
	 * @return ?array<string, mixed>
	 */
	protected function listenerFinding(
		string $hook,
	): ?array
	{
		foreach($this->listeners($hook) as $listener)
		{
			try
			{
				$verdict = $this->judgeListener($listener);
			}
			catch(Throwable)
			{
				$verdict = ['cron_listener_unresolved', Scan::TIER_INFO, 'the listener names nothing PHP can find', 0];
			}
			
			if($verdict !== null)
			{
				return $this->finding($verdict[0], $verdict[1], 'options/cron/' . $hook, $verdict[2], $verdict[3]);
			}
		}
		
		return null;
	}
	
	/**
	 * The callables WordPress runs for $hook, every priority: WP_Hook keeps
	 * them in its public `callbacks`, WordPress before 4.7 in a bare array
	 *
	 * @return list<mixed>
	 */
	protected function listeners(
		string $hook,
	): array
	{
		$registered = $GLOBALS['wp_filter'][$hook] ?? null;
		$priorities = is_object($registered) ? ($registered->callbacks ?? []) : $registered;
		$listeners = [];
		
		foreach(is_array($priorities) ? $priorities : [] as $entries)
		{
			foreach(is_array($entries) ? $entries : [] as $entry)
			{
				if(is_array($entry) && array_key_exists('function', $entry))
				{
					$listeners[] = $entry['function'];
				}
			}
		}
		
		return $listeners;
	}
	
	/**
	 * One listener by the file Reflection says defined it: code eval()
	 * compiled (urgent), a file under uploads or wp-content/cache (urgent), a
	 * file outside every installed component (high) — cron_listener_foreign;
	 * PHP's own function — cron_listener_builtin, urgent for one that runs
	 * code or a command, high for one in BUILTINS_HIGH, info for any other;
	 * null for a component's code. A method only __call or __callStatic
	 * answers is judged by its class's file. Throws for a callable that names
	 * nothing
	 *
	 * @return ?array{0: string, 1: string, 2: string, 3: int} detector, tier, detail, the file's mtime
	 */
	protected function judgeListener(
		mixed $listener,
	): ?array
	{
		$reflection = $this->reflect($listener);
		
		if($reflection === null)
		{
			return null;
		}
		
		if($reflection instanceof ReflectionFunctionAbstract && $reflection->isInternal())
		{
			$name = strtolower($reflection->getName());
			$tier = match(true)
			{
				in_array($name, [...self::COMMANDS, 'assert', 'create_function'], true) => Scan::TIER_URGENT,
				in_array($name, self::BUILTINS_HIGH, true) => Scan::TIER_HIGH,
				default => Scan::TIER_INFO,
			};
			
			return ['cron_listener_builtin', $tier, 'the listener is PHP\'s own ' . $name . '()', 0];
		}
		
		$file = str_replace('\\', '/', (string)$reflection->getFileName());
		// what eval() compiled names the file that called eval(): "x.php(12) : eval()'d code"
		$evaluated = preg_match('~^(.*)\(\d+\) : eval\(\)\'d code$~', $file, $match) === 1;
		$file = $evaluated ? $match[1] : $file;
		$where = $this->place($file);
		$mtime = is_file($file) ? (int)@filemtime($file) : 0;
		
		if($evaluated)
		{
			return ['cron_listener_foreign', Scan::TIER_URGENT, 'the listener was compiled by eval() in ' . $where, $mtime];
		}
		
		$roots = $this->roots();
		$uploads = $roots['uploads'] ?? '';
		$cache = ($roots['content'] ?? '') !== '' ? $roots['content'] . '/cache' : '';
		
		foreach([$uploads, $cache] as $dropzone)
		{
			if($dropzone !== '' && str_starts_with($file, $dropzone . '/'))
			{
				return ['cron_listener_foreign', Scan::TIER_URGENT, 'the listener is defined in ' . $where, $mtime];
			}
		}
		
		return $this->component($file)
			? null
			: ['cron_listener_foreign', Scan::TIER_HIGH, 'the listener is defined outside every installed component, in ' . $where, $mtime];
	}
	
	/**
	 * Reflection of a callable in any form WordPress accepts; a method only
	 * __call or __callStatic answers by the class that answers it (its file
	 * is the code's); null for none of those forms
	 */
	protected function reflect(
		mixed $listener,
	): ReflectionFunctionAbstract|ReflectionClass|null
	{
		if($listener instanceof Closure)
		{
			return new ReflectionFunction($listener);
		}
		
		if(is_string($listener) && str_contains($listener, '::') === false)
		{
			return new ReflectionFunction($listener);
		}
		
		// 'Class::method' by its two halves: ReflectionMethod's one-string form is deprecated
		[$target, $method] = match(true)
		{
			is_string($listener) => explode('::', $listener, 2),
			is_array($listener) && count($listener) === 2 && is_string($listener[1] ?? null)
				&& (is_object($listener[0] ?? null) || is_string($listener[0] ?? null)) => [$listener[0], $listener[1]],
			is_object($listener) => [$listener, '__invoke'],
			default => [null, null],
		};
		
		if($target === null)
		{
			return null;
		}
		
		if(method_exists($target, $method) === false && (method_exists($target, '__call') || method_exists($target, '__callStatic')))
		{
			return new ReflectionClass($target);
		}
		
		return new ReflectionMethod($target, $method);
	}
	
	/**
	 * Whether a file belongs to something installed: core (wp-admin,
	 * wp-includes, its root files), an installed plugin (installedPlugin()),
	 * a must-use plugin, a theme in any registered theme directory, a
	 * drop-in, or a Composer tree (a vendor directory with Composer's
	 * installed.json, as Bedrock keeps its libraries beside the document root)
	 */
	protected function component(
		string $file,
	): bool
	{
		$roots = $this->roots();
		$root = $roots['root'] ?? '';
		$content = $roots['content'] ?? '';
		$prefixes = [$roots['mu'] ?? '', $roots['themes'] ?? ''];
		
		if($this->installedPlugin($file))
		{
			return true;
		}
		
		foreach((array)($GLOBALS['wp_theme_directories'] ?? []) as $directory)
		{
			$prefixes[] = rtrim(str_replace('\\', '/', (string)$directory), '/');
		}
		
		if($root !== '')
		{
			$prefixes[] = $root . '/wp-admin';
			$prefixes[] = $root . '/wp-includes';
		}
		
		foreach($prefixes as $prefix)
		{
			if($prefix !== '' && str_starts_with($file, $prefix . '/'))
			{
				return true;
			}
		}
		
		$parent = dirname($file);
		$name = basename($file);
		
		if(($root !== '' && $parent === $root && in_array($name, Sender::CORE_ROOT_FILES, true))
			|| ($content !== '' && $parent === $content && (in_array($name, Sender::CONTENT_DROPINS, true) || $name === 'wp-cache-config.php')))
		{
			return true;
		}
		
		// a Composer tree: the nearest vendor directory up the path, a dozen levels at most
		for($directory = $parent, $level = 0; $level < 12 && dirname($directory) !== $directory; $directory = dirname($directory), $level++)
		{
			if(basename($directory) === 'vendor' && is_file($directory . '/composer/installed.json'))
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Whether a file under the plugins root belongs to an installed plugin:
	 * a single-file plugin, or a file in a directory with a plugin's main
	 * file at its top — a PHP file whose first 8 KB carry the Plugin Name
	 * header, as WordPress reads it. A folder there no plugin heads is
	 * nobody's
	 */
	protected function installedPlugin(
		string $file,
	): bool
	{
		$plugins = $this->roots()['plugins'] ?? '';
		
		if($plugins === '' || str_starts_with($file, $plugins . '/') === false)
		{
			return false;
		}
		
		$relative = substr($file, strlen($plugins) + 1);
		$slash = strpos($relative, '/');
		$candidates = $slash === false ? [$file] : (array)glob($plugins . '/' . substr($relative, 0, $slash) . '/*.php');
		
		foreach($candidates as $candidate)
		{
			$head = @file_get_contents((string)$candidate, false, null, 0, 8192);
			
			if(is_string($head) && preg_match('~^[ \t/*#@]*Plugin Name:~mi', $head) === 1)
			{
				return true;
			}
		}
		
		return false;
	}
	
	/** a file as a finding names it: relative to the document root when inside it */
	protected function place(
		string $file,
	): string
	{
		$root = $this->roots()['root'] ?? '';
		
		return $root !== '' && str_starts_with($file, $root . '/') ? substr($file, strlen($root) + 1) : $file;
	}
	
	/**
	 * The area roots: the ones handed in, else the plugin's own reading of
	 * WordPress (Scan::roots())
	 *
	 * @return array<string, string>
	 */
	protected function roots(): array
	{
		if($this->roots === [] && defined('ABSPATH'))
		{
			$this->roots = (new Scan(new Config))->roots();
		}
		
		return $this->roots;
	}
	
	/**
	 * The uninstall registry: a callable WordPress runs when a plugin is
	 * deleted, for a plugin that is not there — code execution waiting for
	 * an admin's click
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function uninstallers(
		array &$stats,
	): array
	{
		$findings = [];
		$root = defined('WP_PLUGIN_DIR') ? rtrim(str_replace('\\', '/', (string)WP_PLUGIN_DIR), '/') : '';
		
		foreach((array)get_option('uninstall_plugins', []) as $file => $callable)
		{
			if(is_string($file) === false || $root === '' || is_file($root . '/' . $file))
			{
				continue;
			}
			
			if($this->overflow(count($findings), Scan::TIER_HIGH))
			{
				continue;
			}
			
			$findings[] = $this->finding('uninstall_orphan', Scan::TIER_HIGH, 'options/uninstall_plugins/' . $file,
				'an uninstall callable registered for a plugin that is not installed'
				. (is_string($callable) ? ' (' . $this->clip($callable, 40) . ')' : ''));
		}
		
		return $findings;
	}
	
	/**
	 * Option rows whose value carries code — malware keeps its body in
	 * the options table and evals it from a three-line loader on disk. The
	 * rows the plugin itself writes are left out by name (Lifecycle::OPTIONS:
	 * the scan's report and the executed-file queue carry attacker-named
	 * paths), never by prefix, so a row an intruder names after the plugin is
	 * read like any other; the plugin's transients carry no markers. Only the
	 * NAME and the length are reported, never the value.
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function optionCode(
		array &$stats,
	): array
	{
		global $wpdb;
		
		if(is_object($wpdb) === false)
		{
			return [];
		}
		
		$where = [];
		$values = [];
		
		foreach(self::CODE_MARKERS as $marker)
		{
			$where[] = 'option_value LIKE %s';
			$values[] = '%' . $wpdb->esc_like($marker) . '%';
		}
		
		foreach(Lifecycle::OPTIONS as $own)
		{
			$values[] = $own;
		}
		
		$values[] = self::MAX_PER_DETECTOR;
		$own = implode(', ', array_fill(0, count(Lifecycle::OPTIONS), '%s'));
		
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- a read-only forensic pass over the options table, bounded by LIMIT and run once per scan; the WHERE is built from constants and every value rides through prepare()
		$rows = $wpdb->get_results($wpdb->prepare(
			'SELECT option_name, LENGTH(option_value) AS len FROM ' . $wpdb->options
			. ' WHERE (' . implode(' OR ', $where) . ') AND option_name NOT IN (' . $own . ') ORDER BY len DESC LIMIT %d',
			...$values), ARRAY_A);
		// a full page may have left rows out: the same rows counted, the cap's overflow said
		$marked = count((array)$rows) < self::MAX_PER_DETECTOR ? 0 : (int)$wpdb->get_var($wpdb->prepare(
			'SELECT COUNT(*) FROM ' . $wpdb->options . ' WHERE (' . implode(' OR ', $where) . ') AND option_name NOT IN (' . $own . ')',
			...array_slice($values, 0, -1)));
		$this->truncated[Scan::TIER_HIGH] += max(0, $marked - self::MAX_PER_DETECTOR);
		// phpcs:enable
		
		$stats['options_scanned'] = (int)$wpdb->get_var('SELECT COUNT(*) FROM ' . $wpdb->options); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one COUNT for the report's denominator
		
		$findings = [];
		
		foreach((array)$rows as $row)
		{
			$name = (string)($row['option_name'] ?? '');
			
			if($name === '')
			{
				continue;
			}
			
			$findings[] = $this->finding('option_code', Scan::TIER_HIGH, 'options/' . $name,
				'code markers in the value, ' . (int)($row['len'] ?? 0) . ' bytes');
		}
		
		return $findings;
	}
	
	/**
	 * Content whose body carries a script from a host that is neither the
	 * site nor a known third party, an iframe from such a host, or an
	 * obfuscation idiom — SEO spam, skimmers, redirect injections. Posts and
	 * pages, and the four row types a BLOCK theme keeps its markup in
	 * (CONTENT_TYPES): a template part edited in the Site Editor is not a
	 * file, so nothing that walks the tree will ever see what is in it. Every
	 * status a person or a renderer reaches (CONTENT_STATUSES): a scheduled
	 * post goes live with no further write, a draft runs in its preview. Each
	 * pass reads the rows the last pass reported first (`known`, so a finding
	 * stays listed while it stands — the console takes a complete report's
	 * silence for gone), then the CONTENT_ROWS newest rows that carry a
	 * marker, and as many onward by id from where the last pass stopped
	 * (`posts_cursor`, which starts over once the rows run out), so a row a
	 * site's embeds crowd out of the newest is read a few passes later. The
	 * findings past MAX_PER_DETECTOR are counted (overflow()), never dropped
	 * unsaid. Ids and hosts only; a body is never reported.
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function content(
		array &$stats,
	): array
	{
		global $wpdb;
		
		if(is_object($wpdb) === false)
		{
			return [];
		}
		
		$markers = ['<script', '<iframe', 'eval(', 'fromCharCode', 'unescape('];
		$where = [];
		// the IN list rides prepare() like everything else: its placeholders
		// come first in the statement, so its values come first here
		$values = [...self::CONTENT_STATUSES, ...self::CONTENT_TYPES];
		$statuses = implode(', ', array_fill(0, count(self::CONTENT_STATUSES), '%s'));
		$types = implode(', ', array_fill(0, count(self::CONTENT_TYPES), '%s'));
		
		foreach($markers as $marker)
		{
			$where[] = 'post_content LIKE %s';
			$values[] = '%' . $wpdb->esc_like($marker) . '%';
		}
		
		$select = 'SELECT ID, post_type, post_status, post_content, post_modified_gmt FROM ' . $wpdb->posts
			. ' WHERE post_status IN (' . $statuses . ') AND post_type IN (' . $types . ') AND (' . implode(' OR ', $where) . ')';
		
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- a read-only forensic pass over the content a person or a renderer reaches, bounded by LIMIT and run once per scan; the WHERE is built from constants and every value rides through prepare()
		$newest = (array)$wpdb->get_results($wpdb->prepare($select . ' ORDER BY post_modified_gmt DESC LIMIT %d',
			...[...$values, self::CONTENT_ROWS]), ARRAY_A);
		$onward = (array)$wpdb->get_results($wpdb->prepare($select . ' AND ID > %d ORDER BY ID ASC LIMIT %d',
			...[...$values, $this->cursor, self::CONTENT_ROWS]), ARRAY_A);
		$known = array_slice(array_values(array_unique(array_filter(array_map('intval', $this->known), static fn(int $id): bool => $id > 0))), 0, self::CONTENT_ROWS);
		$again = $known === [] ? [] : (array)$wpdb->get_results($wpdb->prepare($select . ' AND ID IN (' . implode(', ', array_fill(0, count($known), '%d')) . ')',
			...[...$values, ...$known]), ARRAY_A);
		$stats['posts_scanned'] = (int)$wpdb->get_var($wpdb->prepare(
			'SELECT COUNT(*) FROM ' . $wpdb->posts . ' WHERE post_status IN (' . $statuses . ') AND post_type IN (' . $types . ')',
			...self::CONTENT_STATUSES, ...self::CONTENT_TYPES));
		// phpcs:enable
		
		// the next pass reads on from the last row this one read by id, or from the start once they ran out
		$stats['posts_cursor'] = count($onward) < self::CONTENT_ROWS ? 0 : (int)($onward[count($onward) - 1]['ID'] ?? 0);
		$rows = [];
		
		foreach([...$again, ...$newest, ...$onward] as $row)
		{
			$rows[(int)($row['ID'] ?? 0)] ??= $row;
		}
		
		$findings = [];
		
		foreach($rows as $row)
		{
			$id = (int)($row['ID'] ?? 0);
			$modified = strtotime((string)($row['post_modified_gmt'] ?? '') . ' UTC');
			
			// the id alone is unambiguous (one table, one sequence), but nobody
			// hunting "posts/412" expects to find a template part or a draft —
			// so the row type and the status ride the detail when they are not
			// simply a published post or page
			$label = implode(', ', array_filter([
				self::CONTENT_LABELS[(string)($row['post_type'] ?? '')] ?? '',
				self::STATUS_LABELS[(string)($row['post_status'] ?? '')] ?? '',
			]));
			
			foreach($this->injections((string)($row['post_content'] ?? '')) as [$detector, $detail])
			{
				if($this->overflow(count($findings), Scan::TIER_HIGH))
				{
					continue;
				}
				
				$findings[] = $this->finding($detector, Scan::TIER_HIGH, 'posts/' . $id,
					$label === '' ? $detail : $label . ': ' . $detail,
					$modified === false ? 0 : $modified);
				$this->found[] = $id;
			}
		}
		
		$this->found = array_values(array_unique($this->found));
		
		return $findings;
	}
	
	/**
	 * The same injection shapes over the widget options — the classic place
	 * for a hand-planted script tag
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function widgets(
		array &$stats,
	): array
	{
		$findings = [];
		
		foreach(['widget_custom_html', 'widget_text', 'widget_block'] as $option)
		{
			foreach((array)get_option($option, []) as $index => $widget)
			{
				$content = is_array($widget)
					? (string)($widget['content'] ?? ($widget['text'] ?? ''))
					: (is_string($widget) ? $widget : '');
				
				if($content === '')
				{
					continue;
				}
				
				foreach($this->injections($content) as [$detector, $detail])
				{
					if($this->overflow(count($findings), Scan::TIER_HIGH) === false)
					{
						$findings[] = $this->finding($detector, Scan::TIER_HIGH, 'options/' . $option . '/' . (string)$index, $detail);
					}
				}
			}
		}
		
		return $findings;
	}
	
	/**
	 * The option flips the live hook only sees going forward — a site
	 * URL that disagrees with its constant, registration open into a role
	 * above subscriber
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function options(
		array &$stats,
	): array
	{
		$findings = [];
		
		foreach(['siteurl' => 'WP_SITEURL', 'home' => 'WP_HOME'] as $option => $constant)
		{
			if(defined($constant) === false)
			{
				continue;
			}
			
			$stored = rtrim((string)get_option($option), '/');
			$defined = rtrim((string)constant($constant), '/');
			
			if($stored !== '' && $defined !== '' && strtolower($stored) !== strtolower($defined))
			{
				$findings[] = $this->finding('option_drift', Scan::TIER_INFO, 'options/' . $option,
					'the stored URL disagrees with ' . $constant . ' (the constant wins while it is defined)');
			}
		}
		
		$role = (string)get_option('default_role');
		
		if((bool)get_option('users_can_register') && $role !== 'subscriber')
		{
			$findings[] = $this->finding('registration_role', Scan::TIER_HIGH, 'options/default_role',
				'registration is open and new users become ' . Inventory::slugOf($role));
		}
		
		return $findings;
	}
	
	/**
	 * The injection shapes in one piece of content: a script or iframe from
	 * a host that is neither the site's nor a known third party, or an
	 * obfuscation idiom
	 *
	 * @return list<array{0: string, 1: string}>
	 */
	protected function injections(
		string $content,
	): array
	{
		$found = [];
		
		if(preg_match_all('~<(script|iframe)[^>]*\ssrc=["\']?\s*((?:https?:)?//[^"\'\s>]+)~i', $content, $matches, PREG_SET_ORDER) > 0)
		{
			foreach($matches as $match)
			{
				$host = strtolower((string)wp_parse_url(str_starts_with($match[2], '//') ? 'https:' . $match[2] : $match[2], PHP_URL_HOST));
				
				if($host !== '' && $this->isForeignHost($host))
				{
					$found[] = [strtolower($match[1]) === 'script' ? 'content_script' : 'content_iframe',
						strtolower($match[1]) . ' from ' . $this->clip($host, 80)];
				}
			}
		}
		
		if(preg_match('~\beval\s*\(|String\.fromCharCode\s*\(|document\.write\s*\(\s*unescape\s*\(~', $content) === 1)
		{
			$found[] = ['content_obfuscated', 'an obfuscation idiom in the content (eval, fromCharCode or unescape)'];
		}
		
		return $found;
	}
	
	protected function isForeignHost(
		string $host,
	): bool
	{
		$strip = static fn(string $value): string => (string)preg_replace('~^www\.~', '', strtolower($value));
		$host = $strip($host);
		
		if($host === '' || ($this->host !== '' && $host === $strip($this->host)))
		{
			return false;
		}
		
		foreach(self::KNOWN_SCRIPT_HOSTS as $known)
		{
			if($host === $known || str_ends_with($host, '.' . $known))
			{
				return false;
			}
		}
		
		return true;
	}
	
	protected function siteHost(): string
	{
		if(function_exists('home_url') === false)
		{
			return '';
		}
		
		$host = wp_parse_url((string)home_url(), PHP_URL_HOST);
		
		return is_string($host) ? $host : '';
	}
	
	/**
	 * @return array<string, mixed> the scan's finding shape for the database area
	 */
	protected function finding(
		string $detector,
		string $tier,
		string $path,
		string $detail,
		int $mtime = 0,
	): array
	{
		$finding = [
			'detector' => $detector,
			'tier' => $tier,
			'area' => self::AREA,
			'path' => $this->clip($path, 512),
			'detail' => $this->clip($detail, 160),
		];
		
		if($mtime > 0)
		{
			$finding['mtime'] = $mtime;
		}
		
		return $finding;
	}
	
	protected function clip(
		string $value,
		int $max,
	): string
	{
		$value = (string)preg_replace('~[\x00-\x1f\x7f]~', '?', $value);
		
		return strlen($value) > $max ? substr($value, 0, $max) : $value;
	}
}
