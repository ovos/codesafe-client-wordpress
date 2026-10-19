<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Throwable;
use WP_Application_Passwords;
use WP_Session_Tokens;

use function _get_cron_array;
use function array_fill;
use function array_key_exists;
use function class_exists;
use function count;
use function defined;
use function function_exists;
use function get_option;
use function get_users;
use function has_action;
use function home_url;
use function implode;
use function in_array;
use function is_array;
use function is_file;
use function is_int;
use function is_multisite;
use function is_numeric;
use function is_scalar;
use function is_string;
use function max;
use function min;
use function preg_match;
use function preg_match_all;
use function preg_replace;
use function rtrim;
use function str_contains;
use function str_ends_with;
use function str_replace;
use function strtolower;
use function strtotime;
use function substr;
use function time;
use function wp_parse_url;

use const PHP_URL_HOST;

/**
 * The database half of the integrity scan (docs/plans/wordpress-integrity-scan.md,
 * WS3) — the attacker's other filesystem. Half of real WordPress malware never
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
 * from, and it needs no name to say it.
 *
 * Every read is bounded (LIMITs, caps per detector) and wrapped: a failing
 * query costs the detector, never the pass.
 */
class Database
{
	public const AREA = 'database';
	
	protected const MAX_PER_DETECTOR = 20;
	
	/** option values that carry code — the loader's payload */
	protected const CODE_MARKERS = ['<?php', 'eval(', 'base64_decode(', 'gzinflate(', 'gzuncompress(', 'str_rot13(', 'create_function(', 'assert('];
	
	/** a cron hook nobody listens to is common leftover; one of these names is not */
	protected const SUSPICIOUS_HOOK = '~(?:eval|base64|shell|exec|backdoor|payload|inject|cmd)|^[a-f0-9]{16,}$~i';
	
	/**
	 * Third-party script hosts a site embeds on purpose — analytics, fonts,
	 * players, CDNs. A `<script src>` to any other host in post content is
	 * the injection to look at.
	 */
	/**
	 * Where a theme's markup can live BESIDES its files. A block theme — the
	 * default for new sites since 2022, and all four bundled ones — is edited
	 * in the Site Editor, which writes rows, not files: the integrity scan's
	 * tree walk and wordpress.org's checksums can never see an injection
	 * there, and neither can a file-editor observer. `custom_css` is the
	 * Customizer's Additional CSS, the oldest place to hide a `</style>`
	 * breakout.
	 */
	protected const CONTENT_TYPES = ['post', 'page',
		'wp_template', 'wp_template_part', 'wp_global_styles', 'custom_css'];
	
	/** what to call the rows a person would not think of as a post */
	protected const CONTENT_LABELS = [
		'wp_template' => 'site-editor template',
		'wp_template_part' => 'site-editor template part',
		'wp_global_styles' => 'global styles',
		'custom_css' => 'additional CSS',
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
	
	/**
	 * The database findings as the scan's finding shape — detector, tier,
	 * path (relative to the "database" area), detail, mtime — plus the
	 * counters the report's area block carries
	 *
	 * @return array{findings: list<array<string, mixed>>, stats: array<string, int>}
	 */
	public function scan(): array
	{
		$this->host = $this->siteHost();
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
		
		return ['findings' => $findings, 'stats' => $stats];
	}
	
	/**
	 * C1 + C2: every administrator by id with the moment the account was
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
	 * C3: an active plugin whose file is not on disk, or outside the plugins
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
		
		if(function_exists('is_multisite') && is_multisite())
		{
			foreach((array)get_option('active_sitewide_plugins', []) as $file => $time)
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
				$findings[] = $this->finding('active_plugin_missing', Scan::TIER_HIGH, 'options/active_plugins/' . $file,
					$traversal ? 'an active plugin path leaving the plugins directory' : 'an active plugin whose file is not on disk');
				
				if(count($findings) >= self::MAX_PER_DETECTOR)
				{
					break;
				}
			}
		}
		
		return $findings;
	}
	
	/**
	 * C4: scheduled hooks nobody listens to — at scan time every active
	 * plugin has registered its actions, so a hook without one is a leftover
	 * (a deactivated plugin's, usually: info) or a stranger's (a name shaped
	 * like a payload: high)
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
					continue;
				}
				
				$suspicious = preg_match(self::SUSPICIOUS_HOOK, $hook) === 1;
				$schedule = '';
				
				foreach((array)$events as $event)
				{
					$schedule = is_array($event) && is_string($event['schedule'] ?? null) ? $event['schedule'] : $schedule;
				}
				
				$findings[] = $this->finding($suspicious ? 'cron_suspicious' : 'cron_orphan',
					$suspicious ? Scan::TIER_HIGH : Scan::TIER_INFO, 'options/cron/' . $hook,
					'scheduled hook no active plugin or theme listens to'
					. ($schedule !== '' ? ', ' . $schedule : '')
					. ', next ' . gmdate('Y-m-d H:i', (int)$timestamp), (int)$timestamp);
				
				if(count($findings) >= self::MAX_PER_DETECTOR)
				{
					return $findings;
				}
			}
		}
		
		return $findings;
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
			
			$findings[] = $this->finding('uninstall_orphan', Scan::TIER_HIGH, 'options/uninstall_plugins/' . $file,
				'an uninstall callable registered for a plugin that is not installed'
				. (is_string($callable) ? ' (' . $this->clip($callable, 40) . ')' : ''));
			
			if(count($findings) >= self::MAX_PER_DETECTOR)
			{
				break;
			}
		}
		
		return $findings;
	}
	
	/**
	 * C5: option rows whose value carries code — malware keeps its body in
	 * the options table and evals it from a three-line loader on disk. The
	 * plugin's own rows are excluded (this report's detail lines quote the
	 * markers), and only the NAME and the length are reported, never the
	 * value.
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
		
		$values[] = $wpdb->esc_like('ovos_codesafe') . '%';
		$values[] = self::MAX_PER_DETECTOR;
		
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- a read-only forensic pass over the options table, bounded by LIMIT and run once per scan; the WHERE is built from constants and every value rides through prepare()
		$rows = $wpdb->get_results($wpdb->prepare(
			'SELECT option_name, LENGTH(option_value) AS len FROM ' . $wpdb->options
			. ' WHERE (' . implode(' OR ', $where) . ') AND option_name NOT LIKE %s ORDER BY len DESC LIMIT %d',
			...$values), ARRAY_A);
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
	 * C6: published content whose body carries a script from a host that is
	 * neither the site nor a known third party, an iframe from such a host,
	 * or an obfuscation idiom — SEO spam, skimmers, redirect injections.
	 * Posts and pages, and the four row types a BLOCK theme keeps its markup
	 * in (CONTENT_TYPES): a template part edited in the Site Editor is not a
	 * file, so nothing that walks the tree will ever see what is in it. Ids
	 * and hosts only; a body is never reported.
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
		$values = self::CONTENT_TYPES;
		$types = implode(', ', array_fill(0, count(self::CONTENT_TYPES), '%s'));
		
		foreach($markers as $marker)
		{
			$where[] = 'post_content LIKE %s';
			$values[] = '%' . $wpdb->esc_like($marker) . '%';
		}
		
		$values[] = 200;
		
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- a read-only forensic pass over published content, bounded by LIMIT and run once per scan; the WHERE is built from constants and every value rides through prepare()
		$rows = $wpdb->get_results($wpdb->prepare(
			'SELECT ID, post_type, post_content, post_modified_gmt FROM ' . $wpdb->posts
			. " WHERE post_status = 'publish' AND post_type IN (" . $types . ') AND (' . implode(' OR ', $where) . ')'
			. ' ORDER BY post_modified_gmt DESC LIMIT %d',
			...$values), ARRAY_A);
		$stats['posts_scanned'] = (int)$wpdb->get_var($wpdb->prepare(
			'SELECT COUNT(*) FROM ' . $wpdb->posts . " WHERE post_status = 'publish' AND post_type IN (" . $types . ')',
			...self::CONTENT_TYPES));
		// phpcs:enable
		
		$findings = [];
		
		foreach((array)$rows as $row)
		{
			$id = (int)($row['ID'] ?? 0);
			$modified = strtotime((string)($row['post_modified_gmt'] ?? '') . ' UTC');
			
			// the id alone is unambiguous (one table, one sequence), but nobody
			// hunting "posts/412" expects to find a template part — so the row
			// type rides the detail when it is not simply a post or a page
			$label = self::CONTENT_LABELS[(string)($row['post_type'] ?? '')] ?? '';
			
			foreach($this->injections((string)($row['post_content'] ?? '')) as [$detector, $detail])
			{
				$findings[] = $this->finding($detector, Scan::TIER_HIGH, 'posts/' . $id,
					$label === '' ? $detail : $label . ': ' . $detail,
					$modified === false ? 0 : $modified);
			}
			
			if(count($findings) >= self::MAX_PER_DETECTOR)
			{
				break;
			}
		}
		
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
					$findings[] = $this->finding($detector, Scan::TIER_HIGH, 'options/' . $option . '/' . (string)$index, $detail);
				}
				
				if(count($findings) >= self::MAX_PER_DETECTOR)
				{
					return $findings;
				}
			}
		}
		
		return $findings;
	}
	
	/**
	 * C7: the option flips the live hook only sees going forward — a site
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
