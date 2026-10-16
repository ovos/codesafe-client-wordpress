<?php
declare(strict_types=1);
// phpcs:disable WordPress.WP.AlternativeFunctions.curl_curl_init, WordPress.WP.AlternativeFunctions.curl_curl_setopt_array, WordPress.WP.AlternativeFunctions.curl_curl_exec -- the fire-and-forget inventory call needs millisecond timeouts (300 ms connect / 1 s total) the WP HTTP API cannot express; without curl the report is dropped rather than riding a blocking call at shutdown

namespace Ovos\Codesafe;

use Throwable;

use function add_action;
use function array_slice;
use function array_unique;
use function array_values;
use function basename;
use function curl_exec;
use function curl_init;
use function curl_setopt_array;
use function delete_option;
use function dirname;
use function function_exists;
use function get_bloginfo;
use function get_mu_plugins;
use function get_option;
use function get_plugins;
use function get_site_option;
use function get_stylesheet;
use function in_array;
use function is_array;
use function is_string;
use function json_decode;
use function json_encode;
use function ksort;
use function mb_substr;
use function preg_match;
use function preg_replace;
use function register_shutdown_function;
use function sha1;
use function strtolower;
use function substr;
use function time;
use function trim;
use function update_option;
use function wp_get_themes;

use const ABSPATH;
use const PHP_VERSION;

/**
 * Software inventory reporter — the sensor half of the console's CVE
 * matching. Ships WHAT is installed (core/PHP versions plus the
 * plugin/mu-plugin/theme list with versions and active flags) so the
 * console's nightly cve-sync can match it against the vulnerability feed —
 * and nothing else: no paths, no options, no users, no configuration.
 *
 * The console's answer may carry `auto_update`: the installed plugins that
 * are vulnerable AND being probed — with the plugin's own opt-in, WordPress's
 * automatic update is switched on for exactly those (apply()).
 *
 * OPT-IN TWICE, like rollups: the inventory setting here (default off,
 * lockable via CODESAFE_INVENTORY in wp-config.php) and cve_enabled on
 * the console project. Either switch off keeps this inert — an installed-
 * software list is a disclosure, and nothing ships it until someone turns
 * it on at both ends.
 *
 * SEND DISCIPLINE, no WP-Cron (the rollup precedent): the change hooks
 * (installs, updates, (de)activations, deletions, theme switches, core
 * updates) only mark a flag; a shutdown-time check posts when the flag is
 * set OR the stored {hash, ts} option says the last send is a day old —
 * the 24h heartbeat the console reads as "the sensor is alive". The full
 * gather runs only when actually sending, so the common request pays one
 * get_option().
 */
class Inventory
{
	/**
	 * The last send: {hash: canonical-report sha1, ts: unix time}
	 */
	protected const OPTION = 'ovos_codesafe_inventory';
	
	/**
	 * Set by the change hooks, consumed by the next shutdown send
	 */
	protected const OPTION_DIRTY = 'ovos_codesafe_inventory_dirty';
	
	/**
	 * The heartbeat cadence — an unchanged report this old is re-sent and
	 * answered as a duplicate; the console only advances its freshness stamp
	 */
	protected const DAY = 86400;
	
	/**
	 * The console refuses reports past 300 items anyway — capping here keeps
	 * the body bounded before it ever leaves the host
	 */
	protected const MAX_ITEMS = 300;
	
	/**
	 * Everything that changes what is installed — each one only marks dirty
	 */
	protected const CHANGE_HOOKS = [
		'upgrader_process_complete',
		'activated_plugin',
		'deactivated_plugin',
		'deleted_plugin',
		'switch_theme',
		'_core_updated_successfully',
	];
	
	public function __construct(
		protected Config $config,
		protected ?Sender $sender = null,
	)
	{
	}
	
	public function register(): void
	{
		foreach(self::CHANGE_HOOKS as $hook)
		{
			add_action($hook, [$this, 'markDirty']);
		}
		
		// after the Sender's and the Rollup's handlers — inventory is the
		// least urgent thing a shutdown does
		register_shutdown_function([$this, 'maybeSend']);
	}
	
	/**
	 * Inventory needs the plugin's master switch, its own opt-in and the
	 * console transport; the console-side cve_enabled gate answers 403 and
	 * stores nothing, so a report sent before that switch is flipped is
	 * inert rather than wrong
	 */
	public function isEnabled(): bool
	{
		return $this->config->enabled()
			&& $this->config->inventory()
			&& $this->config->url() !== ''
			&& $this->config->apiKey() !== '';
	}
	
	/**
	 * A change hook fired — remember that, gather nothing yet: the hook may
	 * run mid-upgrade, and the shutdown gather sees the finished state
	 */
	public function markDirty(): void
	{
		try
		{
			update_option(self::OPTION_DIRTY, 1, false);
		}
		catch(Throwable)
		{
			// telemetry must never break the host site
		}
	}
	
	/**
	 * The shutdown check: one get_option() on the common path, the full
	 * gather-and-send only when something changed or the heartbeat is due
	 */
	public function maybeSend(): void
	{
		try
		{
			if($this->isEnabled() === false)
			{
				return;
			}
			
			$state = get_option(self::OPTION);
			$sentAt = is_array($state) ? (int)($state['ts'] ?? 0) : 0;
			
			if((bool)get_option(self::OPTION_DIRTY) === false
				&& time() - $sentAt < self::DAY)
			{
				return;
			}
			
			$report = $this->gather();
			
			$this->send($report);
			
			update_option(self::OPTION, [
				'hash' => sha1((string)json_encode([$report['core'],
					$report['php'], $report['items']])),
				'ts' => time(),
			], false);
			delete_option(self::OPTION_DIRTY);
		}
		catch(Throwable)
		{
			// telemetry must never break the host site
		}
	}
	
	/**
	 * The report the console's InventoryPayload expects — platform-tagged
	 * ({platform, core, php, items}), items keyed and sorted (type|slug,
	 * first occurrence wins) so the content hash is order-stable
	 */
	public function gather(): array
	{
		if(function_exists('get_plugins') === false)
		{
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		
		$items = [];
		
		$active = (array)get_option('active_plugins', []);
		$network = function_exists('get_site_option')
			? (array)get_site_option('active_sitewide_plugins', [])
			: [];
		
		foreach((array)get_plugins() as $file => $headers)
		{
			$this->item($items, 'plugin', self::slugOf((string)$file), $headers,
				in_array($file, $active, true) || isset($network[$file]));
		}
		
		foreach((array)get_mu_plugins() as $file => $headers)
		{
			// mu-plugins are single files and always on — that IS the type
			$this->item($items, 'mu-plugin', self::slugOf((string)$file), $headers, true);
		}
		
		$current = function_exists('get_stylesheet') ? get_stylesheet() : '';
		foreach(wp_get_themes() as $stylesheet => $theme)
		{
			$this->item($items, 'theme', self::slugOf((string)$stylesheet), [
				'Name' => (string)$theme->get('Name'),
				'Version' => (string)$theme->get('Version'),
			], (string)$stylesheet === $current);
		}
		
		ksort($items);
		
		return [
			'v' => 1,
			'type' => 'inventory',
			'platform' => 'wordpress',
			'core' => self::version((string)get_bloginfo('version')),
			'php' => self::version(PHP_VERSION),
			'items' => array_values(array_slice($items, 0, self::MAX_ITEMS)),
		];
	}
	
	/**
	 * One inventory entry, keyed like the console dedups (type|slug, the
	 * first occurrence wins). An entry whose slug cannot be shaped is
	 * SKIPPED, never sent: the console refuses a report wholesale over one
	 * hostile-looking slug, and a single unshippable directory name must
	 * not silence the two hundred honest neighbours.
	 */
	protected function item(
		array &$items,
		string $type,
		string $slug,
		array $headers,
		bool $active,
	): void
	{
		if($slug === '')
		{
			return;
		}
		
		$items[$type . '|' . $slug] ??= [
			'type' => $type,
			'slug' => $slug,
			'version' => self::version((string)($headers['Version'] ?? '')),
			'name' => mb_substr(trim((string)($headers['Name'] ?? '')), 0, 100),
			'active' => $active,
		];
	}
	
	/**
	 * A plugin file ("dir/plugin.php" or "single.php") or theme stylesheet
	 * reduced to the console's slug shape — lowercase, starts alphanumeric,
	 * [a-z0-9._-] — or '' when nothing usable remains
	 */
	public static function slugOf(
		string $file,
	): string
	{
		$directory = dirname($file);
		$slug = $directory !== '.' && $directory !== ''
			? $directory
			: (string)preg_replace('~\.php$~', '', basename($file));
		
		$slug = strtolower($slug);
		$slug = (string)preg_replace('~[^a-z0-9._-]+~', '-', $slug);
		$slug = (string)preg_replace('~^[^a-z0-9]+~', '', $slug);
		$slug = substr($slug, 0, 100);
		
		return preg_match('~^[a-z0-9][a-z0-9._-]{0,99}$~', $slug) === 1 ? $slug : '';
	}
	
	/**
	 * A version header reduced to the console's shape ([0-9A-Za-z._-], max
	 * 32) — '' is legal, a header without Version is; the matcher skips
	 * versionless items rather than judging a guess
	 */
	public static function version(
		string $raw,
	): string
	{
		$version = (string)preg_replace('~[^0-9A-Za-z._-]+~', '', trim($raw));
		
		return substr($version, 0, 32);
	}
	
	/**
	 * TLS peer verification, same filter as the Sender's ingest call
	 */
	protected function verifyTls(): bool
	{
		return (bool)Legacy::filter('ovos_codesafe_sslverify', true);
	}
	
	/**
	 * Fire-and-forget POST, the Sender's transport contract (the Rollup's
	 * copy): connection released first, NOSIGNAL for poll-based sub-second
	 * timeouts, hard bounds, no reading the answer — an unchanged report is
	 * a 202 duplicate anyway. curl only: without the extension the report
	 * is dropped rather than riding a blocking wp_remote_post at shutdown.
	 */
	protected function send(
		array $payload,
	): void
	{
		if(function_exists('curl_init') === false)
		{
			return;
		}
		
		if(function_exists('fastcgi_finish_request'))
		{
			@fastcgi_finish_request();
		}
		
		$verify = $this->verifyTls();
		
		$handle = curl_init($this->config->url() . '/api/v1/ingest/inventory');
		
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
		
		$body = curl_exec($handle);
		
		$this->apply(is_string($body) ? $body : '');
	}
	
	/**
	 * The console's answer may name the installed plugins that are VULNERABLE
	 * AND BEING PROBED (docs/plans/wordpress-cyberprotection-brainstorm.md,
	 * P4). With the auto_update_vulnerable setting on, WordPress's own
	 * automatic update is switched on for exactly those — the one virtual
	 * patch WordPress supports natively — and each switch-on is reported as
	 * a privileged_action so the console's audit trail carries it. Off by
	 * default and opt-in at both ends: the console names plugins only when
	 * the project's own switch is on. Nothing is downgraded, deactivated or
	 * deleted here; WordPress updates from wordpress.org on its own clock.
	 */
	protected function apply(
		string $body,
	): void
	{
		if($this->config->autoUpdateVulnerable() === false || $body === '')
		{
			return;
		}
		
		$decoded = json_decode($body, true, 4);
		$slugs = [];
		
		foreach(is_array($decoded) && is_array($decoded['auto_update'] ?? null) ? $decoded['auto_update'] : [] as $slug)
		{
			if(is_string($slug) && self::slugOf($slug) === $slug)
			{
				$slugs[] = $slug;
			}
		}
		
		if($slugs === [])
		{
			return;
		}
		
		if(function_exists('get_plugins') === false)
		{
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		
		$enabled = (array)get_option('auto_update_plugins', []);
		$added = [];
		
		foreach((array)get_plugins() as $file => $headers)
		{
			$directory = dirname((string)$file);
			
			if($directory !== '.' && in_array($directory, $slugs, true) && in_array($file, $enabled, true) === false)
			{
				$enabled[] = (string)$file;
				$added[] = $directory;
			}
		}
		
		if($added === [])
		{
			return;
		}
		
		update_option('auto_update_plugins', array_values(array_unique($enabled)));
		
		if($this->sender !== null)
		{
			foreach($added as $slug)
			{
				$this->sender->reportRefusal('privileged_action',
					'auto-update enabled for ' . $slug . ' (vulnerable and probed, per the console)',
					['action' => 'auto_update_enabled']);
			}
			
			// the Sender's own shutdown flush already ran — this handler
			// registered after it — so the audit line ships from here
			$this->sender->flush();
		}
	}
}
