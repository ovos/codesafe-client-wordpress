<?php
declare(strict_types=1);
// phpcs:disable WordPress.WP.AlternativeFunctions.curl_curl_init, WordPress.WP.AlternativeFunctions.curl_curl_setopt_array, WordPress.WP.AlternativeFunctions.curl_curl_exec -- the fire-and-forget inventory call needs millisecond timeouts (300 ms connect / 1 s total) the WP HTTP API cannot express; without curl the report is dropped rather than riding a blocking call at shutdown

namespace Ovos\Codesafe;

use Throwable;
use WP_Automatic_Updater;

use function add_action;
use function array_diff_key;
use function array_filter;
use function array_intersect_key;
use function array_merge;
use function array_slice;
use function array_unique;
use function array_values;
use function basename;
use function class_exists;
use function count;
use function curl_exec;
use function curl_getinfo;
use function curl_init;
use function curl_setopt_array;
use function defined;
use function delete_option;
use function dirname;
use function function_exists;
use function get_bloginfo;
use function get_mu_plugins;
use function get_option;
use function get_plugins;
use function get_site_option;
use function get_site_transient;
use function get_stylesheet;
use function in_array;
use function is_array;
use function is_object;
use function is_string;
use function json_decode;
use function json_encode;
use function ksort;
use function max;
use function mb_substr;
use function min;
use function parse_url;
use function preg_match;
use function preg_replace;
use function register_shutdown_function;
use function sha1;
use function str_ends_with;
use function str_starts_with;
use function strtolower;
use function substr;
use function time;
use function trim;
use function update_option;
use function update_site_option;
use function wp_get_themes;
use function wp_is_auto_update_enabled_for_type;
use function wp_is_auto_update_forced_for_item;
use function wp_is_file_mod_allowed;

use const ABSPATH;
use const CURLINFO_RESPONSE_CODE;
use const CURLOPT_PROTOCOLS;
use const CURLOPT_REDIR_PROTOCOLS;
use const CURLPROTO_HTTP;
use const CURLPROTO_HTTPS;
use const PHP_URL_HOST;
use const PHP_VERSION;
use const WP_PLUGIN_DIR;

/**
 * Software inventory reporter — the sensor half of the console's CVE
 * matching. Ships WHAT is installed (core/PHP versions plus the
 * plugin/mu-plugin/theme list with versions and active flags) so the
 * console's nightly cve-sync can match it against the vulnerability feed —
 * and nothing else: no paths, no options, no users, no configuration. Per
 * plugin and theme it also says the newest version WordPress's own update
 * check knows (`latest`), whether WordPress auto-updates it, and whether a
 * filter forces that, and where its updates come from (`source`; `package`
 * false when an update is offered without a download); per site, whether
 * WordPress can auto-update at all, the newest core its update check knows
 * (`core_latest`) and core's own automatic updates (`core`, CoreUpdate).
 *
 * The console's answer may name plugins, themes and core to auto-update:
 * what is vulnerable AND being probed, and whatever an operator picked on
 * the project's SOFTWARE list — with the auto_update_vulnerable setting on
 * (the default), WordPress's automatic update is switched on for exactly
 * those, for core its minor releases only (apply()).
 *
 * TWO SWITCHES, like rollups: the inventory here (on, no box;
 * CODESAFE_INVENTORY false in wp-config.php keeps the list on the site) and
 * cve_enabled on the console project. Either switch off keeps this inert.
 *
 * SEND DISCIPLINE, no WP-Cron (the rollup precedent): the change hooks
 * (installs, updates, (de)activations, deletions, theme switches, core
 * updates, the auto-update choices, a new update check) only mark a flag;
 * so does codesafe's software version changing on any answer the site hears
 * (nudge()). A shutdown-time check posts when the flag is set OR the stored
 * {hash, ts} option says the last send is a day old — the 24h heartbeat the
 * console reads as "the sensor is alive". The full gather runs only when
 * actually sending, so the common request pays one get_option().
 */
class Inventory
{
	/**
	 * The last send: {hash: canonical-report sha1, ts: unix time, software:
	 * the software version codesafe's answer carried}, and while a version's
	 * send went unanswered {tried: that version, tried_at, fails: unanswered
	 * sends in a row}
	 */
	protected const OPTION = 'ovos_codesafe_inventory';
	
	/**
	 * Seconds a version whose send went unanswered is not asked for again —
	 * doubled per unanswered send in a row, at most a day (backoff())
	 */
	protected const BACKOFF = 900;
	
	/**
	 * The answers that settle a version besides a 2xx: codesafe took the
	 * report and refused it for good — asking again changes nothing
	 */
	protected const DEFINITIVE = [400, 401, 403, 404, 422];
	
	/**
	 * Set by the change hooks (1) or by a nudge (the software version it
	 * heard), consumed by the next shutdown send
	 */
	protected const OPTION_DIRTY = 'ovos_codesafe_inventory_dirty';
	
	/**
	 * The automatic updates codesafe switched on, by type — the only ones a
	 * TURN OFF from codesafe takes back: the site's own choices are the
	 * site's. A site option, like the lists it shadows
	 */
	public const OURS = 'ovos_codesafe_auto_updates';
	
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
	 * Everything that changes what is installed, what auto-updates, or what
	 * WordPress knows is newer — each one only marks dirty. A first write of
	 * an option is an add_, every later one an update_; the site options are
	 * the network's on a multisite network
	 */
	protected const CHANGE_HOOKS = [
		'upgrader_process_complete',
		'activated_plugin',
		'deactivated_plugin',
		'deleted_plugin',
		'switch_theme',
		'_core_updated_successfully',
		'add_option_auto_update_plugins',
		'update_option_auto_update_plugins',
		'add_option_auto_update_themes',
		'update_option_auto_update_themes',
		'add_site_option_auto_update_plugins',
		'update_site_option_auto_update_plugins',
		'add_site_option_auto_update_themes',
		'update_site_option_auto_update_themes',
		'set_site_transient_update_plugins',
		'set_site_transient_update_themes',
		'set_site_transient_update_core',
		// core's automatic updates: WordPress's two switches, the update it
		// parked as failed, and codesafe's kept switch-on
		'add_option_auto_update_core_minor',
		'update_option_auto_update_core_minor',
		'delete_option_auto_update_core_minor',
		'add_site_option_auto_update_core_minor',
		'update_site_option_auto_update_core_minor',
		'delete_site_option_auto_update_core_minor',
		'add_option_auto_update_core_major',
		'update_option_auto_update_core_major',
		'delete_option_auto_update_core_major',
		'add_site_option_auto_update_core_major',
		'update_site_option_auto_update_core_major',
		'delete_site_option_auto_update_core_major',
		'add_option_auto_core_update_failed',
		'update_option_auto_core_update_failed',
		'delete_option_auto_core_update_failed',
		'add_site_option_auto_core_update_failed',
		'update_site_option_auto_core_update_failed',
		'delete_site_option_auto_core_update_failed',
		'delete_option_' . CoreUpdate::OPTION,
		'delete_site_option_' . CoreUpdate::OPTION,
	];
	
	/**
	 * The reasons codesafe gives for an item it names, as the audit line says them
	 */
	public const REASONS = [
		'probed' => 'vulnerable and probed, per codesafe',
		'requested' => 'requested by an operator in codesafe',
		'both' => 'requested in codesafe; vulnerable and probed',
	];
	
	public function __construct(
		protected Config $config,
		protected ?Sender $sender = null,
		protected ?CoreUpdate $core = null,
	)
	{
	}
	
	public function register(): void
	{
		foreach(self::CHANGE_HOOKS as $hook)
		{
			add_action($hook, [$this, 'markDirty']);
		}
		
		// after the Sender's, the Shield's and the Rollup's handlers — a
		// nudge heard by any of them is sent in this same shutdown, and
		// inventory is the least urgent thing a shutdown does
		register_shutdown_function([$this, 'maybeSend']);
	}
	
	/** core's automatic updates — the one the plugin hooked, else its own */
	protected function core(): CoreUpdate
	{
		return $this->core ??= new CoreUpdate($this->config);
	}
	
	/**
	 * Inventory needs the plugin's master switch, its own setting and the
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
	 * run mid-upgrade, and the shutdown gather sees the finished state. A
	 * version a nudge left in the flag is kept
	 */
	public function markDirty(): void
	{
		try
		{
			if(get_option(self::OPTION_DIRTY) === false)
			{
				update_option(self::OPTION_DIRTY, 1, false);
			}
		}
		catch(Throwable)
		{
			// telemetry must never break the host site
		}
	}
	
	/**
	 * codesafe's answer said the project's software version (`software` on an
	 * ingest answer, X-Codesafe-Software on the Shield's pull): one other than
	 * the version the last inventory answer carried means codesafe has
	 * something for this site — an operator's auto-update pick — so the
	 * inventory goes again, in this request's shutdown when heard before it.
	 * The version is remembered only once an inventory answer settled it
	 * (maybeSend); an empty one says nothing, and one whose send went
	 * unanswered waits out its backoff. Whether it marked the inventory
	 */
	public function nudge(
		string $version,
		?int $now = null,
	): bool
	{
		try
		{
			if($version === '' || $this->isEnabled() === false)
			{
				return false;
			}
			
			$state = get_option(self::OPTION);
			$state = is_array($state) ? $state : [];
			if((string)($state['software'] ?? '') === $version)
			{
				return false;
			}
			
			// a door that timed out or failed is not asked again on every answer heard
			if((string)($state['tried'] ?? '') === $version
				&& ($now ?? time()) < (int)($state['tried_at'] ?? 0) + self::backoff((int)($state['fails'] ?? 1)))
			{
				return false;
			}
			
			// the version rides the flag: an inventory answer without one still settles it
			update_option(self::OPTION_DIRTY, $version, false);
			
			return true;
		}
		catch(Throwable)
		{
			return false;
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
			$state = is_array($state) ? $state : [];
			$dirty = get_option(self::OPTION_DIRTY);
			
			if((bool)$dirty === false
				&& time() - (int)($state['ts'] ?? 0) < self::DAY)
			{
				return;
			}
			
			// the response is out before the gather: reading the update data
			// runs its filters, where a premium updater may call home
			$this->release();
			
			$report = $this->gather();
			['status' => $status, 'body' => $answer] = $this->send($report);
			// the flag holds the version a nudge heard, or a change hook's 1 (read back as '1')
			$asked = (string)$dirty === '1' ? '' : Sender::token(is_string($dirty) ? $dirty : '');
			
			delete_option(self::OPTION_DIRTY);
			update_option(self::OPTION, self::settle($state, $asked, $status, $answer, time()) + [
				'hash' => sha1((string)json_encode([$report['core'],
					$report['php'], $report['items']])),
				'ts' => time(),
			], false);
			
			// after the flag is cleared: a switch-on marks the inventory again,
			// so the next request tells codesafe it took
			$this->apply($status >= 200 && $status < 300 ? $answer : '');
		}
		catch(Throwable)
		{
			// telemetry must never break the host site
		}
	}
	
	/**
	 * Pure: the software part of the stored state after a send. A version the
	 * answer names wins; a 2xx or a definitive refusal settles the version
	 * that asked for the send — asking again would change nothing; anything
	 * else (a 5xx, a 429, a timeout, nothing at all) leaves the stored version
	 * and remembers the one asked for as tried, its unanswered sends counted,
	 * so nudge() waits out backoff() instead of re-sending on every answer
	 * the site hears. A send for a change hook leaves a running backoff as it
	 * stands until one is answered
	 *
	 * @param array $state the stored state before the send
	 * @param string $asked the version that asked for this send, '' for a change hook or the heartbeat
	 * @return array{software: string, tried?: string, tried_at?: int, fails?: int}
	 */
	public static function settle(
		array $state,
		string $asked,
		int $status,
		string $answer,
		int $now,
	): array
	{
		$heard = $status >= 200 && $status < 300 ? Sender::softwareVersion($answer) : '';
		$answered = ($status >= 200 && $status < 300) || in_array($status, self::DEFINITIVE, true);
		$software = match(true)
		{
			$heard !== '' => $heard,
			$answered && $asked !== '' => $asked,
			default => (string)($state['software'] ?? ''),
		};
		
		if($answered)
		{
			return ['software' => $software];
		}
		
		if($asked === '')
		{
			return ['software' => $software] + array_intersect_key($state, ['tried' => 1, 'tried_at' => 1, 'fails' => 1]);
		}
		
		return [
			'software' => $software,
			'tried' => $asked,
			'tried_at' => $now,
			'fails' => (int)($state['fails'] ?? 0) + 1,
		];
	}
	
	/** Pure: seconds a version waits after $fails unanswered sends in a row — 15 minutes doubling, at most a day */
	public static function backoff(
		int $fails,
	): int
	{
		return min(self::DAY, self::BACKOFF << min(16, max(0, $fails - 1)));
	}
	
	/**
	 * The report the console's InventoryPayload expects — platform-tagged
	 * ({platform, core, php, updates, items, environment}), items keyed and sorted
	 * (type|slug, first occurrence wins) so the content hash is order-stable
	 */
	public function gather(): array
	{
		$items = [];
		
		$pluginUpdates = $this->updateData('plugin');
		$themeUpdates = $this->updateData('theme');
		$autoPlugins = (array)get_site_option('auto_update_plugins', []);
		$autoThemes = (array)get_site_option('auto_update_themes', []);
		
		$active = (array)get_option('active_plugins', []);
		$network = (array)get_site_option('active_sitewide_plugins', []);
		
		foreach($this->plugins() as $file => $headers)
		{
			$this->item($items, 'plugin', self::slugOf((string)$file), (array)$headers,
				in_array($file, $active, true) || isset($network[$file]),
				$this->updateFields('plugin', (string)$file, (string)($headers['Version'] ?? ''), $pluginUpdates, $autoPlugins,
					(string)($headers['UpdateURI'] ?? '')));
		}
		
		foreach($this->muPlugins() as $file => $headers)
		{
			// mu-plugins are single files and always on — that IS the type;
			// WordPress never updates one
			$this->item($items, 'mu-plugin', self::slugOf((string)$file), (array)$headers, true, []);
		}
		
		$current = $this->currentTheme();
		foreach($this->themes() as $stylesheet => $headers)
		{
			$this->item($items, 'theme', self::slugOf((string)$stylesheet), $headers, (string)$stylesheet === $current,
				$this->updateFields('theme', (string)$stylesheet, (string)($headers['Version'] ?? ''), $themeUpdates, $autoThemes,
					(string)($headers['UpdateURI'] ?? '')));
		}
		
		ksort($items);
		$blockedBy = $this->blockedBy();
		$core = self::version((string)get_bloginfo('version'));
		$updates = [
			'allowed' => $blockedBy === '',
			'blocked_by' => $blockedBy,
			// how fresh `latest` is: WordPress's last update check
			'checked_at' => max(0, (int)($pluginUpdates->last_checked ?? 0)),
		];
		
		// left out, like an item's `latest`, when the core check knows nothing
		$coreData = $this->coreUpdateData();
		$coreLatest = self::coreLatest($coreData, $core);
		if($coreLatest !== '')
		{
			$updates['core_latest'] = $coreLatest;
		}
		
		// core's own automatic updates: the policy and why, what blocks it, the minor on offer
		$updates['core'] = $this->core()->report($coreData, $core);
		
		$report = [
			'v' => 1,
			'type' => 'inventory',
			'platform' => 'wordpress',
			'core' => $core,
			'php' => self::version(PHP_VERSION),
			'updates' => $updates,
			'items' => array_values(array_slice($items, 0, self::MAX_ITEMS)),
		];
		
		// codesafe keeps one inventory per environment: a developer's copy on the production key never replaces production's
		$environment = $this->config->environment();
		
		if($environment !== '')
		{
			$report['environment'] = $environment;
		}
		
		return $report;
	}
	
	/**
	 * The newest WordPress core the last core update check knows: the
	 * `current` of the first entry offering an upgrade, else the installed
	 * version when an entry says core is the latest — '' when there is no
	 * check, it says neither (development builds, only auto-update entries),
	 * or the version it names is off the shape (a digit first, then
	 * [0-9A-Za-z._-], at most 32)
	 */
	public static function coreLatest(
		?object $data,
		string $installed,
	): string
	{
		$current = false;
		foreach(is_array($data?->updates ?? null) ? $data->updates : [] as $offer)
		{
			$response = self::field($offer, 'response');
			if($response === 'upgrade')
			{
				return self::coreVersion(self::field($offer, 'current'));
			}
			
			$current = $current || $response === 'latest';
		}
		
		return $current ? self::coreVersion($installed) : '';
	}
	
	/** a core version as the check names it, or '' when anything had to be cut away to fit the shape */
	public static function coreVersion(
		string $raw,
	): string
	{
		$version = self::version($raw);
		
		return $version === trim($raw) && preg_match('~^[0-9]~', $version) === 1 ? $version : '';
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
		array $updateFields,
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
		] + $updateFields;
	}
	
	/**
	 * What WordPress knows about one plugin or theme's updates: `latest` —
	 * the version its update check offers, the installed one when the check
	 * found it current, nothing when the check never saw it (not on
	 * wordpress.org and no updater of its own, or not checked yet);
	 * `auto_update` — whether it is on WordPress's auto-update list;
	 * `forced` — whether a filter decides that instead, left out when none does;
	 * `source` — where its updates come from (source()), left out when nothing
	 * says; `package` false — an update is offered without a download, which
	 * WordPress cannot install by itself (commonly a licence not active)
	 *
	 * @param string $key the plugin file or the theme's stylesheet, as WordPress keys both
	 * @param string $updateUri the item's Update URI header
	 */
	protected function updateFields(
		string $type,
		string $key,
		string $installed,
		?object $updates,
		array $auto,
		string $updateUri = '',
	): array
	{
		$fields = [];
		$offered = is_array($updates->response ?? null) ? ($updates->response[$key] ?? null) : null;
		$current = is_array($updates->no_update ?? null) ? ($updates->no_update[$key] ?? null) : null;
		
		$latest = match(true)
		{
			$offered !== null => self::version(self::field($offered, 'new_version')),
			$current !== null => self::version($installed),
			default => '',
		};
		if($latest !== '')
		{
			$fields['latest'] = $latest;
		}
		
		$fields['auto_update'] = in_array($key, $auto, true);
		
		$forced = $this->forced($type, $key, $offered ?? $current);
		if($forced !== null)
		{
			$fields['forced'] = $forced;
		}
		
		$source = self::source($offered ?? $current, $updateUri);
		if($source !== '')
		{
			$fields['source'] = $source;
		}
		
		if($offered !== null && self::field($offered, 'package') === '')
		{
			$fields['package'] = false;
		}
		
		return $fields;
	}
	
	/**
	 * Pure: where an item's updates come from — `wordpress.org` when the update
	 * check's entry says so (its id `w.org/…`, or its url or package on
	 * wordpress.org), else the host of the item's Update URI header, else the
	 * host of the entry's package or url (its own update server), '' when
	 * nothing says (it never updates by itself, or was not checked yet)
	 */
	public static function source(
		mixed $entry,
		string $updateUri,
	): string
	{
		if(str_starts_with(self::field($entry, 'id'), 'w.org/'))
		{
			return 'wordpress.org';
		}
		
		foreach([self::field($entry, 'url'), self::field($entry, 'package')] as $url)
		{
			if(self::host($url) === 'wordpress.org')
			{
				return 'wordpress.org';
			}
		}
		
		// `false` is WordPress's word for an item that never updates
		foreach([strtolower(trim($updateUri)) === 'false' ? '' : $updateUri, self::field($entry, 'package'), self::field($entry, 'url')] as $url)
		{
			$host = self::host($url);
			if($host !== '')
			{
				return $host;
			}
		}
		
		return '';
	}
	
	/**
	 * A URL's host, or a bare host's — lowercase, a DNS name or an address;
	 * wordpress.org and its subdomains (downloads., w.org) are `wordpress.org`;
	 * '' for anything else
	 */
	protected static function host(
		string $url,
	): string
	{
		$url = trim($url);
		if($url === '')
		{
			return '';
		}
		
		$host = strtolower((string)parse_url(preg_match('~^[a-z][a-z0-9+.-]*://~i', $url) === 1 ? $url : 'https://' . $url, PHP_URL_HOST));
		if(preg_match('~^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$~', $host) !== 1)
		{
			return '';
		}
		
		return $host === 'wordpress.org' || $host === 'w.org' || str_ends_with($host, '.wordpress.org') ? 'wordpress.org' : $host;
	}
	
	/**
	 * The `auto_update_{type}` filter's verdict on one item, asked the way
	 * the Plugins and Themes screens ask it (their payload shape, no update
	 * decided yet): true or false when a filter forces it, null when none does
	 */
	protected function forced(
		string $type,
		string $key,
		mixed $entry,
	): ?bool
	{
		if($this->loadUpdateApi() === false || function_exists('wp_is_auto_update_forced_for_item') === false)
		{
			return null;
		}
		
		$known = is_object($entry) ? (array)$entry : (is_array($entry) ? $entry : []);
		$payload = $type === 'plugin'
			? array_merge(['id' => $key, 'slug' => '', 'new_version' => '', 'url' => '', 'package' => ''], $known, ['plugin' => $key])
			: array_merge(['new_version' => '', 'url' => '', 'package' => '', 'requires' => '', 'requires_php' => ''], $known, ['theme' => $key]);
		
		$verdict = wp_is_auto_update_forced_for_item($type, null, (object)$payload);
		
		return $verdict === null ? null : (bool)$verdict;
	}
	
	/**
	 * Why WordPress cannot auto-update plugins here — '' when it can: the
	 * first of DISALLOW_FILE_MODS (`file_mods`), AUTOMATIC_UPDATER_DISABLED or
	 * its filter (`updater_disabled`), the plugins_auto_update_enabled filter
	 * (`filter`), a version-controlled plugins directory (`vcs`)
	 */
	protected function blockedBy(): string
	{
		if($this->loadUpdateApi() === false)
		{
			return '';
		}
		
		if(function_exists('wp_is_file_mod_allowed') && wp_is_file_mod_allowed('automatic_updater') === false)
		{
			return 'file_mods';
		}
		
		$updater = new WP_Automatic_Updater();
		
		return match(true)
		{
			$updater->is_disabled() => 'updater_disabled',
			wp_is_auto_update_enabled_for_type('plugin') === false => 'filter',
			(bool)$updater->is_vcs_checkout(defined('WP_PLUGIN_DIR') ? (string)WP_PLUGIN_DIR : '') => 'vcs',
			default => '',
		};
	}
	
	/**
	 * WordPress's update API lives in wp-admin, which a front-end request has
	 * not loaded: whether it is there now
	 */
	public static function loadUpdateApi(): bool
	{
		if(function_exists('wp_is_auto_update_enabled_for_type') === false && defined('ABSPATH'))
		{
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		
		if(class_exists('WP_Automatic_Updater') === false && defined('ABSPATH'))
		{
			require_once ABSPATH . 'wp-admin/includes/class-wp-automatic-updater.php';
		}
		
		return function_exists('wp_is_auto_update_enabled_for_type') && class_exists('WP_Automatic_Updater');
	}
	
	/**
	 * What WordPress's last update check stored for plugins or themes
	 * ({last_checked, checked, response, no_update}), null before the first
	 */
	protected function updateData(
		string $type,
	): ?object
	{
		$data = get_site_transient('update_' . $type . 's');
		
		return is_object($data) ? $data : null;
	}
	
	/**
	 * What WordPress's last core update check stored ({updates: list of
	 * offers, each with `response` and `current`, version_checked,
	 * last_checked}), null before the first
	 */
	protected function coreUpdateData(): ?object
	{
		$data = get_site_transient('update_core');
		
		return is_object($data) ? $data : null;
	}
	
	/**
	 * The installed plugins, file => headers
	 *
	 * @return array<string, array<string, string>>
	 */
	protected function plugins(): array
	{
		if(function_exists('get_plugins') === false)
		{
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		
		return (array)get_plugins();
	}
	
	/**
	 * The must-use plugins, file => headers
	 *
	 * @return array<string, array<string, string>>
	 */
	protected function muPlugins(): array
	{
		if(function_exists('get_mu_plugins') === false)
		{
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		
		return (array)get_mu_plugins();
	}
	
	/**
	 * The installed themes, stylesheet => {Name, Version}
	 *
	 * @return array<string, array{Name: string, Version: string, UpdateURI: string}>
	 */
	protected function themes(): array
	{
		$themes = [];
		foreach(wp_get_themes() as $stylesheet => $theme)
		{
			$themes[(string)$stylesheet] = [
				'Name' => (string)$theme->get('Name'),
				'Version' => (string)$theme->get('Version'),
				// the header since WordPress 6.1, false before
				'UpdateURI' => (string)$theme->get('UpdateURI'),
			];
		}
		
		return $themes;
	}
	
	/** the active theme's stylesheet */
	protected function currentTheme(): string
	{
		return function_exists('get_stylesheet') ? (string)get_stylesheet() : '';
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
	 * What codesafe's answer asks to auto-update, type|slug => why: the typed
	 * list (`auto_update_items`, plugins, themes and core — `core|wordpress` —
	 * each `probed`, `requested` or `both`) when the answer has one, else the
	 * older list of plugin slugs, all of them probed. Anything else in an
	 * entry drops it
	 *
	 * @return array<string, string>
	 */
	public static function wanted(
		mixed $answer,
	): array
	{
		$wanted = [];
		
		if(is_array($answer) && is_array($answer['auto_update_items'] ?? null))
		{
			foreach($answer['auto_update_items'] as $entry)
			{
				$type = is_array($entry) ? ($entry['type'] ?? null) : null;
				$slug = is_array($entry) ? ($entry['slug'] ?? null) : null;
				$reason = is_array($entry) ? ($entry['reason'] ?? null) : null;
				
				$item = (in_array($type, ['plugin', 'theme'], true) && is_string($slug) && self::slugOf($slug) === $slug)
					|| ($type === 'core' && $slug === 'wordpress');
				if($item && is_string($reason) && isset(self::REASONS[$reason]))
				{
					$wanted[$type . '|' . $slug] = $reason;
				}
			}
			
			return $wanted;
		}
		
		foreach(is_array($answer) && is_array($answer['auto_update'] ?? null) ? $answer['auto_update'] : [] as $slug)
		{
			if(is_string($slug) && self::slugOf($slug) === $slug)
			{
				$wanted['plugin|' . $slug] = 'probed';
			}
		}
		
		return $wanted;
	}
	
	/**
	 * What codesafe's answer asks to stop auto-updating (`auto_update_off`,
	 * an operator's TURN OFF): type|slug => true for plugins, themes and
	 * core — `core|wordpress` — under the same rules as wanted(). A list of
	 * its own, so a plugin that predates it never reads an off as an on
	 *
	 * @return array<string, true>
	 */
	public static function unwanted(
		mixed $answer,
	): array
	{
		$unwanted = [];
		
		foreach(is_array($answer) && is_array($answer['auto_update_off'] ?? null) ? $answer['auto_update_off'] : [] as $entry)
		{
			$type = is_array($entry) ? ($entry['type'] ?? null) : null;
			$slug = is_array($entry) ? ($entry['slug'] ?? null) : null;
			
			if((in_array($type, ['plugin', 'theme'], true) && is_string($slug) && self::slugOf($slug) === $slug)
				|| ($type === 'core' && $slug === 'wordpress'))
			{
				$unwanted[$type . '|' . $slug] = true;
			}
		}
		
		return $unwanted;
	}
	
	/** a key of an update entry — an object for plugins, an array for themes */
	public static function field(
		mixed $entry,
		string $key,
	): string
	{
		$value = is_object($entry) ? ($entry->$key ?? '') : (is_array($entry) ? ($entry[$key] ?? '') : '');
		
		return is_string($value) ? $value : '';
	}
	
	/**
	 * TLS peer verification, same filter as the Sender's ingest call
	 */
	protected function verifyTls(): bool
	{
		return (bool)Legacy::filter('ovos_codesafe_sslverify', true);
	}
	
	/** the response out to the visitor before anything slow happens */
	protected function release(): void
	{
		if(function_exists('fastcgi_finish_request'))
		{
			@fastcgi_finish_request();
		}
	}
	
	/**
	 * Fire-and-forget POST, the Sender's transport contract (the Rollup's
	 * copy): NOSIGNAL for poll-based sub-second timeouts, hard bounds; the
	 * answer's status and body are returned for settle(), apply() and the
	 * software version — an unchanged report is a 202 duplicate anyway. curl
	 * only: without the extension the report is dropped rather than riding a
	 * blocking wp_remote_post at shutdown. Status 0 and '' when nothing came
	 * back
	 *
	 * @return array{status: int, body: string}
	 */
	protected function send(
		array $payload,
	): array
	{
		if(function_exists('curl_init') === false)
		{
			return ['status' => 0, 'body' => ''];
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
			// codesafe is http(s): a gopher:// or dict:// URL would send raw bytes to any host and port it names
			CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
			CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
		]);
		
		$body = curl_exec($handle);
		
		return [
			'status' => is_string($body) ? (int)curl_getinfo($handle, CURLINFO_RESPONSE_CODE) : 0,
			'body' => is_string($body) ? $body : '',
		];
	}
	
	/**
	 * The console's answer may name plugins, themes and core to auto-update
	 * (wanted()): what is VULNERABLE AND BEING PROBED, while the project's
	 * own Auto-update switch is on, and whatever an operator picked on the
	 * project's SOFTWARE list. With the auto_update_vulnerable setting on,
	 * WordPress's own automatic update is switched on for exactly those — the
	 * one virtual patch WordPress supports natively — in the SITE option
	 * WordPress's updater reads (the network's on a multisite network), for
	 * core its minor releases only (CoreUpdate::switchOn()), and each
	 * switch-on is reported as a privileged_action naming why. An operator's
	 * TURN OFF (unwanted()) takes the item out of the same option again —
	 * that entry alone — and for core withdraws codesafe's override only
	 * (CoreUpdate::switchOff()), never WordPress's own minor switch; each
	 * switch-off is a privileged_action too. Nothing is downgraded,
	 * deactivated or deleted here; WordPress updates on its own clock.
	 */
	protected function apply(
		string $body,
	): void
	{
		if($this->config->autoUpdateVulnerable() === false || $body === '')
		{
			return;
		}
		
		$answer = json_decode($body, true, 8);
		$unwanted = self::unwanted($answer);
		// an item named both ways ends off: nothing is switched on only to be switched off
		$wanted = array_diff_key(self::wanted($answer), $unwanted);
		if($wanted === [] && $unwanted === [])
		{
			return;
		}
		
		$added = [];
		$removed = [];
		$withdrawn = isset($unwanted['core|wordpress']) && $this->core()->switchOff();
		
		// core first: the site decides here and now whether it may, and writes nothing when not
		$coreReason = $wanted['core|wordpress'] ?? null;
		$override = $coreReason === null
			? null
			: $this->core()->switchOn($this->coreUpdateData(), self::version((string)get_bloginfo('version')), $coreReason);
		if($override !== null)
		{
			$added[] = ['core', 'wordpress', $coreReason, $override];
		}
		
		$ours = (array)get_site_option(self::OURS, []);
		$oursBefore = $ours;
		foreach(['plugin' => $this->plugins(), 'theme' => $this->themes()] as $type => $installed)
		{
			$option = 'auto_update_' . $type . 's';
			$enabled = (array)get_site_option($option, []);
			$before = count($enabled);
			$mine = array_values(array_filter((array)($ours[$type] ?? []), 'is_string'));
			
			foreach($installed as $key => $headers)
			{
				$slug = self::slugOf((string)$key);
				$reason = $wanted[$type . '|' . $slug] ?? null;
				
				if($reason !== null && in_array((string)$key, $enabled, true) === false)
				{
					$enabled[] = (string)$key;
					$added[] = [$type, $slug, $reason];
					$mine[] = (string)$key;
				}
				
				// that entry alone leaves the list, and only when codesafe put it there: the site's own choices are the site's
				if(isset($unwanted[$type . '|' . $slug]) && in_array((string)$key, $enabled, true) && in_array((string)$key, $mine, true))
				{
					$enabled = array_values(array_filter($enabled, static fn(mixed $file): bool => $file !== (string)$key));
					$mine = array_values(array_filter($mine, static fn(string $file): bool => $file !== (string)$key));
					$removed[] = [$type, $slug];
				}
			}
			if($mine !== [] || isset($ours[$type]))
			{
				$ours[$type] = array_values(array_unique($mine));
			}
			
			if(count($enabled) !== $before || $removed !== [])
			{
				update_site_option($option, array_values(array_unique($enabled)));
			}
		}
		
		if($ours !== $oursBefore)
		{
			update_site_option(self::OURS, $ours);
		}
		
		if($added === [] && $removed === [] && $withdrawn === false)
		{
			return;
		}
		
		// the next request's inventory says it took
		$this->markDirty();
		
		// codesafe's word, not the visitor's: the request this runs on caused none of it
		if($this->sender !== null)
		{
			foreach($added as [$type, $slug, $reason])
			{
				if($type === 'core')
				{
					continue;
				}
				
				$this->sender->reportRefusal('privileged_action',
					'auto-update enabled for ' . ($type === 'theme' ? 'theme ' : '') . $slug . ' (' . self::REASONS[$reason] . ')',
					['action' => 'auto_update_enabled', 'type' => $type, 'reason' => $reason],
					Sender::withoutRequest());
			}
			
			if($override !== null)
			{
				$this->sender->reportRefusal('privileged_action',
					'auto-update enabled for WordPress core, minor releases (' . self::REASONS[$coreReason] . ')'
						. ($override ? ' — WP_AUTO_UPDATE_CORE is false on this site, overridden for minor releases only' : ''),
					['action' => 'auto_update_enabled', 'type' => 'core', 'reason' => $coreReason, 'override' => $override],
					Sender::withoutRequest());
			}
			
			foreach($removed as [$type, $slug])
			{
				$this->sender->reportRefusal('privileged_action',
					'auto-update disabled for ' . ($type === 'theme' ? 'theme ' : '') . $slug . ' (switched off by an operator in codesafe)',
					['action' => 'auto_update_disabled', 'type' => $type],
					Sender::withoutRequest());
			}
			
			if($withdrawn)
			{
				$this->sender->reportRefusal('privileged_action',
					'auto-update disabled for WordPress core, minor releases — codesafe\'s override withdrawn',
					['action' => 'auto_update_disabled', 'type' => 'core'],
					Sender::withoutRequest());
			}
			
			// the Sender's own shutdown flush already ran — this handler
			// registered after it — so the audit line ships from here
			$this->sender->flush();
		}
	}
}
