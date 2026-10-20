<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Closure;

use function preg_match;
use function strtok;

/**
 * Plugin wiring — registers the error handlers at plugin load, before
 * the theme and most other plugins run, so their errors are captured.
 */
final class Plugin
{
	public const VERSION = '1.0.1';
	
	/**
	 * Fixed 60-second cap on 404 access-event reports, so a hard scan cannot
	 * turn this reporter into the flood it is meant to surface
	 */
	protected const MAX_404_PER_MINUTE = 30;
	
	protected static ?self $instance = null;
	
	public readonly Config $config;
	
	public readonly Sender $sender;
	
	protected function __construct(
		public readonly string $file,
	)
	{
		$this->config = new Config();
		$this->sender = new Sender($this->config);
	}
	
	public static function boot(
		string $file,
	): void
	{
		if(self::$instance !== null)
		{
			return;
		}
		
		// a site that ran ovos-console gets its settings copied before anything reads them
		Legacy::migrate();
		
		self::$instance = new self($file);
		self::$instance->register();
	}
	
	/**
	 * The release label announced to the console last (SENDER.md §7) — a
	 * deploy that changes the configured label is told once, on the next
	 * admin request; removed on uninstall
	 */
	public const OPTION_ANNOUNCED = 'ovos_codesafe_announced_release';
	
	public static function instance(): ?self
	{
		return self::$instance;
	}
	
	/**
	 * What hears codesafe's answers — the Sender's batches and the Rollup's
	 * fragments: the ruleset version for the Shield (a changed one is pulled
	 * on the next tick), the software version for the inventory (a changed
	 * one, an operator's auto-update pick, sends it again); null when
	 * neither listens
	 */
	public static function answerHook(
		?Shield\Adapter $shield,
		?Inventory $inventory,
	): ?Closure
	{
		if($shield === null && $inventory === null)
		{
			return null;
		}
		
		return static function(string $answer) use ($shield, $inventory): void
		{
			$shield?->nudge(Sender::shieldVersion($answer));
			$inventory?->nudge(Sender::softwareVersion($answer));
		};
	}
	
	protected function register(): void
	{
		$this->sender->register();
		
		// the Shield (docs: ovos/console wave8-shield-build.md): this site's
		// exploit rules pulled from the console and matched at plugins_loaded,
		// observe or block by the owner's two checkboxes; the kill constant
		// keeps it from registering at all. Built before the rollups: its
		// per-rule hits ride their fragment
		$shield = $this->config->shieldDetect() && $this->config->shieldKill() === false
			? new Shield\Adapter($this->config, $this->sender)
			: null;
		$shield?->register();
		// core's automatic minor releases: the override codesafe's switch-on
		// keeps where WP_AUTO_UPDATE_CORE is false, hooked where WordPress asks
		$core = new CoreUpdate($this->config);
		$core->register();
		// software inventory for the console's CVE matching (here AND
		// cve_enabled on the console project) — built here so codesafe's
		// answers can nudge it, registered below in the shutdown order
		$inventory = $this->config->inventory() ? new Inventory($this->config, $this->sender, $core) : null;
		// codesafe's answers carry the ruleset and the software versions
		$nudge = self::answerHook($shield, $inventory);
		if($nudge !== null)
		{
			$this->sender->onAnswer($nudge);
		}
		// the Shield's own pull carries the software version too, as a header
		if($shield !== null && $inventory !== null)
		{
			$shield->onSoftware([$inventory, 'nudge']);
		}
		// the optional prepend layer (ovos/console docs/plans/shield-prepend.md) reads
		// the consent the plugin last wrote — kept current here, whether or not the
		// adapter runs, so an unticked box or the kill constant reaches it too
		Shield\Adapter::syncPrepend($this->config);
		
		// per-minute traffic rollups (APCu-gated) — registered after the
		// Sender so its shutdown handler runs once error flushing is done
		if($this->config->rollups())
		{
			(new Rollup($this->config, $shield === null ? null : [$shield, 'hits'], $nudge))->register();
		}
		
		// the inventory's shutdown handler registers after the Sender's, the
		// Shield's and the Rollup's, so a nudge any of them heard is sent in
		// the same shutdown — inventory being the least urgent send
		$inventory?->register();
		
		// which of this plugin's switches are on, told to codesafe once a day
		// and whenever one changes (codesafe docs/plans/project-features-live.md)
		(new Hello($this->config, $this->sender))->register();
		
		// the integrity scan: a Scan now button on the settings page always,
		// a shutdown-time background pass while its own switch is on — read-
		// only and chunked; its shutdown handler registers after the others
		$scan = new ScanRunner($this->config, new Scan($this->config));
		$scan->register();
		
		// the executed-file watch (docs: ovos/codesafe prepend-entry-watch.md):
		// what the prepend layer recorded, judged and reported after the
		// response — the last shutdown handler, it posts by itself
		$entries = new Entries($this->config, $this->sender);
		$entries->register();
		
		(new JsClient($this->config, $this->file))->register();
		
		// self-update from the plugin's GitHub releases, through core's
		// own Update URI flow — no update server, no updater plugin
		(new Updater($this->file))->register();
		
		// report front-end 404s as access events so scanner and broken-link
		// traffic reaches the console apart from real errors
		if($this->config->report404())
		{
			add_action('template_redirect', [$this, 'reportNotFound']);
		}
		
		// report refused actions (failed logins, rejected nonces, forbidden
		// REST calls, sensitive admin changes) as security events
		if($this->config->securityEvents())
		{
			(new Security($this->sender))->register();
		}
		
		if(is_admin())
		{
			Legacy::register();
			
			(new Settings($this->config, $this->sender, $this->file, $scan, $entries))->register();
			
			// the deploy step a WordPress site rarely has: a changed release
			// label is announced to the console once, on the next admin request
			add_action('admin_init', [$this, 'announceRelease']);
		}
	}
	
	/**
	 * admin_init: the configured release label, announced to the console the
	 * first time it is seen (SENDER.md §7) — the option remembers what was
	 * announced, so every later admin request costs one option read and no
	 * HTTP call; a refused or unreachable console is retried on the next one
	 */
	public function announceRelease(): void
	{
		$release = $this->config->release();
		if($release === '' || (string)get_option(self::OPTION_ANNOUNCED, '') === $release)
		{
			return;
		}
		if($this->sender->announceRelease($release) === 202)
		{
			update_option(self::OPTION_ANNOUNCED, $release, false);
		}
	}
	
	/**
	 * template_redirect: a resolved front-end 404 is an access event. Skips
	 * static-asset paths (broken images and the like are noise) and rate-limits
	 * so a scan cannot flood; the queued report ships from the shutdown handler.
	 */
	public function reportNotFound(): void
	{
		if(is_404() === false || $this->isStaticAsset() || $this->throttled())
		{
			return;
		}
		
		$this->sender->capture404();
	}
	
	/**
	 * Whether the current request targets a static asset (a broken image,
	 * stylesheet or script) rather than a page — those 404s are noise, not
	 * scanner signal
	 */
	protected function isStaticAsset(): bool
	{
		$uri = isset($_SERVER['REQUEST_URI'])
			? (string)wp_unslash($_SERVER['REQUEST_URI'])
			: '';
		$path = (string)strtok($uri, '?');
		
		return preg_match(
			'~\.(?:jpe?g|png|gif|webp|svg|ico|css|js|map|woff2?|ttf|eot)$~i',
			$path) === 1;
	}
	
	/**
	 * Fixed 60-second window cap on 404 reports (a transient counter), so a
	 * hard scan cannot turn this reporter into the flood it surfaces
	 */
	protected function throttled(): bool
	{
		$key = 'ovos_codesafe_404_rate';
		$count = (int)get_transient($key);
		
		if($count >= self::MAX_404_PER_MINUTE)
		{
			return true;
		}
		
		set_transient($key, $count + 1, 60);
		
		return false;
	}
}
