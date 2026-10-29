<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Closure;

use function add_action;
use function get_option;
use function is_admin;
use function update_option;

/**
 * Plugin wiring — registers the error handlers at plugin load, before
 * the theme and most other plugins run, so their errors are captured.
 */
final class Plugin
{
	public const VERSION = '1.0.1';
	
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
		// wp-content/upgrade/ and upgrade-temp-backup/ closed to the web while an
		// update runs (not on nginx, IIS, Caddy); hooked on every site, connected or not
		(new UpgradeDir())->register();
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
		
		// report pages, REST routes and admin-ajax actions this site does not
		// have as access events, so scanner and broken-link traffic reaches
		// codesafe apart from real errors (nothing is hooked with the switch off)
		(new NotFound($this->config, $this->sender))->register();
		
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
}
