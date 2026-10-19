<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use WP_Automatic_Updater;

use function add_filter;
use function apply_filters;
use function array_slice;
use function constant;
use function defined;
use function delete_site_option;
use function function_exists;
use function get_site_option;
use function implode;
use function in_array;
use function is_admin;
use function is_array;
use function is_bool;
use function is_object;
use function max;
use function preg_replace;
use function preg_split;
use function sprintf;
use function strtolower;
use function substr;
use function time;
use function update_site_option;
use function version_compare;
use function wp_doing_cron;
use function wp_is_file_mod_allowed;

use const ABSPATH;
use const PHP_INT_MAX;

/**
 * WordPress core's own automatic updates, minor releases only: what the
 * site's policy is and why (report() — the inventory's `updates.core`), and
 * codesafe's switch-on (switchOn()), which writes WordPress's own minor
 * option where that decides, and where `WP_AUTO_UPDATE_CORE` is false keeps
 * a flag the `allow_minor_auto_core_updates` filter answers true for — only
 * while the "Auto-update on codesafe's word" box is on — and an operator's
 * TURN OFF, which withdraws that flag alone (switchOff()). Never a major
 * release, never past DISALLOW_FILE_MODS, AUTOMATIC_UPDATER_DISABLED, a
 * version-controlled site, a parked failed update or another plugin's filter
 */
class CoreUpdate
{
	/**
	 * The switch-on kept where WP_AUTO_UPDATE_CORE is false: {at, reason} —
	 * a site option, read where WordPress's updater runs on a network
	 */
	public const OPTION = 'ovos_codesafe_core_auto_update';
	
	/** WordPress's own minor-release switch, 'enabled' unless set otherwise */
	protected const MINOR = 'auto_update_core_minor';
	
	/** WordPress's own major-release switch — read, never written */
	protected const MAJOR = 'auto_update_core_major';
	
	/** the failed automatic update WordPress parks until an update succeeds */
	protected const FAILED = 'auto_core_update_failed';
	
	/** the WP_AUTO_UPDATE_CORE values core reads that switch every kind of update on */
	protected const ALL_ON = ['beta', 'rc', 'development', 'branch-development'];
	
	/**
	 * While a report asks the filter for the site's own answer, every
	 * instance's override answers its input unchanged
	 */
	protected static bool $asking = false;
	
	/** the kept switch-on, read on the first call: {at, reason}, or null */
	protected ?array $flag = null;
	
	protected bool $read = false;
	
	/** whether this instance's override answers WordPress in this request (register()) */
	protected bool $hooked = false;
	
	public function __construct(
		protected Config $config,
	)
	{
	}
	
	/**
	 * The override hooked last, where WordPress asks: its cron run and
	 * wp-admin (the Updates screen's words, Site Health); a front-end request
	 * pays nothing
	 */
	public function register(): void
	{
		if($this->askedHere())
		{
			add_filter('allow_minor_auto_core_updates', [$this, 'allowMinor'], PHP_INT_MAX);
			$this->hooked = true;
		}
	}
	
	/**
	 * allow_minor_auto_core_updates: true while a switch-on is kept and the
	 * box is on; the input unchanged otherwise — untick the box and the
	 * override stops at the next run
	 */
	public function allowMinor(
		mixed $allow,
	): mixed
	{
		if(self::$asking || $this->config->autoUpdateVulnerable() === false || $this->armed() === false)
		{
			return $allow;
		}
		
		return true;
	}
	
	/** whether a switch-on is kept on this site */
	public function armed(): bool
	{
		return $this->flag() !== null;
	}
	
	/** the kept switch-on {at, reason}, or null */
	public function flag(): ?array
	{
		if($this->read === false)
		{
			$stored = get_site_option(self::OPTION, false);
			$this->flag = is_array($stored) ? $stored : null;
			$this->read = true;
		}
		
		return $this->flag;
	}
	
	/**
	 * The inventory's `updates.core`: WordPress's effective verdict for the
	 * next minor and major release and what decided the minor one, the
	 * constant as defined, whether codesafe's override answers (`override`:
	 * kept and the box on) and whether its switch-on is kept at all (`kept`,
	 * whatever the box), the auto_update_core filter's verdict, the first
	 * reason WordPress cannot update itself, the failed update it parked, the
	 * minor release it would install, and when it last checked
	 *
	 * @param ?object $data the update_core site transient
	 * @return array{minor: bool, major: bool, policy: string, constant?: string, override: bool, kept: bool,
	 *     forced?: bool, blocked_by: string, failed?: array, offer?: string, checked_at: int}
	 */
	public function report(
		?object $data,
		string $installed,
	): array
	{
		$constant = $this->constant();
		$option = get_site_option(self::MINOR, 'enabled') === 'enabled';
		$base = self::byConstant($constant, $option, 'minor');
		
		// the site's own answer, every other callback included, this plugin's left out
		self::$asking = true;
		try
		{
			$without = (bool)apply_filters('allow_minor_auto_core_updates', $base);
		}
		finally
		{
			self::$asking = false;
		}
		// what the override makes of it — and, where it is hooked, what WordPress
		// itself will hear, a callback after it having the last word
		$ours = (bool)$this->allowMinor($without);
		$minor = $this->hooked ? (bool)apply_filters('allow_minor_auto_core_updates', $base) : $ours;
		
		$policy = match(true)
		{
			$minor !== $ours => 'filter',
			$minor !== $without => 'codesafe',
			$without !== $base => 'filter',
			self::knownConstant($constant) => 'constant',
			$option === false => 'option',
			default => 'default',
		};
		
		$offer = self::offer($data, $installed);
		$failed = $this->failed();
		$report = [
			'minor' => $minor,
			'major' => (bool)apply_filters('allow_major_auto_core_updates',
				self::byConstant($constant, get_site_option(self::MAJOR, 'unset') === 'enabled', 'major')),
			'policy' => $policy,
		];
		
		if(self::knownConstant($constant))
		{
			$report['constant'] = $constant === true ? 'true' : ($constant === false ? 'false' : (string)$constant);
		}
		
		$report['override'] = $this->armed() && $this->config->autoUpdateVulnerable();
		// the switch-on itself, ticked box or not: an operator's TURN OFF is done when this is false
		$report['kept'] = $this->armed();
		
		$forced = apply_filters('auto_update_core', null, $offer['entry'] ?? self::stubOffer($installed));
		if(is_bool($forced))
		{
			$report['forced'] = $forced;
		}
		
		$report['blocked_by'] = $this->blockedBy($failed, $installed, $offer['version'] ?? '');
		
		if($failed !== null)
		{
			$report['failed'] = $failed;
		}
		
		if($offer !== null)
		{
			$report['offer'] = $offer['version'];
		}
		
		$report['checked_at'] = max(0, (int)($data->last_checked ?? 0));
		
		return $report;
	}
	
	/**
	 * codesafe named core: switch WordPress's minor releases on, if the site
	 * lets it here and now. Where no WP_AUTO_UPDATE_CORE decides, WordPress's
	 * own option — the site's setting from then on, with or without this
	 * plugin; where it is false, the kept flag the override answers for, and
	 * the option too, right once the constant goes. Nothing while WordPress
	 * cannot update itself, a filter forces it off or decides it, or minor
	 * releases are on already. Null when nothing was written, else whether
	 * the constant was overridden
	 *
	 * @param ?object $data the update_core site transient
	 */
	public function switchOn(
		?object $data,
		string $installed,
		string $reason,
	): ?bool
	{
		$report = $this->report($data, $installed);
		if($report['blocked_by'] !== '' || ($report['forced'] ?? null) === false
			|| $report['policy'] === 'filter' || $report['minor'])
		{
			return null;
		}
		
		$minorOff = get_site_option(self::MINOR, 'enabled') !== 'enabled';
		
		if($this->constant() === false)
		{
			$this->flag = ['at' => time(), 'reason' => $reason];
			$this->read = true;
			update_site_option(self::OPTION, $this->flag);
			if($minorOff)
			{
				update_site_option(self::MINOR, 'enabled');
			}
			
			return true;
		}
		
		// another WP_AUTO_UPDATE_CORE value core reads decides, and minor releases are not off under it
		if(self::knownConstant($this->constant()) || $minorOff === false)
		{
			return null;
		}
		
		update_site_option(self::MINOR, 'enabled');
		
		return false;
	}
	
	/**
	 * An operator's TURN OFF for core: codesafe's kept switch-on goes, so the
	 * override stops and WordPress answers by its constant and its own option
	 * again — which this never writes. Whether there was one to withdraw
	 */
	public function switchOff(): bool
	{
		if($this->flag() === null)
		{
			return false;
		}
		
		delete_site_option(self::OPTION);
		$this->flag = null;
		
		return true;
	}
	
	/**
	 * Pure: the settings page's line while a switch-on is kept — what codesafe
	 * did, when and why, and the two ways to end it
	 *
	 * @param array{at?: int, reason?: string} $flag
	 */
	public static function statusLine(
		array $flag,
		string $date,
		bool $boxOn,
	): string
	{
		$why = Inventory::REASONS[(string)($flag['reason'] ?? '')] ?? 'per codesafe';
		
		return sprintf('codesafe switched on WordPress\' automatic minor releases on %s (%s) although WP_AUTO_UPDATE_CORE is false in wp-config.php. ', $date, $why)
			. ($boxOn
				? 'Untick this box to stop it; '
				: 'This box is off, so it is stopped; ')
			. 'wp option delete ' . self::OPTION . ' (wp site option delete on a network) forgets it.';
	}
	
	/**
	 * WP_AUTO_UPDATE_CORE as defined, null when it is not — the one place the
	 * constant is read
	 */
	protected function constant(): mixed
	{
		return defined('WP_AUTO_UPDATE_CORE') ? constant('WP_AUTO_UPDATE_CORE') : null;
	}
	
	/** whether WordPress is asking about its automatic updates in this request */
	protected function askedHere(): bool
	{
		return (function_exists('wp_doing_cron') && wp_doing_cron())
			|| (function_exists('is_admin') && is_admin());
	}
	
	/**
	 * Pure: Core_Upgrader's reading of the constant over the option — false
	 * stops every kind, true and the pre-release words start every kind,
	 * `minor` starts minor releases alone; any other value leaves the option
	 */
	public static function byConstant(
		mixed $constant,
		bool $option,
		string $kind,
	): bool
	{
		return match(true)
		{
			$constant === false => false,
			$constant === true || in_array($constant, self::ALL_ON, true) => true,
			$constant === 'minor' => $kind === 'minor',
			default => $option,
		};
	}
	
	/** whether core reads this WP_AUTO_UPDATE_CORE value — anything else is as good as undefined */
	public static function knownConstant(
		mixed $constant,
	): bool
	{
		return is_bool($constant) || $constant === 'minor' || in_array($constant, self::ALL_ON, true);
	}
	
	/**
	 * Pure: the minor release WordPress would install by itself — the highest
	 * `autoupdate` offer of the installed x.y branch newer than the installed
	 * version: its version and its entry; null when there is none
	 *
	 * @return ?array{version: string, entry: object}
	 */
	public static function offer(
		?object $data,
		string $installed,
	): ?array
	{
		$best = null;
		foreach(is_array($data?->updates ?? null) ? $data->updates : [] as $entry)
		{
			$version = Inventory::coreVersion(Inventory::field($entry, 'current'));
			if(is_object($entry) === false || Inventory::field($entry, 'response') !== 'autoupdate' || $version === ''
				|| self::branch($version) !== self::branch($installed) || version_compare($version, $installed, '<='))
			{
				continue;
			}
			
			if($best === null || version_compare($version, $best['version'], '>'))
			{
				$best = ['version' => $version, 'entry' => $entry];
			}
		}
		
		return $best;
	}
	
	/** a version's x.y, the way Core_Upgrader cuts it */
	protected static function branch(
		string $version,
	): string
	{
		$parts = preg_split('~[.-]~', $version);
		
		return implode('.', array_slice($parts === false ? [] : $parts, 0, 2));
	}
	
	/**
	 * The parked failed update, scrubbed: {attempted, current, code, critical,
	 * retry, at} — never its error data, which carries paths; null without one
	 */
	protected function failed(): ?array
	{
		$stored = get_site_option(self::FAILED, false);
		if(is_array($stored) === false)
		{
			return null;
		}
		
		$code = substr((string)preg_replace('~[^a-z0-9_]+~', '', strtolower((string)($stored['error_code'] ?? ''))), 0, 64);
		
		return [
			'attempted' => Inventory::version((string)($stored['attempted'] ?? '')),
			'current' => Inventory::version((string)($stored['current'] ?? '')),
			'code' => $code === '' ? 'unknown' : $code,
			'critical' => (bool)($stored['critical'] ?? false),
			'retry' => (bool)($stored['retry'] ?? false),
			'at' => max(0, (int)($stored['timestamp'] ?? 0)),
		];
	}
	
	/**
	 * Why WordPress cannot update core by itself — '' when it can: the first
	 * of DISALLOW_FILE_MODS (`file_mods`), AUTOMATIC_UPDATER_DISABLED or its
	 * filter (`updater_disabled`), a version-controlled site (`vcs`), a parked
	 * failure it will not retry (`failed`) — a critical one, or one without
	 * retry of the very update on offer now from the version installed now
	 * (Core_Upgrader::should_update_to_version); a newer offer than the one
	 * that failed is tried, and without an offer nothing waits
	 */
	protected function blockedBy(
		?array $failed,
		string $installed,
		string $offer,
	): string
	{
		if(Inventory::loadUpdateApi() === false)
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
			(bool)$updater->is_vcs_checkout(defined('ABSPATH') ? (string)ABSPATH : '') => 'vcs',
			$failed !== null && ($failed['critical'] || ($failed['retry'] === false && $failed['current'] === $installed
				&& $offer !== '' && $failed['attempted'] === $offer)) => 'failed',
			default => '',
		};
	}
	
	/** an offer as wp_version_check() stores one, for the auto_update_core filter when the check holds none */
	protected static function stubOffer(
		string $installed,
	): object
	{
		return (object)[
			'response' => 'autoupdate',
			'download' => '',
			'locale' => 'en_US',
			'packages' => (object)['full' => '', 'no_content' => '', 'new_bundled' => '', 'partial' => '', 'rollback' => ''],
			'current' => $installed,
			'version' => $installed,
			'php_version' => '',
			'mysql_version' => '',
			'new_bundled' => '',
			'partial_version' => '',
			'notify_email' => '',
			'support_email' => '',
			'new_files' => '',
		];
	}
}
