<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\CoreUpdate as PluginCoreUpdate;
use Ovos\Test;
use Ovos\Test\Internal;
use Tests\Files\TestCoreUpdate;

use function array_diff_key;
use function array_key_exists;
use function str_contains;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;
use const PHP_INT_MAX;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'TestCoreUpdate.file.php';

/**
 * WordPress core's automatic updates: what the site reports — the minor
 * and major verdicts and what decided the minor one, what blocks it, the
 * failed update WordPress parked, the minor release it would install — and
 * codesafe's switch-on, minor releases only: WordPress's own option where it
 * decides, a kept flag the filter answers for where WP_AUTO_UPDATE_CORE is
 * false, nothing where the site cannot or another plugin decides. The
 * installed core is the shim's 6.8.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class CoreUpdate extends Test
{
	protected const string FLAG = 'ovos_codesafe_core_auto_update';
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: `policy` names what decided the minor verdict — WordPress's
	 * default, the minor option, the constant (false, minor, true; another
	 * value is as good as undefined), another plugin's filter, or codesafe's
	 * override, which reads as such even while its own callback is hooked —
	 * and the override only counts with the box on. Falsify: ask the filter
	 * without the guard — the hooked override answers for the site, and a
	 * switch-on reads as another plugin's filter.
	 */
	public function thePolicySaysWhatDecidedMinor(): bool
	{
		$default = $this->report();
		$GLOBALS['wp']['options']['auto_update_core_minor'] = 'disabled';
		$option = $this->report();
		$minorConstant = $this->report(constant: 'minor');
		$unknown = $this->report(constant: 'false');
		unset($GLOBALS['wp']['options']['auto_update_core_minor']);
		$false = $this->report(constant: false);
		$true = $this->report(constant: true);
		$GLOBALS['wp']['filters']['allow_minor_auto_core_updates'] = [static fn(bool $allow): bool => false];
		$filter = $this->report();
		
		$GLOBALS['wp']['options'][self::FLAG] = ['at' => 1_790_000_000, 'reason' => 'requested'];
		$core = $this->core(constant: false);
		// hooked as WordPress would have it on a cron run
		$GLOBALS['wp']['filters']['allow_minor_auto_core_updates'] = [[$core, 'allowMinor']];
		$override = $core->report(null, '6.8');
		$off = $this->core(['auto_update_vulnerable' => false], constant: false)->report(null, '6.8');
		
		return $default['minor'] && $default['policy'] === 'default' && array_key_exists('constant', $default) === false
			&& $default['override'] === false && $default['major'] === false
			&& $option['minor'] === false && $option['policy'] === 'option'
			&& $minorConstant['minor'] && $minorConstant['policy'] === 'constant' && $minorConstant['constant'] === 'minor'
			&& $unknown['minor'] === false && $unknown['policy'] === 'option' && array_key_exists('constant', $unknown) === false
			&& $false['minor'] === false && $false['policy'] === 'constant' && $false['constant'] === 'false'
			&& $true['minor'] && $true['major'] && $true['constant'] === 'true'
			&& $filter['minor'] === false && $filter['policy'] === 'filter'
			&& $override['minor'] && $override['policy'] === 'codesafe' && $override['override']
			&& $off['minor'] === false && $off['policy'] === 'constant' && $off['override'] === false;
	}
	
	/**
	 * RULE: `blocked_by` names the FIRST reason WordPress cannot update core by
	 * itself — DISALLOW_FILE_MODS, the updater switched off, a version-
	 * controlled site, then a parked failure it will not retry: a critical
	 * one, or one without retry of the very update on offer now from the
	 * version installed now (Core_Upgrader's own rule); a failure it retries,
	 * one of an older offer than today's, or one with nothing on offer blocks
	 * nothing but is reported, scrubbed of its error data. Falsify: count every
	 * parked failure as a block — a download that failed once stops core's
	 * updates for good; or drop the offer from the rule — a no-retry failure
	 * of 6.8.1 reads as stuck while WordPress installs 6.8.2 at its next run.
	 */
	public function blockedByNamesTheFirstReasonAndTheFailureIsScrubbed(): bool
	{
		$open = $this->report();
		$retry = ['attempted' => '6.8.3', 'current' => '6.8', 'error_code' => 'download_failed', 'error_data' => '/var/www/x',
			'timestamp' => 1_790_000_000, 'retry' => true];
		$offers = static fn(string $version): object => (object)['updates' => [(object)['response' => 'autoupdate', 'current' => $version]]];
		$GLOBALS['wp']['options']['auto_core_update_failed'] = $retry;
		$retried = $this->core()->report($offers('6.8.3'), '6.8');
		$GLOBALS['wp']['options']['auto_core_update_failed'] = ['retry' => false] + $retry;
		$stuck = $this->core()->report($offers('6.8.3'), '6.8');
		$nothingOnOffer = $this->report();
		$GLOBALS['wp']['options']['auto_core_update_failed'] = ['retry' => false, 'attempted' => '6.8.1'] + $retry;
		$newer = $this->core()->report($offers('6.8.2'), '6.8');
		$GLOBALS['wp']['options']['auto_core_update_failed'] = ['retry' => false, 'current' => '6.7.2'] + $retry;
		$older = $this->core()->report($offers('6.8.3'), '6.8');
		$GLOBALS['wp']['options']['auto_core_update_failed'] = ['critical' => true, 'error_code' => 'Disk Full!'] + $retry;
		$critical = $this->report();
		$GLOBALS['wp']['vcs'] = true;
		$vcs = $this->report()['blocked_by'];
		$GLOBALS['wp']['updater_disabled'] = true;
		$disabled = $this->report()['blocked_by'];
		$GLOBALS['wp']['file_mods'] = false;
		$mods = $this->report()['blocked_by'];
		
		return $open['blocked_by'] === '' && array_key_exists('failed', $open) === false
			&& $retried['blocked_by'] === ''
			&& $retried['failed'] === ['attempted' => '6.8.3', 'current' => '6.8', 'code' => 'download_failed', 'critical' => false,
				'retry' => true, 'at' => 1_790_000_000]
			&& $stuck['blocked_by'] === 'failed'
			&& $nothingOnOffer['blocked_by'] === '' && $nothingOnOffer['failed']['retry'] === false
			&& $newer['blocked_by'] === '' && $newer['failed']['attempted'] === '6.8.1'
			&& $older['blocked_by'] === ''
			&& $critical['blocked_by'] === 'failed' && $critical['failed']['code'] === 'diskfull' && $critical['failed']['critical']
			&& $vcs === 'vcs' && $disabled === 'updater_disabled' && $mods === 'file_mods';
	}
	
	/**
	 * RULE: where the override is hooked (cron, wp-admin), `minor` is what
	 * WordPress itself will hear — a callback answering after the override has
	 * the last word, and the report says `minor: false, policy: filter` with the
	 * override still standing; without a rival the override's yes reads as
	 * codesafe's. Falsify: compute `minor` from the override alone — the site
	 * reports ON by codesafe while WordPress installs nothing.
	 */
	public function aFilterAfterTheOverrideHasTheLastWord(): bool
	{
		$GLOBALS['wp']['options'][self::FLAG] = ['at' => 1_790_000_000, 'reason' => 'requested'];
		$core = $this->core(constant: false);
		$core->here = true;
		$core->register();
		$GLOBALS['wp']['filters']['allow_minor_auto_core_updates'] = [[$core, 'allowMinor']];
		$alone = $core->report(null, '6.8');
		// another plugin at PHP_INT_MAX, hooked after this one: WordPress runs it last
		$GLOBALS['wp']['filters']['allow_minor_auto_core_updates'][] = static fn(bool $allow): bool => false;
		$rival = $core->report(null, '6.8');
		
		return $alone['minor'] && $alone['policy'] === 'codesafe' && $alone['override']
			&& $rival['minor'] === false && $rival['policy'] === 'filter' && $rival['override'] && $rival['kept'];
	}
	
	/**
	 * RULE: `kept` says whether codesafe's switch-on is stored on the site,
	 * whatever the box — `override` says whether it answers (kept and the box
	 * on); codesafe settles an operator's core TURN OFF on `kept` alone.
	 * Falsify: report `kept` as `override` — unticking the box would settle a
	 * TURN OFF while the switch-on stays kept, and re-ticking resumes it.
	 */
	public function keptSaysTheSwitchOnIsStoredWhateverTheBox(): bool
	{
		$none = $this->report(constant: false);
		$GLOBALS['wp']['options'][self::FLAG] = ['at' => 1_790_000_000, 'reason' => 'requested'];
		$on = $this->report(constant: false);
		$boxOff = $this->core(['auto_update_vulnerable' => false], constant: false)->report(null, '6.8');
		
		return $none['kept'] === false && $none['override'] === false
			&& $on['kept'] && $on['override']
			&& $boxOff['kept'] && $boxOff['override'] === false;
	}
	
	/**
	 * RULE: `offer` is the highest `autoupdate` offer of the installed branch
	 * newer than the installed version — a major's autoupdate offer is not
	 * one — absent when there is none; `core_latest` still names the
	 * upgrade; `checked_at` is the core check's time. Falsify: take the first
	 * autoupdate offer — 6.9 goes out as the minor WordPress installs by itself.
	 */
	public function theOfferIsTheMinorWordPressWouldInstall(): bool
	{
		$check = (object)['last_checked' => 1_790_000_500, 'updates' => [
			(object)['response' => 'upgrade', 'current' => '6.9'],
			(object)['response' => 'autoupdate', 'current' => '6.9'],
			(object)['response' => 'autoupdate', 'current' => '6.8.2'],
			(object)['response' => 'autoupdate', 'current' => '6.8.3'],
			(object)['response' => 'autoupdate', 'current' => '6.8.1'],
			(object)['response' => 'latest', 'current' => '6.8'],
		]];
		$report = $this->core()->report($check, '6.8');
		$none = $this->core()->report((object)['updates' => [(object)['response' => 'latest', 'current' => '6.8']]], '6.8');
		$current = $this->core()->report($check, '6.8.3');
		
		return ($report['offer'] ?? null) === '6.8.3'
			&& $report['checked_at'] === 1_790_000_500
			&& array_key_exists('offer', $none) === false && $none['checked_at'] === 0
			&& array_key_exists('offer', $current) === false
			&& PluginCoreUpdate::offer($check, '6.8')['entry']->current === '6.8.3';
	}
	
	/**
	 * RULE: `forced` is the auto_update_core filter's verdict, asked with the
	 * minor offer (an offer as wp_version_check stores it when the check holds
	 * none), absent when no callback decides. Falsify: report false when the
	 * filter says nothing — every site reads as locked off.
	 */
	public function forcedIsTheAutoUpdateCoreFiltersVerdict(): bool
	{
		$asked = [];
		$GLOBALS['wp']['filters']['auto_update_core'] = [static function(mixed $update, object $item) use (&$asked): mixed {
			$asked[] = $item->current;
			
			return $update;
		}];
		$none = $this->report();
		$GLOBALS['wp']['filters']['auto_update_core'][] = static fn(mixed $update, object $item): bool => false;
		$forced = $this->core()->report((object)['updates' => [(object)['response' => 'autoupdate', 'current' => '6.8.3']]], '6.8');
		
		return array_key_exists('forced', $none) === false
			&& $forced['forced'] === false
			&& $asked === ['6.8', '6.8.3'];
	}
	
	/**
	 * RULE: where no WP_AUTO_UPDATE_CORE decides, a switch-on writes
	 * WordPress's own minor option — nothing else, no flag, never the major
	 * one. Falsify: keep the flag here too — the plugin's filter would answer
	 * for a site whose own setting was enough.
	 */
	public function aSwitchOnWritesWordPressesOwnOption(): bool
	{
		$GLOBALS['wp']['options']['auto_update_core_minor'] = 'disabled';
		$written = $this->core()->switchOn(null, '6.8', 'requested');
		
		return $written === false
			&& $GLOBALS['wp']['options']['auto_update_core_minor'] === 'enabled'
			&& array_key_exists(self::FLAG, $GLOBALS['wp']['options']) === false
			&& array_key_exists('auto_update_core_major', $GLOBALS['wp']['options']) === false;
	}
	
	/**
	 * RULE: under WP_AUTO_UPDATE_CORE false a switch-on keeps the flag (when
	 * and why) and the option, and the override answers true — its input
	 * unchanged once the box is off, the flag kept; never the major option.
	 * Falsify: answer true without asking the box — unticking it stops nothing.
	 */
	public function aSwitchOnUnderTheConstantKeepsTheFlag(): bool
	{
		$GLOBALS['wp']['options']['auto_update_core_minor'] = 'disabled';
		$core = $this->core(constant: false);
		$written = $core->switchOn(null, '6.8', 'probed');
		$flag = $GLOBALS['wp']['options'][self::FLAG] ?? [];
		$on = $core->allowMinor(false);
		$off = $this->core(['auto_update_vulnerable' => false], constant: false)->allowMinor(false);
		
		return $written === true
			&& ($flag['reason'] ?? null) === 'probed' && ($flag['at'] ?? 0) > 0
			&& $GLOBALS['wp']['options']['auto_update_core_minor'] === 'enabled'
			&& array_key_exists('auto_update_core_major', $GLOBALS['wp']['options']) === false
			&& $on === true && $off === false
			&& array_key_exists(self::FLAG, $GLOBALS['wp']['options']);
	}
	
	/**
	 * RULE: a switch-on writes nothing where the site says no here and now —
	 * DISALLOW_FILE_MODS, a filter forcing core's update off, another plugin's
	 * filter deciding the minor verdict — or where minor releases are on
	 * already. Falsify: drop the forced check — a site whose owner forced core
	 * off gets the flag anyway.
	 */
	public function aSwitchOnWritesNothingWhereTheSiteSaysNo(): bool
	{
		$on = $this->core(constant: false);
		$GLOBALS['wp']['options'][self::FLAG] = ['at' => 1, 'reason' => 'requested'];
		$already = $on->switchOn(null, '6.8', 'requested');
		unset($GLOBALS['wp']['options'][self::FLAG]);
		$default = $this->core()->switchOn(null, '6.8', 'requested');
		
		$GLOBALS['wp']['filters']['auto_update_core'] = [static fn(mixed $update): bool => false];
		$forced = $this->core(constant: false)->switchOn(null, '6.8', 'requested');
		$GLOBALS['wp']['filters']['auto_update_core'] = [];
		$GLOBALS['wp']['filters']['allow_minor_auto_core_updates'] = [static fn(bool $allow): bool => false];
		$filter = $this->core()->switchOn(null, '6.8', 'requested');
		$GLOBALS['wp']['filters']['allow_minor_auto_core_updates'] = [];
		$GLOBALS['wp']['file_mods'] = false;
		$mods = $this->core(constant: false)->switchOn(null, '6.8', 'requested');
		
		return $already === null && $default === null && $forced === null && $filter === null && $mods === null
			&& array_diff_key($GLOBALS['wp']['options'], [Config::OPTION => 1]) === [];
	}
	
	/**
	 * RULE: the override is hooked last (PHP_INT_MAX), and only where WordPress
	 * asks — its cron run, wp-admin — never on a front-end request. Falsify:
	 * hook it at the default priority — a later callback undoes the switch-on.
	 */
	public function theOverrideIsHookedLastWhereWordPressAsks(): bool
	{
		$front = $this->core();
		$front->register();
		$quiet = $GLOBALS['wp']['hooked'] === [];
		$cron = $this->core();
		$cron->here = true;
		$cron->register();
		
		return $quiet && $GLOBALS['wp']['hooked'] === [['allow_minor_auto_core_updates', [$cron, 'allowMinor'], PHP_INT_MAX]];
	}
	
	/**
	 * RULE: the settings page's line says when and why, and how to end it —
	 * untick the box, or forget the kept switch-on — and that it is stopped
	 * while the box is off. Falsify: one sentence whatever the box — a site
	 * with the box off is told to untick it.
	 */
	public function theSettingsLineSaysHowToEndIt(): bool
	{
		$on = PluginCoreUpdate::statusLine(['at' => 1, 'reason' => 'requested'], '2026-10-19 14:00', true);
		$off = PluginCoreUpdate::statusLine(['at' => 1, 'reason' => 'probed'], '2026-10-19 14:00', false);
		
		return str_contains($on, 'on 2026-10-19 14:00 (requested by an operator in codesafe)')
			&& str_contains($on, 'Untick this box to stop it')
			&& str_contains($on, 'wp option delete ovos_codesafe_core_auto_update')
			&& str_contains($off, '(vulnerable and probed, per codesafe)')
			&& str_contains($off, 'This box is off, so it is stopped')
			&& str_contains($off, 'Untick') === false;
	}
	
	/** the core block of a report on a site with no core check, under $constant */
	protected function report(
		mixed $constant = null,
	): array
	{
		return $this->core(constant: $constant)->report(null, '6.8');
	}
	
	/** a CoreUpdate over a connected site with the box as set, WP_AUTO_UPDATE_CORE as given (null: undefined) */
	protected function core(
		array $settings = [],
		mixed $constant = null,
	): TestCoreUpdate
	{
		$GLOBALS['wp']['options'][Config::OPTION] = $settings;
		$core = new TestCoreUpdate(new Config);
		$core->constantValue = $constant;
		
		return $core;
	}
}
