<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Inventory as PluginInventory;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Codesafe\CoreUpdate;
use Ovos\Test\Internal;
use ReflectionClassConstant;
use Tests\Files\TestCoreUpdate;

use function array_column;
use function array_diff;
use function array_diff_key;
use function array_key_exists;
use function count;
use function in_array;
use function json_encode;
use function str_repeat;
use function time;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'TestCoreUpdate.file.php';

/**
 * The inventory beside what is installed: the newest version WordPress's own
 * update check knows per plugin and theme, whether WordPress auto-updates it
 * and whether a filter forces that, and whether the site can auto-update at
 * all — and codesafe's answer turning auto-update on for what it names and
 * off for what an operator switches off, in the site option WordPress's
 * updater reads, that entry alone. A changed software
 * version on an answer sends the inventory again.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Inventory extends Test
{
	protected const string CF7 = 'contact-form-7/wp-contact-form-7.php';
	
	protected const string AKISMET = 'akismet/akismet.php';
	
	protected const string HELLO = 'hello.php';
	
	protected const string OPTION = 'ovos_codesafe_inventory';
	
	protected const string DIRTY = 'ovos_codesafe_inventory_dirty';
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: `latest` is the version the update check offers, the installed one
	 * when the check found it current, nothing when the check never saw it —
	 * plugins as objects, themes as arrays, the way WordPress stores them; a
	 * mu-plugin carries none of the update keys. Falsify: read `response` only —
	 * Akismet, known current, goes out as unknown.
	 */
	public function theLatestVersionIsWhatWordPressKnows(): bool
	{
		$this->updateData();
		$items = $this->items($this->inventory()->gather());
		
		return ($items['plugin|contact-form-7']['latest'] ?? null) === '5.9.8'
			&& ($items['plugin|akismet']['latest'] ?? null) === '5.3'
			&& isset($items['plugin|hello']['latest']) === false
			&& ($items['theme|twentytwentyfour']['latest'] ?? null) === '1.3'
			&& ($items['theme|astra']['latest'] ?? null) === '4.6'
			&& isset($items['mu-plugin|ovos-codesafe-shield']['latest']) === false
			&& isset($items['mu-plugin|ovos-codesafe-shield']['auto_update']) === false
			&& ($items['plugin|contact-form-7']['version'] ?? null) === '5.7';
	}
	
	/**
	 * RULE: `auto_update` is the item on WordPress's site option, `forced` the
	 * auto_update_{type} filter's verdict asked with the screens' payload
	 * (the plugin file under `plugin`, the stylesheet under `theme`), left out
	 * when no filter decides. Falsify: report `forced` as false when the filter
	 * says nothing — every plugin reads as locked off.
	 */
	public function autoUpdateAndForcedAreWhatTheScreensShow(): bool
	{
		$GLOBALS['wp']['options']['auto_update_plugins'] = [self::AKISMET];
		$GLOBALS['wp']['options']['auto_update_themes'] = ['astra'];
		$GLOBALS['wp']['filters']['auto_update_plugin'] = [static fn(mixed $update, object $item): mixed => $item->plugin === self::HELLO ? true : $update];
		$GLOBALS['wp']['filters']['auto_update_theme'] = [static fn(mixed $update, object $item): mixed => $item->theme === 'twentytwentyfour' ? false : $update];
		$items = $this->items($this->inventory()->gather());
		
		return ($items['plugin|akismet']['auto_update'] ?? null) === true
			&& ($items['plugin|contact-form-7']['auto_update'] ?? null) === false
			&& ($items['plugin|hello']['forced'] ?? null) === true
			&& isset($items['plugin|contact-form-7']['forced']) === false
			&& ($items['theme|twentytwentyfour']['forced'] ?? null) === false
			&& ($items['theme|astra']['auto_update'] ?? null) === true
			&& isset($items['theme|astra']['forced']) === false;
	}
	
	/**
	 * RULE: the updates block names the FIRST reason WordPress cannot
	 * auto-update — DISALLOW_FILE_MODS, then the updater switched off, then
	 * the plugins filter, then a version-controlled directory — and says when
	 * WordPress last checked. Falsify: ask VCS first — a site with
	 * DISALLOW_FILE_MODS in a git checkout reads as "vcs".
	 */
	public function theUpdatesBlockNamesTheFirstReason(): bool
	{
		$this->updateData();
		$inventory = $this->inventory();
		$open = $inventory->gather()['updates'];
		$GLOBALS['wp']['vcs'] = true;
		$vcs = $inventory->gather()['updates']['blocked_by'];
		$GLOBALS['wp']['filters']['plugins_auto_update_enabled'] = [static fn(): bool => false];
		$filter = $inventory->gather()['updates']['blocked_by'];
		$GLOBALS['wp']['updater_disabled'] = true;
		$disabled = $inventory->gather()['updates']['blocked_by'];
		$GLOBALS['wp']['file_mods'] = false;
		$closed = $inventory->gather()['updates'];
		
		return array_diff_key($open, ['core' => 1]) === ['allowed' => true, 'blocked_by' => '', 'checked_at' => 1_790_000_000]
			&& isset($open['core']['policy'])
			&& $vcs === 'vcs'
			&& $filter === 'filter'
			&& $disabled === 'updater_disabled'
			&& $closed['allowed'] === false && $closed['blocked_by'] === 'file_mods';
	}
	
	/**
	 * RULE: `core_latest` is the `current` of the first entry of the core check
	 * offering an upgrade — wherever it stands — else the installed version
	 * when an entry says core is the latest (not that entry's own `current`).
	 * Falsify: take the first entry whatever it says — the `latest` entry in
	 * front hides the upgrade; or take a `latest` entry's `current` — 6.8-x
	 * goes out for the installed 6.8.
	 */
	public function coreLatestIsTheUpgradeOfferedElseTheInstalledCore(): bool
	{
		$offered = $this->coreLatest([(object)['response' => 'latest', 'current' => '6.8-x'],
			(object)['response' => 'upgrade', 'current' => '6.8.3'], (object)['response' => 'upgrade', 'current' => '6.9']]);
		$current = $this->coreLatest([(object)['response' => 'autoupdate', 'current' => '6.8.1'],
			(object)['response' => 'latest', 'current' => '6.8-x']]);
		
		return $offered === '6.8.3' && $current === '6.8';
	}
	
	/**
	 * RULE: no core check, an empty one, or one that offers neither an upgrade
	 * nor says core is the latest (development builds, auto-update entries
	 * only) leaves `core_latest` out — never a guess. Falsify: fall back to the
	 * installed version — a site that never checked reads as up to date.
	 */
	public function coreLatestIsLeftOutWhenTheCheckSaysNothing(): bool
	{
		$missing = $this->inventory()->gather()['updates'];
		
		return array_key_exists('core_latest', $missing) === false
			&& $this->coreLatest([]) === null
			&& $this->coreLatest([(object)['response' => 'development', 'current' => '6.9-beta1'],
				(object)['response' => 'autoupdate', 'current' => '6.8.1']]) === null;
	}
	
	/**
	 * RULE: a version the core check names that does not fit the shape — a
	 * character outside [0-9A-Za-z._-], a word for a number, past 32
	 * characters — leaves `core_latest` out instead of going out trimmed.
	 * Falsify: send self::version() of it — "6.9<b>" goes out as "6.9b".
	 */
	public function aMalformedCoreVersionIsLeftOut(): bool
	{
		return $this->coreLatest([(object)['response' => 'upgrade', 'current' => '6.9<b>']]) === null
			&& $this->coreLatest([(object)['response' => 'upgrade', 'current' => 'nightly']]) === null
			&& $this->coreLatest([(object)['response' => 'upgrade', 'current' => '6.' . str_repeat('9', 40)]]) === null
			&& $this->coreLatest([(object)['response' => 'upgrade', 'current' => '7.0']]) === '7.0';
	}
	
	/**
	 * RULE: the typed list wins over the older one; it names plugins and
	 * themes, each switched on in the site option WordPress's updater reads,
	 * next to what is already there, with one audit line naming why; an
	 * unknown reason or an item not installed is dropped; a second answer adds
	 * nothing. Falsify: also take `auto_update` beside the typed list —
	 * Akismet is switched on though the typed list does not name it.
	 */
	public function theTypedListSwitchesOnPluginsAndThemesAndSaysWhy(): bool
	{
		$GLOBALS['wp']['options']['auto_update_plugins'] = ['some/other.php'];
		$inventory = $this->inventory();
		$answer = (string)json_encode([
			'accepted' => 1,
			'auto_update' => ['akismet'],
			'auto_update_items' => [
				['type' => 'plugin', 'slug' => 'contact-form-7', 'reason' => 'requested'],
				['type' => 'theme', 'slug' => 'twentytwentyfour', 'reason' => 'both'],
				['type' => 'plugin', 'slug' => 'hello', 'reason' => 'probed'],
				['type' => 'plugin', 'slug' => 'not-installed', 'reason' => 'requested'],
				['type' => 'plugin', 'slug' => 'akismet', 'reason' => 'because'],
				['type' => 'mu-plugin', 'slug' => 'ovos-codesafe-shield', 'reason' => 'requested'],
			],
		]);
		
		$inventory->applyAnswer($answer);
		$first = $inventory->sender->said;
		$inventory->applyAnswer($answer);
		
		return $GLOBALS['wp']['options']['auto_update_plugins'] === ['some/other.php', self::CF7, self::HELLO]
			&& $GLOBALS['wp']['options']['auto_update_themes'] === ['twentytwentyfour']
			&& array_column($first, 1) === [
				'auto-update enabled for contact-form-7 (requested by an operator in codesafe)',
				'auto-update enabled for hello (vulnerable and probed, per codesafe)',
				'auto-update enabled for theme twentytwentyfour (requested in codesafe; vulnerable and probed)',
			]
			&& $first[0][0] === 'privileged_action'
			&& $first[0][2] === ['action' => 'auto_update_enabled', 'type' => 'plugin', 'reason' => 'requested']
			// codesafe's word, never the visitor's request it happened to run on
			&& array_column($first, 3) === [Sender::withoutRequest(), Sender::withoutRequest(), Sender::withoutRequest()]
			&& count($inventory->sender->said) === 3
			&& $inventory->sender->flushed === 1;
	}
	
	/**
	 * RULE: an answer from a codesafe without the typed list still switches on
	 * the plugins it names as probed — plugins only; with the site's box off
	 * nothing is switched on. Falsify: read themes from the older list — the
	 * active theme named by slug is switched on.
	 */
	public function theOlderListStillNamesPluginsOnly(): bool
	{
		$inventory = $this->inventory();
		$inventory->applyAnswer('{"accepted":1,"auto_update":["akismet","astra"]}');
		$off = $this->inventory(['auto_update_vulnerable' => false]);
		$GLOBALS['wp']['options']['auto_update_plugins'] = [];
		$off->applyAnswer('{"accepted":1,"auto_update":["akismet"]}');
		
		return $inventory->sender->said !== []
			&& array_column($inventory->sender->said, 1) === ['auto-update enabled for akismet (vulnerable and probed, per codesafe)']
			&& isset($GLOBALS['wp']['options']['auto_update_themes']) === false
			&& $GLOBALS['wp']['options']['auto_update_plugins'] === []
			&& $off->sender->said === [];
	}
	
	/**
	 * RULE: a software version other than the one the last inventory answer
	 * carried marks the inventory, an equal or empty one does not; the send
	 * that follows remembers the answer's version, or — when a 2xx names none
	 * (codesafe held no version yet when it answered) or codesafe refused the
	 * report for good — the version that asked for it, so it cannot ask again.
	 * Falsify: remember only the answer's version — a refused report is sent
	 * again on every answer the site hears.
	 */
	public function aChangedSoftwareVersionSendsTheInventoryAgain(): bool
	{
		$inventory = $this->inventory();
		$GLOBALS['wp']['options'][self::OPTION] = ['hash' => '', 'ts' => time(), 'software' => 'v1'];
		
		$empty = $inventory->nudge('');
		$same = $inventory->nudge('v1');
		$quiet = ($GLOBALS['wp']['options'][self::DIRTY] ?? null) === null;
		$changed = $inventory->nudge('v2');
		$marked = ($GLOBALS['wp']['options'][self::DIRTY] ?? null) === 'v2';
		
		$inventory->answer = '{"accepted":1,"software":"v3"}';
		$inventory->maybeSend();
		$answered = $GLOBALS['wp']['options'][self::OPTION]['software'] === 'v3' && isset($GLOBALS['wp']['options'][self::DIRTY]) === false;
		$inventory->maybeSend();
		$once = count($inventory->sent) === 1;
		
		$inventory->nudge('v4');
		$inventory->answer = '{"accepted":1}';
		$inventory->maybeSend();
		$settled = $GLOBALS['wp']['options'][self::OPTION]['software'] === 'v4' && $inventory->nudge('v4') === false;
		
		$inventory->nudge('v5');
		$inventory->status = 403;
		$inventory->answer = '{"success":false,"error":"inventory reports are switched off"}';
		$inventory->maybeSend();
		$refused = $GLOBALS['wp']['options'][self::OPTION]['software'] === 'v5' && $inventory->nudge('v5') === false;
		
		return $empty === false && $same === false && $quiet && $changed && $marked
			&& $answered && $once && $settled && $refused;
	}
	
	/**
	 * RULE: a send codesafe did not answer — a 503 with its JSON body, a
	 * timeout — settles nothing: the version waits out its backoff (15
	 * minutes, then 30) instead of re-sending on every answer the site hears,
	 * and an answered send settles it and ends the backoff. Falsify: settle on
	 * any body — a 503 page parks the pick until tomorrow's heartbeat; or drop
	 * the backoff in nudge() — a slow door is asked on every answer.
	 */
	public function aSendCodesafeDidNotAnswerBacksOff(): bool
	{
		$inventory = $this->inventory();
		$GLOBALS['wp']['options'][self::OPTION] = ['hash' => '', 'ts' => time(), 'software' => 'v1'];
		
		$inventory->nudge('v2');
		$inventory->status = 503;
		$inventory->answer = '{"success":false,"error":"ingestion unavailable"}';
		$inventory->maybeSend();
		$state = $GLOBALS['wp']['options'][self::OPTION];
		$unsettled = $state['software'] === 'v1' && $state['tried'] === 'v2' && $state['fails'] === 1;
		
		// the same version heard again within the window marks nothing, so nothing is sent
		$waits = $inventory->nudge('v2') === false;
		$inventory->maybeSend();
		$quiet = count($inventory->sent) === 1;
		$after = $inventory->nudge('v2', $state['tried_at'] + 901);
		
		$inventory->status = 0;
		$inventory->answer = '';
		$inventory->maybeSend();
		$state = $GLOBALS['wp']['options'][self::OPTION];
		$doubled = $state['fails'] === 2
			&& $inventory->nudge('v2', $state['tried_at'] + 901) === false
			&& $inventory->nudge('v2', $state['tried_at'] + 1801);
		
		$inventory->status = 202;
		$inventory->answer = '{"accepted":1}';
		$inventory->maybeSend();
		$state = $GLOBALS['wp']['options'][self::OPTION];
		$reset = $state['software'] === 'v2' && isset($state['tried']) === false && isset($state['fails']) === false;
		
		return $unsettled && $waits && $quiet && $after && $doubled && $reset && count($inventory->sent) === 3;
	}
	
	/**
	 * RULE: a 2xx and a definitive refusal (400, 401, 403, 404, 422) settle the
	 * version that asked; a 5xx, a 429 or nothing at all count an unanswered
	 * send; a send for a change hook keeps a running backoff until one is
	 * answered; the window doubles from 15 minutes and stops at a day.
	 * Falsify: count a 429 as answered — a rate-limited door settles the pick.
	 */
	public function onlyAnAnsweredSendSettlesAndTheWindowDoubles(): bool
	{
		$state = ['software' => 'v1'];
		$answered = [];
		foreach([200, 202, 400, 401, 403, 404, 422, 429, 500, 502, 503, 0] as $status)
		{
			$answered[$status] = PluginInventory::settle($state, 'v2', $status, '', 1_000) === ['software' => 'v2'];
		}
		$running = ['software' => 'v1', 'tried' => 'v2', 'tried_at' => 1_000, 'fails' => 3];
		
		return $answered === [200 => true, 202 => true, 400 => true, 401 => true, 403 => true, 404 => true, 422 => true,
				429 => false, 500 => false, 502 => false, 503 => false, 0 => false]
			&& PluginInventory::settle($running, '', 503, '', 2_000) === $running
			&& PluginInventory::settle($running, '', 202, '', 2_000) === ['software' => 'v1']
			&& PluginInventory::settle($running, 'v2', 503, '', 2_000) === ['software' => 'v1', 'tried' => 'v2', 'tried_at' => 2_000, 'fails' => 4]
			&& PluginInventory::settle($state, 'v2', 202, '{"software":"v9"}', 1_000) === ['software' => 'v9']
			&& PluginInventory::backoff(1) === 900
			&& PluginInventory::backoff(2) === 1800
			&& PluginInventory::backoff(3) === 3600
			&& PluginInventory::backoff(7) === 57600
			&& PluginInventory::backoff(8) === 86400
			&& PluginInventory::backoff(60) === 86400;
	}
	
	/**
	 * RULE: a switch-on marks the inventory again AFTER the send cleared the
	 * flag, so the next request tells codesafe it took; a change hook keeps a
	 * version a nudge left in the flag. Falsify: clear the flag after apply()
	 * — the confirmation waits a day.
	 */
	public function aSwitchOnIsReportedByTheNextInventory(): bool
	{
		$inventory = $this->inventory();
		$GLOBALS['wp']['options'][self::DIRTY] = 1;
		$inventory->answer = '{"accepted":1,"auto_update_items":[{"type":"plugin","slug":"akismet","reason":"requested"}]}';
		$inventory->maybeSend();
		$again = ($GLOBALS['wp']['options'][self::DIRTY] ?? null) === 1;
		
		$GLOBALS['wp']['options'][self::DIRTY] = 'v7';
		$inventory->markDirty();
		
		return $again && $GLOBALS['wp']['options'][self::DIRTY] === 'v7';
	}
	
	/**
	 * RULE: the auto-update choices — added or updated, the site's or the
	 * network's — and a stored update check mark the inventory. Falsify: drop
	 * the add_ hooks — a site's first auto-update toggle never reaches codesafe.
	 */
	public function theAutoUpdateChoicesAndTheUpdateCheckMarkTheInventory(): bool
	{
		$hooks = (array)(new ReflectionClassConstant(PluginInventory::class, 'CHANGE_HOOKS'))->getValue();
		$wanted = [
			'add_option_auto_update_plugins', 'update_option_auto_update_plugins',
			'add_option_auto_update_themes', 'update_option_auto_update_themes',
			'add_site_option_auto_update_plugins', 'update_site_option_auto_update_plugins',
			'add_site_option_auto_update_themes', 'update_site_option_auto_update_themes',
			'set_site_transient_update_plugins', 'set_site_transient_update_themes', 'set_site_transient_update_core',
			'upgrader_process_complete', 'activated_plugin',
		];
		
		return array_diff($wanted, $hooks) === [] && in_array('switch_theme', $hooks, true);
	}
	
	/**
	 * RULE: the typed list may name core — `core|wordpress`, no other slug —
	 * and the switch-on is the site's call made by CoreUpdate: under
	 * WP_AUTO_UPDATE_CORE false the flag is kept and the audit line says the
	 * constant was overridden, minor releases only; the inventory goes again.
	 * Falsify: drop the core entry in wanted() — an operator's pick for core
	 * never reaches the site.
	 */
	public function theAnswerNamesCoreAndTheSwitchOnSaysSo(): bool
	{
		$wanted = PluginInventory::wanted(['auto_update_items' => [
			['type' => 'core', 'slug' => 'wordpress', 'reason' => 'requested'],
			['type' => 'core', 'slug' => 'drupal', 'reason' => 'requested'],
			['type' => 'core', 'slug' => 'wordpress', 'reason' => 'because'],
		]]);
		$GLOBALS['wp']['options']['auto_update_core_minor'] = 'disabled';
		$inventory = $this->inventory();
		$inventory->testCore = new TestCoreUpdate(new Config);
		$inventory->testCore->constantValue = false;
		$inventory->applyAnswer('{"accepted":1,"auto_update_items":[{"type":"core","slug":"wordpress","reason":"requested"}]}');
		$overridden = $inventory->sender->said;
		$flag = $GLOBALS['wp']['options']['ovos_codesafe_core_auto_update'] ?? [];
		$dirty = $GLOBALS['wp']['options'][self::DIRTY] ?? null;
		
		$GLOBALS['wp']['options']['auto_update_core_minor'] = 'disabled';
		unset($GLOBALS['wp']['options']['ovos_codesafe_core_auto_update']);
		$plain = $this->inventory();
		$plain->applyAnswer('{"accepted":1,"auto_update_items":[{"type":"core","slug":"wordpress","reason":"probed"}]}');
		
		return $wanted === ['core|wordpress' => 'requested']
			&& array_column($overridden, 1) === ['auto-update enabled for WordPress core, minor releases (requested by an operator in codesafe)'
				. ' — WP_AUTO_UPDATE_CORE is false on this site, overridden for minor releases only']
			&& $overridden[0][2] === ['action' => 'auto_update_enabled', 'type' => 'core', 'reason' => 'requested', 'override' => true]
			&& $overridden[0][3] === Sender::withoutRequest()
			&& ($flag['reason'] ?? null) === 'requested'
			&& $dirty === 1
			&& array_column($plain->sender->said, 1) === ['auto-update enabled for WordPress core, minor releases (vulnerable and probed, per codesafe)']
			&& $plain->sender->said[0][2]['override'] === false
			&& isset($GLOBALS['wp']['options']['ovos_codesafe_core_auto_update']) === false
			&& $GLOBALS['wp']['options']['auto_update_core_minor'] === 'enabled';
	}
	
	/**
	 * RULE: an operator's TURN OFF (`auto_update_off`) takes exactly the named
	 * plugin and theme out of WordPress's lists — every other entry stays —
	 * reports each as a privileged_action and marks the inventory so the next
	 * request confirms; an entry off the rules (a mu-plugin, another core, a
	 * slug off its shape) is dropped, and an item that is not on changes
	 * nothing. Falsify: write the list back without the site's other entries —
	 * the admin's own choices go with the named one.
	 */
	public function turnOffTakesOutTheNamedItemAlone(): bool
	{
		$GLOBALS['wp']['options']['auto_update_plugins'] = ['some/other.php', self::CF7, self::AKISMET];
		$GLOBALS['wp']['options']['auto_update_themes'] = ['twentytwentyfour', 'astra'];
		// codesafe switched these two on: its own to take back
		$GLOBALS['wp']['options'][PluginInventory::OURS] = ['plugin' => [self::CF7], 'theme' => ['twentytwentyfour']];
		$unwanted = PluginInventory::unwanted(['auto_update_off' => [
			['type' => 'plugin', 'slug' => 'contact-form-7'],
			['type' => 'theme', 'slug' => 'twentytwentyfour'],
			['type' => 'core', 'slug' => 'wordpress'],
			['type' => 'mu-plugin', 'slug' => 'ovos-codesafe-shield'],
			['type' => 'core', 'slug' => 'drupal'],
			['type' => 'plugin', 'slug' => 'Not A Slug'],
		]]);
		$inventory = $this->inventory();
		$inventory->applyAnswer((string)json_encode(['accepted' => 1, 'auto_update_off' => [
			['type' => 'plugin', 'slug' => 'contact-form-7'],
			['type' => 'theme', 'slug' => 'twentytwentyfour'],
			['type' => 'plugin', 'slug' => 'hello'],
			['type' => 'mu-plugin', 'slug' => 'ovos-codesafe-shield'],
		]]));
		
		return $unwanted === ['plugin|contact-form-7' => true, 'theme|twentytwentyfour' => true, 'core|wordpress' => true]
			&& $GLOBALS['wp']['options']['auto_update_plugins'] === ['some/other.php', self::AKISMET]
			&& $GLOBALS['wp']['options']['auto_update_themes'] === ['astra']
			&& array_column($inventory->sender->said, 1) === [
				'auto-update disabled for contact-form-7 (switched off by an operator in codesafe)',
				'auto-update disabled for theme twentytwentyfour (switched off by an operator in codesafe)',
			]
			&& $inventory->sender->said[0][0] === 'privileged_action'
			&& $inventory->sender->said[1][2] === ['action' => 'auto_update_disabled', 'type' => 'theme']
			&& array_column($inventory->sender->said, 3) === [Sender::withoutRequest(), Sender::withoutRequest()]
			&& ($GLOBALS['wp']['options'][self::DIRTY] ?? null) === 1
			&& $inventory->sender->flushed === 1;
	}
	
	/**
	 * RULE: codesafe takes back only what codesafe switched on: a switch-on
	 * is remembered, and a TURN OFF of an entry the site's owner put on the
	 * list changes nothing and says nothing, while one codesafe put there
	 * leaves it and the record. Falsify: take any named entry out — a
	 * codesafe, or whoever holds it, switches off the automatic update an
	 * owner set for a vulnerable plugin and keeps it exploitable.
	 */
	public function turnOffTakesBackOnlyCodesafesOwnSwitchOn(): bool
	{
		$GLOBALS['wp']['options']['auto_update_plugins'] = [self::AKISMET];
		$on = $this->inventory();
		$on->applyAnswer('{"accepted":1,"auto_update_items":[{"type":"plugin","slug":"contact-form-7","reason":"requested"}]}');
		$recorded = $GLOBALS['wp']['options'][PluginInventory::OURS] ?? null;
		$off = $this->inventory();
		$off->applyAnswer('{"accepted":1,"auto_update_off":[{"type":"plugin","slug":"contact-form-7"},{"type":"plugin","slug":"akismet"}]}');
		
		return $recorded === ['plugin' => [self::CF7]]
			&& $GLOBALS['wp']['options']['auto_update_plugins'] === [self::AKISMET]
			&& array_column($off->sender->said, 1) === ['auto-update disabled for contact-form-7 (switched off by an operator in codesafe)']
			&& ($GLOBALS['wp']['options'][PluginInventory::OURS] ?? null) === ['plugin' => []];
	}
	
	/**
	 * RULE: TURN OFF for core withdraws codesafe's kept switch-on and nothing
	 * else — WordPress's own minor switch keeps its value; with nothing kept
	 * there is nothing to withdraw or say. Falsify: also write
	 * auto_update_core_minor `disabled` — codesafe would switch off
	 * WordPress's own security releases.
	 */
	public function coreOffWithdrawsTheOverrideAndNothingElse(): bool
	{
		$GLOBALS['wp']['options']['auto_update_core_minor'] = 'enabled';
		$GLOBALS['wp']['options'][CoreUpdate::OPTION] = ['at' => 1_790_000_000, 'reason' => 'requested'];
		$inventory = $this->inventory();
		$inventory->applyAnswer('{"accepted":1,"auto_update_off":[{"type":"core","slug":"wordpress"}]}');
		$said = $inventory->sender->said;
		$again = $this->inventory();
		$again->applyAnswer('{"accepted":1,"auto_update_off":[{"type":"core","slug":"wordpress"}]}');
		
		return isset($GLOBALS['wp']['options'][CoreUpdate::OPTION]) === false
			&& $GLOBALS['wp']['options']['auto_update_core_minor'] === 'enabled'
			&& array_column($said, 1) === ['auto-update disabled for WordPress core, minor releases — codesafe\'s override withdrawn']
			&& $said[0][2] === ['action' => 'auto_update_disabled', 'type' => 'core']
			&& $said[0][3] === Sender::withoutRequest()
			&& $again->sender->said === [];
	}
	
	/**
	 * RULE: an item codesafe names in both lists ends off — never switched on
	 * only to be switched off in the same answer — whether it was on before or
	 * not; the rest of the answer applies. Falsify: drop the exclusion —
	 * Contact Form 7 is switched on and off again, two audit lines for nothing.
	 */
	public function anItemNamedOnAndOffEndsOff(): bool
	{
		$both = '{"accepted":1,"auto_update_items":[{"type":"plugin","slug":"contact-form-7","reason":"requested"},'
			. '{"type":"plugin","slug":"hello","reason":"requested"}],'
			. '"auto_update_off":[{"type":"plugin","slug":"contact-form-7"}]}';
		$GLOBALS['wp']['options']['auto_update_plugins'] = [];
		$wasOff = $this->inventory();
		$wasOff->applyAnswer($both);
		$fromOff = $GLOBALS['wp']['options']['auto_update_plugins'];
		$GLOBALS['wp']['options']['auto_update_plugins'] = [self::CF7];
		$GLOBALS['wp']['options'][PluginInventory::OURS] = ['plugin' => [self::CF7]];
		$wasOn = $this->inventory();
		$wasOn->applyAnswer($both);
		
		return $fromOff === [self::HELLO]
			&& array_column($wasOff->sender->said, 1) === ['auto-update enabled for hello (requested by an operator in codesafe)']
			&& $GLOBALS['wp']['options']['auto_update_plugins'] === [self::HELLO]
			&& array_column($wasOn->sender->said, 1) === [
				'auto-update enabled for hello (requested by an operator in codesafe)',
				'auto-update disabled for contact-form-7 (switched off by an operator in codesafe)',
			];
	}
	
	/**
	 * RULE: with the site's box unticked codesafe switches nothing on and
	 * nothing off — core's kept switch-on stays too — and says nothing.
	 * Falsify: drop the box's check — Contact Form 7 leaves the list and core's
	 * switch-on goes.
	 */
	public function withTheBoxOffNeitherOnNorOffApplies(): bool
	{
		$GLOBALS['wp']['options']['auto_update_plugins'] = [self::CF7];
		$GLOBALS['wp']['options'][CoreUpdate::OPTION] = ['at' => 1_790_000_000, 'reason' => 'requested'];
		$inventory = $this->inventory(['auto_update_vulnerable' => false]);
		$inventory->applyAnswer('{"accepted":1,"auto_update_items":[{"type":"plugin","slug":"hello","reason":"requested"}],'
			. '"auto_update_off":[{"type":"plugin","slug":"contact-form-7"},{"type":"core","slug":"wordpress"}]}');
		
		return $GLOBALS['wp']['options']['auto_update_plugins'] === [self::CF7]
			&& isset($GLOBALS['wp']['options'][CoreUpdate::OPTION])
			&& $inventory->sender->said === []
			&& isset($GLOBALS['wp']['options'][self::DIRTY]) === false;
	}
	
	/**
	 * RULE: `source` says where an item's updates come from — wordpress.org
	 * when the check's entry says so (its id, url or package), else the host
	 * of the Update URI header, else the entry's own server; nothing when
	 * nothing says, or the header is `false`; a host off the shape is no host.
	 * Falsify: read the header before the entry — a wordpress.org plugin with
	 * a stray header reads as commercial.
	 */
	public function theSourceIsWhereUpdatesComeFrom(): bool
	{
		return PluginInventory::source((object)['id' => 'w.org/plugins/akismet'], 'https://vendor.example/x') === 'wordpress.org'
			&& PluginInventory::source(['url' => 'https://wordpress.org/themes/astra/'], '') === 'wordpress.org'
			&& PluginInventory::source((object)['package' => 'https://downloads.wordpress.org/plugin/x.zip'], '') === 'wordpress.org'
			&& PluginInventory::source(null, 'https://Updates.Vendor.example/check') === 'updates.vendor.example'
			&& PluginInventory::source(null, 'vendor.example/plugin') === 'vendor.example'
			&& PluginInventory::source((object)['package' => 'https://dl.vendor.io/get?key=1'], '') === 'dl.vendor.io'
			&& PluginInventory::source(null, 'false') === ''
			&& PluginInventory::source(null, '') === ''
			&& PluginInventory::source(null, 'https://exa mple/x') === '';
	}
	
	/**
	 * RULE: the report carries `source` per plugin and theme, and `package`
	 * false only for an update offered without a download — WordPress cannot
	 * install that by itself (commonly a licence not active); never for an
	 * item the check found current, never for a mu-plugin. Falsify: send
	 * `package` false for every missing package — a current plugin reads as
	 * locked behind a licence.
	 */
	public function theReportSaysWhereUpdatesComeFromAndWhatCannotInstall(): bool
	{
		$this->updateData();
		$GLOBALS['wp']['site_transients']['update_plugins']->response['pro/pro.php'] = (object)['slug' => 'pro', 'plugin' => 'pro/pro.php',
			'new_version' => '3.1', 'url' => 'https://pro.example/', 'package' => ''];
		$GLOBALS['wp']['site_transients']['update_plugins']->no_update['quiet/quiet.php'] = (object)['slug' => 'quiet', 'plugin' => 'quiet/quiet.php',
			'new_version' => '1.0', 'package' => ''];
		$inventory = $this->inventory();
		$inventory->installed = [
			self::CF7 => ['Name' => 'Contact Form 7', 'Version' => '5.7'],
			'pro/pro.php' => ['Name' => 'Pro', 'Version' => '3.0', 'UpdateURI' => 'https://updates.pro.example/'],
			'quiet/quiet.php' => ['Name' => 'Quiet', 'Version' => '1.0', 'UpdateURI' => 'https://quiet.example/'],
			'mine/mine.php' => ['Name' => 'Mine', 'Version' => '0.1', 'UpdateURI' => 'false'],
		];
		$items = $this->items($inventory->gather());
		
		return ($items['plugin|contact-form-7']['source'] ?? null) === 'wordpress.org'
			&& isset($items['plugin|contact-form-7']['package']) === false
			&& ($items['plugin|pro']['source'] ?? null) === 'updates.pro.example'
			&& ($items['plugin|pro']['package'] ?? null) === false
			&& ($items['plugin|quiet']['source'] ?? null) === 'quiet.example'
			&& isset($items['plugin|quiet']['package']) === false
			&& isset($items['plugin|mine']['source']) === false
			&& ($items['theme|twentytwentyfour']['source'] ?? null) === 'wordpress.org'
			&& isset($items['mu-plugin|ovos-codesafe-shield']['source']) === false;
	}
	
	/** WordPress's last update check, as it stores plugins (objects) and themes (arrays) */
	protected function updateData(): void
	{
		$GLOBALS['wp']['site_transients']['update_plugins'] = (object)[
			'last_checked' => 1_790_000_000,
			'checked' => [self::CF7 => '5.7', self::AKISMET => '5.3', self::HELLO => '1.7.2'],
			'response' => [self::CF7 => (object)['id' => 'w.org/plugins/contact-form-7', 'slug' => 'contact-form-7', 'plugin' => self::CF7,
				'new_version' => '5.9.8', 'package' => 'https://downloads.wordpress.org/plugin/contact-form-7.5.9.8.zip']],
			'no_update' => [self::AKISMET => (object)['id' => 'w.org/plugins/akismet', 'slug' => 'akismet', 'plugin' => self::AKISMET, 'new_version' => '5.3']],
		];
		$GLOBALS['wp']['site_transients']['update_themes'] = (object)[
			'last_checked' => 1_790_000_100,
			'response' => ['twentytwentyfour' => ['theme' => 'twentytwentyfour', 'new_version' => '1.3',
				'url' => 'https://wordpress.org/themes/twentytwentyfour/', 'package' => 'https://downloads.wordpress.org/theme/twentytwentyfour.1.3.zip']],
			'no_update' => ['astra' => ['theme' => 'astra', 'new_version' => '4.6', 'url' => 'https://wordpress.org/themes/astra/']],
		];
	}
	
	/**
	 * `core_latest` of a gather over a core check holding these offers — the
	 * installed core is the shim's 6.8 — null when the report leaves it out
	 *
	 * @param list<object> $offers
	 */
	protected function coreLatest(
		array $offers,
	): ?string
	{
		$GLOBALS['wp']['site_transients']['update_core'] = (object)['updates' => $offers, 'version_checked' => '6.8', 'last_checked' => 1_790_000_000];
		
		return $this->inventory()->gather()['updates']['core_latest'] ?? null;
	}
	
	/**
	 * The report's items by type|slug
	 *
	 * @return array<string, array<string, mixed>>
	 */
	protected function items(
		array $report,
	): array
	{
		$items = [];
		foreach($report['items'] as $item)
		{
			$items[$item['type'] . '|' . $item['slug']] = $item;
		}
		
		return $items;
	}
	
	/**
	 * An inventory over a fixed site — Contact Form 7 and Akismet in
	 * directories, Hello Dolly as one file, a mu-plugin, two themes with Astra
	 * active — connected, whose send() answers what the test set, beside a
	 * Sender that keeps the audit lines
	 */
	protected function inventory(
		array $settings = [],
	): PluginInventory
	{
		$GLOBALS['wp']['options'][Config::OPTION] = $settings + ['enabled' => true, 'url' => 'https://codesafe.invalid',
			'api_key' => str_repeat('a', 64)];
		$sender = new class extends Sender
		{
			/** @var list<array{0: string, 1: string, 2: array, 3: array}> */
			public array $said = [];
			
			public int $flushed = 0;
			
			public function __construct()
			{
			}
			
			public function reportRefusal(
				string $kind,
				string $message = '',
				array $extra = [],
				array $context = [],
				?int $priority = null,
			): void
			{
				$this->said[] = [$kind, $message, $extra, $context];
			}
			
			public function flush(): void
			{
				$this->flushed++;
			}
		};
		
		return new class(new Config, $sender) extends PluginInventory
		{
			/** what send() answers: the body, and its status (0 = nothing came back) */
			public string $answer = '';
			
			/** the installed plugins when a test sets them, file => headers */
			public ?array $installed = null;
			
			/** core's automatic updates under a WP_AUTO_UPDATE_CORE the test sets */
			public ?TestCoreUpdate $testCore = null;
			
			public int $status = 202;
			
			/** @var list<array> what was sent */
			public array $sent = [];
			
			public function __construct(
				Config $config,
				public ?Sender $sender = null,
			)
			{
				parent::__construct($config, $sender);
			}
			
			public function applyAnswer(
				string $body,
			): void
			{
				$this->apply($body);
			}
			
			protected function core(): CoreUpdate
			{
				return $this->testCore ?? parent::core();
			}
			
			protected function plugins(): array
			{
				return $this->installed ?? [
					'contact-form-7/wp-contact-form-7.php' => ['Name' => 'Contact Form 7', 'Version' => '5.7'],
					'akismet/akismet.php' => ['Name' => 'Akismet', 'Version' => '5.3'],
					'hello.php' => ['Name' => 'Hello Dolly', 'Version' => '1.7.2'],
				];
			}
			
			protected function muPlugins(): array
			{
				return ['ovos-codesafe-shield.php' => ['Name' => 'ovos codesafe Shield', 'Version' => '1.0.0']];
			}
			
			protected function themes(): array
			{
				return [
					'twentytwentyfour' => ['Name' => 'Twenty Twenty-Four', 'Version' => '1.2'],
					'astra' => ['Name' => 'Astra', 'Version' => '4.6'],
				];
			}
			
			protected function currentTheme(): string
			{
				return 'astra';
			}
			
			protected function send(
				array $payload,
			): array
			{
				$this->sent[] = $payload;
				
				return ['status' => $this->status, 'body' => $this->answer];
			}
		};
	}
}
