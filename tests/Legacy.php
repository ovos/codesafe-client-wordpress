<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Legacy as BaseLegacy;
use Ovos\Codesafe\Plugin;
use Ovos\Test;
use Ovos\Test\Internal;

use function define;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The switch from ovos-console: a wp-config written with OVOS_CONSOLE_*
 * constants keeps working, the old settings are copied once, and a site's
 * filter under the old name still applies. A process defines a constant
 * once, so every claim uses its own made-up key.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Legacy extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	public function oldConstantIsReadWhenTheNewOneIsMissing(): bool
	{
		define('OVOS_CONSOLE_ZZ_OLD_ONLY', 'old');
		$config = new Config();
		
		return $config->constantName('zz_old_only') === 'OVOS_CONSOLE_ZZ_OLD_ONLY'
			&& $config->isConstant('zz_old_only')
			&& $config->get('zz_old_only') === 'old';
	}
	
	public function newConstantWinsOverTheOldOne(): bool
	{
		define('OVOS_CONSOLE_ZZ_BOTH', 'old');
		define('CODESAFE_ZZ_BOTH', 'new');
		$config = new Config();
		
		return $config->constantName('zz_both') === 'CODESAFE_ZZ_BOTH'
			&& $config->get('zz_both') === 'new';
	}
	
	public function withNeitherDefinedTheNewNameIsNamed(): bool
	{
		$config = new Config();
		
		return $config->constantName('zz_neither') === 'CODESAFE_ZZ_NEITHER'
			&& $config->isConstant('zz_neither') === false;
	}
	
	public function oldSettingsAreCopiedUnderTheNewNames(): bool
	{
		$GLOBALS['wp']['options'] = [
			'ovos_console' => ['enabled' => true, 'url' => 'https://codesafe.example'],
			'ovos_console_scan' => ['phase' => 3],
			'ovos_console_announced_release' => 'abc123',
		];
		
		BaseLegacy::migrate();
		$options = $GLOBALS['wp']['options'];
		
		return $options[Config::OPTION] === ['enabled' => true, 'url' => 'https://codesafe.example']
			&& $options['ovos_codesafe_scan'] === ['phase' => 3]
			&& $options[Plugin::OPTION_ANNOUNCED] === 'abc123'
			&& isset($options['ovos_codesafe_inventory']) === false
			&& $options['ovos_console'] === ['enabled' => true, 'url' => 'https://codesafe.example'];
	}
	
	/**
	 * RULE: ovos-console saved every unticked box as false — the switches
	 * that default on here, and the inventory and the Shield, which have no
	 * box, are left out of the copy, so the site runs on this plugin's
	 * defaults; everything else the old row set is kept. Falsify: copy the
	 * row whole — the Shield and the inventory stay off with no box to turn
	 * them on.
	 */
	public function aMigratedSiteStartsOnTheNewDefaults(): bool
	{
		$GLOBALS['wp']['options'] = [
			'ovos_console' => ['enabled' => true, 'log_level' => 3, 'inventory' => false, 'shield_detect' => false,
				'shield_enforce' => false, 'report_404' => false, 'rollups' => false, 'security_events' => false,
				'auto_update_vulnerable' => false, 'scan' => false, 'snapshot' => false, 'snapshot_styles' => false],
		];
		
		BaseLegacy::migrate();
		$config = new Config();
		
		return $GLOBALS['wp']['options'][Config::OPTION] === ['enabled' => true, 'log_level' => 3]
			&& $config->logLevel() === 3
			&& $config->inventory()
			&& $config->shieldDetect()
			&& $config->shieldEnforce()
			&& $config->report404()
			&& $config->rollups()
			&& $config->securityEvents()
			&& $config->autoUpdateVulnerable()
			&& $config->scan()
			&& $config->snapshot()
			&& $config->snapshotStyles();
	}
	
	public function existingSettingsAreNeverOverwritten(): bool
	{
		$GLOBALS['wp']['options'] = [
			Config::OPTION => ['enabled' => false],
			'ovos_console' => ['enabled' => true],
			'ovos_console_scan' => ['phase' => 3],
		];
		
		BaseLegacy::migrate();
		$options = $GLOBALS['wp']['options'];
		
		return $options[Config::OPTION] === ['enabled' => false]
			&& isset($options['ovos_codesafe_scan']) === false;
	}
	
	public function aFreshInstallGetsAnEmptyOptionSoTheCheckRunsOnce(): bool
	{
		BaseLegacy::migrate();
		
		return $GLOBALS['wp']['options'] === [Config::OPTION => []];
	}
	
	public function aFilterUnderTheOldNameAppliesAfterTheNewOne(): bool
	{
		$GLOBALS['wp']['filters'] = [
			'ovos_codesafe_sslverify' => [static fn(bool $value): bool => false],
			'ovos_console_sslverify' => [static fn(bool $value): string => $value ? 'old saw true' : 'old saw false'],
		];
		
		return BaseLegacy::filter('ovos_codesafe_sslverify', true) === 'old saw false'
			&& BaseLegacy::filter('ovos_codesafe_unrelated', 'x') === 'x';
	}
}
