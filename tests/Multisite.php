<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Inventory;
use Ovos\Codesafe\Scan;
use Ovos\Codesafe\ScanRunner;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Settings;
use Ovos\Test;
use Ovos\Test\Internal;
use Tests\Files\TestCoreUpdate;

use function array_key_exists;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'TestCoreUpdate.file.php';

/**
 * M14 of the 2026-10-03 security audit: on a multisite network the Shield's
 * store, consent and stub are ONE under WP_CONTENT_DIR while the settings
 * are per site — a subsite admin pointing at their own codesafe could serve
 * `uri prefix /` PROVEN and 403 the whole network. The network's Shield is
 * now the main site's, set by a super admin; a subsite's boxes do nothing
 * and its form cannot change them.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Multisite extends Test
{
	protected const array BOXES = ['enabled' => true, 'url' => 'https://codesafe.invalid', 'api_key' => 'k',
		'shield_detect' => true, 'shield_enforce' => true, 'entry_watch' => true];
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		$GLOBALS['wp']['options']['ovos_codesafe'] = self::BOXES;
	}
	
	public function aSingleSiteKeepsItsBoxes(): bool
	{
		$config = new Config();
		
		return $config->shieldDetect() && $config->shieldEnforce() && $config->entryWatch()
			&& $config->ownsSharedStore() && $config->mayChangeNetworkKeys();
	}
	
	/** a subsite's ticked boxes drive nothing: no adapter, no pull, no consent, no watch */
	public function aSubsitesBoxesDriveNothing(): bool
	{
		$this->network(main: false);
		$config = new Config();
		
		return $config->shieldDetect() === false
			&& $config->shieldEnforce() === false
			&& $config->entryWatch() === false
			&& $config->ownsSharedStore() === false;
	}
	
	public function theMainSitesBoxesAreTheNetworks(): bool
	{
		$this->network(main: true);
		$config = new Config();
		
		return $config->shieldDetect() && $config->shieldEnforce() && $config->entryWatch();
	}
	
	/** only a super admin on the main site may change the network's keys */
	public function onlyASuperAdminOnTheMainSiteMayChangeThem(): bool
	{
		$this->network(main: true);
		$admin = (new Config())->mayChangeNetworkKeys();
		$GLOBALS['wp']['super_admins'] = [7];
		$super = (new Config())->mayChangeNetworkKeys();
		$this->network(main: false);
		$superOnSubsite = (new Config())->mayChangeNetworkKeys();
		
		return $admin === false && $super === true && $superOnSubsite === false;
	}
	
	/**
	 * A subsite admin's form ticks the boxes and names a proxy: the stored
	 * values stay, every other field saves as before
	 */
	public function aSubsitesFormCannotChangeTheNetworksKeys(): bool
	{
		$this->network(main: false);
		$GLOBALS['wp']['options']['ovos_codesafe'] = ['entry_watch' => false, 'trusted_proxy_header' => '', 'trusted_proxies' => ''];
		$clean = $this->settings()->sanitize(['shield_detect' => '1', 'entry_watch' => '1',
			'trusted_proxy_header' => 'X-Forwarded-For', 'trusted_proxies' => '0.0.0.0/0', 'report_404' => '1', 'scan_interval' => '7']);
		$GLOBALS['wp']['super_admins'] = [7];
		$this->network(main: true);
		$super = $this->settings()->sanitize(['entry_watch' => '1', 'trusted_proxies' => 'cloudflare', 'scan_interval' => '7']);
		
		// the Shield is no form field at all since 2026-10-13 (codesafe decides; the constants are the site's off)
		return array_key_exists('shield_detect', $clean) === false
			&& $clean['entry_watch'] === false
			&& $clean['trusted_proxy_header'] === ''
			&& $clean['trusted_proxies'] === ''
			&& $clean['report_404'] === true
			&& $super['entry_watch'] === true
			&& $super['trusted_proxies'] === 'cloudflare';
	}
	
	/** the proxy is the server's: a subsite reads the main site's */
	public function aSubsiteReadsTheMainSitesTrustedProxy(): bool
	{
		$this->network(main: false);
		$GLOBALS['wp']['options']['ovos_codesafe']['trusted_proxy_header'] = 'X-Spoofed';
		$GLOBALS['wp']['main_options']['ovos_codesafe'] = ['trusted_proxy_header' => 'CF-Connecting-IP', 'trusted_proxies' => '10.0.0.0/8'];
		$config = new Config();
		
		return $config->trustedProxyHeader() === 'CF-Connecting-IP'
			&& $config->trustedProxies() === ['10.0.0.0/8'];
	}
	
	/**
	 * RULE: on a network codesafe's auto-update switch-on lands in the
	 * network's site option, the one WordPress's updater reads — never in the
	 * subsite's own options table. Falsify: write update_option() — the
	 * network never auto-updates the plugin.
	 */
	public function aSwitchOnLandsInTheNetworksOption(): bool
	{
		$this->network(main: true);
		$GLOBALS['wp']['site_options']['auto_update_plugins'] = ['akismet/akismet.php'];
		$inventory = new class(new Config) extends Inventory
		{
			public function applyAnswer(
				string $body,
			): void
			{
				$this->apply($body);
			}
			
			protected function plugins(): array
			{
				return ['contact-form-7/wp-contact-form-7.php' => ['Name' => 'Contact Form 7', 'Version' => '5.7']];
			}
			
			protected function themes(): array
			{
				return [];
			}
		};
		$inventory->applyAnswer('{"auto_update_items":[{"type":"plugin","slug":"contact-form-7","reason":"requested"}]}');
		
		return $GLOBALS['wp']['site_options']['auto_update_plugins'] === ['akismet/akismet.php', 'contact-form-7/wp-contact-form-7.php']
			&& array_key_exists('auto_update_plugins', $GLOBALS['wp']['options']) === false;
	}
	
	/**
	 * RULE: on a network core's switch-on — WordPress's minor option and the
	 * flag kept over WP_AUTO_UPDATE_CORE false — lands in the network's site
	 * options, where WordPress's updater runs and reads them. Falsify: keep
	 * the flag with update_option() — the main site's cron never sees it.
	 */
	public function aCoreSwitchOnLandsInTheNetworksOptions(): bool
	{
		$this->network(main: true);
		$GLOBALS['wp']['site_options']['auto_update_core_minor'] = 'disabled';
		$core = new TestCoreUpdate(new Config);
		$core->constantValue = false;
		$written = $core->switchOn(null, '6.8', 'requested');
		
		return $written === true
			&& $GLOBALS['wp']['site_options']['auto_update_core_minor'] === 'enabled'
			&& isset($GLOBALS['wp']['site_options']['ovos_codesafe_core_auto_update'])
			&& array_key_exists('ovos_codesafe_core_auto_update', $GLOBALS['wp']['options']) === false
			&& array_key_exists('auto_update_core_minor', $GLOBALS['wp']['options']) === false;
	}
	
	protected function network(
		bool $main,
	): void
	{
		$GLOBALS['wp']['multisite'] = true;
		$GLOBALS['wp']['main_site'] = $main;
		$GLOBALS['wp']['user_id'] = 7;
	}
	
	protected function settings(): Settings
	{
		$config = new Config();
		
		return new Settings($config, new Sender($config), '/srv/wp/wp-content/plugins/ovos-codesafe/ovos-codesafe.php',
			new ScanRunner($config, new Scan($config)));
	}
}
