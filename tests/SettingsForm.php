<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Scan;
use Ovos\Codesafe\ScanRunner;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Settings;
use Ovos\Test;
use Ovos\Test\Internal;

use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * Settings::sanitize() is WordPress's sanitize_callback for the whole option:
 * whatever reaches it — the form, the connect flow, an update_option() of a
 * plugin or a script — is cleaned field by field, a field missing included.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class SettingsForm extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: an input that leaves fields out saves each at its unticked or
	 * default value without a notice, and an interval outside 1 and 7 days
	 * saves as the default.
	 * Falsify: read scan_interval without a fallback — a partial input
	 * raises an undefined-key warning.
	 */
	public function aPartialInputSavesWithoutANotice(): bool
	{
		$empty = $this->settings()->sanitize([]);
		$daily = $this->settings()->sanitize(['scan_interval' => '1']);
		$odd = $this->settings()->sanitize(['scan_interval' => '3']);
		
		return $empty['scan_interval'] === Config::DEFAULTS['scan_interval']
			&& $empty['url'] === ''
			&& $empty['enabled'] === false
			&& $empty['log_level'] === Config::DEFAULTS['log_level']
			&& $daily['scan_interval'] === 1
			&& $odd['scan_interval'] === Config::DEFAULTS['scan_interval'];
	}
	
	protected function settings(): Settings
	{
		$config = new Config();
		
		return new Settings($config, new Sender($config), '/srv/wp/wp-content/plugins/ovos-codesafe/ovos-codesafe.php',
			new ScanRunner($config, new Scan($config)));
	}
}
