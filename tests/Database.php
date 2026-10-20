<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Database as PluginDatabase;
use Ovos\Test;
use Ovos\Test\Internal;

use function add_action;
use function count;
use function str_contains;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The integrity scan's database detectors without WordPress: the shim's
 * _get_cron_array() and has_action() stand in for the site.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Database extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: a scheduled hook nothing listens to is a cron_orphan that names
	 * its schedule and next run in the detail and carries no mtime, since the
	 * next run is no write and codesafe dates a row's mtime against attack
	 * waves; a hook with a listener is no finding. Falsify: pass the next run
	 * as the mtime — the console matches a schedule against a probing address.
	 */
	public function aCronOrphanCarriesNoDateAndNamesTheNextRun(): bool
	{
		$GLOBALS['wp']['cron'] = [1_792_500_000 => [
			'gone_plugin_cleanup' => ['abc' => ['schedule' => 'hourly']],
			'kept_hook' => ['def' => ['schedule' => 'daily']],
		]];
		add_action('kept_hook', 'strlen');
		
		$database = new class extends PluginDatabase
		{
			public function cronFindings(): array
			{
				$stats = ['cron_hooks' => 0];
				
				return $this->cron($stats);
			}
		};
		$findings = $database->cronFindings();
		
		return count($findings) === 1
			&& $findings[0]['detector'] === 'cron_orphan'
			&& $findings[0]['path'] === 'options/cron/gone_plugin_cleanup'
			&& isset($findings[0]['mtime']) === false
			&& str_contains($findings[0]['detail'], 'hourly, next 2026-10-20 12:40');
	}
}
