<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function array_slice;
use function constant;
use function defined;
use function max;
use function mb_substr;
use function min;
use function preg_split;
use function rtrim;
use function strtoupper;
use function trim;

use const PREG_SPLIT_NO_EMPTY;

/**
 * Plugin configuration: the ovos_codesafe option, with every key
 * overridable by a CODESAFE_<KEY> constant in wp-config.php —
 * deploy-time configuration for sites we manage; a defined constant
 * locks the field in the settings UI.
 */
class Config
{
	public const OPTION = 'ovos_codesafe';
	
	public const DEFAULTS = [
		'enabled' => false,
		'url' => '',
		'api_key' => '',
		'log_level' => 4,
		'report_404' => false,
		'rollups' => false,
		'security_events' => false,
		'inventory' => false,
		'auto_update_vulnerable' => false,
		'shield_detect' => false,
		'shield_enforce' => false,
		'shield_kill' => false,
		'scan' => false,
		'scan_interval' => 7,
		'entry_watch' => true,
		'release' => '',
		'environment' => '',
		'tags' => '',
		'js_enabled' => true,
		'js_key' => '',
		'js_trace' => true,
		'request_body' => Body::MODE_STRUCTURE,
		'snapshot' => false,
		'snapshot_styles' => false,
		'js_admin' => false,
	];
	
	protected ?array $settings = null;
	
	public function get(
		string $key,
	): mixed
	{
		if($this->isConstant($key))
		{
			return constant($this->constantName($key));
		}
		
		$this->settings ??= (array)get_option(self::OPTION, []);
		
		return $this->settings[$key] ?? self::DEFAULTS[$key] ?? null;
	}
	
	public function isConstant(
		string $key,
	): bool
	{
		return defined($this->constantName($key));
	}
	
	/**
	 * CODESAFE_<KEY>, or the plugin's first name for it, OVOS_CONSOLE_<KEY>,
	 * when only that one is defined — a wp-config written for ovos-console
	 * keeps working
	 */
	public function constantName(
		string $key,
	): string
	{
		$name = 'CODESAFE_' . strtoupper($key);
		$legacy = Legacy::CONSTANT_PREFIX . strtoupper($key);
		
		return defined($name) === false && defined($legacy) ? $legacy : $name;
	}
	
	/**
	 * Drops the option cache — used after the settings page saved
	 */
	public function refresh(): void
	{
		$this->settings = null;
	}
	
	public function enabled(): bool
	{
		return (bool)$this->get('enabled');
	}
	
	public function url(): string
	{
		return rtrim(trim((string)$this->get('url')), '/');
	}
	
	public function apiKey(): string
	{
		return trim((string)$this->get('api_key'));
	}
	
	public function logLevel(): int
	{
		return max(0, min(7, (int)$this->get('log_level')));
	}
	
	/**
	 * How much of a request BODY leaves this site — one of Body::MODES.
	 *
	 * Validated through Body::mode() rather than trusted: an option row edited
	 * by hand, or written by a future version, must not turn into "no mode"
	 * and take the body decision with it. Anything unrecognised reads as the
	 * default, which is the conservative end — never `full`.
	 */
	public function requestBody(): string
	{
		return Body::mode((string)$this->get('request_body'));
	}
	
	public function report404(): bool
	{
		return (bool)$this->get('report_404');
	}
	
	public function rollups(): bool
	{
		return (bool)$this->get('rollups');
	}
	
	public function inventory(): bool
	{
		return (bool)$this->get('inventory');
	}
	
	/**
	 * Switch on WordPress's automatic update for the plugins the console
	 * names as vulnerable AND probed (Inventory::apply) — opt-in at both ends
	 */
	public function autoUpdateVulnerable(): bool
	{
		return (bool)$this->get('auto_update_vulnerable');
	}
	
	public function securityEvents(): bool
	{
		return (bool)$this->get('security_events');
	}
	
	/**
	 * "Exploit detection": pull this site's exploit rules from the console and
	 * OBSERVE every request (Shield\Adapter) — a match is reported, nothing is
	 * blocked
	 */
	public function shieldDetect(): bool
	{
		return (bool)$this->get('shield_detect');
	}
	
	/**
	 * "Block detected exploits": answer 403 to a request a PROVEN rule matches —
	 * inert without detection; read per request, never cached
	 */
	public function shieldEnforce(): bool
	{
		return (bool)$this->get('shield_enforce');
	}
	
	/**
	 * The kill switch — the CODESAFE_SHIELD_KILL constant, no checkbox: the
	 * shield is off entirely and calls no one, for a host that must never
	 */
	public function shieldKill(): bool
	{
		return (bool)$this->get('shield_kill');
	}
	
	/**
	 * The background integrity scan (ScanRunner) — the Scan now button on the
	 * settings page does not depend on it
	 */
	public function scan(): bool
	{
		return (bool)$this->get('scan');
	}
	
	/**
	 * Days between background passes, daily to monthly
	 */
	public function scanInterval(): int
	{
		return max(1, min(30, (int)$this->get('scan_interval')));
	}
	
	/**
	 * The executed-file watch on the prepend layer (Entries): the PHP file
	 * PHP is about to run, recorded before WordPress and judged on the next
	 * request — on by default, since pointing PHP at the stub is the
	 * operator's own deliberate act and the watch only reads;
	 * CODESAFE_ENTRY_WATCH locks it either way
	 */
	public function entryWatch(): bool
	{
		return (bool)$this->get('entry_watch');
	}
	
	public function release(): string
	{
		return mb_substr(trim((string)$this->get('release')), 0, 64);
	}
	
	/**
	 * Deployment stage sent with every report. An explicit setting (or the
	 * CODESAFE_ENVIRONMENT constant) wins; unset, WP's own
	 * wp_get_environment_type() goes out — production included (the console
	 * stores and filters it, but only badges anything else).
	 */
	public function environment(): string
	{
		$environment = mb_substr(trim((string)$this->get('environment')), 0, 64);
		
		return $environment !== '' ? $environment : (string)wp_get_environment_type();
	}
	
	/**
	 * The tags stamped on every report (ovos/console docs/plans/event-tags.md):
	 * the Tags setting (or the CODESAFE_TAGS constant), one comma list —
	 * split on commas, semicolons and whitespace, trimmed, at most ten (the
	 * console's own cap per event). The console lowercases and validates each.
	 *
	 * @return string[]
	 */
	public function tags(): array
	{
		$tokens = preg_split('~[,;\s]+~', trim((string)$this->get('tags')), -1, PREG_SPLIT_NO_EMPTY);
		
		return array_slice($tokens === false ? [] : $tokens, 0, 10);
	}
	
	public function jsEnabled(): bool
	{
		return (bool)$this->get('js_enabled');
	}
	
	public function jsKey(): string
	{
		return trim((string)$this->get('js_key'));
	}
	
	public function jsTrace(): bool
	{
		return (bool)$this->get('js_trace');
	}
	
	public function snapshot(): bool
	{
		return (bool)$this->get('snapshot');
	}
	
	public function snapshotStyles(): bool
	{
		return (bool)$this->get('snapshot_styles');
	}
	
	public function jsAdmin(): bool
	{
		return (bool)$this->get('js_admin');
	}
}
