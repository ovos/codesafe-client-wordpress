<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function array_push;
use function array_slice;
use function array_unique;
use function array_values;
use function constant;
use function defined;
use function function_exists;
use function get_blog_option;
use function get_main_site_id;
use function is_main_site;
use function is_multisite;
use function is_super_admin;
use function max;
use function mb_substr;
use function min;
use function preg_match;
use function preg_split;
use function rtrim;
use function strtolower;
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
		'trusted_proxy_header' => '',
		'trusted_proxies' => '',
	];
	
	/**
	 * The keys whose effect reaches past this site on a multisite network: the
	 * Shield's two boxes and the executed-file watch drive ONE store under
	 * WP_CONTENT_DIR, and the prepend layer that reads it runs before
	 * WordPress knows which site a request is for. So on a network only the
	 * main site's word counts, and only a super admin may give it (security
	 * audit 2026-10-03 M14); the trusted proxy rides the same consent file
	 */
	public const NETWORK_KEYS = ['shield_detect', 'shield_enforce', 'entry_watch', 'trusted_proxy_header', 'trusted_proxies'];
	
	/**
	 * The CIDR ranges `cloudflare` stands for in trusted_proxies — Cloudflare's
	 * published edge list (cloudflare.com/ips), bundled: the plugin never
	 * fetches it
	 */
	public const CLOUDFLARE = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
		'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
		'198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
		'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
		'2a06:98c0::/29', '2c0f:f248::/32'];
	
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
		return (bool)$this->get('shield_detect') && $this->ownsSharedStore();
	}
	
	/**
	 * "Block detected exploits": answer 403 to a request a PROVEN rule matches —
	 * inert without detection; read per request, never cached
	 */
	public function shieldEnforce(): bool
	{
		return (bool)$this->get('shield_enforce') && $this->ownsSharedStore();
	}
	
	/**
	 * Whether this site drives the store the Shield and the executed-file
	 * watch keep under WP_CONTENT_DIR (NETWORK_KEYS): a single site always; on
	 * a multisite network the main site alone — a subsite's boxes would
	 * otherwise pull its own console's rules into the file every site of the
	 * network is judged by. The network's Shield is the main site's
	 */
	public function ownsSharedStore(): bool
	{
		return function_exists('is_multisite') === false
			|| is_multisite() === false
			|| (function_exists('is_main_site') && is_main_site());
	}
	
	/**
	 * Whether this request's user may change the NETWORK_KEYS: anyone who may
	 * open the settings page on a single site; on a network a super admin, on
	 * the main site
	 */
	public function mayChangeNetworkKeys(): bool
	{
		if(function_exists('is_multisite') === false || is_multisite() === false)
		{
			return true;
		}
		
		return $this->ownsSharedStore() && is_super_admin();
	}
	
	/**
	 * The header a trusted proxy names the visitor's address in
	 * (CF-Connecting-IP, X-Forwarded-For, X-Real-IP …), '' for none — then
	 * REMOTE_ADDR is the visitor, which is the default and the only safe
	 * answer without a proxy (security audit 2026-10-03 M5). A server's
	 * property, so on a network the main site's
	 */
	public function trustedProxyHeader(): string
	{
		$header = trim((string)$this->networkValue('trusted_proxy_header'));
		
		return preg_match('~^[A-Za-z0-9-]{1,64}$~', $header) === 1 ? $header : '';
	}
	
	/**
	 * The ranges whose REMOTE_ADDR is a proxy the header above may be taken
	 * from: CIDRs or bare addresses, split on commas and whitespace, and the
	 * word `cloudflare` for Cloudflare's published edge list (CLOUDFLARE).
	 * Empty means the header is never read — a header any client can send is
	 * worth only the proxy that set it
	 *
	 * @return list<string>
	 */
	public function trustedProxies(): array
	{
		$tokens = preg_split('~[,;\s]+~', trim((string)$this->networkValue('trusted_proxies')), -1, PREG_SPLIT_NO_EMPTY);
		$ranges = [];
		
		foreach($tokens === false ? [] : $tokens as $token)
		{
			if(strtolower($token) === 'cloudflare')
			{
				array_push($ranges, ...self::CLOUDFLARE);
				
				continue;
			}
			
			if(preg_match('~^[0-9A-Fa-f:.]+(?:/\d{1,3})?$~', $token) === 1)
			{
				$ranges[] = $token;
			}
		}
		
		return array_values(array_unique(array_slice($ranges, 0, 256)));
	}
	
	/**
	 * A NETWORK_KEYS value: the constant, else on a network's subsite the main
	 * site's stored value, else this site's
	 */
	protected function networkValue(
		string $key,
	): mixed
	{
		if($this->isConstant($key) || $this->ownsSharedStore() || function_exists('get_blog_option') === false)
		{
			return $this->get($key);
		}
		
		$main = (array)get_blog_option((int)get_main_site_id(), self::OPTION, []);
		
		return $main[$key] ?? self::DEFAULTS[$key] ?? null;
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
		return (bool)$this->get('entry_watch') && $this->ownsSharedStore();
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
