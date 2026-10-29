<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Prepend;

use function function_exists;
use function get_option;
use function in_array;
use function is_array;
use function json_encode;
use function md5;
use function register_shutdown_function;
use function time;
use function update_option;

use const PHP_SAPI;

/**
 * The hello (codesafe docs/plans/project-features-live.md): which of this
 * plugin's own switches are on, told to codesafe once a day and whenever one
 * of them changes.
 *
 * Every feature is a lock with two keys — the project's switch in codesafe
 * and the box on this site's settings page — and codesafe only ever saw its
 * own: a project with CVE on in codesafe and the inventory box unticked here
 * wore a CVE chip on SETUP › PROJECTS for a feature the site never ran. With
 * the hello, codesafe dims that chip and says why.
 *
 * The option keeps the signature last told (the plugin's version and the
 * switches) and when, so a request costs one option read until a day is up
 * or a box changed. A refused or unreachable codesafe is asked again an hour
 * later, one without the endpoint (404, older than the hello) a day later.
 */
final class Hello
{
	public const OPTION = 'ovos_codesafe_hello';
	
	public const DAY = 86400;
	
	public const RETRY = 3600;
	
	/**
	 * @param ?bool $apcu whether APCu is there to count the rollups in;
	 * null asks this SAPI (Rollup::hasApcu)
	 * @param ?string $prepend the prepend layer's state (Prepend::status());
	 * null asks this site (prependState())
	 */
	public function __construct(
		protected Config $config,
		protected Sender $sender,
		protected ?bool $apcu = null,
		protected ?string $prepend = null,
	)
	{
	}
	
	/** after the Sender's handler, so the response is out before the post */
	public function register(): void
	{
		register_shutdown_function([$this, 'maybeSend']);
	}
	
	/**
	 * The switches in codesafe's words. The Shield's two count only where the
	 * adapter really runs: detect without the kill constant, enforce on top of
	 * detect — enforce alone is inert (Config::shieldEnforce); the rollups
	 * only where APCu lets them count. `shield_prepend` says whether PHP's
	 * auto_prepend_file runs the Shield before WordPress, whatever its boxes
	 * say: codesafe reads it beside shield_detect
	 *
	 * @return array<string, bool>
	 */
	public function features(): array
	{
		$detect = $this->config->shieldDetect() && $this->config->shieldKill() === false;
		
		return [
			'errors' => true,
			'not_found' => $this->config->report404(),
			'rollups' => $this->config->rollups() && ($this->apcu ?? Rollup::hasApcu()),
			'security' => $this->config->securityEvents(),
			'inventory' => $this->config->inventory(),
			'auto_update' => $this->config->autoUpdateVulnerable(),
			'files' => $this->config->scan(),
			'entry_watch' => $this->config->entryWatch(),
			'shield_detect' => $detect,
			'shield_enforce' => $detect && $this->config->shieldEnforce(),
			// the Shield off by the server's constant — codesafe says so instead of a silent site
			'shield_kill' => $this->config->shieldKill(),
			// an older stub PHP still names (this plugin's prepend.php, ovos-console's) runs the layer: live as well
			'shield_prepend' => in_array($this->prepend ?? self::prependState(), ['active', 'legacy'], true),
			'js' => $this->config->jsEnabled(),
		];
	}
	
	/**
	 * The prepend layer's state as the settings page reads it (Prepend::status()),
	 * off the store's paths as named, creating no directory; `unavailable` where
	 * the content directory is unknown
	 */
	public static function prependState(): string
	{
		$paths = Adapter::storePaths();
		if($paths['stub'] === '')
		{
			return 'unavailable';
		}
		
		return Prepend::status($paths['stub'], null, Adapter::legacyStub() ?: null)['state'];
	}
	
	/**
	 * Shutdown: tell codesafe when the switches changed or a day has passed —
	 * whether a hello went out and was taken
	 */
	public function maybeSend(
		?int $now = null,
	): bool
	{
		if($this->sender->isEnabled() === false)
		{
			return false;
		}
		
		$now ??= time();
		$features = $this->features();
		// the environment rides the hello (Sender::hello()): a changed one is told at once
		$signature = md5(Plugin::VERSION . '|' . $this->config->environment() . '|' . json_encode($features));
		$told = get_option(self::OPTION, []);
		$told = is_array($told) ? $told : [];
		
		if((int)($told['next'] ?? 0) > $now
			|| (($told['sig'] ?? '') === $signature && $now - (int)($told['at'] ?? 0) < self::DAY))
		{
			return false;
		}
		
		// the response is already sent — the post stays invisible to the visitor
		if(function_exists('fastcgi_finish_request') && PHP_SAPI !== 'cli')
		{
			fastcgi_finish_request();
		}
		
		$code = $this->sender->hello($features);
		if($code >= 200 && $code < 300)
		{
			update_option(self::OPTION, ['sig' => $signature, 'at' => $now, 'next' => 0], false);
			
			return true;
		}
		
		update_option(self::OPTION, [
			'sig' => (string)($told['sig'] ?? ''),
			'at' => (int)($told['at'] ?? 0),
			'next' => $now + ($code === 404 ? self::DAY : self::RETRY),
		], false);
		
		return false;
	}
}
