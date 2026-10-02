<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function function_exists;
use function get_option;
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
	
	public function __construct(
		protected Config $config,
		protected Sender $sender,
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
	 * detect — enforce alone is inert (Config::shieldEnforce)
	 *
	 * @return array<string, bool>
	 */
	public function features(): array
	{
		$detect = $this->config->shieldDetect() && $this->config->shieldKill() === false;
		
		return [
			'errors' => true,
			'not_found' => $this->config->report404(),
			'rollups' => $this->config->rollups(),
			'security' => $this->config->securityEvents(),
			'inventory' => $this->config->inventory(),
			'auto_update' => $this->config->autoUpdateVulnerable(),
			'files' => $this->config->scan(),
			'entry_watch' => $this->config->entryWatch(),
			'shield_detect' => $detect,
			'shield_enforce' => $detect && $this->config->shieldEnforce(),
			'js' => $this->config->jsEnabled(),
		];
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
		$signature = md5(Plugin::VERSION . '|' . json_encode($features));
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
