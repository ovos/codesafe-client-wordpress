<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function function_exists;
use function rawurlencode;

/**
 * Prints the async browser-client bootstrap: a pre-init stub that buffers
 * error/unhandledrejection events (capture phase, so resource failures
 * are seen too) plus the init() options, then a literal async <script>
 * tag; the client drains the stub on arrival and replays the buffer
 * through its normal filters. A slow or missing script never blocks the
 * page, and errors thrown before it arrives are no longer lost. The
 * client itself is bundled — wordpress.org forbids loading executable
 * code from external servers, and a pinned copy beats depending on the
 * console instance being reachable at page load; the ?ver= cache-buster
 * keeps stub and client in lockstep (both ship with the plugin).
 */
class JsClient
{
	public function __construct(
		protected Config $config,
		protected string $file,
	)
	{
	}
	
	public function register(): void
	{
		add_action('wp_head', [$this, 'printLoader'], 1);
		
		if($this->config->jsAdmin())
		{
			add_action('admin_head', [$this, 'printLoader'], 1);
			add_action('login_head', [$this, 'printLoader'], 1);
		}
	}
	
	public function isEnabled(): bool
	{
		return $this->config->enabled()
			&& $this->config->jsEnabled()
			&& $this->config->url() !== ''
			&& $this->config->jsKey() !== '';
	}
	
	public function printLoader(): void
	{
		if($this->isEnabled() === false)
		{
			return;
		}
		
		$src = plugins_url('assets/console-client.js', $this->file)
			. '?ver=' . rawurlencode(Plugin::VERSION);
			
		$options = [
			'url' => $this->config->url(),
			'key' => $this->config->jsKey(),
			'logLevel' => $this->config->logLevel(),
		];
		
		if($this->config->release() !== '')
		{
			$options['release'] = $this->config->release();
		}
		
		// wp_get_environment_type() answers even unconfigured ('production'),
		// so this is always set — the console badges only non-production
		if($this->config->environment() !== '')
		{
			$options['environment'] = $this->config->environment();
		}
		
		// the same tags the PHP reports carry, on every browser report
		if($this->config->tags() !== [])
		{
			$options['tags'] = $this->config->tags();
		}
		
		// the client defaults to trace: true — only the opt-out is emitted
		if($this->config->jsTrace() === false)
		{
			$options['trace'] = false;
		}
		
		if($this->config->snapshot())
		{
			// masked DOM snapshot with the first error per page load
			// (replay-lite); inputs/scripts are stripped client-side
			$options['snapshot'] = true;
			
			if($this->config->snapshotStyles())
			{
				$options['snapshotStyles'] = true;
			}
		}
		
		$context = '';
		
		if(function_exists('get_current_user_id') && (int)get_current_user_id() > 0)
		{
			$context = "\n\toptions.context = function () { return {userId: "
				. wp_json_encode((string)get_current_user_id())
				. "}; };";
		}
		
		// phpcs:disable WordPress.Security.EscapeOutput.OutputNotEscaped -- inline bootstrap script; every dynamic value is wp_json_encode()d or esc_url()d
		echo "<script>\n"
			. "(function (w) {\n"
			. "\tvar stub = {events: [], calls: [], options: null};\n"
			. "\tstub.capture = function (event) {\n"
			. "\t\tif (stub.events.length < 50) { stub.events.push(event); }\n"
			. "\t};\n"
			. "\tw.addEventListener('error', stub.capture, true);\n"
			. "\tw.addEventListener('unhandledrejection', stub.capture);\n"
			. "\tw.ovosConsole = {\n"
			. "\t\tstub: stub,\n"
			. "\t\tinit: function (options) { stub.options = options; },\n"
			. "\t\tcaptureException: function () { stub.calls.push(['captureException'].concat([].slice.call(arguments))); },\n"
			. "\t\tcaptureMessage: function () { stub.calls.push(['captureMessage'].concat([].slice.call(arguments))); },\n"
			. "\t\tflush: function () {}\n"
			. "\t};\n"
			. "\tvar options = " . wp_json_encode($options, JSON_UNESCAPED_SLASHES) . ";" . $context . "\n"
			. "\tw.ovosConsole.init(options);\n"
			. "})(window);\n"
			. "</script>\n"
			// a literal tag, not createElement injection — the preload scanner
			// only discovers literal tags, so the fetch starts during the parse
			. '<script async src="' . esc_url($src) . '"></script>' . "\n";
		// phpcs:enable WordPress.Security.EscapeOutput.OutputNotEscaped
	}
}
