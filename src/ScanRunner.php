<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Throwable;

use function add_action;
use function add_option;
use function add_query_arg;
use function admin_url;
use function check_admin_referer;
use function current_user_can;
use function delete_option;
use function esc_html__;
use function function_exists;
use function get_option;
use function ini_get;
use function is_admin;
use function is_array;
use function is_wp_error;
use function json_encode;
use function max;
use function min;
use function register_shutdown_function;
use function time;
use function update_option;
use function wp_die;
use function wp_remote_post;
use function wp_remote_retrieve_response_code;
use function wp_safe_redirect;

use const JSON_INVALID_UTF8_SUBSTITUTE;
use const JSON_PARTIAL_OUTPUT_ON_ERROR;
use const PHP_SAPI;

/**
 * Runs the integrity scan (Scan) in two ways over one persisted position:
 *
 * - SCAN NOW: a button on the settings page. The admin who just installed
 *   the plugin on a site they suspect wants the answer in this sitting, so
 *   an admin-post request spends up to fifteen seconds on the walk and
 *   redirects back; the page shows the progress and re-submits itself until
 *   the pass is complete.
 * - BACKGROUND: opt-in (the `scan` setting), a shutdown-time chunk of half a
 *   second per request after the response went out, one full pass per
 *   interval — the Inventory idiom, no WP-Cron, not gated on APCu (shared
 *   hosting, this plugin's audience, has neither reliably).
 *
 * Both persist the walk's position in ONE option between requests and hold
 * a lock while they advance it, so a button press and a shutdown chunk
 * never walk the same pass twice. A completed pass becomes the report: kept
 * here for wp-admin, posted to the console when one is connected.
 */
class ScanRunner
{
	public const ACTION = 'ovos_codesafe_scan';
	
	/**
	 * {state: <the pass in progress or null>, last: {finished, sent, report}}
	 */
	public const OPTION = 'ovos_codesafe_scan';
	
	public const LOCK = 'ovos_codesafe_scan_lock';
	
	/**
	 * A lock older than this was left by a request that died mid-chunk
	 */
	protected const LOCK_TTL = 90;
	
	protected const BUDGET_BACKGROUND_MS = 500;
	
	protected const BUDGET_MANUAL_MS = 15000;
	
	protected const DAY = 86400;
	
	public function __construct(
		protected Config $config,
		protected Scan $scan,
	)
	{
	}
	
	public function register(): void
	{
		if($this->config->scan() && $this->config->enabled())
		{
			// after the Sender, the Rollup and the Inventory: the walk is
			// the least urgent thing a shutdown does, and it runs after the
			// response is gone
			register_shutdown_function([$this, 'maybeContinue']);
		}
		
		if(is_admin())
		{
			add_action('admin_post_' . self::ACTION, [$this, 'handleManual']);
		}
	}
	
	/**
	 * The pass in progress, or null
	 */
	public function state(): ?array
	{
		$state = $this->option()['state'] ?? null;
		
		return is_array($state) ? $state : null;
	}
	
	/**
	 * The last completed pass: {finished, sent, report}, or null
	 *
	 * @return array{finished: int, sent: int, report: array}|null
	 */
	public function last(): ?array
	{
		$last = $this->option()['last'] ?? null;
		
		return is_array($last) && is_array($last['report'] ?? null) ? $last : null;
	}
	
	/**
	 * When the next background pass is due — null while the feature is off
	 */
	public function dueAt(): ?int
	{
		if($this->config->scan() === false)
		{
			return null;
		}
		
		$last = $this->last();
		
		return $last === null ? time() : (int)$last['finished'] + $this->config->scanInterval() * self::DAY;
	}
	
	/**
	 * The shutdown chunk: continue a pass in progress, or start one when the
	 * interval has elapsed. Never on the CLI, never when another request
	 * holds the pass, never past its half-second.
	 */
	public function maybeContinue(): void
	{
		try
		{
			if(PHP_SAPI === 'cli' || $this->config->scan() === false || $this->config->enabled() === false)
			{
				return;
			}
			
			$stored = $this->option();
			$running = is_array($stored['state'] ?? null);
			$due = $this->dueAt();
			
			if($running === false && ($due === null || $due > time()))
			{
				return;
			}
			
			if($this->lock() === false)
			{
				return;
			}
			
			try
			{
				if(function_exists('fastcgi_finish_request'))
				{
					@fastcgi_finish_request();
				}
				
				$this->run('background', self::BUDGET_BACKGROUND_MS);
			}
			finally
			{
				// released only by the request that took it — a failed
				// lock() above returned before this block
				$this->unlock();
			}
		}
		catch(Throwable)
		{
			// telemetry must never break the host site
		}
	}
	
	/**
	 * admin-post: one round of the manual scan, then back to the settings
	 * page with the outcome in the query (running | done | busy)
	 */
	public function handleManual(): void
	{
		if(current_user_can('manage_options') === false)
		{
			wp_die(esc_html__('Insufficient permissions.', 'ovos-codesafe'));
		}
		
		check_admin_referer(self::ACTION);
		
		$outcome = 'busy';
		
		if($this->lock())
		{
			try
			{
				$outcome = $this->run('manual', $this->manualBudget());
			}
			catch(Throwable)
			{
				$outcome = 'failed';
			}
			finally
			{
				$this->unlock();
			}
		}
		
		wp_safe_redirect(add_query_arg('ovos-codesafe-scan', $outcome,
			admin_url('options-general.php?page=' . Settings::PAGE)));
		
		exit;
	}
	
	/**
	 * Advance the pass (starting one when none is in progress) within the
	 * budget and persist the position; a completed pass is finished into
	 * the report. A button press takes over a background pass — same walk,
	 * more time per round.
	 */
	protected function run(
		string $mode,
		int $budgetMs,
	): string
	{
		$stored = $this->option();
		$state = is_array($stored['state'] ?? null) ? $stored['state'] : $this->scan->start($mode);
		
		if($mode === 'manual')
		{
			$state['mode'] = 'manual';
		}
		
		$state = $this->scan->advance($state, $budgetMs);
		
		if($state['done'] === true)
		{
			$this->finish($stored, $state);
			
			return 'done';
		}
		
		$stored['state'] = $state;
		
		update_option(self::OPTION, $stored, false);
		
		return 'running';
	}
	
	protected function finish(
		array $stored,
		array $state,
	): void
	{
		$report = $this->scan->report($state, 'wordpress/' . Plugin::VERSION);
		
		$stored['state'] = null;
		$stored['last'] = [
			'finished' => time(),
			'sent' => $this->send($report),
			'report' => $report,
		];
		
		update_option(self::OPTION, $stored, false);
	}
	
	/**
	 * The report to the console's files ingest: the HTTP status back, -1
	 * when no console is configured, 0 when it is out of reach. Synchronous
	 * through the WP HTTP API — the manual round wants the status for its
	 * notice, and the background round runs after fastcgi_finish_request.
	 */
	protected function send(
		array $report,
	): int
	{
		return self::post($this->config, $report);
	}
	
	/**
	 * One integrity report to the console's files ingest — the walk's and
	 * the executed-file watch's (Entries) alike: the HTTP status back, -1
	 * when no console is configured, 0 when it is out of reach
	 */
	public static function post(
		Config $config,
		array $report,
	): int
	{
		if($config->url() === '' || $config->apiKey() === '')
		{
			return -1;
		}
		
		$response = wp_remote_post($config->url() . '/api/v1/ingest/files', [
			'timeout' => 5,
			'headers' => [
				'Content-Type' => 'application/json',
				'X-Codesafe-Key' => $config->apiKey(),
				'X-Console-Key' => $config->apiKey(),
			],
			'body' => (string)json_encode($report,
				JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR),
			'sslverify' => (bool)Legacy::filter('ovos_codesafe_sslverify', true),
		]);
		
		if(is_wp_error($response))
		{
			return 0;
		}
		
		return (int)wp_remote_retrieve_response_code($response);
	}
	
	/**
	 * Up to fifteen seconds, and always five short of max_execution_time
	 */
	protected function manualBudget(): int
	{
		$limit = (int)ini_get('max_execution_time');
		
		return $limit > 0
			? max(2000, min(self::BUDGET_MANUAL_MS, ($limit - 5) * 1000))
			: self::BUDGET_MANUAL_MS;
	}
	
	protected function option(): array
	{
		$stored = get_option(self::OPTION);
		
		return is_array($stored) ? $stored : [];
	}
	
	/**
	 * add_option() is an INSERT: it fails when the row exists, which makes
	 * it the one atomic primitive the options table offers. A lock older
	 * than LOCK_TTL belongs to a request that died and is taken over.
	 */
	protected function lock(): bool
	{
		$held = get_option(self::LOCK);
		
		if($held !== false && time() - (int)$held < self::LOCK_TTL)
		{
			return false;
		}
		
		if($held !== false)
		{
			delete_option(self::LOCK);
		}
		
		return add_option(self::LOCK, time(), '', false);
	}
	
	protected function unlock(): void
	{
		delete_option(self::LOCK);
	}
}
