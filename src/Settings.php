<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function array_keys;
use function implode;
use function in_array;
use function is_array;
use function max;
use function mb_substr;
use function min;
use function sprintf;
use function str_starts_with;
use function strtoupper;
use function trim;

/**
 * Settings → ovos codesafe.
 *
 * Values locked by an CODESAFE_* constant in wp-config.php render
 * disabled and keep their stored value on save; the API key is
 * write-only (blank keeps the stored key).
 */
class Settings
{
	public const PAGE = 'ovos-codesafe';
	
	protected const LEVELS = [
		0 => 'emergency',
		1 => 'alert',
		2 => 'critical',
		3 => 'error',
		4 => 'warning',
		5 => 'notice',
		6 => 'info',
		7 => 'debug',
	];
	
	public function __construct(
		protected Config $config,
		protected Sender $sender,
		protected string $file,
		protected ScanRunner $runner,
		protected ?Entries $entries = null,
	)
	{
	}
	
	public function register(): void
	{
		add_action('admin_menu', [$this, 'addPage']);
		add_action('admin_init', [$this, 'registerSetting']);
		add_action('admin_post_ovos_codesafe_test', [$this, 'handleTest']);
		add_filter('plugin_action_links_' . plugin_basename($this->file),
			[$this, 'actionLinks']);
	}
	
	public function actionLinks(
		array $links,
	): array
	{
		$url = admin_url('options-general.php?page=' . self::PAGE);
		
		array_unshift($links,
			'<a href="' . esc_url($url) . '">'
			. esc_html__('Settings', 'ovos-codesafe') . '</a>');
			
		return $links;
	}
	
	public function addPage(): void
	{
		add_options_page(
			__('ovos codesafe', 'ovos-codesafe'),
			__('ovos codesafe', 'ovos-codesafe'),
			'manage_options',
			self::PAGE,
			[$this, 'renderPage']);
	}
	
	public function registerSetting(): void
	{
		register_setting('ovos_codesafe', Config::OPTION, [
			'type' => 'array',
			'sanitize_callback' => [$this, 'sanitize'],
			'default' => Config::DEFAULTS,
		]);
	}
	
	/**
	 * @param mixed $input
	 */
	public function sanitize(
		$input,
	): array
	{
		$input = is_array($input) ? $input : [];
		$stored = (array)get_option(Config::OPTION, []);
		
		$clean = [
			'enabled' => $this->truthy($input['enabled'] ?? ''),
			'url' => esc_url_raw(trim((string)($input['url'] ?? ''))),
			'api_key' => trim((string)($input['api_key'] ?? '')),
			'log_level' => max(0, min(7, (int)($input['log_level'] ?? Config::DEFAULTS['log_level']))),
			'report_404' => $this->truthy($input['report_404'] ?? ''),
			'rollups' => $this->truthy($input['rollups'] ?? ''),
			'security_events' => $this->truthy($input['security_events'] ?? ''),
			'inventory' => $this->truthy($input['inventory'] ?? ''),
			'auto_update_vulnerable' => $this->truthy($input['auto_update_vulnerable'] ?? ''),
			'shield_detect' => $this->truthy($input['shield_detect'] ?? ''),
			'shield_enforce' => $this->truthy($input['shield_enforce'] ?? ''),
			'request_body' => Body::mode((string)($input['request_body'] ?? '')),
			'scan' => $this->truthy($input['scan'] ?? ''),
			'scan_interval' => in_array((int)($input['scan_interval'] ?? 7), [1, 7], true)
				? (int)$input['scan_interval']
				: 7,
			'entry_watch' => $this->truthy($input['entry_watch'] ?? ''),
			'release' => mb_substr(sanitize_text_field((string)($input['release'] ?? '')), 0, 64),
			'environment' => mb_substr(sanitize_text_field((string)($input['environment'] ?? '')), 0, 64),
			// a comma list of tags; Config::tags() splits it, the console validates each
			'tags' => mb_substr(sanitize_text_field((string)($input['tags'] ?? '')), 0, 400),
			'js_enabled' => $this->truthy($input['js_enabled'] ?? ''),
			'js_key' => sanitize_text_field((string)($input['js_key'] ?? '')),
			'js_trace' => $this->truthy($input['js_trace'] ?? ''),
			'snapshot' => $this->truthy($input['snapshot'] ?? ''),
			'snapshot_styles' => $this->truthy($input['snapshot_styles'] ?? ''),
			'js_admin' => $this->truthy($input['js_admin'] ?? ''),
		];
		
		// write-only: a blank key keeps the stored one
		if($clean['api_key'] === '')
		{
			$clean['api_key'] = (string)($stored['api_key'] ?? '');
		}
		
		// constants win — never let the form overwrite a locked value
		foreach(array_keys($clean) as $key)
		{
			if($this->config->isConstant($key))
			{
				$clean[$key] = $stored[$key] ?? Config::DEFAULTS[$key];
			}
		}
		
		return $clean;
	}
	
	/**
	 * Checkbox value → bool, tolerating an already-sanitized boolean: on the
	 * first-ever save core routes update_option() into add_option(), which
	 * sanitizes the sanitized array a second time (trac #21989) — a strict
	 * '1' comparison would wipe every checked box back to false.
	 */
	protected function truthy(
		mixed $value,
	): bool
	{
		return $value === true || $value === '1';
	}
	
	public function renderPage(): void
	{
		if(current_user_can('manage_options') === false)
		{
			return;
		}
		
		$this->renderTestNotice();
		$this->renderScanNotice();
		
		echo '<div class="wrap"><h1>' . esc_html__('ovos codesafe', 'ovos-codesafe') . '</h1>';
		
		echo '<form method="post" action="' . esc_url(admin_url('options.php')) . '">';
		
		settings_fields('ovos_codesafe');
		
		echo '<h2>' . esc_html__('Console connection', 'ovos-codesafe') . '</h2>';
		echo '<p>' . esc_html__('Create a project in your console instance and paste its keys here. PHP errors use the secret API key; browser errors use the public JS key — allowlist this site\'s origin in the project settings.', 'ovos-codesafe') . '</p>';
		echo '<table class="form-table" role="presentation">';
		
		$this->checkboxField('enabled',
			__('Enabled', 'ovos-codesafe'),
			__('Master switch for PHP and browser error reporting.', 'ovos-codesafe'));
		$this->inputField('url',
			__('Console URL', 'ovos-codesafe'), 'url', 'https://console.example');
		$this->inputField('api_key',
			__('API key', 'ovos-codesafe'), 'password', '',
			__('The project\'s secret api_key. Stored value is kept when left blank.', 'ovos-codesafe'));
		$this->levelField();
		$this->checkboxField('report_404',
			__('Report 404s', 'ovos-codesafe'),
			__('Report front-end not-found (404) requests as access events. Surfaces scanner and broken-link traffic in the console, grouped apart from real errors and never creating issues. Rate-limited, and static-asset 404s are ignored.', 'ovos-codesafe'));
		$this->apcuStatusRow();
		$this->checkboxField('rollups',
			__('Traffic rollups', 'ovos-codesafe'),
			__('Send anonymous per-minute traffic counters (request totals split by status, method, resolved page type and logged-in state — never URLs or visitor data), so the console can read error and probe counts as rates. Requires the APCu PHP extension and the project\'s rollups switch in the console; without APCu nothing is collected or sent.', 'ovos-codesafe'));
		$this->checkboxField('security_events',
			__('Security events', 'ovos-codesafe'),
			__('Report refused actions as security events, apart from errors: failed logins (any door — form, XML-RPC, application passwords, with the username masked), a login succeeding after recent failures (the credential-stuffing success; clean logins are never reported), rejected nonce checks, forbidden REST calls, and sensitive admin changes (user creation and role grants, plugin installs and activations, signup/site-URL/admin-e-mail option changes, file-editor saves, admin application passwords). Informational by default in the console — they feed its attack detection without raising alerts. Rate-limited to 60 per minute.', 'ovos-codesafe'));
		$this->checkboxField('inventory',
			__('Software inventory', 'ovos-codesafe'),
			__('Report the installed plugin/theme list with versions (plus WordPress core and PHP versions) once a day and after installs, updates or (de)activations, so the console can match it against a public vulnerability feed (CVE findings on its SECURITY view). Exactly what is sent per entry: type, directory slug, version, display name, active flag — never paths, options or user data. Inert until the project\'s CVE switch is also enabled in the console.', 'ovos-codesafe'));
		$this->checkboxField('auto_update_vulnerable',
			__('Auto-update probed vulnerable plugins', 'ovos-codesafe'),
			__('When the console\'s vulnerability matching says an installed plugin is vulnerable AND the console has seen requests probing for it, switch on WordPress\' own automatic update for exactly that plugin — the one virtual patch WordPress supports natively. Needs the software inventory above and the project\'s Auto-update switch in the console; every switch-on is reported as a security event. Nothing is downgraded, deactivated or deleted, and WordPress updates from wordpress.org on its own schedule.', 'ovos-codesafe'));
		$this->checkboxField('shield_detect',
			__('Exploit detection', 'ovos-codesafe'),
			__('Pull this site\'s exploit rules from the console every five minutes — the request shapes of the CVEs the software inventory matched, drafted from each fix and reviewed by a person — and match every request against them before WordPress runs. A match is REPORTED as a security event (kind shield_observe: the rule, the CVE, the matched fragment capped at 200 bytes, the address) and NOTHING is blocked. What is read: the request path and query, the user agent, the address, and the body only while a body rule is live (form fields as name=value lines, other bodies capped at 64 KB) — nothing of it is stored or sent but the match. Needs the software inventory above and the project\'s CVE switch in the console; the rules are cached in APCu and in wp-content/ovos-codesafe/shield.json (the file alone on a host without APCu), and a console that goes silent for a day lifts them. Fails open: a rule the engine cannot run, a console that does not answer, an error of any kind — the request is served as if this were off.', 'ovos-codesafe'));
		$this->checkboxField('shield_enforce',
			__('Block detected exploits', 'ovos-codesafe'),
			__('Answer 403 to a request a PROVEN rule matches — a rule a person promoted in the console after seeing what it matched on live traffic; an observe rule never blocks, whatever this box says. Inert without Exploit detection. A rule can be wrong: a pattern wider than the fix blocks an editor\'s save, a user-agent fragment shared with a partner blocks a webhook. Every block is reported (kind shield_block), the console alarms when a rule starts blocking logged-in users or addresses in good standing, and unticking this box stops blocking on the very next request — it is read per request, never cached. The CODESAFE_SHIELD_KILL constant switches the whole shield off and calls no one.', 'ovos-codesafe'));
		$this->shieldStatusRow();
		$this->prependStatusRow();
		$this->entryWatchFields();
		$this->scanFields();
		$this->inputField('release',
			__('Release label', 'ovos-codesafe'), 'text', '',
			__('Optional deploy label (git sha, version), max 64 characters.', 'ovos-codesafe'));
		$this->inputField('environment',
			__('Environment', 'ovos-codesafe'), 'text', '',
			__('Deployment stage sent with every report. Left blank, WordPress\' own environment type (WP_ENVIRONMENT_TYPE) is sent — the console shows non-production values as a badge beside the project name.', 'ovos-codesafe'));
		$this->inputField('tags',
			__('Tags', 'ovos-codesafe'), 'text', '',
			__('Optional tags on every report (PHP and browser), comma-separated — a tenant, a region, a team: shop, eu, tenant:acme. Lowercase letters, digits and _ . : - only, up to 10; the console shows them in its TAGS column, one filter per tag. The CODESAFE_TAGS constant overrides this field.', 'ovos-codesafe'));
			
		echo '</table>';
		
		echo '<h2>' . esc_html__('Browser errors', 'ovos-codesafe') . '</h2>';
		echo '<table class="form-table" role="presentation">';
		
		$this->checkboxField('js_enabled',
			__('Report JavaScript errors', 'ovos-codesafe'),
			__('Loads the bundled console-client.js on the front end.', 'ovos-codesafe'));
		$this->inputField('js_key',
			__('JS key', 'ovos-codesafe'), 'text', '',
			__('The project\'s public js_key (distinct from the secret API key).', 'ovos-codesafe'));
		$this->checkboxField('js_trace',
			__('Trace correlation', 'ovos-codesafe'),
			__('Send a W3C traceparent header on the page\'s same-origin fetch/XHR calls, so browser and PHP errors of the same request share a trace id in the console. Disable if a firewall or security plugin rejects the extra request header.', 'ovos-codesafe'));
		$this->requestBodyField();
		$this->checkboxField('snapshot',
			__('DOM snapshot', 'ovos-codesafe'),
			__('Upload a masked DOM snapshot with the first error per page load (replay-lite). Input values and scripts are stripped in the browser before upload.', 'ovos-codesafe'));
		$this->checkboxField('snapshot_styles',
			__('Inline styles into snapshots', 'ovos-codesafe'),
			__('Embeds the page\'s CSS so snapshots render styled in the console viewer.', 'ovos-codesafe'));
		$this->checkboxField('js_admin',
			__('Also load in wp-admin and on the login page', 'ovos-codesafe'),
			'');
			
		echo '</table>';
		
		submit_button(__('Save changes', 'ovos-codesafe'));
		
		echo '</form>';
		
		echo '<hr><h2>' . esc_html__('Test', 'ovos-codesafe') . '</h2>';
		
		if($this->sender->isEnabled())
		{
			echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
			
			wp_nonce_field('ovos_codesafe_test');
			
			echo '<input type="hidden" name="action" value="ovos_codesafe_test">';
			
			submit_button(__('Send test error', 'ovos-codesafe'), 'secondary', 'submit', false);
			
			echo '</form>';
		}
		else
		{
			echo '<p>' . esc_html__('Save an enabled configuration (console URL + API key) first, then send a test error.', 'ovos-codesafe') . '</p>';
		}
		
		$this->renderScanSection();
		
		echo '</div>';
	}
	
	public function handleTest(): void
	{
		if(current_user_can('manage_options') === false)
		{
			wp_die(esc_html__('Insufficient permissions.', 'ovos-codesafe'));
		}
		
		check_admin_referer('ovos_codesafe_test');
		
		$status = $this->sender->isEnabled() ? $this->sender->sendTest() : -1;
		
		wp_safe_redirect(add_query_arg(
			'ovos-codesafe-test',
			(string)$status,
			admin_url('options-general.php?page=' . self::PAGE)));
			
		exit;
	}
	
	protected function renderTestNotice(): void
	{
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- reads a status flag set by our own redirect; integer-cast, display only
		if(isset($_GET['ovos-codesafe-test']) === false)
		{
			return;
		}
		
		$status = (int)$_GET['ovos-codesafe-test'];
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		
		[$class, $message] = match(true)
		{
			$status === 202 => ['notice-success',
				__('Test error accepted by the console — it appears in the grid within a second.', 'ovos-codesafe')],
			$status === -1 => ['notice-warning',
				__('Not configured — enable reporting and set the console URL and API key first.', 'ovos-codesafe')],
			$status === 0 => ['notice-error',
				__('Console unreachable — check the URL.', 'ovos-codesafe')],
			$status === 401, $status === 403 => ['notice-error',
				sprintf(
					/* translators: %d: HTTP status code */
					__('Console rejected the key (HTTP %d) — check the project API key.', 'ovos-codesafe'),
					$status)],
			default => ['notice-error',
				sprintf(
					/* translators: %d: HTTP status code */
					__('Unexpected response (HTTP %d).', 'ovos-codesafe'),
					$status)],
		};
		
		echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>'
			. esc_html($message) . '</p></div>';
	}
	
	protected function inputField(
		string $key,
		string $label,
		string $type = 'text',
		string $placeholder = '',
		string $description = '',
	): void
	{
		$locked = $this->config->isConstant($key);
		$value = $type === 'password' ? '' : (string)$this->config->get($key);
		
		if($type === 'password' && $this->config->get($key) !== '')
		{
			$placeholder = __('(unchanged)', 'ovos-codesafe');
		}
		
		echo '<tr><th scope="row"><label for="ovos-codesafe-' . esc_attr($key) . '">'
			. esc_html($label) . '</label></th><td>';
			
		echo '<input type="' . esc_attr($type) . '" class="regular-text"'
			. ' id="ovos-codesafe-' . esc_attr($key) . '"'
			. ' name="' . esc_attr(Config::OPTION . '[' . $key . ']') . '"'
			. ' value="' . esc_attr($value) . '"'
			. ($placeholder !== '' ? ' placeholder="' . esc_attr($placeholder) . '"' : '')
			. ($locked ? ' disabled' : '')
			. ' autocomplete="off">';
			
		$this->fieldNotes($key, $locked, $description);
		
		echo '</td></tr>';
	}
	
	protected function checkboxField(
		string $key,
		string $label,
		string $description,
	): void
	{
		$locked = $this->config->isConstant($key);
		
		echo '<tr><th scope="row">' . esc_html($label) . '</th><td><label>';
		
		if($locked === false)
		{
			// unchecked boxes are absent from the POST — submit an explicit 0
			echo '<input type="hidden"'
				. ' name="' . esc_attr(Config::OPTION . '[' . $key . ']') . '" value="0">';
		}
		
		echo '<input type="checkbox" value="1"'
			. ' name="' . esc_attr(Config::OPTION . '[' . $key . ']') . '"'
			. checked((bool)$this->config->get($key), true, false)
			. ($locked ? ' disabled' : '')
			. '> ' . esc_html($description) . '</label>';
			
		$this->fieldNotes($key, $locked, '');
		
		echo '</td></tr>';
	}
	
	/**
	 * Whether this server's PHP has APCu, in one line above the switch that is
	 * inert without it. A reader who ticks Traffic rollups on a host without
	 * shared memory otherwise sees nothing arrive and nothing complain — the
	 * feature is a deliberate no-op there — so the page says it first
	 */
	protected function apcuStatusRow(): void
	{
		$line = Rollup::hasApcu()
			? __('available — traffic counters and the Shield\'s hit counters can run on this server.', 'ovos-codesafe')
			: __('NOT available on this server\'s PHP — Traffic rollups below collects nothing until your host enables the apcu extension for the web server (the CLI\'s php -m does not count). Everything else on this page works without it; the Shield keeps its rules in a file instead and only its hit counters are missing.', 'ovos-codesafe');
		echo '<tr><th scope="row">' . esc_html__('APCu', 'ovos-codesafe') . '</th><td>'
			. '<p class="description" style="margin: 0;">' . esc_html($line) . '</p>'
			. '</td></tr>';
	}
	
	/**
	 * What the Shield holds on this site, in one line under its two switches
	 * (Shield\Adapter::status): the rules live and the ones that may block,
	 * when they were pulled, whether blocking is on — or why the shield is off.
	 * The design's open question 4 (ovos/console wave8-shield-build.md, S2.d):
	 * the owner who ticked "Block detected exploits" sees what it is blocking with
	 */
	protected function shieldStatusRow(): void
	{
		echo '<tr><th scope="row">' . esc_html__('Shield status', 'ovos-codesafe') . '</th><td>'
			. '<p class="description" style="margin: 0;">' . esc_html((new Shield\Adapter($this->config, $this->sender))->status()) . '</p>'
			. '</td></tr>';
	}
	
	/**
	 * The optional layer before WordPress (ovos/console docs/plans/shield-prepend.md):
	 * whether PHP's auto_prepend_file points at the plugin's stub, and the two
	 * lines an operator pastes to make it so — only while detection is on,
	 * since the layer judges by the same consent
	 */
	protected function prependStatusRow(): void
	{
		$shield = $this->config->shieldDetect() && $this->config->shieldKill() === false;
		if($shield === false && $this->config->entryWatch() === false)
		{
			return;
		}
		$status = Shield\Adapter::prependStatus();
		$line = match($status['state'])
		{
			'active' => __('ACTIVE — anonymous requests are judged before WordPress runs, direct hits on plugin files included; a request carrying a login cookie is judged at plugins_loaded as before.', 'ovos-codesafe'),
			'other' => sprintf(
				/* translators: %s: the file PHP's auto_prepend_file names */
				__('not active — PHP already prepends %s (a host\'s or another plugin\'s file); this plugin never chains onto it. Leave it, or point the directive at the stub below instead.', 'ovos-codesafe'), $status['ini']),
			'legacy' => sprintf(
				/* translators: %s: the old stub PHP's auto_prepend_file names */
				__('ACTIVE through the old ovos-console stub %s, which now runs this plugin. Point the directive at the new stub below when convenient; leave the old file in place until you have.', 'ovos-codesafe'), $status['ini']),
			'unavailable' => __('not available — the store directory under wp-content could not be written.', 'ovos-codesafe'),
			default => __('not active — optional. The Shield judges at plugins_loaded; with the prepend it judges every anonymous request before WordPress exists, direct hits on plugin files included, and a block costs a file read instead of a WordPress bootstrap. Paste ONE of the lines below into your PHP configuration, then reload this page.', 'ovos-codesafe'),
		};
		if($this->config->entryWatch())
		{
			$line .= ' ' . __('The executed-file watch below rides the same layer.', 'ovos-codesafe');
		}
		echo '<tr><th scope="row">' . esc_html__('Before WordPress', 'ovos-codesafe') . '</th><td>'
			. '<p class="description" style="margin: 0;">' . esc_html($line) . '</p>';
		if($status['state'] !== 'unavailable' && $status['state'] !== 'active')
		{
			echo '<p class="description" style="margin: 6px 0 0;">' . esc_html__('.user.ini or php.ini (PHP-FPM, CGI):', 'ovos-codesafe')
				. ' <code>' . esc_html($status['lines']['ini']) . '</code></p>'
				. '<p class="description" style="margin: 4px 0 0;">' . esc_html__('.htaccess (Apache with mod_php):', 'ovos-codesafe')
				. ' <code>' . esc_html($status['lines']['htaccess']) . '</code></p>'
				. '<p class="description" style="margin: 4px 0 0;">' . esc_html__('The stub is written by the plugin and is safe to delete — PHP then prepends nothing until the plugin writes it again. Everything fails open: a stub that cannot judge serves the request.', 'ovos-codesafe') . '</p>';
		}
		echo '</td></tr>';
	}
	
	/**
	 * The executed-file watch (Entries, ovos/codesafe docs/plans/prepend-
	 * entry-watch.md): its switch, and a status line that says whether it
	 * has anything to ride on — the layer above, the core list — and what
	 * it last found
	 */
	protected function entryWatchFields(): void
	{
		$this->checkboxField('entry_watch',
			__('Executed-file watch', 'ovos-codesafe'),
			__('With the prepend layer above active, record every PHP file this site runs that WordPress did not ship as an entry point — the dropped webshell, the moment it is used — and judge it on the site\'s next request against what wordpress.org shipped: a file nobody shipped becomes an integrity finding in the console (the FILES ledger, an INBOX case, the mail and chat digest, removal advice) plus one security event carrying the address that ran it. wp-admin\'s own entries come from the core checksum list, never from a pattern; a plugin\'s own endpoint hit directly is judged shipped once and never recorded again. Read-only: nothing is blocked, deleted or changed. The request that is the site (index.php) costs one string comparison; only a stranger writes.', 'ovos-codesafe'));
		if($this->entries === null || $this->config->entryWatch() === false)
		{
			return;
		}
		$status = $this->entries->status();
		$prepend = Shield\Adapter::prependStatus()['state'];
		$line = match(true)
		{
			$status['enabled'] === false => __('inactive — the plugin is not connected to a console.', 'ovos-codesafe'),
			$prepend !== 'active' && $prepend !== 'legacy' => __('waiting for the layer — PHP does not prepend the stub yet, so nothing is recorded; paste one of the lines above.', 'ovos-codesafe'),
			$status['exported'] === false => __('waiting for the wordpress.org core checksum list — the known wp-admin entries are written from it; until then nothing is recorded. Tried again a few minutes after every request.', 'ovos-codesafe'),
			default => sprintf(
				/* translators: 1: wp-admin entries known, 2: learnt paths, 3: paths waiting for the judge */
				__('ACTIVE — %1$d wp-admin entries and %2$d learnt paths known, %3$d waiting for the next judge.', 'ovos-codesafe'),
				$status['core'], $status['learnt'], $status['queued']),
		};
		$last = $status['last'];
		if($status['exported'] && is_array($last))
		{
			$line .= ' ' . sprintf(
				/* translators: 1: the file, 2: its tier, 3: the detector word, 4: when it last ran, 5: whether the console took the report */
				__('Last finding: %1$s (%2$s, %3$s), last run %4$s%5$s.', 'ovos-codesafe'),
				(string)($last['path'] ?? ''), (string)($last['tier'] ?? ''), (string)($last['detector'] ?? ''),
				wp_date('Y-m-d H:i', (int)($last['at'] ?? 0)),
				(int)($last['sent'] ?? 0) === 202 ? __(' — reported', 'ovos-codesafe') : __(' — the console did not take the report', 'ovos-codesafe'));
		}
		if($status['exported'] && is_array($status['refused']))
		{
			$line .= ' ' . sprintf(
				/* translators: 1: the HTTP status, 2: when */
				__('The console refused a report with %1$d at %2$s — is the project\'s file switch on?', 'ovos-codesafe'),
				(int)($status['refused']['status'] ?? 0), wp_date('Y-m-d H:i', (int)($status['refused']['at'] ?? 0)));
		}
		echo '<tr><th scope="row">' . esc_html__('Executed files', 'ovos-codesafe') . '</th><td>'
			. '<p class="description" style="margin: 0;">' . esc_html($line) . '</p></td></tr>';
	}
	
	protected function levelField(): void
	{
		$locked = $this->config->isConstant('log_level');
		$current = $this->config->logLevel();
		
		echo '<tr><th scope="row"><label for="ovos-codesafe-log-level">'
			. esc_html__('Log level', 'ovos-codesafe') . '</label></th><td>';
			
		echo '<select id="ovos-codesafe-log-level"'
			. ' name="' . esc_attr(Config::OPTION . '[log_level]') . '"'
			. ($locked ? ' disabled' : '') . '>';
			
		foreach(self::LEVELS as $level => $name)
		{
			echo '<option value="' . esc_attr((string)$level) . '"'
				. selected($current, $level, false) . '>'
				. esc_html($level . ' — ' . $name) . '</option>';
		}
		
		echo '</select>';
		
		$this->fieldNotes('log_level', $locked,
			__('Errors with priority up to and including this level are sent.', 'ovos-codesafe'));
			
		echo '</td></tr>';
	}
	
	protected function fieldNotes(
		string $key,
		bool $locked,
		string $description,
	): void
	{
		if($description !== '')
		{
			echo '<p class="description">' . esc_html($description) . '</p>';
		}
		
		if($locked)
		{
			$constant = $this->config->constantName($key);
			
			echo '<p class="description"><code>'
				. esc_html($constant)
				. '</code> ' . esc_html__('is defined in wp-config.php — the value is locked.', 'ovos-codesafe');
			
			if(str_starts_with($constant, Legacy::CONSTANT_PREFIX))
			{
				echo ' ' . esc_html(sprintf(
					/* translators: %s: the constant's new name */
					__('That is its old name; it keeps working, and %s is the new one.', 'ovos-codesafe'),
					'CODESAFE_' . strtoupper($key),
				));
			}
			
			echo '</p>';
		}
	}
	
	/**
	 * The integrity-scan controls in the settings table: the background
	 * switch and its cadence. The Scan now button lives in its own section
	 * below the form and needs neither.
	 */
	protected function scanFields(): void
	{
		$this->checkboxField('scan',
			__('Integrity scan', 'ovos-codesafe'),
			__('Walk this site\'s files in the background for what nobody shipped — PHP under uploads, images that open with a PHP tag, files in the document root WordPress did not ship, .htaccess directives that make images execute, drop-ins without an installed plugin behind them — plus the site\'s hardening posture, and send the findings to the console. Read-only: nothing is ever deleted or changed. Half a second per request after the response went out, one full pass per interval. The Scan now button below works without this switch.', 'ovos-codesafe'));
		
		$locked = $this->config->isConstant('scan_interval');
		$current = $this->config->scanInterval();
		
		echo '<tr><th scope="row"><label for="ovos-codesafe-scan-interval">'
			. esc_html__('Scan interval', 'ovos-codesafe') . '</label></th><td>';
		
		echo '<select id="ovos-codesafe-scan-interval"'
			. ' name="' . esc_attr(Config::OPTION . '[scan_interval]') . '"'
			. ($locked ? ' disabled' : '') . '>';
		
		foreach([1 => __('daily', 'ovos-codesafe'), 7 => __('weekly', 'ovos-codesafe')] as $days => $label)
		{
			echo '<option value="' . esc_attr((string)$days) . '"'
				. selected($current, $days, false) . '>' . esc_html($label) . '</option>';
		}
		
		echo '</select>';
		
		$this->fieldNotes('scan_interval', $locked,
			__('How often the background pass runs.', 'ovos-codesafe'));
		
		echo '</td></tr>';
	}
	
	/**
	 * How much of a request body leaves the site.
	 *
	 * A setting because there was none: the body was read on every non-GET
	 * report, 16 KB of it, at every log level, with no way to turn it off.
	 */
	protected function requestBodyField(): void
	{
		$locked = $this->config->isConstant('request_body');
		$current = $this->config->requestBody();
		
		echo '<tr><th scope="row"><label for="ovos-codesafe-request-body">'
			. esc_html__('Request body', 'ovos-codesafe') . '</label></th><td>';
		
		echo '<select id="ovos-codesafe-request-body"'
			. ' name="' . esc_attr(Config::OPTION . '[request_body]') . '"'
			. ($locked ? ' disabled' : '') . '>';
		
		$labels = [
			Body::MODE_OFF => __('off — never send one', 'ovos-codesafe'),
			Body::MODE_STRUCTURE => __('structure — parsed, secrets removed (recommended)', 'ovos-codesafe'),
			Body::MODE_FULL => __('full — the raw body, 16 KB', 'ovos-codesafe'),
		];
		
		foreach($labels as $mode => $label)
		{
			echo '<option value="' . esc_attr($mode) . '"'
				. selected($current, $mode, false) . '>' . esc_html($label) . '</option>';
		}
		
		echo '</select>';
		
		$this->fieldNotes('request_body', $locked,
			__('The console stores the body so it can REPLAY the request that failed — a REST or admin-ajax call carrying JSON has an empty $_POST, so without it a replay is a bare method and URL. `structure` parses the body, drops the fields named like credentials and re-encodes it; `full` sends the raw text. A login endpoint (wp-login.php, xmlrpc.php) never sends one, whichever you pick.', 'ovos-codesafe'));
		
		echo '</td></tr>';
	}
	
	/**
	 * The outcome of a manual scan round, read back from our own redirect
	 */
	protected function renderScanNotice(): void
	{
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- reads an outcome word set by our own redirect; matched against a closed list, display only
		if(isset($_GET['ovos-codesafe-scan']) === false)
		{
			return;
		}
		
		$outcome = sanitize_key((string)$_GET['ovos-codesafe-scan']);
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		
		[$class, $message] = match($outcome)
		{
			'done' => ['notice-success', __('Scan finished — the findings are below.', 'ovos-codesafe')],
			'running' => ['notice-info', __('Scan in progress — this page continues it until the pass is complete.', 'ovos-codesafe')],
			'busy' => ['notice-warning', __('Another request is scanning right now — try again in a minute.', 'ovos-codesafe')],
			'failed' => ['notice-error', __('The scan round failed — the position is kept; Continue resumes it.', 'ovos-codesafe')],
			default => ['', ''],
		};
		
		if($message === '')
		{
			return;
		}
		
		echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>'
			. esc_html($message) . '</p></div>';
	}
	
	/**
	 * Below the form: the Scan now button (or the pass in progress), then
	 * the last completed pass — its findings and the site's posture
	 */
	protected function renderScanSection(): void
	{
		echo '<hr><h2>' . esc_html__('Integrity scan', 'ovos-codesafe') . '</h2>';
		echo '<p>' . esc_html__('A read-only walk of this site\'s files for what nobody shipped: PHP under uploads, images that open with a PHP tag, files in the document root WordPress did not ship, hidden PHP, .htaccess and .user.ini directives that make other files execute or send visitors elsewhere, drop-ins and plugin data directories without their plugin — and the hardening posture the advice depends on. Results stay on this page and are sent to the console when one is connected. Nothing is ever deleted or changed; a finding is a place to look, not a verdict.', 'ovos-codesafe') . '</p>';
		
		$state = $this->runner->state();
		
		if($state !== null)
		{
			$this->renderScanProgress($state);
		}
		else
		{
			echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
			
			wp_nonce_field(ScanRunner::ACTION);
			
			echo '<input type="hidden" name="action" value="' . esc_attr(ScanRunner::ACTION) . '">';
			
			submit_button(__('Scan now', 'ovos-codesafe'), 'secondary', 'submit', false);
			
			echo '</form>';
		}
		
		$last = $this->runner->last();
		
		if($last !== null)
		{
			$this->renderScanResult($last);
		}
	}
	
	/**
	 * A pass in progress: where it stands, and the Continue form — which a
	 * manual pass submits by itself, round after round, until it is done
	 */
	protected function renderScanProgress(
		array $state,
	): void
	{
		$progress = Scan::progress($state);
		
		echo '<p><strong>' . esc_html__('Scan in progress', 'ovos-codesafe') . '</strong> — '
			. esc_html(sprintf(
				/* translators: 1: the area being walked, 2: files counted so far, 3: findings so far */
				__('walking %1$s, %2$s files so far, %3$d findings', 'ovos-codesafe'),
				$progress['area'],
				number_format_i18n($progress['files']),
				$progress['findings'])) . '</p>';
		
		echo '<form method="post" id="ovos-codesafe-scan-continue" action="'
			. esc_url(admin_url('admin-post.php')) . '">';
		
		wp_nonce_field(ScanRunner::ACTION);
		
		echo '<input type="hidden" name="action" value="' . esc_attr(ScanRunner::ACTION) . '">';
		
		submit_button(__('Continue', 'ovos-codesafe'), 'secondary', 'submit', false);
		
		echo '</form>';
		
		if(($state['mode'] ?? '') === 'manual')
		{
			wp_print_inline_script_tag('window.setTimeout(function () { document.getElementById("ovos-codesafe-scan-continue").submit(); }, 400);');
		}
	}
	
	/**
	 * The last completed pass: one summary line, the findings table (every
	 * path escaped — it is attacker-authored), the area roots, the posture
	 */
	protected function renderScanResult(
		array $last,
	): void
	{
		$report = (array)$last['report'];
		$scan = (array)($report['scan'] ?? []);
		$counts = (array)($scan['counts'] ?? []);
		$truncated = (array)($scan['truncated'] ?? []);
		$findings = (array)($report['findings'] ?? []);
		$sent = (int)($last['sent'] ?? -1);
		$format = (string)get_option('date_format') . ' ' . (string)get_option('time_format');
		
		$delivery = match(true)
		{
			$sent === 202 => __('accepted by the console', 'ovos-codesafe'),
			$sent === -1 => __('kept here only — no console configured', 'ovos-codesafe'),
			$sent === 0 => __('console unreachable', 'ovos-codesafe'),
			default => sprintf(
				/* translators: %d: HTTP status code */
				__('console answered HTTP %d', 'ovos-codesafe'),
				$sent),
		};
		
		echo '<p>' . esc_html(sprintf(
			/* translators: 1: date and time, 2: manual or background, 3: file count, 4: seconds, 5: delivery outcome */
			__('Last scan: %1$s (%2$s) — %3$s files in %4$s s, %5$s.', 'ovos-codesafe'),
			date_i18n($format, (int)$last['finished']),
			($scan['mode'] ?? '') === 'manual' ? __('manual', 'ovos-codesafe') : __('background', 'ovos-codesafe'),
			number_format_i18n((int)($scan['files'] ?? 0)),
			number_format_i18n(((int)($scan['duration'] ?? 0)) / 1000, 1),
			$delivery)) . '</p>';
		
		if(($scan['complete'] ?? true) === false)
		{
			echo '<p>' . esc_html__('The pass did not complete — the findings below are from the part that was walked.', 'ovos-codesafe') . '</p>';
		}
		
		if($findings === [])
		{
			echo '<p><strong>' . esc_html__('No findings.', 'ovos-codesafe') . '</strong></p>';
		}
		else
		{
			echo '<p><strong>' . esc_html(sprintf(
				/* translators: 1: urgent count, 2: high count, 3: informational count */
				__('%1$d urgent, %2$d high, %3$d informational.', 'ovos-codesafe'),
				(int)($counts[Scan::TIER_URGENT] ?? 0),
				(int)($counts[Scan::TIER_HIGH] ?? 0),
				(int)($counts[Scan::TIER_INFO] ?? 0))) . '</strong>';
			
			$left = (int)($truncated[Scan::TIER_URGENT] ?? 0) + (int)($truncated[Scan::TIER_HIGH] ?? 0)
				+ (int)($truncated[Scan::TIER_INFO] ?? 0);
			
			if($left > 0)
			{
				echo ' ' . esc_html(sprintf(
					/* translators: %d: findings past the cap */
					__('%d more were counted but not listed.', 'ovos-codesafe'),
					$left));
			}
			
			echo '</p>';
			
			echo '<table class="widefat striped"><thead><tr>'
				. '<th>' . esc_html__('Tier', 'ovos-codesafe') . '</th>'
				. '<th>' . esc_html__('File', 'ovos-codesafe') . '</th>'
				. '<th>' . esc_html__('What', 'ovos-codesafe') . '</th>'
				. '<th>' . esc_html__('Detail', 'ovos-codesafe') . '</th>'
				. '<th>' . esc_html__('Modified', 'ovos-codesafe') . '</th>'
				. '</tr></thead><tbody>';
			
			foreach($findings as $finding)
			{
				$finding = (array)$finding;
				$mtime = (int)($finding['mtime'] ?? 0);
				
				echo '<tr>'
					. '<td>' . esc_html($this->tierWord((string)($finding['tier'] ?? ''))) . '</td>'
					. '<td><code>' . esc_html((string)($finding['area'] ?? '') . ':' . (string)($finding['path'] ?? '')
						. (isset($finding['line']) ? ':' . (int)$finding['line'] : '')) . '</code></td>'
					. '<td>' . esc_html($this->detectorLabel((string)($finding['detector'] ?? ''))) . '</td>'
					. '<td>' . esc_html((string)($finding['detail'] ?? '')) . '</td>'
					. '<td>' . esc_html($mtime > 0 ? date_i18n($format, $mtime) : '') . '</td>'
					. '</tr>';
			}
			
			echo '</tbody></table>';
			
			$roots = [];
			
			foreach((array)($report['areas'] ?? []) as $area => $stats)
			{
				$roots[] = (string)$area . ' = ' . (string)(((array)$stats)['root'] ?? '');
			}
			
			echo '<p class="description">' . esc_html(implode(' · ', $roots)) . '</p>';
		}
		
		echo '<h3>' . esc_html__('Posture', 'ovos-codesafe') . '</h3><ul>';
		
		foreach($this->postureLines((array)($report['posture'] ?? [])) as $line)
		{
			echo '<li>' . esc_html($line) . '</li>';
		}
		
		echo '</ul>';
	}
	
	protected function tierWord(
		string $tier,
	): string
	{
		return match($tier)
		{
			Scan::TIER_URGENT => __('urgent', 'ovos-codesafe'),
			Scan::TIER_HIGH => __('high', 'ovos-codesafe'),
			default => __('info', 'ovos-codesafe'),
		};
	}
	
	protected function detectorLabel(
		string $detector,
	): string
	{
		return match($detector)
		{
			'uploads_php' => __('PHP file under uploads', 'ovos-codesafe'),
			'polyglot' => __('PHP code in a media file', 'ovos-codesafe'),
			'root_php' => __('PHP file in the document root that WordPress did not ship', 'ovos-codesafe'),
			'root_php_owned' => __('PHP file in the document root (owned by a plugin)', 'ovos-codesafe'),
			'hidden_php' => __('PHP file in a hidden path', 'ovos-codesafe'),
			'content_php' => __('PHP file in wp-content outside any plugin or theme', 'ovos-codesafe'),
			'mu_plugin' => __('must-use plugin (loads on every request)', 'ovos-codesafe'),
			'dropin' => __('drop-in', 'ovos-codesafe'),
			'dropin_orphan' => __('drop-in without an installed owner or a vendor header', 'ovos-codesafe'),
			'writer_dir' => __('plugin data directory (not scanned)', 'ovos-codesafe'),
			'writer_dir_orphan' => __('plugin data directory whose plugin is not installed', 'ovos-codesafe'),
			'directive_prepend' => __('auto_prepend/append directive to a file nobody owns', 'ovos-codesafe'),
			'directive_owned' => __('auto_prepend/append directive (owned by a plugin)', 'ovos-codesafe'),
			'handler_php_extension' => __('PHP handler mapped to another extension', 'ovos-codesafe'),
			'set_handler_php' => __('SetHandler to PHP', 'ovos-codesafe'),
			'engine_on_uploads' => __('PHP engine switched on under uploads', 'ovos-codesafe'),
			'cgi_uploads' => __('CGI execution under uploads', 'ovos-codesafe'),
			'redirect_external' => __('redirect to another host', 'ovos-codesafe'),
			'ini_prepend' => __('auto_prepend/append file live in php.ini', 'ovos-codesafe'),
			'ini_prepend_owned' => __('auto_prepend/append file live in php.ini (owned by a plugin)', 'ovos-codesafe'),
			'core_modified' => __('core file differs from what wordpress.org shipped', 'ovos-codesafe'),
			'core_foreign' => __('file under core that wordpress.org never shipped', 'ovos-codesafe'),
			'plugin_modified' => __('plugin file differs from what wordpress.org shipped', 'ovos-codesafe'),
			'plugin_foreign' => __('file in a wp.org plugin that its release never shipped', 'ovos-codesafe'),
			'admin_account' => __('administrator account (registered, sessions)', 'ovos-codesafe'),
			'admin_app_password' => __('application password on an administrator', 'ovos-codesafe'),
			'active_plugin_missing' => __('active plugin whose file is not on disk', 'ovos-codesafe'),
			'cron_orphan' => __('scheduled hook no plugin listens to', 'ovos-codesafe'),
			'cron_suspicious' => __('scheduled hook no plugin listens to, named like a payload', 'ovos-codesafe'),
			'uninstall_orphan' => __('uninstall callable for a plugin that is not installed', 'ovos-codesafe'),
			'option_code' => __('option value carrying code markers', 'ovos-codesafe'),
			'content_script' => __('script from a foreign host in published content', 'ovos-codesafe'),
			'content_iframe' => __('iframe from a foreign host in published content', 'ovos-codesafe'),
			'content_obfuscated' => __('obfuscation idiom in published content', 'ovos-codesafe'),
			'option_drift' => __('stored site URL disagrees with its constant', 'ovos-codesafe'),
			'registration_role' => __('registration open into a role above subscriber', 'ovos-codesafe'),
			'dir_changed' => __('directory changed after its newest file (something removed)', 'ovos-codesafe'),
			'owner_anomaly' => __('file owned by another uid than its siblings', 'ovos-codesafe'),
			'symlink_outside' => __('symlink leaving the site', 'ovos-codesafe'),
			'debug_log_public' => __('debug.log written to a web-reachable path', 'ovos-codesafe'),
			default => $detector,
		};
	}
	
	/**
	 * The posture block as plain lines — what the removal advice leans on
	 *
	 * @return string[]
	 */
	protected function postureLines(
		array $posture,
	): array
	{
		if($posture === [])
		{
			return [__('not recorded', 'ovos-codesafe')];
		}
		
		$yes = __('yes', 'ovos-codesafe');
		$no = __('no', 'ovos-codesafe');
		$unknown = __('unknown', 'ovos-codesafe');
		$word = static fn(mixed $value): string => $value === null ? $unknown : ($value ? $yes : $no);
		$ini = (array)($posture['ini'] ?? []);
		$vcs = (array)($posture['vcs_exposed'] ?? []);
		
		return [
			__('Web server', 'ovos-codesafe') . ': ' . (string)($posture['server'] ?? $unknown),
			__('File editor disabled (DISALLOW_FILE_EDIT)', 'ovos-codesafe') . ': ' . $word($posture['file_edit_disabled'] ?? null),
			__('File modifications disabled (DISALLOW_FILE_MODS)', 'ovos-codesafe') . ': ' . $word($posture['file_mods_disabled'] ?? null),
			__('Debug output displayed', 'ovos-codesafe') . ': ' . $word($posture['debug_display'] ?? null),
			__('PHP execution denied under uploads by .htaccess', 'ovos-codesafe') . ': ' . $word($posture['uploads_php_denied'] ?? null),
			__('Uploads directory writable by everyone', 'ovos-codesafe') . ': ' . $word($posture['uploads_world_writable'] ?? null),
			__('wp-config.php readable by everyone', 'ovos-codesafe') . ': ' . $word($posture['config_world_readable'] ?? null),
			__('XML-RPC enabled', 'ovos-codesafe') . ': ' . $word($posture['xmlrpc'] ?? null),
			__('Registration open', 'ovos-codesafe') . ': ' . $word($posture['users_can_register'] ?? null)
				. (($posture['users_can_register'] ?? false) ? ' (' . (string)($posture['default_role'] ?? '') . ')' : ''),
			__('Version control in the document root', 'ovos-codesafe') . ': ' . ($vcs === [] ? $no : implode(', ', $vcs)),
			__('readme.html present', 'ovos-codesafe') . ': ' . $word($posture['readme_html'] ?? null),
			'auto_prepend_file: ' . ((string)($ini['auto_prepend_file'] ?? '') !== '' ? (string)$ini['auto_prepend_file'] : $no),
			'disable_functions: ' . ((string)($ini['disable_functions'] ?? '') !== '' ? (string)$ini['disable_functions'] : $no),
			'open_basedir: ' . ((string)($ini['open_basedir'] ?? '') !== '' ? $yes : $no),
			'OPcache: ' . $word($ini['opcache'] ?? null),
			__('Login protection plugin', 'ovos-codesafe') . ': ' . ((string)($posture['login_protection'] ?? '') !== '' ? (string)$posture['login_protection'] : __('none detected', 'ovos-codesafe')),
			__('Two-factor plugin', 'ovos-codesafe') . ': ' . ((string)($posture['two_factor'] ?? '') !== '' ? (string)$posture['two_factor'] : __('none detected', 'ovos-codesafe')),
			__('Upload scanner plugin', 'ovos-codesafe') . ': ' . ((string)($posture['upload_scanner'] ?? '') !== '' ? (string)$posture['upload_scanner'] : __('none detected', 'ovos-codesafe')),
			__('debug.log under the site', 'ovos-codesafe') . ': ' . $word($posture['debug_log'] ?? null),
		];
	}
}
