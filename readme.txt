=== ovos codesafe ===
Contributors: ovos
Tags: error monitoring, error reporting, javascript errors, logging, debugging
Requires at least: 6.0
Tested up to: 7.0
Requires PHP: 8.3
Stable tag: 1.0.2
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Error monitoring and cyberdefence for WordPress: PHP and JavaScript errors, scanner probes, failed logins, a read-only integrity scan for files nobody shipped, and a request-side shield for the CVEs you run — sent to your own ovos codesafe.

== Description ==

This plugin reports errors from your WordPress site to [ovos codesafe](https://ovos.github.io/codesafe/) — one live dashboard for the errors of every site and service you run, grouped into issues, alerted and resolved, and one place where the attacks on your sites read as a map of your weak spots. You get your own codesafe instance, not a shared tenancy: run for you by ovos in Vienna, or set up on your own infrastructure for larger organisations. The plugin itself is free and GPL-licensed.

**Up to half of what a public WordPress site reports is not a bug.** It is automated traffic looking for a way in — `/wp-login.php`, `/wp-includes/ID3/file.php`, and a long tail of random filenames probing for a backdoor someone else already installed. On our own instances, not-found probes and refused logins are around 45–50% of everything reported. codesafe counts those apart from real errors so they never drown your bug list, folds them into attack waves by the address behind them, matches your installed plugins against a public vulnerability feed — so "vulnerable **and** being probed" is something you can see rather than guess — and, for a CVE with no patch out yet, drafts the exploit's request shape from the fix and lets this plugin shield the site until the update lands.

See it working first: the [live demo](https://console-demo.ovos.at/) is a public instance filled with synthetic errors, no login required.

What the plugin sends:

* **PHP errors** — warnings, notices and fatals (uncaught exceptions included) are batched and posted once per request from the shutdown handler, after the response went out. Reporting never blocks or breaks the site: every failure is swallowed, the HTTP call has a hard 1 s timeout.
* **JavaScript errors** — the bundled browser client captures window errors, unhandled rejections and failed fetch/XHR calls, with breadcrumbs and an optional masked DOM snapshot (replay-lite). Same-origin calls carry a W3C traceparent header, so a failed browser request and the PHP error behind it share one trace id in codesafe. Reports carry automation evidence, zero-config: a `webdriver` admission (headless browsers, AI agents) and the external scripts the visitor never even attempted to load — the signature of bots that run inline JS without loading script files. codesafe indexes both as `flags`, so bot-caused issues facet and filter apart from real-user ones.
* **Context** — request variables (redacted before sending), logged-in user id, WordPress version, active theme, and source attribution: each error is tagged with the component its file belongs to — a plugin, a mu-plugin, a theme, a drop-in, WordPress core — or with nobody, when the file is under `uploads` or standing in the site and shipped by no one.
* **Traffic rollups (opt-in)** — anonymous per-minute request counters: totals split by response status, HTTP method, the page type WordPress resolved (front page, post type, archive, search, login, admin, REST) and logged-in state. Never URLs, IPs or visitor data. They give codesafe a denominator, so error and scanner-probe counts read as rates against real traffic — a request answered 404 counts only as "matched nothing", which is exactly the probe signal. Requires the APCu PHP extension (counters accumulate in shared memory, one small POST per minute of traffic; without APCu the feature is silently inert). Enable it under Settings → ovos codesafe (or `CODESAFE_ROLLUPS`) *and* on codesafe project — either switch off keeps it inert. Requests served by a page-cache plugin before WordPress boots are not counted.
* **Security events (opt-in)** — what WordPress *refused*, beside what broke: failed logins from any door (wp-login form, XML-RPC, application passwords — the username is masked to every fourth character, the rest starred: marcin -> m***i*, and past 24 characters the mask states the real length in brackets, so an oversized login shows as what it is), rejected nonce checks (the CSRF signal), REST calls answered 401/403 (permission probing), and sensitive admin changes worth an audit trail — user creation and role grants, plugin installs and activations, changes to the signup, site-URL and admin-e-mail options, saves from the theme/plugin file editor, application passwords minted for administrators. It also reports the one login that *succeeded after recent failures* (`auth_success`, with the failure counts) — the credential-stuffing success; clean logins are never reported. They arrive in codesafe as `security` events, grouped apart from errors and accepted independently of the project's severity threshold. The refusals are informational and feed codesafe's attack detection; a login that succeeded after failures and a sensitive admin change become issues, and codesafe's default rules page for the ones that matter — five or more failures before a success, a known attacker's address, a theme install through the admin, a file-editor save, a new application password. Capped at 60 reports per minute so an attack cannot flood its own report channel. Enable it under Settings → ovos codesafe (or `CODESAFE_SECURITY_EVENTS`).
* **Software inventory (opt-in)** — the installed plugin/theme list with versions (plus WordPress core and PHP versions), reported once a day and after installs, updates or (de)activations, so codesafe can match it against the public vulnerability feeds and show CVE findings on its SECURITY view — including whether the vulnerable path is already being probed. Per entry: type, slug, version, display name, active flag; never paths, options or user data. Double opt-in: this setting (or `CODESAFE_INVENTORY`) *and* the project's CVE switch in codesafe — either off keeps it inert.
* **Auto-update probed vulnerable plugins (opt-in)** — when codesafe says an installed plugin is vulnerable *and* someone is already probing for it, the plugin switches on WordPress' own automatic update for exactly that plugin — the one virtual patch WordPress supports natively — and reports the switch-on as a security event. Nothing is downgraded, deactivated or deleted; WordPress updates from wordpress.org on its own schedule. Needs the software inventory and the project's Auto-update switch in codesafe.
* **The Shield (opt-in, two switches)** — `Exploit detection` pulls this site's exploit rules from codesafe every five minutes — the request shapes of the CVEs the software inventory matched, drafted from each fix or advisory and reviewed by a person — and matches every request against them at `plugins_loaded`, before WordPress runs. A match is reported as a security event (`shield_observe`: the rule, the CVE, the matched fragment capped at 200 bytes) and nothing is blocked. `Block detected exploits` answers 403 to a request matching a rule a person marked PROVEN in codesafe after seeing what it matched live, reported as `shield_block`; observe rules never block, both boxes are read on every request so unticking is instant, and `CODESAFE_SHIELD_KILL` switches the whole thing off with no network. What is read per request: path and query, user agent, address, and the body only while a body rule is live (form fields as `name=value` lines, other bodies capped at 64 KB); nothing of it is kept. The rules are cached in APCu and in `wp-content/ovos-codesafe/shield.json` behind a deny `.htaccess`, a codesafe silent for a day lifts them, a rule exists only while a live CVE finding on this site justifies it, and everything fails open. codesafe alarms when a blocking rule starts refusing logged-in users or addresses in good standing — a person demotes it, nothing is demoted automatically. A Shield status line under the two switches says what the site holds.
* **Integrity scan (opt-in background pass, and a Scan now button)** — the static half of finding the file nobody shipped. Every other sensor needs the foreign file to *do* something after the plugin is installed: throw an error, be saved through the editor, be activated. A webshell dropped before the plugin arrived, used once and left behind, does none of that — so the scan asks the tree directly, in a read-only walk: PHP under uploads (`x.php`, and `shell.php.jpg`), media files that open with a PHP tag (the `favicon_a1b2.ico` family), PHP in the document root that WordPress did not ship, hidden PHP, `.htaccess` / `.user.ini` / `php.ini` directives that make other files execute (`auto_prepend_file`, `AddHandler … .jpg`, `SetHandler`, `engine on` under uploads) or send visitors to another host, drop-ins and plugin data directories whose plugin is not installed, and the live `auto_prepend_file` of the PHP configuration itself — plus the hardening posture the removal advice depends on (file editor, file modifications, debug display, PHP denied under uploads, world-writable uploads, world-readable `wp-config.php`, XML-RPC, open registration, version control in the document root). Findings are paths, sizes and dates, never a file's content; nothing is ever deleted or changed. The **Scan now** button under Settings → ovos codesafe answers within seconds on that same page, codesafe or not; the background pass (`Integrity scan`, or `CODESAFE_SCAN`) spends half a second per request after the response went out, one full pass per interval (`CODESAFE_SCAN_INTERVAL`, days: 1 or 7), no WP-Cron, no APCu. Completed reports go to codesafe's SECURITY view. The known false positives are held down by rule — the `index.php` stubs plugins write into uploads, WordPress' own `.l10n.php` translations, dotfile tool configs inside vendored packages, Wordfence's `wordfence-waf.php` and its prepend directive, managed hosts' drop-ins carrying a vendor header. A finding is a place to look, not a verdict.

Configuration lives under Settings → ovos codesafe, or in wp-config.php via `CODESAFE_*` constants (which lock the corresponding UI field — handy for deploy-time configuration):

`define('CODESAFE_ENABLED', true);`
`define('CODESAFE_URL', 'https://codesafe.example');`
`define('CODESAFE_API_KEY', '...');`
`define('CODESAFE_JS_KEY', '...');`
`define('CODESAFE_SCAN', true);`

For a codesafe instance behind a self-signed certificate (intranet setups), TLS verification of the ingest call can be disabled:

`add_filter('ovos_codesafe_sslverify', '__return_false');`

The integrity scan's checksum lists come from wordpress.org over TLS; behind a proxy that re-signs traffic, that verification has its own switch:

`add_filter('ovos_codesafe_sslverify_wporg', '__return_false');`

Manual captures from theme or plugin code:

`ovos_codesafe()->captureException($e, ['orderId' => 7]);`
`ovos_codesafe()->captureMessage('checkout step skipped', 4);`

== Installation ==

The plugin is distributed as a release zip from its [GitHub repository](https://github.com/ovos/codesafe-client-wordpress) and updates itself from there afterwards.

1. Download `ovos-codesafe.zip` from the [latest release](https://github.com/ovos/codesafe-client-wordpress/releases/latest) and install it under Plugins → Add New Plugin → Upload Plugin, or install it with WP-CLI:

`wp plugin install https://github.com/ovos/codesafe-client-wordpress/releases/latest/download/ovos-codesafe.zip --activate`

2. Activate the plugin.
3. In your codesafe instance, create a project; note its secret API key and public JS key, and allowlist this site's origin for browser errors.
4. Enter the instance URL and keys under Settings → ovos codesafe, enable reporting, and use "Send test error" to verify the connection.

The plugin keeps itself current: its `Update URI` header points WordPress core's own update flow at this repository's GitHub releases, so new versions appear under Dashboard → Updates and install like any directory plugin — including unattended, via the plugin's "Enable auto-updates" toggle (`wp plugin auto-updates enable ovos-codesafe`). No updater plugin and no license key involved; a failed check simply means "no update visible right now". Every release is signed (Ed25519) and the plugin verifies the signature before WordPress installs a byte — a package that does not verify is refused, and a release without a signature is not offered at all.

== Frequently Asked Questions ==

= Which settings should I turn on? =

For a public site: **Enabled**, **Report 404s**, **Security events**, **Software inventory**, **Exploit detection** and the **Integrity scan** (weekly), plus **Report JavaScript errors** with the project's JS key — none of these blocks anything or changes the site. **Traffic rollups** too, when your server has APCu. Leave **Block detected exploits** off for the first week: detection reports what the rules would have blocked, you read that in codesafe, and you turn blocking on once a rule has proven itself on your traffic. **Auto-update probed vulnerable plugins** is for sites that let WordPress update plugins anyway. Every switch says exactly what it sends, and every one is off until you turn it on.

= Do I need APCu? =

Only for **Traffic rollups**: the per-minute counters live in APCu's shared memory, and without it that one switch collects nothing (and says nothing — it is a deliberate no-op). The settings page tells you whether APCu is available right above the switch. Everything else works without it; the Shield keeps its rules in a file and only its per-rule hit counters need APCu. Your host enables the `apcu` PHP extension for the web server — the CLI's `php -m` does not count.

= Does the plugin slow the site? =

No. Every report is sent from the shutdown handler after the response went out, with a hard timeout, and every failure is swallowed. The Shield's match runs before WordPress with a bounded grammar and fails open; the integrity scan spends half a second per request after the response; the rollups cost one shared-memory increment per request.

= Is blocking safe? =

Four things must be true before any request is refused: the project's blocking switch in codesafe, the rule marked PROVEN by a person who saw what it matched live, and both of this site's boxes. An observe rule never blocks. codesafe alarms when a blocking rule starts refusing logged-in users or addresses in good standing, and a person demotes it — nothing is demoted or promoted automatically. Unticking **Block detected exploits** stops blocking on the very next request.

= I run the old ovos-console plugin. How do I switch? =

Install ovos codesafe beside it and activate it. Its settings are copied, the old plugin is deactivated on the next admin page, and `OVOS_CONSOLE_*` constants, `ovos_console()` and the old filter names keep working. If PHP's `auto_prepend_file` names `wp-content/ovos-console/prepend.php`, keep that file until you have pointed the directive at `wp-content/ovos-codesafe/prepend.php`; the plugin keeps it working meanwhile. Then delete ovos console under Plugins.

= What leaves the site? =

Errors with their request context, redacted first: credentials and nonces dropped by field name, usernames and e-mail addresses masked, the request body parsed and cleaned (or off). Counters, never URLs or visitor data, for the rollups. The installed software list (versions, never paths or options) when you opt in. File paths, sizes and dates from the scan, never content. The matched fragment of a request the Shield flagged, capped at 200 bytes. Once a day, which of the plugin's own switches are on, and its version. Nothing is ever deleted or changed on the site.

== Changelog ==

= 1.0.2 =
* The plugin tells codesafe which of its own switches are on — 404 reports, traffic rollups, security events, the software inventory, auto-update, the integrity scan, the executed-file watch, the Shield, the JavaScript client — once a day and whenever one changes. Every feature needs its switch on in codesafe AND here, and codesafe's project list used to show only its own half: a feature switched on there but off on this site now shows dimmed, with the reason. It also shows this site's plugin version even when the site reports no errors. Nothing else is sent: no setting values, no keys, no content.

= 1.0.1 =
* A failed login on an **administrator** account (`manage_options`, or a multisite super admin) is reported as a WARNING: codesafe makes it an issue and alerts where the project alerts at that level, while every other wrong password stays at the kind's default and pages nobody.
* A failed login on an existing account now names the account, as a login that succeeded after failures already did: codesafe keeps each account's failures as one issue, and can tell many accounts refused at once — an outage, a group locked out — from one person retrying. A username no account carries stays nameless.
* A security event can carry the priority its sender gives it: `Sender::reportRefusal()` takes a last, optional priority, which codesafe keeps when it is more severe than the kind's default, so a refusal a site knows matters becomes an issue, and an alert where the project alerts at that level. Without one, every event goes out as before and codesafe applies the kind's default.

= 1.0.0 =
* First public release: PHP and JavaScript error reporting, security events, traffic rollups, the software inventory and auto-update of probed vulnerable plugins, the integrity scan, and the Shield — match and rate rules, at `plugins_loaded` and optionally before WordPress. Every release is signed, and the plugin verifies the signature before WordPress installs an update.
* **Executed-file watch** on the prepend layer: with PHP's `auto_prepend_file` pointing at the plugin's stub, every PHP file the site runs that WordPress did not ship as an entry point is recorded the moment it runs — the dropped webshell, in use — with its size, md5 and the request's address, and judged on the site's next request against what wordpress.org shipped. A file nobody shipped (under uploads, in the document root, foreign or modified under core or a wp.org plugin, hidden, or already deleted again) becomes an integrity finding in codesafe — its FILES ledger, an INBOX case, the mail and chat digest, removal advice — plus one security event (`file_executed`) carrying the address that ran it. A plugin's own endpoint hit directly is judged shipped once and never recorded again; wp-admin's entries come from the core checksum list, never from a pattern. On by default while the layer is active; the *Executed-file watch* box or `CODESAFE_ENTRY_WATCH` switches it off. Read-only: nothing is blocked, deleted or changed.
* The plugin was called ovos-console before: `ovos-codesafe` is its directory and text domain, `CODESAFE_*` its constants, `ovos_codesafe*` its options and filters. A site running ovos-console switches with one activation — see the FAQ.
