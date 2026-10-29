<p align="center">
	<img src="docs/header.png" alt="ovos codesafe — the WordPress client: from the first error to the verified fix" width="940">
</p>

# ovos codesafe — error monitoring and cyberdefence for WordPress

This plugin sends a WordPress site's PHP errors, JavaScript errors, failed logins and scanner probes to [ovos codesafe](https://ovos.github.io/codesafe/), which ranks what broke, proposes the fix, and reads the attacks on your site as a map of your weak spots. You get **your own codesafe instance** — run for you by ovos, or set up on your own infrastructure for larger organisations. **The plugin is the client, and it is free** — GPL-2.0, no telemetry of its own. [Talk to us](#talk-to-us) about getting an instance, or [try the live demo](https://console-demo.ovos.at/) first.

**Roughly half of what a public WordPress site reports is not a bug** — it is scanners looking for a way in. codesafe counts those apart from real errors, folds them into attack waves, matches your installed plugins against the vulnerability feeds so "vulnerable **and** being probed" is something you see rather than guess, and, for a CVE with no patch out yet, lets this plugin **shield** the site against the exploit's request shape until the update lands.

## Contents

- [Requirements](#requirements) · [Quick start](#quick-start) · [Recommended settings](#recommended-settings) · [APCu](#apcu)
- [Settings reference](#settings-reference) · [What leaves the site](#what-leaves-the-site-and-what-never-does) · [Updates](#updates) · [Coming from ovos-console](#coming-from-ovos-console) · [Troubleshooting](#troubleshooting)
- [What codesafe does with it](#what-codesafe-does-with-it) · [Advanced](#advanced) · [For developers](#for-developers) · [Talk to us](#talk-to-us)
- The long version of every feature: [docs/FEATURES.md](docs/FEATURES.md)

## Requirements

- **WordPress 6.0+** and **PHP 8.3+** — the `Requires PHP` header keeps older hosts from activating it.
- **An ovos codesafe instance** reachable from this site (HTTPS). One instance serves all your sites and services.
- **APCu — optional, but worth having.** Traffic rollups need it; nothing else does. See [APCu](#apcu).

## Quick start

1. **Install.** Download [`ovos-codesafe.zip`](https://github.com/ovos/codesafe-client-wordpress/releases/latest/download/ovos-codesafe.zip) and upload it under **Plugins → Add New Plugin → Upload Plugin**, or:

   ```sh
   wp plugin install https://github.com/ovos/codesafe-client-wordpress/releases/latest/download/ovos-codesafe.zip --activate
   ```

   The plugin is not on wordpress.org; it updates itself from this repository afterwards ([Updates](#updates)).

2. **Have the project in codesafe.** On the PROJECTS tab, add a project for this site if it has none. For browser errors, switch JS errors on for the project.

3. **Connect.** In wp-admin go to **Settings → ovos codesafe**, type your codesafe address under *Connect to codesafe* and press **Connect**. codesafe asks you to sign in and pick this site's project — any operator may — and adds this site's origin to the project's allowed JS origins; the browser comes back with the URL and both keys saved, **Enabled** ticked and a test error sent. The keys never travel through the browser: the site trades a one-time code for them, server to server, with a secret that never left it. Connect needs a codesafe that has the connect page; on an older one, or if you prefer, paste the project's keys into the fields below the button and tick **Enabled**, the master switch.

4. **Test.** The page says what codesafe answered to the test error, and the error is in the grid within a second; **Send test error** sends another.

5. **Read through the switches** ([below](#recommended-settings)). They all start on — each one is a feature of codesafe, described where you would switch it off — and codesafe's project switches decide what it takes. Browser errors and DOM snapshots start once the JS key is set.

Prefer code? Each setting has a `wp-config.php` constant that wins over the page and locks the field — with `CODESAFE_URL` or `CODESAFE_API_KEY` defined, the connection is the server's and the page offers no **Connect**:

```sh
wp config set CODESAFE_ENABLED true --raw
wp config set CODESAFE_URL https://codesafe.example
wp config set CODESAFE_API_KEY 'the project api_key'
wp config set CODESAFE_JS_KEY 'the project js_key'
```

## Recommended settings

<p align="center">
	<img src="docs/settings.png" alt="The plugin's settings screen in WordPress admin: the Connect to codesafe box with its address field and Connect button, then the codesafe URL and API key, log level, the switches for 404 reporting, traffic rollups (under an APCu line), security events and auto-update on codesafe's word — all ticked, as they start — the Shield status, the Shield coverage line with its two paste lines, the store, the executed-file watch, the integrity scan and its interval, release label, environment, tags and the trusted proxy, the browser-error options, and the Send test error and Scan now buttons" width="940">
</p>

**Everything starts on; codesafe decides.** Every feature on the page is on by default (only *Enabled*, the master switch, and *Also load in wp-admin* start off), and every one that sends something has a second half on the codesafe project: the 404, SECURITY and ROLLUPS switches, CVE for the inventory, FILES for the integrity scan and the executed-file watch, AUTO-UPDATE, JS errors with the origins allowlist, and the Shield. codesafe takes only what the project has on, so the boxes here say what this site *can* send, and a box you untick (or a constant set to `false`) is the site's own no. Read through them once: each describes a feature of codesafe.

**Always on, no box to tick.** The software inventory and the Shield run whenever the plugin is connected: codesafe drafts the Shield's rules from the inventory's CVE findings, publishes them to this site automatically, and decides which may block — the project's Shield switch (block, observe or off) and each rule's mode, with every rule's side effects shown and a switch to turn one rule off for this project alone. The server keeps its own say through constants (see [Advanced](#advanced)).

**The defaults, and when to change them.** None of these blocks anything; only auto-update changes the site, and only once codesafe asks.

| Setting | Default | Change it when |
|---|---|---|
| Enabled | off | tick it once the URL and the key are in — the master switch |
| Log level | `4 — warning` | `3 — error` for a noisy legacy site, `5 — notice` when you want more |
| Report 404s | on | never, as a rule — scanner and broken-link traffic, counted apart from errors and never turned into issues, is the probe signal |
| Traffic rollups | on | never — it counts only where the [APCu](#apcu) line says *available*, and codesafe takes it only with the project's ROLLUPS switch on. A project with it off refuses; the site then sends nothing for an hour, asks again, and says so under the box |
| Security events | on | never, as a rule — failed logins, the login that succeeded after failures, rejected nonces, forbidden REST calls, sensitive admin changes; usernames masked, a per-minute budget per kind (a flood is summarised, admin changes never held back) |
| Auto-update on codesafe's word | on | nothing happens until codesafe names a plugin, a theme or WordPress itself: one that is vulnerable **and** probed while the project's AUTO-UPDATE switch is on, or one an operator picks with **TURN ON** on the project's SOFTWARE list — then WordPress' own auto-update is switched on for it, the one virtual patch WordPress supports natively; an operator's **TURN OFF** there switches it off again (that entry alone; for WordPress itself it only withdraws codesafe's override). For WordPress itself that is minor releases only, even where `WP_AUTO_UPDATE_CORE` is `false` (untick the box to stop that; never a major release, never past `DISALLOW_FILE_MODS`, `AUTOMATIC_UPDATER_DISABLED` or a version-controlled site). On a site with a release pipeline untick it, or leave the project's switch off and pick nothing |
| Integrity scan | on, weekly | a read-only walk for files nobody shipped and the site's hardening posture, shown on this page; codesafe takes the report with the project's FILES switch on. Press **Scan now** once right after installing |
| Report JavaScript errors | on, with the JS key | window errors, unhandled rejections, failed fetch/XHR calls from the browser |
| Trace correlation | on | off only if a firewall rejects the extra header — a failed browser request and the PHP error behind it share one trace id |
| Request body | `structure` | `off` keeps every body on the site, and a failed POST cannot be replayed |
| DOM snapshot | on | off where pages carry personal data you do not want in codesafe: a snapshot carries the page's text ([What leaves the site](#what-leaves-the-site-and-what-never-does)) |
| Inline styles into snapshots | on | off where upload size matters — up to 400 KB of CSS per snapshot, so it renders styled |
| Also load in wp-admin and on the login page | off | on when admin-side JavaScript errors matter to you (noisier) |

**Turn on when it applies.**

| Setting | When | Why |
|---|---|---|
| Shield coverage FULL (`auto_prepend_file`) | when you can add one line to the PHP configuration — the page prints it | codesafe shows SHIELD FULL instead of SHIELD BASIC: the Shield judges every anonymous request before WordPress exists, direct hits on plugin files included, and the *Executed-file watch* (on by default) starts recording the PHP files nobody shipped the moment they run — see [Advanced](#advanced) |
| Release label | when you deploy with a version or a commit | every report carries it, and codesafe compares a release against the one before |
| Environment | on staging and test sites | `staging` shows as a badge beside the project name; blank sends WordPress' own `WP_ENVIRONMENT_TYPE` |
| Tags | when one instance serves many tenants or regions | one filter per tag in codesafe |
| Trusted proxy header and ranges | behind Cloudflare, a load balancer or another proxy | reports, rate rules and offender scores name the visitor instead of the proxy |

**Leave off unless you know why:** the Shield's `CODESAFE_SHIELD_KILL` constant, which switches the whole Shield off with no network — for a host that must never call home, or the moment a rule misbehaves and codesafe cannot be reached.

## APCu

APCu is PHP's shared memory between requests. On this page it matters for one switch:

- **Traffic rollups need it.** The per-minute counters accumulate in APCu and one request per minute ships them. Without APCu the switch collects nothing and sends nothing — deliberately silent, because a host without shared memory could only produce wrong numbers. The Shield's per-rule hit counters ride the same memory, so they are missing too.
- **Everything else works without it.** Errors, security events, the inventory, the integrity scan and the Shield's matching itself — the Shield keeps its rules in a file under `wp-content/ovos-codesafe/` (or `CODESAFE_STORE_DIR`) when there is no APCu. Only the Shield's rate rules need it too: without APCu they are skipped.

**How to tell:** the settings page says so on the **APCu** line right above *Traffic rollups* — *available* or *NOT available on this server's PHP*. Ask your host to enable the `apcu` extension for the **web server's** PHP (mod_php or PHP-FPM); on your own server that is `apt install php-apcu` or the equivalent, then a restart of PHP. The command line's `php -m` does not count: CLI PHP usually has APCu off even when the web server has it on.

## Settings reference

Every value lives under **Settings → ovos codesafe**, or as a constant in `wp-config.php` — a defined constant wins and locks the field.

| Setting | Constant | Default | |
|---|---|---|---|
| Enabled | `CODESAFE_ENABLED` | `false` | master switch for PHP and browser reporting |
| Console URL | `CODESAFE_URL` | — | the codesafe instance's base URL, e.g. `https://codesafe.example`; http(s) only — the form saves any other scheme as no URL and the plugin's own connections speak nothing else; a private or loopback address works |
| API key | `CODESAFE_API_KEY` | — | the project's secret api_key (PHP errors) |
| Log level | `CODESAFE_LOG_LEVEL` | `4` | send errors with syslog priority ≤ this (0 emergency … 7 debug) |
| Report 404s | `CODESAFE_REPORT_404` | `true` | front-end not-found requests, REST routes and admin-ajax actions this site does not have, as access events — rate-limited, static assets ignored, never issues |
| Traffic rollups | `CODESAFE_ROLLUPS` | `true` | anonymous per-minute request counters and duration histograms by the page type WordPress resolved — REST per registered namespace, admin-ajax per registered action — and logged-in state; needs APCu and the project's rollups switch |
| Security events | `CODESAFE_SECURITY_EVENTS` | `true` | refused actions and sensitive admin changes as `security` events; a per-minute budget per kind, the excess summarised |
| — | `CODESAFE_INVENTORY` | `true` | no settings box: installed plugin/theme/core versions, daily and on change; `false` keeps them on the site; needs the project's CVE switch (on by default) |
| Auto-update on codesafe's word | `CODESAFE_AUTO_UPDATE_VULNERABLE` | `true` | WordPress' own auto-update switched on for what codesafe names: a plugin or WordPress itself that is vulnerable and probed (with the project's Auto-update switch), or a plugin, a theme or WordPress' minor releases an operator picks on the project's SOFTWARE list; for WordPress itself minor releases only, over `WP_AUTO_UPDATE_CORE` `false` while this is on; an operator's TURN OFF switches it off again (for WordPress itself: codesafe's override withdrawn, WordPress' own setting untouched); needs the inventory |
| — | `CODESAFE_SHIELD_DETECT` | `true` | no settings box: pull this site's exploit rules (match, rate and virtual-patch rules) and codesafe's threat addresses every five minutes, and judge every request — an anonymous one before the other plugins load, a signed-in one there by the blocks that refuse whoever asks and whole at `plugins_loaded`; `false` stops the judging; fails open |
| — | `CODESAFE_SHIELD_ENFORCE` | `true` | no settings box: 403 on a request a blocking rule or a threat address matches — which rules block is codesafe's word; `false` stops all blocking on this site; inert without detection; read per request |
| — | `CODESAFE_SHIELD_KILL` | `false` | constant only: the whole Shield off, no network; codesafe shows the project's Shield as switched off by the server |
| Integrity scan | `CODESAFE_SCAN` | `true` | the background read-only walk for files nobody shipped; **Scan now** works without it |
| Scan interval | `CODESAFE_SCAN_INTERVAL` | `7` | days between background passes (`1` or `7`) |
| Executed-file watch | `CODESAFE_ENTRY_WATCH` | `true` | record every PHP file the site runs that WordPress did not ship as an entry point; records only while the `auto_prepend_file` layer is active ([Advanced](#advanced)); on multisite the main site's |
| Release label | `CODESAFE_RELEASE` | — | deploy label on every report, announced to codesafe once when it changes |
| Environment | `CODESAFE_ENVIRONMENT` | — | deployment stage; blank sends `WP_ENVIRONMENT_TYPE` |
| Tags | `CODESAFE_TAGS` | — | comma list on every report (`shop, eu, tenant:acme`); lowercase, up to ten |
| Report JavaScript errors | `CODESAFE_JS_ENABLED` | `true` | loads the bundled browser client on the front end |
| JS key | `CODESAFE_JS_KEY` | — | the project's public js_key (browser errors) |
| Trace correlation | `CODESAFE_JS_TRACE` | `true` | W3C traceparent header on the page's same-origin fetch/XHR calls |
| Request body | `CODESAFE_REQUEST_BODY` | `structure` | `off` — none; `structure` — parsed, credentials dropped, 8 KB |
| DOM snapshot | `CODESAFE_SNAPSHOT` | `true` | DOM snapshot with the first error per page load: inputs and scripts stripped, `data-codesafe-mask` areas blanked, the page's text included |
| Inline styles into snapshots | `CODESAFE_SNAPSHOT_STYLES` | `true` | embed the page's CSS so snapshots render styled |
| Also load in wp-admin and on the login page | `CODESAFE_JS_ADMIN` | `false` | also report browser errors from wp-admin and the login page |
| Trusted proxy header | `CODESAFE_TRUSTED_PROXY_HEADER` | — | behind a proxy/CDN only: the header naming the visitor (`CF-Connecting-IP`, `X-Forwarded-For`); read only from the ranges below |
| Trusted proxy ranges | `CODESAFE_TRUSTED_PROXIES` | — | the proxies' CIDRs or addresses, comma-separated; `cloudflare` = Cloudflare's published ranges (bundled). Empty: `REMOTE_ADDR` is the visitor |
| — | `CODESAFE_STORE_DIR` | — | constant only: an absolute directory **outside the document root** for the Shield's and the watch's store (recommended on nginx/IIS); the prepend stub stays in `wp-content/ovos-codesafe/` |

Example `wp-config.php` block:

```php
define('CODESAFE_ENABLED', true);
define('CODESAFE_URL', 'https://codesafe.example');
define('CODESAFE_API_KEY', '...');
define('CODESAFE_JS_KEY', '...');
define('CODESAFE_RELEASE', '2026.09.24');
define('CODESAFE_ENVIRONMENT', 'production');
```

## What leaves the site, and what never does

Every report is reduced in the plugin before it is sent; codesafe redacts again on its side as a backstop.

- **Errors** travel with their request context: the URL, method, headers and variables, the logged-in user id, WordPress version, active theme, and which plugin or theme the failing file belongs to. **Credentials are dropped by field name** wherever they stand — passwords in every spelling, tokens, keys, cookies, authorization headers, CSRF nonces, card numbers and security codes, account numbers and IBANs, and in the request's query and post the reset link's `key`, `code`, `otp`, `sig` and their kin. The request body is parsed and cleaned the same way (`structure`), or not sent at all (`off`). **E-mail addresses and usernames travel as written** — in the variables, the body, the URL and referrer, the extra data and a WP-CLI command's arguments: codesafe masks them on arrival and keeps the original encrypted for an audited reveal and a replay. Masked here, they could never be revealed.
- **Security events** carry the refused action's kind, the masked username or the option's *name*, never a value. The username is the one identity masked here: inside a sentence (`login failed for m***i*`) codesafe could not recognise it, and the account travels beside it as its user id. A login typed as an e-mail address travels as written, for codesafe to mask and keep.
- **Traffic rollups** are counts under names WordPress defines — never a URL, an address, a user agent or a cookie.
- **The inventory** is the list of what is installed with versions, the newest version WordPress's own update check knows for each and for core, whether each one auto-updates, where each one's updates come from (wordpress.org, or the host of its own update server) and whether an offered update has no download (a licence not active, commonly), whether the site can auto-update at all, and core's own update policy — minor and major on or off and what decided it, `WP_AUTO_UPDATE_CORE` as defined, what blocks it, the failed update WordPress parked (its code, never its paths) and the minor release on offer — never paths, options or user data.
- **A switch-on codesafe asked for** is reported as a security event naming why: `auto-update enabled for akismet (requested by an operator in codesafe)`, `auto-update enabled for WordPress core, minor releases (vulnerable and probed, per codesafe) — WP_AUTO_UPDATE_CORE is false on this site, overridden for minor releases only`.
- **The integrity scan** sends paths, sizes and dates — never a file's content — and changes nothing on the site.
- **The Shield** sends the matched fragment of a flagged request, capped at 200 bytes — none where a secret could be it (any cookie, a header or field named like a secret), and scrubbed of secrets as an error message is — and reads the request body only while a body rule is live.
- **DOM snapshots** (on by default) carry the page as the visitor saw it, with the first browser error per page load: input values and scripts are stripped in the browser, areas marked `data-codesafe-mask` are blanked, and the page's **text goes as it is** — a customer's account page with it. Untick *DOM snapshot* where that is more than you want in codesafe.

The full account, per feature, is in [docs/FEATURES.md](docs/FEATURES.md#what-never-leaves-the-site).

## Updates

The plugin updates itself from this repository through WordPress' own update flow: new versions appear under **Dashboard → Updates** and install like any directory plugin, one click or unattended (**Enable auto-updates** on the Plugins screen, or `wp plugin auto-updates enable ovos-codesafe`). **Every release is signed**, and the plugin verifies the signature before WordPress installs a byte; a package that does not verify is refused, a release without a signature is not offered. Details, and how to pin a version, in [docs/FEATURES.md](docs/FEATURES.md#automatic-signed-updates).

## Coming from ovos-console

The plugin was called `ovos-console` before 1.0.0. WordPress treats the new directory as a different plugin, so a site that runs `ovos-console` installs `ovos-codesafe` beside it and activates it. The rest happens by itself:

- **Settings** are copied from the `ovos_console*` options on first load. The old rows stay until you delete the old plugin.
- **The old plugin is deactivated** on the next admin page, so nothing is reported twice, and a notice says it can be deleted under Plugins.
- **`OVOS_CONSOLE_*` constants** in wp-config.php keep working; `CODESAFE_*` wins where both are defined. The settings page names each old one it finds.
- **`ovos_console()`** and the **`ovos_console_sslverify`** / **`ovos_console_sslverify_wporg`** filters keep working beside `ovos_codesafe()` and the `ovos_codesafe_*` filters.
- **The Shield before WordPress:** if PHP's `auto_prepend_file` still names `wp-content/ovos-console/prepend.php`, that stub is rewritten to run this plugin, so the layer stays on. Point the directive at `wp-content/ovos-codesafe/codesafe-shield.php` when convenient, and do not delete the old file before you have: PHP fails every request whose prepend file is gone.

## Troubleshooting

- **"Console unreachable — check the URL."** The site could not reach the instance: a typo in the URL, a firewall between the host and codesafe, or a self-signed certificate — see [Advanced](#advanced) for the TLS switch.
- **"Console rejected the key."** The API key is not the project's api_key, or belongs to another project. Copy it again from the project in codesafe.
- **Browser errors do not arrive.** *Report JavaScript errors* on, the **JS key** set, JS errors switched on for the project, and this site's exact origin (`https://www.example.com`, no path) in the project's JS origins.
- **Traffic rollups show nothing.** The APCu line above the switch says *NOT available*, or the project's rollups switch in codesafe is off — the page then says so under the box, and the site asks again every hour. Cached pages served before WordPress boots are never counted, by design.
- **No CVE findings.** The inventory needs the project's CVE switch in codesafe (on by default) and no `CODESAFE_INVENTORY` set to `false`; the first report goes out at the first request after the plugin is connected, and the matching runs nightly.
- **Shield status says "no ruleset yet".** The first request after saving pulls it; "off — …" names what switched it off. A rule exists only while codesafe has an open CVE finding for this site, so an empty ruleset on a fully updated site is the normal state.
- **A blocking rule refuses a real visitor.** Switch the rule off for this project in codesafe (SECURITY → SHIELD → **OFF HERE**) or demote it — the site drops it with its next report to codesafe, at the latest at its next five-minute pull; the INBOX will already carry its alarm. On the server, `CODESAFE_SHIELD_ENFORCE` set to `false` stops all blocking at the very next request, and `CODESAFE_SHIELD_KILL` the whole Shield.

## What codesafe does with it

<p align="center">
	<a href="https://console-demo.ovos.at/"><img src="docs/errors.png" alt="The ovos codesafe ERRORS grid: live PHP, JavaScript, Node, Python, security and 404 events from several sites with project, priority, message, URI and occurrence counts, and scanner probes from 31 addresses folded into one attack series" width="940"></a>
</p>

**[Try the live demo →](https://console-demo.ovos.at/)** — a public instance filled with synthetic errors, no login. One codesafe for everything you run:

- **Issues, not noise** — the same error a thousand times is one row with a count and an open → resolved → regressed lifecycle; a failed browser request and the PHP error behind it share one trace id.
- **OPS** — the INBOX, one list of what needs a person now, across issues, attack campaigns, probed CVE findings, files nobody shipped, late monitors, releases and the Shield's alarms, most urgent first, each with its one ready action.
- **Security** — probes folded into waves and cross-site campaigns, an address reputation, a blocklist export for your edge, CVE findings with a PROBED count, and the Shield's rules — drafted automatically from the CVE's fix and tested against real traffic, published to the sites that carry the finding, each rule's side effects on show and a switch to turn it off for one project.
- **Releases and performance** — a release compared against the one before it; response-time trends from the rollups.
- **Alerting** — throttled mail and chat per project; policies that notify, ticket or assign by themselves.
- **Ask your AI** — point Claude or any MCP client at codesafe, or hit `◇ AI EXPLAIN` on a row for a root-cause read.

Your own instance, not a shared tenancy — run for you by ovos in Vienna, or on your own infrastructure when the data has to stay there. More on the [product page](https://ovos.github.io/codesafe/).

## Advanced

**A self-signed certificate on the instance** (intranet setups) — TLS verification of the ingest call is on by default; disable it from an mu-plugin or your theme:

```php
add_filter('ovos_codesafe_sslverify', '__return_false');
```

The integrity scan's checksum lists come from wordpress.org over TLS; behind a proxy that re-signs traffic, that verification has its own switch: `add_filter('ovos_codesafe_sslverify_wporg', '__return_false');`

**Manual captures** from theme or plugin code — safe to call unconditionally, no-ops while the plugin is disabled:

```php
ovos_codesafe()->captureException($e, ['orderId' => 7]);
ovos_codesafe()->captureMessage('checkout step skipped', 4); // priority 4 = warning
```

**The Shield before the other plugins** (always on). While the Shield is on, the plugin keeps a must-use plugin, `wp-content/mu-plugins/ovos-codesafe-shield.php`, which judges every request before any other plugin's code runs: an anonymous one whole, a signed-in one — whose user only WordPress can name — by the blocks that refuse whoever asks (match rules, virtual patches for anyone); the rest of a signed-in request is judged at `plugins_loaded`, with its user. It goes when the Shield is switched off, the plugin deactivated or uninstalled.

**The Shield before WordPress** (optional, `auto_prepend_file`). The `plugins_loaded` hook never sees a direct request to a plugin file, and a block there has already paid for the WordPress bootstrap. The settings page prints one line for your PHP configuration that points PHP's prepend at a stub the plugin writes into `wp-content/ovos-codesafe/`:

```ini
; .user.ini or php.ini (PHP-FPM, CGI)
auto_prepend_file = "/var/www/site/wp-content/ovos-codesafe/codesafe-shield.php"
```

```apache
# .htaccess (Apache with mod_php)
php_value auto_prepend_file "/var/www/site/wp-content/ovos-codesafe/codesafe-shield.php"
```

With it, every anonymous request is judged before WordPress exists. A request carrying a login cookie to a file WordPress runs through (`index.php`, `wp-login.php`, wp-admin's own pages …), or a REST request carrying Basic credentials (an application password, which WordPress checks only later), is judged here with its caller unknown: anyone can send a cookie by that name, and a plugin's own files run before `plugins_loaded`, so a block that refuses whoever asks — a match rule, a virtual patch for anyone — refuses it here; everything else waits for `plugins_loaded`, which judges the request whole, with its user. A REST request with a token another plugin reads (Bearer, JWT, OAuth) and an XML-RPC call are judged here by the rules for anyone, while the rules for anonymous visitors or a capability wait until WordPress has signed the caller in and are judged then. WordPress's installer pages (`wp-admin/install.php`, `upgrade.php`, `setup-config.php`, and `wp-activate.php`) load no plugins, so this layer judges them whole, as it does anywhere else — a direct hit on a plugin's file — cookie or not. The stub is outside the plugin directory and includes the plugin only if it is still there, so removing the plugin never leaves PHP with a missing prepend file; the layer fails open on everything; the settings page says *ACTIVE* once PHP reports the directive. The stub's name says what it is, as Wordfence's `wordfence-waf.php` does; a directive that still names the plugin's earlier stub, `wp-content/ovos-codesafe/prepend.php`, keeps working — the plugin keeps that file current and never deletes it by itself, the settings page asks once for the new line, and you remove the old file once no directory's PHP configuration names it. Before any rule, the layer refuses every PHP file run from WordPress's update working directories (`wp-content/upgrade/`, `upgrade-temp-backup/`), which the updater never requests over HTTP. The plugin never edits your server configuration; the only `.htaccess` files it writes outside its store deny those two directories while WordPress updates (WordPress 6.4 and later, which have the `pre_unzip_file` hook) — layer or not, on every server but nginx, IIS and Caddy, which ignore them; OpenLiteSpeed reads a new `.htaccess` only after a restart unless its auto-load is on. Every file in the store begins with a PHP `exit` and the ruleset's file name is random, so a server that ignores `.htaccess` (nginx, IIS) serves nothing from it — the settings page warns there, and `CODESAFE_STORE_DIR` moves the data out of the document root. **Deactivating** the plugin switches the layer off through its consent file; **uninstalling** removes the store, leaving the stubs in place (doing nothing) while PHP names either of them or the configuration cannot be read, since another directory's `php.ini` or `.user.ini` may name the other — remove the `auto_prepend_file` lines, then the directory. On a **multisite** network the Shield, the executed-file watch and the trusted proxy are one for every site — they share one store — so the watch and the proxy are set on the main site, by a super admin. Details in [docs/FEATURES.md](docs/FEATURES.md#the-shield).

**The executed-file watch** rides the same layer (on by default while it is active; the *Executed-file watch* box or `CODESAFE_ENTRY_WATCH` switches it off): every PHP file the site runs that WordPress did not ship as an entry point is recorded the moment it runs — size, md5, the request's address — and judged on the next request against what wordpress.org shipped. A file nobody shipped becomes an integrity finding in the console, with one security event (`file_executed`) for the address that ran it. Details in [docs/FEATURES.md](docs/FEATURES.md#the-executed-file-watch).

**Pinning or rolling back** to one version, for a fleet:

```sh
wp plugin install https://github.com/ovos/codesafe-client-wordpress/releases/download/v1.0.0/ovos-codesafe.zip --force
```

**From git** — clone into `wp-content/plugins/ovos-codesafe` (the directory name matters), activate, update with `git pull`, and leave auto-updates off for that copy: an update from wp-admin replaces the whole directory with the release zip.

## For developers

- The repository root **is** the plugin directory — junction or symlink it into `wp-content/plugins/ovos-codesafe`.
- `assets/console-client.js` is a byte-identical copy of codesafe's browser client (intentionally ES5), and `src/Shield/Kernel.php` and `src/Shield/Wordpress.php` of its request-side kernel, the platform-neutral core and WordPress's module; all are synced from the console repository, never edited here. `Adapter.php` and `Prepend.php` require the module right after the core, by path, and hand it to every kernel and Facts they build. `Tests\Shield` holds both kernel files to php-library's copies (and to the console's `client-php/Shield.php` and `client-php/Shield/Wordpress.php` when a checkout is beside this one), checks that both layers read the module, and smokes a judge without WordPress.
- Tests run on php-library's harness, the way the console's do, and on every push (`.github/workflows/tests.yml`, PHP 8.3–8.5): `cd ci && composer install && cp .env.tests .env && php cli.php tests run`. `ci/` is a test-only application and `tests/` holds the classes — the Updater's signed-update path, the Shield kernel and the prepend layer, and `Tests\Sanitizer`, which drives a WooCommerce checkout through the plugin's real request path so no password, cookie or nonce leaves the site raw. Neither directory ships in the release zip.
- Two classes skip themselves unless pointed somewhere: `Tests\SanitizerStored` runs the same checkout through the console's own scrubbing (`OVOS_CONSOLE_PATH`, or `../console` beside this repository), and `Tests\WordPressLive` drives the signed update on a real WordPress with this plugin active (`OVOS_WP_PATH`).
- The product is codesafe; the identifiers stay: the `ovos-codesafe` slug and directory, the text domain, the `CODESAFE_*` constants, the `ovos_codesafe_*` filters and the `ovos-codesafe.zip` asset every install URL and updater knows.
- Releasing: [`docs/RELEASE.md`](docs/RELEASE.md) — the four version spots, the changelog, one `v*` tag; the workflow verifies, builds, signs and publishes.

## Talk to us

codesafe is built and run by [ovos](https://ovos.at/) in Vienna. We use it on our own client sites every day, which is why it is shaped the way it is.

- **Questions about the plugin, or a bug in it** — open an [issue](https://github.com/ovos/codesafe-client-wordpress/issues).
- **Want codesafe for your sites?** Write to **[office@ovos.at](mailto:office@ovos.at)**. You get your own instance: we run it for you, or for larger organisations we set one up on your own infrastructure. Happy to just answer whether it fits what you have.
- **Try it first** — the [live demo](https://console-demo.ovos.at/) needs no login.

## License

This plugin is [GPL-2.0-or-later](LICENSE) and always will be — it is a WordPress plugin and a client, and you can read, fork and audit every line of what runs on your site.

The ovos codesafe it talks to is a commercial product — your own instance, run for you by ovos or set up on your infrastructure. It is not covered by this licence.
