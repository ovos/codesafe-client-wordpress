# ovos codesafe for WordPress — the features in depth

The [README](../README.md) says how to install the plugin, which switches to
turn on and what needs APCu. This document is the long version of each
feature: exactly what is read, what is sent, what never leaves the site, and
what codesafe does with it. Read it when a switch's one-line description is
not enough.

- [Traffic rollups](#traffic-rollups)
- [Software inventory](#software-inventory)
- [Auto-update probed vulnerable plugins](#auto-update-probed-vulnerable-plugins)
- [The Shield](#the-shield)
- [Integrity scan](#integrity-scan)
- [Security events](#security-events)
- [What never leaves the site](#what-never-leaves-the-site)
- [Automatic, signed updates](#automatic-signed-updates)

## Traffic rollups

Error reports alone have no denominator: "37 requests for pages this site
does not serve" reads very differently on 50 000 requests a minute than on
200. With rollups enabled, the plugin counts every request WordPress handles
into per-minute counters — request total, split by response status, HTTP
method, the *page type* WordPress resolved (front page, `singular/{post_type}`,
`archive/{taxonomy}`, search, login, admin, REST, …) and logged-in state —
and ships each completed minute as **one** small POST to codesafe. A
request answered 404 counts only as "matched nothing", which is exactly the
scanner-probe signal codesafe's attack detection reads as a rate.

The same fragment also carries **request-duration histograms**:
every request's wall time (PHP start to shutdown) counted into 12 fixed
buckets, per site and per page type, the fastest of them (up to 25 ms, where
most requests land) split once more into up to 5, 10 and 25 ms. codesafe reads them back as
≈p50/≈p95 trends with release markers and a slowest-pages table on its
PERFORMANCE panel — bucket counts only, so a raw timing never leaves the
site and the payload grows by a few hundred bytes a minute.

It also carries the **Shield's hit counters** — how many
requests each rule observed and how many it refused, per minute — which is
what the SHIELD band's hour, day and lifetime columns are made of, and what
the alarm judges a blocking rule by. Counts per rule id, nothing else.

What deliberately never travels: URLs, query strings, IP addresses, user
agents, cookies, or anything else request-derived — the counter names come
from a closed vocabulary WordPress itself defines, so the payload is
structurally incapable of carrying visitor data.

Enabling it takes **two switches** (either one off keeps the feature inert):

1. **In WordPress:** Settings → ovos codesafe → *Traffic rollups*, or lock it
   in `wp-config.php`:

   ```php
   define('CODESAFE_ROLLUPS', true);
   ```

2. **In codesafe:** tick *Traffic rollups* (`rollups_enabled`) on the
   project — a sender posting to a project without it is refused and stays
   inert, so enabling the two sides in either order is safe.

Requirements and caveats:

- **APCu is required** (the `apcu` PHP extension, enabled for the web SAPI).
  Counters accumulate in APCu shared memory and one request per minute ships
  them; without APCu the feature is a silent no-op — no counting, no sends,
  no errors — because a WordPress host without shared memory could only
  produce undercounted numbers, and a wrong denominator is worse than none.
  The settings page says above the switch whether APCu is there.
- Requests served entirely by a page-cache plugin (or a CDN) before WordPress
  boots are not counted — cached traffic never reaches PHP. Probe traffic is
  never a cache hit, so the attack signal is unaffected.
- Overhead is one APCu increment set per request (sub-microsecond, no I/O)
  plus a single sub-second POST per minute of traffic, sent after the
  response went out.

## Software inventory

Off by default, because an installed-software list is a **disclosure**: it
names exactly which plugins (and versions) a site runs, which is precisely
what an attacker probes for. It therefore ships only when BOTH ends opt in —
this setting (or `CODESAFE_INVENTORY`) and the project's CVE switch in
codesafe; codesafe answers `403` and stores nothing until its side is on too.

What one report contains, exactly: `platform` (`wordpress`), the core and
PHP versions, and up to 300 items of `{type: plugin|theme|mu-plugin, slug,
version, name, active}`. No file paths, no option values, no user data —
the report says *what* is installed, never where or how it is configured.

When it ships: once a day (the heartbeat codesafe reads as "the sensor is
alive"), and after anything that changes the list — installs, updates,
(de)activations, deletions, theme switches, core updates. The change hooks
only mark a flag; the actual gather-and-send runs at shutdown, fire-and-
forget with the same millisecond bounds as every other call this plugin
makes, so it can never slow a visitor down. An unchanged report is
acknowledged by codesafe as a duplicate and costs one timestamp update.

codesafe's nightly `security cve-sync` matches stored inventories against
the vulnerability feeds and keeps per-project findings: installed version,
the version that fixes it, CVSS, the CVE and its weakness class — and a
PROBED count when codesafe has already seen requests naming that plugin's
path, which is the "you run X *and* someone is looking for it" signal worth
acting on first. A finding is a case in the INBOX from the moment it is
probed; it resolves by itself when the inventory says the update landed.

## Auto-update probed vulnerable plugins

The answer to an inventory report may name the installed plugins that are
vulnerable **and** already being probed on this site. With *Auto-update
probed vulnerable plugins* on (or `CODESAFE_AUTO_UPDATE_VULNERABLE`), the
plugin adds exactly those to WordPress' own `auto_update_plugins` list — the
same toggle you flip on the Plugins screen, the one virtual patch WordPress
supports natively — and reports each switch-on as a `privileged_action`
security event, so codesafe's audit trail carries it.

Nothing is downgraded, deactivated or deleted, and nothing is installed by
this plugin: WordPress updates from wordpress.org on its own schedule, the way
it would for a plugin you ticked yourself. Opt-in at both ends — codesafe
names plugins only while the project's own Auto-update switch is on — and a
plugin that later drops out of the vulnerable set keeps its auto-update; that
is a WordPress setting you own, and the plugin never takes one away.

## The Shield

A CVE in a plugin you run has a window: from the day it is public until the
day you update. Scanners read the same advisories you do, and the exploit
usually arrives before the patch is out or before you get to it. The Shield
closes that window with a **request-side match**, run by this plugin before
WordPress does anything: codesafe drafts the exploit's request shape from
the CVE's fix commit or advisory, a person reviews it, and every site with
an open finding of that CVE pulls the rule and matches its requests against
it.

**Two switches, four gates.** *Exploit detection* (`CODESAFE_SHIELD_DETECT`)
pulls the rules and **observes**: a match is reported to codesafe as a
`shield_observe` security event — the rule, the CVE, the matched fragment
capped at 200 bytes, the address — and the request is served. Nothing is
blocked. *Block detected exploits* (`CODESAFE_SHIELD_ENFORCE`) answers
403 to a request that matches a rule marked **PROVEN** — a rule a person
promoted in codesafe after reading what it matched on live traffic — and
reports it as `shield_block`, with an `X-Shield-Rule` header naming the rule.
Before any request is refused, four things have to be true: codesafe's own
per-project blocking switch, the rule's `proven` mode, this site's detection
box, and this site's blocking box. An observe rule never blocks, whatever the
boxes say. Both boxes are read on every request and never cached with the
rules, so unticking acts on the very next request. `CODESAFE_SHIELD_KILL`
(a constant only) switches the whole Shield off with no network at all — for
a host that must never call home.

**What is read per request:** the path and query string, the user agent, the
address — and the request body only while a *body rule* is live for this
site (form fields as `name=value` lines, other bodies capped at 64 KB).
Nothing of it is stored or sent except the matched fragment.

**Where the rules live:** the kernel pulls `GET /api/v1/shield` from codesafe
every five minutes as a conditional request (a `304` costs nothing), and caches
the ruleset in APCu and in a file under `wp-content/ovos-codesafe/` behind a
deny `.htaccess` — the file alone on a host without APCu. The file's name is
drawn at random and every other file in the directory begins with a PHP
`exit`, so a server that ignores `.htaccess` (nginx, IIS) serves nothing from
it; the settings page warns there, and the `CODESAFE_STORE_DIR` constant moves
the store to a directory outside the document root (the prepend stub stays
where PHP's configuration names it). A codesafe that goes
silent for a day lifts the rules: a stale shield is not a shield. The rules a
site holds are never more than 25, and each is one of `uri`, `ua`, `ip` or
`body` with `equals`, `prefix`, `contains`, `cidr` or a **bounded regex** —
the same grammar the JS side and codesafe's own screen run, conformance-tested
in all three, with nothing that can be made to run slow.

**It fails open, always.** A rule the engine cannot run, a codesafe that does
not answer, a store that cannot be written, an error of any kind — the request
is served as if the Shield were not there. The Shield may never be why a page
does not load.

**Rules are temporary by construction.** A finding rule exists only while a
live CVE finding on this site justifies it: update the plugin, and the rule
leaves the next pull by itself. A rule a person writes by hand in codesafe
carries an expiry or a name and a note — every rule either expires or is
accountable.

**The alarm.** A blocking rule can be wrong — a pattern wider than the fix
that refuses an editor's save, a user-agent fragment shared with a partner's
webhook. codesafe watches every PROVEN rule's refusals: signed-in requests
refused, a spread of addresses that is a real share of the site's traffic,
addresses with no attack history. Any of those raises an Urgent case in the
INBOX with one action — **DEMOTE TO OBSERVE** — and pages the project's mail
and chat. Nothing is demoted automatically; a person decides, and the sites
stop refusing within five minutes of the click.

The **Shield status** line under the two switches says what this site holds:
how many rules are live and how many of them may block, when the ruleset was
last pulled, and whether blocking is on — or why the Shield is off.

The Shield needs the software inventory (the rules follow the findings) and
the project's CVE switch in codesafe. Hits are counted into the traffic
rollups where APCu is available.

**Rate rules.** A rule can also COUNT: the same predicate plus
a limit per window (`≤ 60 / 60 s`), for an endpoint that is expensive and
gets hammered during an attack — the search, `wp-login.php`, `xmlrpc.php`,
a heavy REST route. The count is per address, per user (the signed-in user's
id, or on a `wp-login.php` POST the login name being tried — the spray against
one account from many addresses; the name is only a counter's key and never
leaves the site) or for the route itself, whoever asks — a ceiling that sheds
load so the endpoint cannot take the site down. Fixed windows, two adjacent
buckets (a sliding estimate), in APCu: **no APCu, no rate rules** — the file
cannot count — and the limit is per server. Past it the request is reported
once per window as `shield_rate`, and a rule a person promoted, with
*Block detected exploits* ticked, answers **429** with `Retry-After` — at
`plugins_loaded` and in the before-WordPress layer. A match rule is judged
first: a request one refuses is never charged to a rate rule's count. It does
not stop a flood (that is the edge's job — your host, a CDN, `limit_req`); it
keeps an expensive endpoint from being the thing that falls over. The pull
names `X-Shield-Kinds: match,rate`, so a site on an older plugin is never sent
a rate rule.

**Before WordPress — the optional `auto_prepend_file` layer.** The
`plugins_loaded` hook runs after WordPress has loaded every plugin; a direct
request to a plugin file (`wp-content/plugins/x/upload.php`, a standalone
script — the shape a large share of WordPress CVEs take) never reaches it,
and a block there has already paid for the bootstrap and the database
connection. The plugin writes a stub into `wp-content/ovos-codesafe/prepend.php`
and the settings page prints the one line that points PHP's prepend at it
(`auto_prepend_file = "…"` for `.user.ini` / `php.ini`, `php_value
auto_prepend_file "…"` for `.htaccess` under mod_php). With it, every
**anonymous** request is judged against the cached ruleset before WordPress
exists — the same rules, the same two switches, read from a small consent
file the plugin rewrites whenever a box changes — and a block answers 403
with `X-Shield-Rule` and `X-Shield-Layer: prepend` for the cost of a file
read. A request carrying a WordPress login cookie to a file WordPress runs
through — `index.php`, `wp-login.php`, `xmlrpc.php`, `wp-cron.php`,
`wp-comments-post.php`, wp-admin's own pages but `load-scripts.php` and
`load-styles.php` — is left to `plugins_loaded`, which knows the user: an
editor is never refused by a layer that cannot tell them from a bot, and the
alarm's signed-in signal keeps working. Anywhere else (a direct hit on a
plugin's PHP file) no adapter will ever run and the cookie's name proves
nothing, so this layer judges it like any other request. The queued
reports' URLs are scrubbed before they are written. Behind a proxy or CDN the
*Trusted proxy* settings make this layer, the adapter and every report name
the visitor instead of the edge; the header is read only when the connecting
address is in the trusted ranges. Deactivating the plugin rewrites the consent
with every box off, so the layer stops on the next request; on a multisite
network the store is one for every site, and only the main site — set by a
super admin — drives it. An observe
verdict is handed to the plugin to report with the request's full context
(one verdict, one count, one report per request); a block's report — and an
observe verdict on a request WordPress never loads for, such as a direct hit
on a plugin file — is queued with that request's own URI, address, user agent,
status and time, and sent on the site's next request wearing them, not the
next request's. The stub lives outside the plugin
directory and includes the plugin only if it is still there, so removing the
plugin never leaves PHP with a missing prepend file — a fatal on every
request — and everything fails open. The plugin never edits server
configuration; the integrity scan recognises the stub as the plugin's own.

## The executed-file watch

The integrity scan below finds the file nobody shipped while it sits on
disk; every other sensor needs it to throw. A working webshell does neither —
it answers 200 and is used. With the prepend layer above active, the plugin's
code runs before every PHP file on the site, the dropped one included, and
`SCRIPT_FILENAME` names it. So the layer records **every PHP file the site
runs that WordPress did not ship as an entry point**, the moment it runs.

What it costs: for the request that is the site (`index.php`, `wp-login.php`,
`wp-cron.php`, `xmlrpc.php`, the other root entries) one `realpath()` and one
string comparison, no file read. A `wp-admin` page or a plugin's own endpoint
reads one small JSON file — the *known set* — and is done. Only a stranger
writes: its path, hit count, first and last time, and the file as it was when
it ran (size, mtime, md5 — the evidence that survives its deletion), with the
last request's address, URI, user agent and method.

What decides *known*: wp-admin's entry scripts come from the wordpress.org
core checksum list for the running version, never from a pattern
(`wp-admin/evil.php` would match one) and never from the disk (a compromised
tree would vouch for its own shell); until that list is cached the watch is
inactive and the settings page says so. A shipped file hit directly — a
plugin's own AJAX endpoint — is judged once and joins the known set, so it is
never recorded again.

What judges: on the site's next request, after the response, the plugin takes
the queue and asks the same questions the scan asks — where is it, and does
wordpress.org's list for that root know it, with the md5 **as it ran**:

| the executed file | detector | tier proposed |
|---|---|---|
| under uploads (not a *silence is golden* stub) | `executed_uploads` | urgent |
| in the document root, not a core root file, no installed owner | `executed_root` | urgent |
| in a directory of its own under the root (a second application?) | `executed_root` | high |
| a plugin's own root file (`wordfence-waf.php`) | `executed_root_owned` | info, once |
| a hidden path segment anywhere | `executed_hidden` | urgent |
| loose in `wp-content` | `executed_content` | urgent |
| under `wp-admin` / `wp-includes`, not in the core list / md5 differs | `executed_core_foreign` / `executed_core_modified` | urgent |
| in a wp.org plugin, not in its list / md5 differs | `executed_plugin_foreign` / `executed_plugin_modified` | urgent |
| a premium or custom plugin, a single-file plugin, a theme, a must-use plugin | `executed_unverified` | info, once |
| recorded, but gone by the time the judge looks | `executed_vanished` | urgent |

Executed is a stronger fact than present: where the scan says *high* for a
plugin's foreign file, this proposes *urgent*. The console decides, as it does
for every scan tier.

What is sent: the findings ride the integrity-scan report (`POST
/api/v1/ingest/files`, `scan.mode: entry`, never complete — it saw a queue,
not the tree, so the console's ledger never reads a missing path as gone from
it) with the path, size, mtime and a line like *executed 4× · first 25.09.
03:12 · last 25.09. 03:14 UTC · from 203.0.113.9 · GET*. The console's FILES
ledger, INBOX case, mail and chat digest, removal advice and it-came-back
logic are the scan's. Beside it, **one security event per foreign file**
(kind `file_executed`, `extra.source` uploads or unknown, `extra.file`,
`extra.hits`, `extra.md5`, `extra.layer: prepend`) wearing the last
request's own facts, so the address that ran it scores as an offender and
joins the attack waves. Info rows are listed, not scored.

Consent: the *Executed-file watch* box (on by default — pointing PHP at the
stub is already the operator's deliberate act, and the watch only reads), or
`CODESAFE_ENTRY_WATCH` in wp-config.php; the plugin must be connected to a
console, and the console project's file switch must be on for the report to
be taken. The Shield's boxes and kill constant do not gate it. **Nothing is
blocked, deleted or changed**: a finding is a place to look, and the request
it came from was served as it would have been.

## Integrity scan

Every other sensor in this plugin needs the foreign file to *do* something after
the plugin is installed: throw an error (so `source` can say `uploads` or
`unknown`), be saved through the editor, be activated. A webshell dropped before
the plugin arrived, used once and left behind, does none of that. The integrity
scan asks the tree directly.

What it looks for, in a read-only walk (root → uploads → wp-content → plugins →
core → themes, so an interrupted pass has already covered the urgent part):

| finding | tier | what it catches |
|---------|------|-----------------|
| executable-shaped file under uploads (`x.php`, `shell.php.jpg`, `.phtml`, `.phar`) | urgent | the classic drop — the `index.php` listing stubs plugins write there are recognised and skipped |
| media file whose first kilobyte carries `<?php` / `<?=` (`.ico .jpg .png .gif .webp .bmp .pdf .svg`; `.txt .log .csv` under uploads) | urgent | the `favicon_a1b2.ico` family, the image behind an `AddHandler` |
| PHP in the document root that is not one of core's own root files | urgent | `about.php`, `wp-conflg.php`; Wordfence's `wordfence-waf.php` is recognised when Wordfence is installed |
| `.htaccess` / `.user.ini` / `php.ini` directives: `auto_prepend_file` / `auto_append_file` to a file no installed plugin owns, `AddHandler`/`AddType` mapping PHP to another extension, `SetHandler` to PHP, `engine on` or CGI under uploads, `RewriteRule`/`Redirect`/`ErrorDocument` to another host | urgent / high | persistence, the polyglot's trigger, the redirect hack — reported as directive kind, file and line, never the line's text |
| the live `auto_prepend_file` / `auto_append_file` of the PHP configuration | urgent | the `.user.ini` trick from the running interpreter's point of view |
| PHP in a hidden path (`.x.php`, `.well-known/…`) | high | the hidden drop — dotfile tool configs in vendored packages are recognised |
| PHP in `wp-content` outside any plugin, theme, mu-plugin or upload path | high | `wp-content/strange/s.php`; WordPress' own `.l10n.php` translations are recognised |
| a drop-in (`object-cache.php`, `advanced-cache.php`, `db.php`, `wp-cache-config.php`) with none of its known plugins installed and no vendor header | high | the shell disguised as a cache config — a drop-in with a vendor header or an installed owner is listed as `info` |
| a plugin data directory (`wflogs`, `w3tc-config`, `updraft`, …) whose plugin is not installed | high | listed and never descended: the directory is the finding |
| must-use plugins, drop-ins with an owner, `install.php` | info / high | listed for the operator; `install.php` on a live site is high |
| **checksums** — a core file that differs from wordpress.org's list for this version, or a PHP file under `wp-admin/` / `wp-includes/` the list never had | urgent | the backdoored `wp-load.php`, the `class-wp-helper.php` nobody shipped — `core_modified` / `core_foreign` |
| **checksums** — the same two verdicts inside a wp.org plugin's directory, against the plugin's own list for its installed version | high | `plugin_modified` / `plugin_foreign`; a premium or custom plugin has no list and is not judged, themes are never judged this way |
| **database** — administrators (registration date, sessions, last login), application passwords on admins, active plugins whose file is gone, scheduled hooks nobody listens to, uninstall callables of gone plugins, options carrying code markers, foreign scripts / iframes / obfuscation in published content and widgets (posts and pages, plus the rows a block theme keeps its markup in: Site Editor templates and template parts, global styles, the Customizer's Additional CSS — none of them files), a site URL disagreeing with its constant, registration into a role above subscriber | info – high | the attacker's other filesystem; ids, option names and hook names only — never a login, an e-mail, a value or a post body |
| a directory under uploads or in the root that changed after its newest file | info | something was removed or renamed here recently — dated, so codesafe can hold it against the waves |
| a file owned by another uid than its siblings; a symlink leaving the site | high | the web server writing among the deploy user's files; the symlink attack (silent on Windows and single-uid hosting) |

Plus which protection is present — the active login-rate-limit, two-factor and
upload-scanner plugins, or "none detected" (commodity features this plugin
deliberately does not re-implement) — and a `debug.log` written under the
document root as a high finding.

Plus the **posture**: `DISALLOW_FILE_EDIT`, `DISALLOW_FILE_MODS`, debug
display, whether uploads denies PHP by `.htaccess` (Apache/LiteSpeed only),
world-writable uploads, world-readable `wp-config.php`, XML-RPC, open
registration and its default role, version control in the document root,
`readme.html`, and the ini fingerprint (`auto_prepend_file`, `open_basedir`,
`disable_functions`, `user_ini.filename`, OPcache).

The checksum lists come from wordpress.org — core by version and locale
(`api.wordpress.org/core/checksums`), every wp.org plugin by slug and installed
version (`downloads.wordpress.org/plugin-checksums`) — fetched once per version,
kept in a transient for a month, a 404 remembered for a week. A background
chunk fetches at most one list and yields the rest to the next request; a
*Scan now* round fetches three. Listed files missing from disk are counted per
area, never listed: hosts strip readmes, and a missing file is not an
intrusion. Every finding a list produced carries `md5 differs …` or `not in
the wordpress.org list …` as its detail, so the authority behind it is visible.

The database checks run once per pass, bounded (`LIMIT`s, twenty findings per
detector), read-only, and report what can be acted on without disclosing
anything private: `users/<id>` with the registration date as the finding's
date (codesafe holds it against the attack waves of the same hours —
*admin #57 was registered forty seconds after 27.0.113.86 stopped probing*),
`options/<name>` with the length and the marker, `options/cron/<hook>`,
`posts/<id>` with the foreign host.

What it never does: write, delete, rename, quarantine or touch `.htaccess`;
follow a symlink; descend into `.git`, `node_modules`, `wp-content/cache` or
`wp-content/upgrade`; read more than the first kilobyte of a media file or
64 KB of a directive file; send a file's content. Findings are paths, sizes
and dates. A finding is a place to look, not a verdict.

**Scan now** — the button under Settings → ovos codesafe → Integrity scan. Each
round spends up to fifteen seconds (always five short of `max_execution_time`)
and the page re-submits itself until the pass is complete; the results table
stays on that page, codesafe or not. **Background** — the *Integrity scan*
switch (or `CODESAFE_SCAN`): half a second per request after the response
went out, one pass per interval (`CODESAFE_SCAN_INTERVAL`, `1` or `7`
days), the position kept in one option between requests, no WP-Cron, no APCu.
A completed pass is posted to codesafe's `/api/v1/ingest/files` (the
SECURITY view's FILES band); an instance without that endpoint answers 404 and
the settings page still shows the result.

The tier on a finding is the plugin's proposal. codesafe decides — against
the project's repository where one is mapped, the attack waves of the same
hours, and what an operator has already acknowledged — and a new urgent or
high finding, or a path that comes BACK after a scan said it was gone, pages
the project's channels at once.

## Security events

Errors say what *broke*; security events say what was *refused* — and refusals
are where an attack is visible before anything breaks. With the switch on, the
plugin reports:

- **Failed logins** (`auth_failure`) — every door funnels through the same
  hook: the wp-login form, XML-RPC, REST basic auth, and rejected application
  passwords. The username is masked to every fourth character, the rest
  starred (`marcin` -> `m***i*`), so the line keeps the length — and past 24
  characters it states the real length instead (`x***x***...[4000]`), which is
  what a credential-stuffing probe looks like. It is the one identity masked
  in the plugin: inside a sentence codesafe could not recognise it as a name,
  and the account travels beside the line as `context.userId`. A login typed
  as an e-mail address travels as written — codesafe finds an address
  anywhere, masks it and keeps the original encrypted. The reason travels as
  WordPress' error codes (`invalid_username`, `incorrect_password`), never as
  core's HTML error messages.
- **The login that succeeded after failures** (`auth_success`) — the
  credential-stuffing success, with the failure counts and the account it
  landed on. Clean logins are never reported.
- **Rejected nonce checks** (`csrf_reject`) — a failed `check_admin_referer` /
  `check_ajax_referer` is the CSRF signal (or an expired-session replay);
  the nonce action name says which form was targeted.
- **Forbidden REST calls** (`permission_denied`) — REST requests answered
  401/403, the shape of user enumeration and capability probing; reported
  with the error code and route.
- **Sensitive admin changes** (`privileged_action`) — the moves an attacker
  makes *after* getting in, routine for an admin but an audit trail during an
  incident: user creation and role grants (an administrator created is its
  own kind), plugin and theme installs and activations, changes to the
  `users_can_register`, `default_role`, `admin_email`, `siteurl` and `home`
  options (the option *name* only — values are deliberately not reported),
  saves from the theme/plugin file editor, application passwords minted for
  administrators, and every plugin the auto-update switched on.

They arrive in codesafe as `security` events, grouped apart from errors and
accepted independently of the project's severity threshold. The refusals
(failed logins, rejected nonces, REST 401/403s) are informational: no issues,
no alerts, they feed codesafe's attack detection and the address reputation.
The two kinds that *happened* do become issues — a login that succeeded after
failures, and a sensitive admin change — and codesafe's default rules escalate
the ones that matter: a success after five or more failures or from a known
attacker's address, a theme install through the admin (the forced install that
opens the Click2Shell chain on WordPress before 7.1.1), a file-editor save and
a newly minted application password — those reach whoever the project's alert
policy names. Each kind has its own per-minute budget — 30 for the
refusals, 60 for `shield_observe`, 120 for `shield_block` — so a
credential-stuffing run cannot turn the reporter into the flood it surfaces,
nor silence the privilege grant or the block that follows it. Sensitive admin
changes (`privileged_action`) and executed files are never held back; what goes
over a budget is counted and sent as one summary event of its kind (`summary`,
`suppressed`) when the minute closes.

Enable it under Settings → ovos codesafe → *Security events*, or lock it in
`wp-config.php`:

```php
define('CODESAFE_SECURITY_EVENTS', true);
```

The codesafe side is on by default for every project (the per-project
*Security events* switch under the project's Data tab is the off switch).
The Shield's own kinds (`shield_observe`, `shield_block`, `shield_rate`) do
not depend on this switch — detection is its own consent.

## What never leaves the site

Every report is reduced before it is sent, in the plugin — codesafe redacts
again on its side as a backstop, but the first cut happens here:

- **Credentials are dropped**, by field name, wherever they stand: request
  variables, headers, the request body and the URL's query string. The list
  covers passwords in every spelling (`pass`, `pwd`, `user_pass`, `pass1`),
  tokens, secrets, keys, authorization headers, cookies — and a
  **CSRF nonce** (`_wpnonce`, `_ajax_nonce`, every field with `nonce` at a word
  start). A nonce is short-lived, but it is a per-user, per-action token, and
  it had no business travelling. Names that merely contain the letters
  (`announce`) are untouched. Payment fields go the same way in every
  gateway's spelling — card number, security code (`cvv`, `cvc`, `csc`),
  expiry — with `rp_key`, account numbers and IBANs.
- **Query-only credentials** — `key`, `code`, `auth`, `sig`, `signature`,
  `otp`, `pin`, `hash`, by exact name — are dropped from the URL and from the request's query and post bags alike, so
  the password-reset link's `key` never leaves in a bag while the URL beside it
  says `[redacted]`.
  The login name beside them (`log`, `user_login`) still travels as typed:
  codesafe masks it on arrival and keeps the original encrypted for an
  audited REVEAL — masked here, it could never be revealed.
- **The request body is a document, not text**: `structure`, the
  default, parses it — form, JSON, XML-RPC — walks the keys the way the
  variables are walked (so `opts[api_key]` is caught, and a percent-encoded
  credential is decoded first), masks what is left inside the values, and
  re-encodes at 8 KB. A body that will not parse is dropped rather than handed
  to a regex. `off` sends none; `full` is the raw body, 16 KB.
- **E-mail addresses and usernames travel as written** to codesafe, which
  masks them on arrival and keeps the original encrypted for an audited
  REVEAL and a replay — the request variables and body, the URL and referrer, the extra data, a WP-CLI command's arguments, a
  security event's or a not-found line and a Shield report drained from the
  early layer. Every secret above is still dropped here. The one exception is
  a login name written into a failed-login line, masked to every fourth
  character (`marcin` -> `m***i*`): codesafe cannot recognise a name inside a
  sentence. The early layer's own queue files on the site keep their URLs with
  the secrets dropped and the people in them, like everything else.
- **URLs are read raw and judged decoded**: the uri and the referer
  never pass through `sanitize_text_field()`, which deletes every `%XX` and
  turned `anna%40example.com` into an unrecognisable `annaexample.com`. A
  secret's name is recognised percent-encoded (`%74oken=`), behind an encoded
  `=` (`token%3D…`) and inside a URL carried as a value (`redirect_to`, up to
  three levels deep) — in the uri, and in a request field that holds a URL
  or a query, whose nested `pwd=` the query bag used to carry whole.
- **Traffic rollups** carry counts under names WordPress itself defines —
  never a URL, an address, a user agent or a cookie.
- **The inventory** says what is installed, never where or how it is
  configured; **the scan** sends paths, sizes and dates, never content; **the
  Shield** sends the matched fragment, capped at 200 bytes, and reads the body
  only while a body rule is live.
- **Browser reports** strip input values and scripts from a DOM snapshot in
  the browser, before upload.
- **The hello** says which of the plugin's own switches are on, on or off,
  and the plugin's version — once a day and whenever a box changes, so
  codesafe's project list can dim a feature switched on there but off here.
  Never a setting's value, a URL or a key.

## Automatic, signed updates

The plugin keeps itself current, with no updater plugin, license
key or update server involved. Its header declares the GitHub repository as its
`Update URI`, so WordPress core's own update flow (5.8+) asks the plugin for
its latest GitHub release: new versions appear under **Dashboard → Updates**
and install like any directory plugin, straight from the release zip.

- **One-click**, from **Dashboard → Updates** or the Plugins screen, or `wp plugin update ovos-codesafe`.
- **Unattended** — flip **Enable auto-updates** in the Plugins list (`wp plugin auto-updates enable ovos-codesafe`) and core's twice-daily cron installs new versions on its own.
- The check is fire-and-forget: an offline host, a rate-limited GitHub API or a missing asset just means "no update visible right now", never an error on your dashboard.
- A successful answer is cached for twelve hours. **Check again** on the updates screen bypasses core's own cache; to also drop the plugin's, `wp transient delete ovos_codesafe_latest_release`.

**Every release is signed, and the plugin verifies the signature before WordPress installs a byte**. The release workflow signs the zip — Ed25519, over the whole file — with a key that lives in a GitHub environment admitting release tags only, and publishes the signature beside the zip (`ovos-codesafe.zip.sig`). On update the plugin downloads both, verifies with `sodium_crypto_sign_verify_detached()` (WordPress bundles it for its own update signing, so it exists on every install) and hands WordPress the verified file. A package that does not verify is refused with a message on the update screen and nothing is installed; a release without a signature is not offered at all. There is no degraded mode. The public key is in the source (`Updater::PUBLIC_KEY`, `0d91f295…919c04`) and in [`RELEASE.md`](RELEASE.md).
