# ovos codesafe for WordPress — the features in depth

The [README](../README.md) says how to install the plugin, what each switch
defaults to and what needs APCu. This document is the long version of each
feature: exactly what is read, what is sent, what never leaves the site, and
what codesafe does with it. Read it when a switch's one-line description is
not enough.

- [Connect](#connect)
- [Not-found requests](#not-found-requests)
- [Traffic rollups](#traffic-rollups)
- [Software inventory](#software-inventory)
- [Auto-update on codesafe's word](#auto-update-on-codesafes-word)
- [The Shield](#the-shield)
- [Integrity scan](#integrity-scan)
- [Security events](#security-events)
- [What never leaves the site](#what-never-leaves-the-site)
- [Automatic, signed updates](#automatic-signed-updates)

## Connect

**Connect** under Settings → ovos codesafe fills in the codesafe URL and both
keys without anyone copying them — the flow of OAuth's authorization code
with PKCE (RFC 7636), with codesafe's operator as the one who says yes:

1. The admin types the codesafe address and presses **Connect**. The site
   draws a random *state* and a random *verifier*, keeps both for ten minutes
   in a transient tied to that WordPress user, and sends the browser to
   codesafe's `#/connect` page with the site's address and name, the address
   to come back to, the state, and the verifier's SHA-256 (the *challenge*) —
   all in the URL's fragment, which no web server logs.
2. In codesafe, an operator signs in and picks the site's project from the
   existing ones; codesafe adds the site's origin to the project's allowed JS
   origins when it is missing, and sends the browser back with a one-time
   code, valid for five minutes. **Cancel** sends it back with nothing.
3. The site checks the state against the one it kept for that user — an
   answer it did not ask for is refused — and posts the code and the verifier
   to codesafe, server to server, at the address the admin typed. codesafe
   burns the code on the first try and answers the keys only when the
   verifier's SHA-256 is the challenge.
4. The site saves the URL and both keys, ticks **Enabled**, and sends a test
   error; the page says which project it joined and what codesafe answered.

What the browser carries is a code nobody can use without the verifier, and
the verifier never leaves the site's server. With `CODESAFE_URL` or
`CODESAFE_API_KEY` defined in `wp-config.php` the connection is the server's,
and the page offers no **Connect**.

Connect needs a codesafe that has the `#/connect` page and the
`/api/v1/connect/exchange` door; with an older one, paste the project's keys
into the fields below the button instead.

## Not-found requests

With *Report 404s* on (the default; `CODESAFE_REPORT_404`), three kinds of
request for what this site does not have are reported as **access events**
(`kind: not_found`), apart from errors and never turned into issues:

- **Pages** WordPress resolved to a 404 — the path as the message, its query
  stripped. Static assets (a broken image, a stylesheet, a font) are noise
  and are not reported.
- **REST routes** the REST server has no handler for — WordPress's own
  `rest_no_route` answer, for an unknown path or a known one asked with a
  method it does not serve. The row names the route under the site's REST
  prefix (`404 Not Found: /wp-json/foo/v1/bar`) whatever spelling the request
  used, so `/wp-json/…` and `?rest_route=` are one group while the row's
  address keeps what was asked; `extra.namespace` names the registered
  namespace the route falls under. Empty says no such plugin here; a name
  says the plugin is here and that route is not (another version?). Another
  404 of a route that exists — a post id that does not — is no miss, and a
  sub-request inside a batch or an `_embed` is not reported. A miss asked
  with `_envelope`, which WordPress answers 200 with the 404 inside, is a
  row too (status 200, as answered); the rollups count it as an answered
  request.
- **admin-ajax actions** nothing handles — admin-ajax.php runs `admin_init`,
  every plugin's hooks with it, and then asks whether anything handles the
  action for this caller; when nothing does it answers `0` with status 400
  (an empty or non-scalar action is refused before `admin_init` and names
  nothing). The row keeps the one query
  parameter that names what was asked for, `404 Not Found:
  /wp-admin/admin-ajax.php?action=<action>` (the action cut to 64 characters,
  nothing else of the query); its status is WordPress's 400, and
  `extra.handler` says `none` — nothing handles the action, the plugin is not
  here — or `signed_in`: the action exists for signed-in users only and an
  anonymous caller asked for it, so the plugin IS here. The Shield's or a
  firewall's 403, or a handler's own answer, is no miss.

One budget serves the three: 30 reports a minute, so a hard scan cannot turn
the reporter into the flood it surfaces — the [traffic
rollups](#traffic-rollups) carry the full counts, these rows are the
samples. The site's box and the project's `report_404` switch in codesafe
both have to be on.

What codesafe does with them: they feed the attack waves and the offender
bar like any probe, and the CVE lane's PROBED count reads them —
`admin-ajax.php?action=<name>` for an ajax entry point, the namespace for a
REST one — so a vulnerability whose entry point a scanner is hunting reads as
probed on this site.

## Traffic rollups

Error reports alone have no denominator: "37 requests for pages this site
does not serve" reads very differently on 50 000 requests a minute than on
200. With rollups enabled, the plugin counts every request WordPress handles
into per-minute counters — request total, split by response status, HTTP
method, the *page type* WordPress resolved (front page, `singular/{post_type}`,
`archive/{taxonomy}`, search, login, admin, REST per registered namespace,
admin-ajax per registered action, …) and logged-in state —
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
structurally incapable of carrying visitor data. A REST namespace or an
admin-ajax action enters a counter only when this site registered it
(`/rest/wp/v2`, `/admin/ajax/heartbeat`); a request for one it did not counts
as "matched nothing", like a 404 page. At most 40 distinct names of those two
families count in a minute, the rest under `/rest` and `/admin/ajax`: APCu is
finite, and a full one would undercount every counter.

It runs on **two switches** (either one off keeps the feature inert):

1. **In WordPress:** Settings → ovos codesafe → *Traffic rollups*, on by
   default; untick it, or lock it off in `wp-config.php`:

   ```php
   define('CODESAFE_ROLLUPS', false);
   ```

2. **In codesafe:** *Traffic rollups* (`rollups_enabled`) on the project, on
   for new projects. A project with it off answers 403: the site then counts
   and sends nothing for an hour, asks again, and the settings page says
   under the box since when codesafe refuses — so the two sides can be
   switched in either order.

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

On whenever the plugin is connected to codesafe: the Shield's rules are
drafted from the findings the inventory opens, so a site without it is a
site the Shield cannot protect. It is still a **disclosure** — it names
exactly which plugins (and versions) a site runs — so it goes to the
project's own codesafe and nowhere else; `CODESAFE_INVENTORY` set to false
keeps it on the site, and codesafe answers `403` and stores nothing while
the project's CVE switch is off.

What one report contains, exactly: `platform` (`wordpress`), the core and
PHP versions, the `environment` every report carries (so codesafe keeps a
developer's copy on the production key apart from production), and up to
300 items of `{type: plugin|theme|mu-plugin, slug,
version, name, active}`. A plugin or theme also carries what WordPress's own
update check knows about it — the same numbers the Plugins and Themes screens
show, premium and GitHub-hosted plugins included, since every updater files
its version there: `latest` (the newest version offered, the installed one
when the check found it current, left out when the check never saw it),
`auto_update` (whether WordPress auto-updates it), `forced` (whether a
filter decides that instead, left out when none does), `source` (where its
updates come from: `wordpress.org` when the check's entry says so, else the
host of its `Update URI` header or of its own update server; left out when
nothing says — it never updates by itself, or was not checked yet) and
`package: false` when an update is offered without a download, which
WordPress cannot install by itself — commonly a commercial plugin whose
licence is not active. Whether a licence is paid or active is not knowable
from the site; where the updates come from is, and it is the honest proxy.
And one block says whether WordPress can auto-update at all here —
`updates: {allowed, blocked_by, checked_at, core_latest, core}`, `blocked_by` naming the first reason it
cannot (`file_mods` for `DISALLOW_FILE_MODS`, `updater_disabled`, `filter` for
the `plugins_auto_update_enabled` filter, `vcs` for a version-controlled
plugins directory), `checked_at` when WordPress last checked, and
`core_latest` the newest WordPress core its own core check knows — the
upgrade it offers, the installed version when core is current, left out when
the check knows neither or names a version off the shape. `core` is core's
own update policy (see [WordPress core](#wordpress-core)): `minor` and
`major` (WordPress's verdict for the next release of each kind — on
WordPress's cron run and in wp-admin what WordPress itself will hear, so a
plugin's filter answering after codesafe's override reads as `filter`),
`policy` (what decided `minor`: `default`, `option`, `constant`, `filter` or
`codesafe`), `constant` (`WP_AUTO_UPDATE_CORE` as defined, when core reads
it), `override` (codesafe's switch-on kept here and the box ticked, so it
answers), `kept` (the switch-on stored here, whatever the box — codesafe
settles an operator's TURN OFF on it), `forced` (the `auto_update_core`
filter's verdict, left out when none decides), `blocked_by` (`file_mods`,
`updater_disabled`, `vcs`, or `failed` for a failed update WordPress will not
retry: a critical one, or the very update on offer again from the same
installed version — a newer release than the one that failed is tried, and
with nothing on offer nothing waits), `failed` (that update — attempted
and installed version, its error code, critical, retry, when — never its
error data, which carries paths), `offer` (the minor release WordPress would
install by itself) and `checked_at` (its core check's time). No file paths, no
option values, no user data — the report says *what* is installed, never
where or how it is configured. codesafe's SOFTWARE list on the project shows
it: name, version, the latest version, vulnerabilities, auto-update — and
the core version beside the latest one.

When it ships: once a day (the heartbeat codesafe reads as "the sensor is
alive"), and after anything that changes the list — installs, updates,
(de)activations, deletions, theme switches, core updates, a changed
auto-update choice, a new update check — and when codesafe has something for
the site: every answer codesafe gives (to an error batch, a rollup, the
Shield's five-minute check) carries the project's *software version*, and a
version other than the one the last inventory answer carried sends the
inventory again, so an operator's pick reaches the site within minutes. A
version is settled once codesafe answers that send — a 2xx, or a refusal that
asking again would not change (400, 401, 403, 404, 422); a send codesafe does
not answer (a 5xx, a 429, a timeout) leaves it unsettled, and the same
version is asked for again only after 15 minutes, then 30, doubling up to a
day, until one is answered — a slow or failing codesafe is never asked on
every answer the site hears. Only a version in the shape codesafe sends
(letters, digits, `.`, `_`, `-`, at most 64 characters) is taken at all. The
change hooks only mark a flag; the actual gather-and-send runs at shutdown,
after the response went out, fire-and-forget with the same millisecond
bounds as every other call this plugin makes, so it can never slow a visitor
down. An unchanged report is
acknowledged by codesafe as a duplicate and costs one timestamp update.

codesafe's nightly `security cve-sync` matches stored inventories against
the vulnerability feeds and keeps per-project findings: installed version,
the version that fixes it, CVSS, the CVE and its weakness class — and a
PROBED count when codesafe has already seen requests naming that plugin's
path, which is the "you run X *and* someone is looking for it" signal worth
acting on first. A finding is a case in the INBOX from the moment it is
probed; it resolves by itself when the inventory says the update landed.

## Auto-update on codesafe's word

The answer to an inventory report may name plugins and themes to auto-update,
each with its reason, and — in a list of its own, `auto_update_off` — ones an
operator switched off:

- **probed** — a plugin that is vulnerable **and** already being probed on
  this site, named while the project's own AUTO-UPDATE switch is on (off for
  new projects). Plugins only.
- **requested** — a plugin or theme an operator picked with **TURN ON** on the
  project's SOFTWARE list in codesafe. No project switch needed: the click is
  the decision.
- **both** — requested, and vulnerable and probed too.

With *Auto-update on codesafe's word* on (the default;
`CODESAFE_AUTO_UPDATE_VULNERABLE` locks it, the name kept from when it covered
the probed plugins alone), the plugin adds exactly those to WordPress' own
`auto_update_plugins` / `auto_update_themes` lists — the same toggles you flip
on the Plugins and Themes screens, kept in the network's options on a
multisite network, where WordPress's updater reads them — and reports each
switch-on as a `privileged_action` security event naming why ("auto-update
enabled for contact-form-7 (requested by an operator in codesafe)"). The next
inventory tells codesafe it took, and the SOFTWARE list then shows it on.

### WordPress core

codesafe may name WordPress itself (`core`), for the same reasons: an
operator's **TURN ON** on the project's SOFTWARE list, or a core
vulnerability codesafe saw requests shaped like its exploit for, while the
project's AUTO-UPDATE switch is on. For core that means **minor releases
only** — 7.1.2 to 7.1.3, never 7.1 to 7.2 — and the site decides at that
moment whether it may:

- **Nothing happens** where WordPress cannot update itself
  (`DISALLOW_FILE_MODS`, `AUTOMATIC_UPDATER_DISABLED`, a version-controlled
  site, a failed update WordPress will not retry), where a filter forces
  core's update off or another plugin's filter decides it, or where minor
  releases are on already — WordPress's own default.
- **Where WordPress's own switch decides**, the plugin sets it: the
  `auto_update_core_minor` option to `enabled` — the site's setting from
  then on, with or without this plugin (`wp option update
  auto_update_core_minor disabled` turns it off again).
- **Where `WP_AUTO_UPDATE_CORE` is `false`** in `wp-config.php`, the plugin
  keeps the switch-on (`ovos_codesafe_core_auto_update`: when and why) and
  answers WordPress's `allow_minor_auto_core_updates` question with yes —
  hooked last, on WordPress's cron run and in wp-admin only — **while the
  box is ticked**. Untick *Auto-update on codesafe's word* (or set
  `CODESAFE_AUTO_UPDATE_VULNERABLE` to `false`) and it stops at the next
  run; delete the option (`wp option delete ovos_codesafe_core_auto_update`,
  `wp site option delete` on a network) or deactivate the plugin and it is
  gone. The settings page says it under the box while it is kept. Majors
  are never touched: WordPress asks that question only for a release of
  the installed branch.

Each switch-on is a `privileged_action` security event: "auto-update
enabled for WordPress core, minor releases (requested by an operator in
codesafe) — WP_AUTO_UPDATE_CORE is false on this site, overridden for minor
releases only". Every such line codesafe's word caused (on, off, the override
and its withdrawal) names no request: it is applied at the end of whatever
request read the answer, and that visitor's address, page, session and
account had nothing to do with it. WordPress then installs the minor release at its own
twice-daily check, with its own compatibility and filesystem checks; the
inventory's `core` block says the new policy at once and the new version
once it landed. Not reported: whether WordPress has the filesystem
credentials to write — that shows up after the fact as a failed update.

**On is not updated.** Nothing is installed by this plugin: WordPress updates
from wordpress.org, or the plugin's own update server, on its own schedule —
twice a day — the way it would for a plugin you ticked yourself, and the
VERSION column shows when it landed. A site that cannot auto-update
(`DISALLOW_FILE_MODS`, the updater switched off, a version-controlled plugins
directory) says so in its inventory, and codesafe offers no button there.
Nothing is downgraded, deactivated or deleted.

**Off again only on an operator's word.** A plugin that later drops out of the
vulnerable set, or a request an operator withdraws before the site picked it
up, keeps its auto-update. What switches it off is an operator's **TURN OFF**
on the project's SOFTWARE list: the plugin takes that one entry out of
WordPress' `auto_update_plugins` / `auto_update_themes` list — every other
entry, the site admin's own choices included, stays — reports it as a
`privileged_action` ("auto-update disabled for contact-form-7 (switched off by
an operator in codesafe)"), and the next inventory confirms it. For WordPress
itself TURN OFF only withdraws codesafe's override (the kept
`ovos_codesafe_core_auto_update`); WordPress' own `auto_update_core_minor` and
`WP_AUTO_UPDATE_CORE` decide again, and codesafe never switches WordPress'
own security releases off. The hold lives in codesafe: while an operator's
OFF stands, codesafe names that item in no switch-on, the vulnerable-and-probed
path included. An item named both ways in one answer ends off. Unticking
*Auto-update on codesafe's word* stops both directions.

## The Shield

A CVE in code you run — a plugin, a theme, WordPress itself, any part of
the application's source — has a window: from the day it is public until
the day you update. Scanners read the same advisories you do, and the exploit
usually arrives before the patch is out or before you get to it. The Shield
closes that window with a **request-side match**, run by this plugin before
WordPress does anything: codesafe drafts the exploit's request shape from
the CVE's fix commit or advisory, tests it against real traffic, and every
site with an open finding of that CVE pulls the rule and matches its
requests against it — automatically, nobody has to approve it.

**On by default; codesafe decides.** The Shield pulls the rules and
matches every request. A rule in **observe** reports a match to codesafe as
a `shield_observe` security event — the rule, the CVE, the matched fragment
capped at 200 bytes and never a secret (below), the address — and the
request is served. A rule set to
**block** answers 403 and reports `shield_block`, with an `X-Shield-Rule`
header naming the rule. Which rules may block is codesafe's word: the
project's Shield switch (block, observe or off) and each rule's mode — and a
rule can be switched off on one project alone. codesafe sets a rule to block
at once only when two independent drafts of it agree on the request it
targets and its guard fits the fix — a capability every administrator holds,
or for a forged request a nonce; every other rule observes first. On the site, three constants
are the server's own say, read on every request and never cached with the
rules: `CODESAFE_SHIELD_DETECT` false stops the matching,
`CODESAFE_SHIELD_ENFORCE` false stops the blocking, and `CODESAFE_SHIELD_KILL`
switches the whole Shield off with no network at all — for a host that must
never call home, or the moment a rule misbehaves and codesafe cannot be
reached. The site tells codesafe when the kill constant is set.

**What is read per request:** the path and query string, the user agent, the
address — and the request body only while a *body rule* is live for this
site (form fields as `name=value` lines, other bodies capped at 64 KB).
Nothing of it is stored, and the one part sent is the matched fragment — never
where a secret could be it: a rule that reads any cookie, a header or a
parameter named like a secret, or a parameter by a wildcard name reports no
fragment, nor does a `uri` rule on a request whose query carries a
secret-named parameter, nor a `body` rule on a body that holds one or can be
read only raw. What is sent is scrubbed of secrets by text as an error message
is, so a pattern that matched a form does not carry the `pwd=` beside the
match.

**How a rule reads it:** a `uri` rule matches the query as sent and as PHP's
`$_GET` reads it, every `+` a space, so a rule on `union select` meets
`union+select`. A virtual patch's `request:` condition reads the query's and
the form's values, then whatever PHP's `$_REQUEST` holds beside them — the
cookies, on a host whose `request_order` takes them in. A JSON body is
decoded up to 1 MiB; a larger one sent to the handler a blocking virtual
patch pins is taken to carry what the patch looks for and refused — the
application decodes it whole, and padding must not turn a block into an
observe — while on any other handler such a rule only observes it.

**Where the rules live:** the kernel pulls `GET /api/v1/shield` from codesafe
every five minutes as a conditional request (a `304` costs nothing), and caches
the ruleset in APCu and in a file under `wp-content/ovos-codesafe/` behind a
deny `.htaccess` — the file alone on a host without APCu. The file's name is
drawn at random and every other file in the directory begins with a PHP
`exit`, so a server that ignores `.htaccess` (nginx, IIS) serves nothing from
it; the settings page warns there, and the `CODESAFE_STORE_DIR` constant moves
the store to a directory outside the document root (the prepend stub stays
where PHP's configuration names it). The ruleset kept there is sealed, an
HMAC under a key derived from the project key over every field of it, the
kernel's modules among them, and a record not sealed under this site's key is
ignored as if there were none. That stops a record written by something that
can write the store but cannot read its directory, by another site sharing the
APCu pool, by an earlier plugin version or another kernel, or pulled under
another API key. It does not stop code that runs as the web server's own user:
that code can read the consent file, which holds the seal key, and the API key
in the site's options too. The request that finds such a record is not judged
by it and pulls the ruleset whole; the settings page says so meanwhile. The
layers before WordPress judge by the consent file the plugin rewrites when a
setting or the API key changes; where it cannot be rewritten (its owner or
permissions changed, a read-only filesystem) the settings page's Shield status
says so, and a layer that cannot read the rules leaves every request to
`plugins_loaded`. A codesafe that goes
silent for a day lifts the rules: a stale shield is not a shield. Of what
codesafe serves a site keeps at most 25 match and rate rules, 100 virtual
patches and 5 000 threat addresses — the rest is dropped — and no match rule
that would refuse an ordinary visitor: one that holds on the home page asked
by a current browser with no body, or an address range wider than a /8 (IPv6:
a /32). A match rule is one of `uri`, `ua`, `ip` or `body` with `equals`,
`prefix`, `contains`, `cidr` or a **regex** — the same grammar the JS side and
codesafe's own screen run, conformance-tested in all three. The regex runs in
PHP's PCRE, which backtracks: a pattern written to run slow stops at PHP's
`pcre.backtrack_limit` and matches nothing.

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
webhook. codesafe watches every blocking rule's refusals: signed-in requests
refused, a spread of addresses that is a real share of the site's traffic,
addresses with no attack history. A rule codesafe set to block by itself is
switched back to observe automatically when its refusals reach that share of
the traffic — the one signal an attacker cannot produce. The other two, and
any signal on a rule a person set to block, raise an Urgent case in the INBOX
with one action — **SET TO OBSERVE** — and page the project's mail and chat.
codesafe's SHIELD tab shows every rule's side effects of the last day and can
switch a rule off on one project alone (**OFF HERE**). The sites stop refusing
with their next report to codesafe, at the latest at the next five-minute pull.

The **Shield status** line on the settings page says what this site holds:
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
once per window as `shield_rate`, and a rate rule set to block answers
**429** with `Retry-After` — at
`plugins_loaded` and in the before-WordPress layer. A match rule is judged
first: a request one refuses is never charged to a rate rule's count. It does
not stop a flood (that is the edge's job — your host, a CDN, `limit_req`); it
keeps an expensive endpoint from being the thing that falls over. The pull
names `X-Shield-Kinds: match,rate`, so a site on an older plugin is never sent
a rate rule.

**Before the other plugins — the mu-plugin stage, always on.** While the
Shield is on the plugin keeps `wp-content/mu-plugins/ovos-codesafe-shield.php`
(it creates the directory if needed; removed when the Shield is switched off,
on deactivation and on uninstall; a file of that name it did not write is
never touched). WordPress loads must-use plugins before every other plugin,
so a request is judged before a vulnerable plugin's own code has run — the
before-WordPress layer's judge below, without the server edit: an
**anonymous** one whole, a signed-in one by the blocks that refuse whoever
asks, the rest of it at `plugins_loaded` (below). One judge per
request: with the prepend layer active the mu-plugin does nothing, and a
request either early layer passed is not judged again (a rate rule counts it
once).

**Shield coverage FULL — the optional `auto_prepend_file` layer.** The settings page and codesafe's PROJECTS list say the Shield's coverage: FULL where this layer runs, BASIC where it does not. The
`plugins_loaded` hook runs after WordPress has loaded every plugin; a direct
request to a plugin file (`wp-content/plugins/x/upload.php`, a standalone
script — the shape a large share of WordPress CVEs take) never reaches it,
and a block there has already paid for the bootstrap and the database
connection. The plugin writes a stub into `wp-content/ovos-codesafe/codesafe-shield.php`
— named for the product and its job, as Wordfence's `wordfence-waf.php` is;
a bare `prepend.php` reads as malware persistence to people and scanners —
and the settings page prints the one line that points PHP's prepend at it
(`auto_prepend_file = "…"` for `.user.ini` / `php.ini`, `php_value
auto_prepend_file "…"` for `.htaccess` under mod_php). With it, every
**anonymous** request is judged against the cached ruleset before WordPress
exists — the same rules, the same two switches, read from a small consent
file the plugin rewrites whenever a box or the API key changes; it carries the
key the ruleset's seal is checked with, derived from the project key and never
the key itself, so this layer reads the rules but cannot fetch them — and a block answers 403
with `X-Shield-Rule` and `X-Shield-Layer: prepend` for the cost of a file
read. A request carrying a WordPress login cookie to a file WordPress runs
through — `index.php`, `wp-login.php`, `xmlrpc.php`, `wp-cron.php`,
`wp-comments-post.php`, wp-admin's own pages but `load-scripts.php`,
`load-styles.php` and the installer's `install.php`, `upgrade.php` and
`setup-config.php` — is judged here with its caller unknown. Anyone can send
a cookie by that name, and mu-plugins, drop-ins and a plugin's own files run
before `plugins_loaded`, so a block that refuses whoever asks — a match rule,
a virtual patch for anyone — refuses it here; a rule that asks who the
caller is, a rate rule and every observe wait for `plugins_loaded`, which
judges the request whole, with its user: an editor is refused here only by a
rule that would refuse them there too, and the alarm's signed-in signal keeps
working. So is a REST request carrying Basic credentials, judged here the
same way and whole at `plugins_loaded`: WordPress checks an application
password only after this layer, and at `plugins_loaded` the plugin checks it
the same way, read-only
(no use recorded, no action fired), so an integration is judged as its user
— not as anonymous; the REST prefix comes from the consent file, where the
plugin writes `rest_get_url_prefix()` once every plugin and the theme have
set theirs. A REST request the login cookie alone signs in, without a valid
REST nonce, is judged anonymous at `plugins_loaded`, as WordPress runs it.
A caller WordPress signs in only later — a REST request with a token another
plugin reads (Bearer, JWT, OAuth), every XML-RPC call, whose credentials
each method checks — is unknown to the kernel at `plugins_loaded`: a rule
for anonymous callers or a capability waits instead of refusing, and the
request is judged again where WordPress has settled the user
(`rest_pre_dispatch`, `xmlrpc_call`), its verdict reported once then; never
judged again, it is reported as the observe it was. The early layers judge
such a request by the rules for anyone and leave the rest to the adapter the
same way, and the must-use plugin, which runs inside WordPress, treats every
signed-in request as this layer treats one to a file WordPress runs through,
whatever the script. A request to the REST API's `/batch/v1` has each
request its body lists judged as a request of its own. Where the user cannot
be told, a rule that asks only observes. Anywhere else — a direct hit on a
plugin's PHP file, or WordPress's installer pages (`wp-admin/install.php`,
`upgrade.php`, `setup-config.php`, `wp-activate.php`), which load no
plugins — no adapter will ever run and the cookie's name proves nothing, so
this layer judges the request whole, like any other. The queued reports'
URLs are scrubbed before they are written, and what a queued report carries
of its request is capped — the URL at 2 KB, the user agent, referer and host
at 512 bytes each — since every refused request rewrites the queue. Behind a proxy or CDN the
*Trusted proxy* settings make this layer, the adapter and every report name
the visitor instead of the edge; the header is read only when the connecting
address is in the trusted ranges. Deactivating the plugin says goodbye to
codesafe (`sensor_goodbye`, see *Security events*), then rewrites the consent
with every box off, so the layer stops on the next request; on a multisite
network the store is one for every site, and only the main site — set by a
super admin — drives it. An observe
verdict is handed to the plugin to report with the request's full context
(one verdict, one count, one report per request); a block's report — and an
observe verdict on a request WordPress never loads for, such as a direct hit
on a plugin file — is queued with that request's own URI, address, user agent,
status and time, and sent on the site's next request wearing them and nothing
of the next request's — not its status, session, signed-in account or trace.
The stub lives outside the plugin
directory and includes the plugin only if it is still there, so removing the
plugin never leaves PHP with a missing prepend file — a fatal on every
request — and everything fails open. The plugin never edits server
configuration (the only `.htaccess` files it writes outside its store are
the denies below); the integrity scan recognises the stub as the plugin's own.
A configuration that still names an older stub — the plugin's earlier
`wp-content/ovos-codesafe/prepend.php`, or ovos console's
`wp-content/ovos-console/prepend.php` — keeps working: the plugin keeps
that file current, never deletes it, reports the layer live, and the
settings page asks once for the new line. Its own old stub stays current as
long as it is there — another directory's `php.ini` or `.user.ini` may still
name it. The uninstall removes the stubs only when PHP's configuration
names neither and can be read; while it names either, or cannot be read
(WP-CLI), both stay, inert — another directory's configuration may name the
other one.

**WordPress's update working directories.** Before any rule, the layer
refuses every PHP file run from `wp-content/upgrade/` or
`wp-content/upgrade-temp-backup/`: WordPress unpacks each update into the
first and parks the version it replaces in the second, and reads both
through the filesystem, never over HTTP — a script run there is a staged or
parked copy somebody found. The refusal is a 403 with `X-Shield-Guard:
upgrade_dir`, reported as `shield_block` with the message *shield guard
refused a script in the upgrade working directory*; it needs no rule and
follows the same switches (with blocking off it is observed and reported as
`shield_observe`, with detection off or the kill constant it does nothing).
The plugin also closes both directories without the layer, on WordPress 6.4
and later (the first with the `pre_unzip_file` hook): each time
WordPress unpacks a package into `wp-content/upgrade/` — after it emptied
the directory, before the first file is extracted and before the rollback
parks the old version (`pre_unzip_file`) — it writes a deny `.htaccess` and
an `index.php` into each of them, making `upgrade-temp-backup/` when
WordPress has not yet, through WordPress's own filesystem. WordPress's weekly
cleanup empties `upgrade-temp-backup/`, the two files with it; the next update
writes them again before it parks anything. A file by either name the plugin
did not write is left as it is (WordPress 7.1.4 and later keep an `index.php`
of their own in `upgrade/`). It skips only a server known to ignore
`.htaccess` — nginx, IIS, Caddy — and writes on an unnamed one (WP-CLI),
where the file is inert if ignored; on those three the layer's guard, or a
rule in the server's own configuration, is what closes the directories.
OpenLiteSpeed reads a new `.htaccess` only after a restart unless its
`.htaccess` auto-load is switched on.

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
last request's address, URI, user agent and method, and the HTTP status that
request ended with, written as it ends.

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
| under uploads | `executed_uploads` | urgent |
| in the document root, not a core root file, no installed owner | `executed_root` | urgent |
| in a directory of its own under the root (a second application?) | `executed_root` | high |
| a plugin's own root file (`wordfence-waf.php`) | `executed_root_owned` | info, once |
| a hidden path segment anywhere | `executed_hidden` | urgent |
| loose in `wp-content`, and not a file core ships there | `executed_content` | urgent |
| under uploads or loose in `wp-content`, stopping before any code runs (an `exit` or `__halt_compiler()` first, as W3 Total Cache and AIOS write their data), judged on the bytes as they ran | `inert_php` | info, once |
| under `wp-admin` / `wp-includes`, not in the core list / md5 differs | `executed_core_foreign` / `executed_core_modified` | urgent |
| in a wp.org plugin, not in its list / md5 differs | `executed_plugin_foreign` / `executed_plugin_modified` | urgent |
| a premium or custom plugin, a single-file plugin, a theme, a must-use plugin | `executed_unverified` | info, once |
| inside a plugin-owned data directory (`w3tc-config`, `wflogs`, …) whose plugin is not installed | `executed_leftover` | urgent when code ran; info, once, when it stops before any code runs |
| in a `plugins/` directory that is no installed plugin | `executed_leftover` | high when code ran; info, once, when it stops before any code runs |
| a shipped file of a plugin active on no site, or any file of such a plugin wordpress.org has no list for | `executed_inactive` | info, once |
| a theme no site runs (a theme registered a directory deep, `vendor/mytheme`, is matched as a whole) | `executed_inactive` | info, once |
| recorded, but gone by the time the judge looks | `executed_vanished` | urgent |

WordPress does not load a plugin or a theme no site runs, but the web
server still serves its files to whoever asks for them by name — which is
how a scanner reaches the vulnerable file of a plugin someone only
deactivated, or of one uninstalled with its data directory left behind. The
detail names the place and its owner, and so what to delete (`in wflogs/
(wordfence, not installed)`, `no installed plugin owns plugins/js_composer`).
Code that ran in a data directory stays urgent: the directory's name says
whose it was, not who put the file there — `wflogs/shell.php` on a site
without Wordfence is a shell first. A foreign or modified file of a plugin
active on no site stays urgent and says `not active on any site`. On a
multisite network *active* means network-active or active on any site, read
for up to 100 sites; past that the watch cannot know, and calls nothing
inactive. Network-active is read for the current network only, while the
sites of every network are walked.

Two answers come before the table, anywhere under `wp-content`. A *silence is
golden* stub — an opener, comments, an optional closer, judged by PHP's own
tokenizer — runs no code: core's listing guards in `wp-content/`, `plugins/`
and `themes/`, the ones plugins write under uploads. It is judged on the bytes
**as they ran**: a stub on disk that the layer saw run with another md5 is a
shell swapped out after use, and keeps its row. And a file core's own checksum
list names with the md5 it ran with — the guards, Hello Dolly, Akismet, the
default themes as the release ships them — is shipped. That list is read only
once it is cached (the watch needs it before it records anything), and a file
it names with other bytes is no verdict, since a bundled plugin or theme
updates on its own: the table decides.

Executed is a stronger fact than present: where the scan says *high* for a
plugin's foreign file, this proposes *urgent*. The console decides, as it does
for every scan tier.

What is sent: the findings ride the integrity-scan report (`POST
/api/v1/ingest/files`, `scan.mode: entry`, never complete — it saw a queue,
not the tree, so the console's ledger never reads a missing path as gone from
it) with the path, size, mtime and a line like *executed 4× · first 25.09.
03:12 · last 25.09. 03:14 UTC · from 203.0.113.9 · GET*. The console's INTEGRITY
ledger, INBOX case, mail and chat digest, removal advice and it-came-back
logic are the scan's. Beside it, **one security event per foreign file**
(kind `file_executed`, `extra.source` uploads or unknown, `extra.file`,
`extra.hits`, `extra.md5`, `extra.layer: prepend`) wearing the last
request's own facts and nothing of the request that sends it, so the address
that ran it scores as an offender and
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
| executable-shaped file under uploads (`x.php`, `shell.php.jpg`, `.phtml`, `.phar`) | urgent | the classic drop — the `index.php` listing stubs plugins write there are recognised and skipped, judged by PHP's own tokenizer (a `//` comment ended by a bare CR, a `?>` inside a comment or a `#[` attribute line is code, not a stub); a known writer's data file with its plugin installed (Ultimate Addons' and ConvertPlug's `smile_fonts/*/charmap.php`, nothing in it but literal assignments) is listed as `uploads_php_owned` info |
| media file whose first kilobyte carries a PHP opener (`<?php` in any case, `<?=`) whose code up to its closer PHP could compile (`.ico .jpg .png .gif .webp .bmp .pdf .svg`; `.txt .log .csv` under uploads) | urgent | the `favicon_a1b2.ico` family, the image behind an `AddHandler` — the `<?=` that compressed image data happens to contain, followed by a byte PHP refuses, is no opener |
| PHP in the document root that is not one of core's own root files | urgent | `about.php`, `wp-conflg.php`; Wordfence's `wordfence-waf.php` and AIOS's `aios-bootstrap.php` are recognised when their plugin is installed |
| `.htaccess` / `.user.ini` / `php.ini` directives: `auto_prepend_file` / `auto_append_file` to a file no installed plugin owns, `AddHandler`/`AddType` mapping PHP to another extension, `SetHandler` to PHP, `engine on` or CGI under uploads, `RewriteRule`/`Redirect`/`ErrorDocument` to another host | urgent / high | persistence, the polyglot's trigger, the redirect hack — reported as directive kind, file and line, never the line's text |
| the live `auto_prepend_file` / `auto_append_file` of the PHP configuration | urgent | the `.user.ini` trick from the running interpreter's point of view |
| PHP in a hidden path (`.x.php`, `.well-known/…`) | high | the hidden drop — dotfile tool configs in vendored packages are recognised |
| PHP in `wp-content` outside any plugin, theme, mu-plugin or upload path | high | `wp-content/strange/s.php`; WordPress' own `.l10n.php` translations are recognised |
| PHP under uploads or in `wp-content` that stops before any code runs: its first statement is `__halt_compiler()`, or an `exit` / `die` that is bare or takes a literal | info | `inert_php` — the data files plugins keep under PHP names (AIOS's firewall settings, a W3 Total Cache config); an exit after other code, a conditional one or `exit(system(…))` is no guard |
| this plugin's own store (`wp-content/ovos-codesafe/`, the legacy `ovos-console/`, a `CODESAFE_STORE_DIR` inside `wp-content`) and its mu-plugin, held against what the plugin writes: the prepend stub and the mu-plugin byte for byte, the data files by their exit guard and JSON body | urgent / high | `store_modified` — urgent for the stub and the mu-plugin, which run on every request, high for a data file; verified files are silent and any other PHP in the store is a stranger |
| a drop-in (`object-cache.php`, `advanced-cache.php`, `db.php`, `wp-cache-config.php`) with none of its known plugins installed and no vendor header | high | the shell disguised as a cache config — a drop-in with a vendor header or an installed owner is listed as `info` |
| a plugin data directory (`wflogs`, `w3tc-config`, `updraft`, …) whose plugin is not installed | high | listed and never descended: the directory is the finding |
| must-use plugins, drop-ins with an owner, `install.php` | info / high | listed for the operator (this plugin's own mu-plugin is verified instead); `install.php` on a live site is high |
| **checksums** — a core file that differs from wordpress.org's list for this version, or a PHP file under `wp-admin/` / `wp-includes/` the list never had | urgent | the backdoored `wp-load.php`, the `class-wp-helper.php` nobody shipped — `core_modified` / `core_foreign` |
| **checksums** — the same two verdicts inside a wp.org plugin's directory, against the plugin's own list for its installed version | high | `plugin_modified` / `plugin_foreign`; a file the list names under several md5s matches any of them; a premium or custom plugin has no list and is not judged, themes are never judged this way |
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
kept in a transient for a month, a 404 remembered for a week. wordpress.org
lists every md5 a file shipped under when it built a version more than once
(a tag edited after it was cut, trunk shipped under the same number); any of
them matches. A background
chunk fetches at most one list and yields the rest to the next request; a
*Scan now* round fetches three. Listed files missing from disk are counted per
area, never listed: hosts strip readmes, and a missing file is not an
intrusion. Every finding a list produced carries `md5 differs …` or `not in
the wordpress.org list …` as its detail, so the authority behind it is visible.

The database checks run once per pass, on a request that loaded every
plugin: a WP-Cron, admin or *Scan now* request at once, any request that
reached `wp_loaded` after a day of waiting for one. A request that exits
early (a language redirect at `setup_theme`) has not heard of the plugins'
cron listeners, and some plugins load none for anonymous visitors. They are
bounded (`LIMIT`s, twenty findings per detector), read-only, and report what
can be acted on without disclosing anything private: `users/<id>` with the registration date as the finding's
date (codesafe holds it against the attack waves of the same hours —
*admin #57 was registered forty seconds after 27.0.113.86 stopped probing*),
`options/<name>` with the length and the marker, `options/cron/<hook>` with
its schedule and next run in the detail and no date (a next run is no write),
`posts/<id>` with the foreign host.

What it never does: write, delete, rename, quarantine or touch `.htaccess`;
follow a symlink; descend into `.git`, `node_modules`, `wp-content/cache` or
`wp-content/upgrade`; read more than the first kilobyte of a media file,
64 KB of a directive file or 256 KB of a PHP file judged as data; send a
file's content. Findings are paths, sizes
and dates. A finding is a place to look, not a verdict.

**Scan now** — the button under Settings → ovos codesafe → Integrity scan. Each
round spends up to fifteen seconds (always five short of `max_execution_time`)
and the page re-submits itself until the pass is complete; the results table
stays on that page, codesafe or not. **Background** — the *Integrity scan*
switch, on by default (or `CODESAFE_SCAN`): half a second per request after the response
went out, one pass per interval (`CODESAFE_SCAN_INTERVAL`, `1` or `7`
days), the position kept in one option between requests, no WP-Cron, no APCu.
A completed pass is posted to codesafe's `/api/v1/ingest/files` (the
SECURITY view's INTEGRITY tab); an instance without that endpoint answers 404 and
the settings page still shows the result, as it does when the project's
INTEGRITY switch is off and codesafe refuses the report.

The tier on a finding is the plugin's proposal. codesafe decides — against
the project's repository where one is mapped, the attack waves of the same
hours, and what an operator has already acknowledged — and a new urgent or
high finding, or a path that comes BACK after a scan said it was gone, pages
the project's channels at once.

## Security events

Errors say what *broke*; security events say what was *refused* — and refusals
are where an attack is visible before anything breaks. With the switch on (the
default), the plugin reports:

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
  own kind; a sign-up is not reported — see below), plugin and theme
  installs and activations, changes to the
  `users_can_register`, `default_role`, `admin_email`, `siteurl` and `home`
  options (the option *name* only — values are deliberately not reported),
  saves from the theme/plugin file editor by an account WordPress lets edit
  those files (anyone else's attempt, which WordPress refuses, is a
  `permission_denied` under that kind's budget), application passwords minted
  for administrators, and every plugin the auto-update switched on.

  A sign-up is routine and reports nothing, as a clean login does: an account
  made by no one who may create accounts, with no capability the site's
  default role lacks — what an open registration or a shop's checkout makes.
  An account above the default role, any account an administrator creates,
  and every sign-up while the default role itself can write posts (the
  open-signup-into-administrator trap) are reported.
- **The plugin's own words** (`sensor_goodbye`, `sensor_settings`) — codesafe
  relies on this plugin to see the site, so the plugin says when it stops
  seeing: a deactivation sends `sensor_goodbye` before the Shield's consent is
  rewritten, with the deactivating admin's account; a saved settings page
  sends `sensor_settings` naming the keys that changed and the switches that
  went off or on — **names only, never a value**: not the URL, not the key,
  not an address. A site pointed at another console tells the console it is
  leaving first, synchronously, with the key that console knew. Both go out
  whatever the *Security events* box says (they are about this plugin, not the
  site), and neither becomes an issue: codesafe opens a **sensor case** on its
  INBOX for the project and closes it when the plugin says hello again — the
  goodbye keeps that request's own hello quiet, and the activation hook makes
  the first request after a reactivation say hello at once; a plugin update
  deactivates and reactivates silently, with neither word. The hello itself
  is sent while the plugin is pointed at a console with a key, even with the
  enabled box unticked or `CODESAFE_ENABLED` false — it then says
  `errors: false`, so codesafe reads the switch-off instead of a day of
  silence. It names the site's host (`home_url`), so codesafe tells two
  senders on one key apart, and it is never sent from the command line
  (WP-CLI, cron): php-cli reads no `.user.ini`, so its prepend layer would
  read off and the hello would say the site lost a layer it still has.

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

It is on by default; untick Settings → ovos codesafe → *Security events*, or
lock it off in `wp-config.php`:

```php
define('CODESAFE_SECURITY_EVENTS', false);
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
  to a regex. `off` sends none.
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
  Shield** sends the matched fragment, capped at 200 bytes, none where a
  secret could be it and scrubbed of secrets by text, and reads the body only
  while a body rule is live.
- **DOM snapshots** (on by default) strip input values and scripts in the
  browser, before upload, and blank every area marked `data-codesafe-mask`;
  the page's text goes as it is — a customer's account page with it. Untick
  *DOM snapshot* where that is more than you want in codesafe.
- **The hello** says which of the plugin's own switches are on, on or off,
  whether PHP's `auto_prepend_file` runs the Shield before WordPress, the
  plugin's version and the environment every report carries — once a day and
  whenever one of them changes, so codesafe's project list can dim a feature
  switched on there but off here. Never another setting's value, a URL or a
  key.

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
