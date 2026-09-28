/**
 * ovos/console browser error client — no dependencies, no build.
 *
 *   <script src="https://console.example/js/console-client.js"></script>
 *   <script>
 *     ovosConsole.init({
 *       url: 'https://console.example',   // console instance base URL
 *       key: 'PUBLIC_JS_KEY',             // project js_key (public by design)
 *       logLevel: 4,                      // send priority <= logLevel
 *       release: '2026.06.28',            // optional deploy label (indexed)
 *       tags: ['shop', 'eu'],             // optional tags on every report (indexed, one filter each)
 *       context: function () { return {userId: '...'}; }  // optional extras
 *     });
 *   </script>
 *
 * Loading async (recommended — a slow or unreachable console then never
 * blocks the page): emit the pre-init stub inline BEFORE the async script
 * tag (canonical snippet in docs/CLIENT.md). The stub buffers window
 * error/unhandledrejection events (capture phase, so resource failures are
 * seen too), records the init() options and queues manual
 * captureException/captureMessage calls while this file is in flight; on
 * arrival this file swaps the stub out and replays the buffers through the
 * normal handlers, so filtering (first-party allowlist, ignore, maxErrors,
 * dedup) still runs in one place and the async gap loses nothing. Pages
 * that include the file synchronously have no stub and behave as before.
 *
 * Further options (all optional), by feature:
 *
 * - Filtering: maxErrors (10 unique per page load), ignore (RegExp[]
 *   matched against messages), reportResourceErrors (false — report
 *   same-origin <script> load failures as errors; webpack's lazy-chunk
 *   failures (ChunkLoadError) follow the same switch — the same failed
 *   download, repackaged by the bundler as a rejection), reportAborts
 *   (false — AbortError rejections are deliberate cancels), scrub (RegExp[]
 *   applied to urls/referrers on top of the default sensitive-query-param
 *   redaction).
 * - Instrumentation: breadcrumbs (true), maxBreadcrumbs (20),
 *   instrumentFetch (true), instrumentXhr (true).
 * - Trace correlation: trace (true — send a W3C traceparent header on the
 *   page's same-origin fetch/XHR calls, so a backend sender that honors
 *   it (php-library's Console\Sender does) reports the same trace id and
 *   frontend + backend errors of one request correlate in the console;
 *   failed-request reports carry the id as traceId, fetch/xhr
 *   breadcrumbs too), traceOrigins (null — extra origins to propagate
 *   to, string prefixes or RegExp; traceparent is not CORS-safelisted,
 *   so a listed origin must allow it via Access-Control-Allow-Headers).
 * - OTLP export: otlp ('' — an OpenTelemetry Collector's OTLP/HTTP logs
 *   endpoint, e.g. https://collector:4318/v1/logs; when set, reports are
 *   sent there as OTLP/JSON log records instead of to the console's js
 *   endpoint — a webjs-tagged resource, so a console fed by the
 *   collector still ingests them as type js; url/key become optional,
 *   only snapshots still need them; the export uses fetch + CORS, so the
 *   collector must allow the page's origin), otlpHeaders (null — extra
 *   request headers for that endpoint, e.g. auth).
 * - DOM snapshots: snapshot (false — upload a masked snapshot with the
 *   first error per page load), snapshotPerPage (1), snapshotMask
 *   ([selectors] to blank, PII areas), snapshotMaxBytes, snapshotStyles
 *   (false — inline the page's styling: same-origin sheets via the
 *   CSSOM, cross-origin via CORS fetch, expanded @imports and
 *   CSSOM-injected/adopted rules, so the snapshot renders styled in the
 *   viewer), snapshotStyleMaxBytes (raw-CSS budget for that).
 *
 * Captures window "error" and "unhandledrejection" events; duplicates
 * within a page load are counted, not re-sent. Only errors attributable to
 * code we put on the page are reported — an ALLOWLIST (see isFirstParty()):
 * our same-origin scripts and the inline <script>s of our own HTML (document
 * URL at line > 1). Everything else running in the page is someone else's
 * code: browser extensions, in-app-browser native bridges (document URL at
 * line 1), cross-origin/CDN third parties, blob:/data: payloads minted by any
 * of them (a blob's origin is the creating page's, not proof we authored it),
 * reason-less rejections — dropped, and no new injected-noise variant needs a
 * client change. Batches are flushed after a short debounce and on page hide
 * via sendBeacon (text/plain keeps the request preflight-free — the server
 * validates Origin).
 *
 * Every report carries diagnostics under `extra`: network/page state,
 * viewport, a per-page-load pageId, a breadcrumb trail (fetch/XHR,
 * clicks, navigation, console.error/warn, failed resources) and — for
 * failed fetch calls — the request itself with a stack captured at
 * call time, because a rejected fetch ("Load failed" / "Failed to
 * fetch") carries no stack of its own. Such reports also use the
 * failing request path as their `file`, so network errors group into
 * one issue per endpoint instead of one site-wide bucket.
 *
 * This file must never throw into the host page.
 *
 * Intentionally ES5 ("var", no arrow functions, no template literals) —
 * do not modernize: the script must PARSE in the oldest WebViews and
 * embedded browsers, because a SyntaxError would silence error reporting
 * exactly where the errors live. Newer runtime APIs are feature-detected
 * instead (sendBeacon, fetch), and every handler swallows its own
 * exceptions. The "latest browsers only" rule covers the console UI, not
 * this embed.
 */
(function () {
	'use strict';
	
	var config = null;
	// the tags option, normalized once at init() — listed on every entry
	var tags = [];
	var queue = [];
	var seen = {};        // dedup key -> report (count increments)
	var uniqueSent = 0;
	var flushTimer = null;
	var pageId = '';      // random per page load — correlates sibling reports
	var breadcrumbs = []; // ring buffer, oldest first
	// first-party scripts that FAILED to load (a resource error fired) — the
	// second dependency-failure shape beside the never-fetched diff: a bot
	// that timed out on the bundle, a user's network that dropped it. Stamped
	// as extra.scriptsFailed at flush (docs/plans/dependency-failures.md)
	var failedScripts = [];
	var loadStart = Date.now();
	var navInstrumented = false;   // history/popstate wrapping is one-time
	var clicksInstrumented = false;
	var lifecycleBound = false;    // the window/document listeners init() adds
	var pendingEvents = null;      // error events buffered by the async-loader stub
	var pendingCalls = null;       // manual captures made against the stub API
	
	// Values of sensitive-looking query params -> [redacted]. Two groups, the
	// same split the server backstop makes: names distinctive enough to match
	// as a SUBSTRING (api_key, csrf_token), and generic ones that must be the
	// WHOLE name — `code` is an OAuth authorization code and `sig`/`signature`
	// are webhook signatures, but matched loosely they would also eat
	// ?design=, ?assign= and ?barcode=. Server side: Scrubber::NAMES (substring)
	// and Scrubber::QUERY_NAMES (exact); keep the two lists in step.
	var SCRUB_PARAMS = /([?&#](?:[^=&#]*(?:token|key|password|passwd|pwd|auth|session|secret|email)[^=&#]*|code|sig|signature)=)[^&#]*/gi;
	// Token-shaped PATH segments -> [redacted]. Query params live in
	// SCRUB_PARAMS, but single-use credentials travel in paths and are followed
	// over GET: /reset-password/<jwt>, /invite/<token>, a magic link.
	//
	// The candidate is deliberately loose and the DECISION is in looksSecret():
	// the old rule redacted any 24+ character segment of [A-Za-z0-9_-], which
	// is also what a readable slug looks like — /de/pre-und-onboarding/ came
	// back as /de/[redacted]/ and the URI column stopped saying anything.
	var SCRUB_PATH = /(\/)([A-Za-z0-9_.-]{20,})(?=[/?#]|$)/g;
	// an e-mail address (plain or %40-encoded) anywhere -> first char + domain
	// kept (j***@example.com)
	var EMAIL_VALUE = /([A-Za-z0-9._%+-]+)(@|%40)([A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;
	// the same shape without the g flag (a global .test() is stateful) — a
	// one-character local part masks to ITSELF, so "changed" cannot see it
	var EMAIL_PLAIN = /[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
	// an address already masked: its local part holds a star (or the
	// bracketed cut length) where a real local part never does
	var MASKED_EMAIL = /[*\]][A-Za-z0-9._%+-]*(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
	// anchored username-ish query params -> maskName() (the lookahead skips
	// values the e-mail mask already handled)
	var SCRUB_USER_PARAMS = /([?&#](?:user(?:[_-]?(?:name|login))?|login)=)(?![^&#]*(?:\*{3}|@|%40))([^&#]+)/gi;
	// secret-named keys of the extra bag -> [redacted]
	var SCRUB_KEYS = /pass(word|wd)?|pwd|token|secret|authorization|cookie|api[-_]?key/i;
	// anchored username keys of the extra bag -> maskName()
	var USER_KEYS = /^(user([_-]?(name|login))?|login)$/i;
	
	// maskName() keeps every MASK_GROUP-th character of a value and stars the
	// rest, up to MASK_MAX characters; past the cut it states the real length
	// instead ("[200]"). Mirrors MASK_GROUP in the node client, the
	// server-side backstop (Scrubber) and ovos/php-library — the four answers
	// must agree, or one event means different things depending on which
	// client sent it.
	var MASK_GROUP = 4;
	var MASK_MAX = 24;
	// a mask that was cut: re-masking it would measure the mask (29 for a value
	// of 200), so maskName() returns this form untouched. Brackets like
	// [redacted] — and the php senders un-encode them again, so a cut mask
	// stays readable in a scrubbed url
	var MASKED_CUT = /^(?:.\*{3})+\[\d+\]$/;
	
	var DEFAULTS = {
		url: '',
		key: '',
		logLevel: 4,
		maxErrors: 10,      // unique errors per page load
		flushDelay: 2000,
		maxBytes: 60000,    // sendBeacon payload cap
		ignore: [/^Script error\.?$/, /^ResizeObserver loop/],
		release: '',        // deploy label (git sha, version) — indexed server-side
		environment: '',    // deployment stage (staging, development) — indexed server-side;
		                    // the console badges non-production values beside the project name
		tags: [],           // tags on every report (docs/plans/event-tags.md): an array of
		                    // tokens (['shop', 'eu']) or one string split on commas and
		                    // whitespace — indexed server-side, one filter per tag; the
		                    // console lowercases and validates them. Per-report tags go
		                    // into the extra bag (context() or a capture's extra) as `tags`
		context: null,
		breadcrumbs: true,
		maxBreadcrumbs: 20,
		instrumentFetch: true,
		instrumentXhr: true,
		trace: true,        // traceparent on same-origin fetch/XHR (backend correlation)
		traceOrigins: null, // extra origins to trace (string prefixes or RegExp)
		otlp: '',           // OTLP/HTTP logs endpoint — reports go to a collector instead
		otlpHeaders: null,  // extra headers for the OTLP endpoint (e.g. auth)
		reportResourceErrors: false,
		reportAborts: false,
		scrub: null,
		snapshot: false,        // masked DOM snapshot on error (replay-lite)
		snapshotPerPage: 1,
		snapshotMask: null,     // extra CSS selectors to mask (PII areas)
		snapshotMaxBytes: 512000,
		snapshotStyles: false,  // inline same-origin stylesheets into the snapshot
		snapshotStyleMaxBytes: 400000, // cumulative raw-CSS budget for inlining
	};
	var snapshotsSent = 0;
	
	function init(options) {
		try {
			config = {};
			for (var key in DEFAULTS) {
				config[key] = options && options[key] !== undefined ? options[key] : DEFAULTS[key];
			}
			config.url = String(config.url || '').replace(/\/+$/, '');
			config.otlp = String(config.otlp || '').replace(/\/+$/, '');
			tags = normalizeTags(config.tags);
			// OTLP mode stands alone; the console transport needs url + key
			if (config.otlp === '' && (!config.url || !config.key)) {
				config = null;
				return;
			}
			
			pageId = randomHex(8);
			
			// Once. The four named handlers are deduped by addEventListener,
			// but the visibilitychange one is anonymous and a second init()
			// added another copy of it — one flush per registration.
			// Re-initialising to change config stays supported; only the
			// wiring is one-time.
			if (!lifecycleBound) {
				lifecycleBound = true;
				
				window.addEventListener('error', onError);
				window.addEventListener('unhandledrejection', onRejection);
				window.addEventListener('pagehide', flush);
				document.addEventListener('visibilitychange', onVisibilityChange);
				
				// resource load failures do not bubble — capture phase only
				window.addEventListener('error', onResourceError, true);
			}
			
			raiseResourceBuffer();
			
			if (config.instrumentFetch) {
				instrumentFetch();
			}
			if (config.instrumentXhr) {
				instrumentXhr();
			}
			if (config.breadcrumbs) {
				instrumentClicks();
				instrumentNav();
				instrumentConsole();
			}
			
			drainStub();
		} catch (ignored) { /* never break the host page */ }
	}
	
	// Replays what the async-loader stub buffered while this file was in
	// flight: error/unhandledrejection events go through the regular
	// handlers — so the first-party allowlist, ignore, maxErrors and dedup
	// run here, in one place; the stub captures blindly — and queued manual
	// captures re-run against the real API. Sits at the end of init()
	// because the handlers need config, and one-shot: a re-init() to change
	// config finds the buffers empty.
	function drainStub() {
		var events = pendingEvents;
		var calls = pendingCalls;
		var i;
		pendingEvents = null;
		pendingCalls = null;
		
		for (i = 0; events && i < events.length; i++) {
			var event = events[i];
			if (!event) {
				continue;
			}
			if (event.type === 'unhandledrejection') {
				onRejection(event);
			} else if (window.ErrorEvent && event instanceof window.ErrorEvent) {
				onError(event);
			} else {
				onResourceError(event);
			}
		}
		
		for (i = 0; calls && i < calls.length; i++) {
			var call = calls[i];
			if (call && call[0] === 'captureMessage') {
				captureMessage(call[1], call[2], call[3]);
			} else if (call && call[0] === 'captureException') {
				captureException(call[1], call[2], call[3]);
			}
		}
	}
	
	function onError(event) {
		try {
			if (!(event instanceof ErrorEvent)) {
				return; // resource load errors are handled by onResourceError
			}
			// only errors attributable to code we put on the page: our same-origin
			// scripts and the inline <script>s of our own HTML. Everything else —
			// browser extensions, in-app-browser native bridges, cross-origin/CDN
			// third parties — is not ours to fix and is dropped. See isFirstParty
			// (an allowlist).
			if (!isFirstParty(event.filename, event.error && event.error.stack, event.lineno)) {
				return;
			}
			report({
				message: event.message,
				name: event.error && event.error.name || 'Error',
				stack: event.error && event.error.stack || '',
				file: event.filename,
				line: event.lineno,
				col: event.colno,
				priority: 3,
				cause: causeChain(event.error),
			});
		} catch (ignored) {}
	}
	
	function onRejection(event) {
		try {
			var reason = event.reason;
			
			// aborted fetches are deliberate cancellations, not errors
			if (!config.reportAborts && reason && reason.name === 'AbortError') {
				return;
			}
			
			// a tagged reason IS a failed fetch our wrapper saw — but the wrapper
			// instruments window.fetch for the WHOLE page, third parties included,
			// so being tagged is not evidence of ownership. Ours only when the
			// endpoint or the call site is ours (isFirstPartyRequest). An untagged
			// rejection must carry a first-party frame in its reason's stack — a
			// reason-less rejection (undefined/null) has none and drops here too.
			var request = reason && reason.__ovosConsoleRequest;
			if (request
				? !isFirstPartyRequest(request)
				: !isFirstParty('', reason && reason.stack)) {
				return;
			}
			
			report({
				message: stringifyReason(reason),
				name: reason && reason.name || 'UnhandledRejection',
				stack: reason && reason.stack || '',
				// a tagged reason IS a failed fetch (only the wrapper's rejection
				// path tags) — group by the failing endpoint instead of collapsing
				// into one site-wide issue; Safari has no stack here, Chrome's
				// points at internals, neither groups usefully
				file: request ? urlPath(request.url) : '',
				priority: 3,
				request: request,
				cause: causeChain(reason),
			});
		} catch (ignored) {}
	}
	
	function onResourceError(event) {
		try {
			var target = event.target;
			if (!target || target === window || !target.tagName || event instanceof ErrorEvent) {
				return; // JS errors go through onError
			}
			
			var tag = target.tagName.toLowerCase();
			var url = String(target.src || target.href || '');
			if (!url || isInjectedUrl(url)) {
				return;
			}
			
			// often the root cause of the TypeErrors that follow
			crumb('resource', {tag: tag, url: scrub(url, 200)});
			
			// one of OUR scripts failed: whatever the inline code throws next is
			// a dependency failure, not a bug — the console flags it scripts_failed
			if (tag === 'script' && failedScripts.length < 10 && isFirstParty(url, '', 0)) {
				failedScripts.push(scrub(url, 200));
			}
			
			// a broken same-origin script is a deploy problem — loud, if enabled
			if (config.reportResourceErrors && tag === 'script'
				&& window.location.origin && url.indexOf(window.location.origin) === 0) {
				report({
					message: 'script failed to load: ' + scrub(url, 300),
					name: 'ResourceError',
					file: urlPath(url),
					priority: 3,
				});
			}
		} catch (ignored) {}
	}
	
	function captureException(error, extra, priority) {
		try {
			var request = error && error.__ovosConsoleRequest;
			report({
				message: error && error.message || String(error),
				name: error && error.name || 'Error',
				stack: error && error.stack || '',
				file: request ? urlPath(request.url) : '',
				priority: priority === undefined ? 3 : priority,
				extra: extra,
				request: request,
				cause: causeChain(error),
			});
		} catch (ignored) {}
	}
	
	function captureMessage(message, priority, extra) {
		try {
			report({
				message: String(message),
				name: 'Message',
				priority: priority === undefined ? 5 : priority,
				extra: extra,
			});
		} catch (ignored) {}
	}
	
	function report(error) {
		if (!config || error.priority > config.logLevel) {
			return;
		}
		if (isIgnored(error.message)) {
			return;
		}
		
		// a chunk failure is a failed script DOWNLOAD, not broken code:
		// webpack rejects with ChunkLoadError when a lazy chunk times out on
		// the visitor's network or a stale page requests a hash a deploy has
		// replaced — and the stack full of same-origin runtime frames walks
		// it past isFirstParty. Same policy as onResourceError: a breadcrumb
		// for the trail (the timeout/missing flavors fire no error event, so
		// onResourceError never saw them), a report only when
		// reportResourceErrors asked for broken script loads to be loud.
		if (!config.reportResourceErrors && isChunkFailure(error.name, error.message)) {
			var chunkSrc = /https?:\/\/[^\s)]+/.exec(String(error.message || ''));
			crumb('resource', {tag: 'script', url: chunkSrc ? scrub(chunkSrc[0], 200) : ''});
			return;
		}
		
		// producers may omit what they do not have
		error.stack = error.stack || '';
		error.file = error.file || '';
		error.line = error.line || 0;
		error.col = error.col || 0;
		
		var key = [error.message, error.file, error.line, error.col].join('|');
		
		if (seen[key]) {
			seen[key].count++; // error loops send once, not 60/s
			return;
		}
		
		if (uniqueSent >= config.maxErrors) {
			return; // page error budget exhausted
		}
		uniqueSent++;
		
		var entry = {
			message: truncate(error.message, 2000),
			name: truncate(error.name, 100),
			stack: truncate(error.stack, 8000),
			// scrub, not just truncate: window.onerror hands us event.filename,
			// and for an inline <script> that IS the document url — reset
			// tokens, magic links and query strings included. The urlPath()
			// callers are already redacted and scrub() is idempotent.
			file: scrub(error.file, 500),
			line: error.line,
			col: error.col,
			priority: error.priority,
			count: 1,
			url: scrub(location.href, 500),
			timestamp: Date.now(),
			extra: buildExtra(error),
		};
		
		if (config.release) {
			entry.release = truncate(config.release, 64);
		}
		if (config.environment) {
			entry.environment = truncate(config.environment, 64);
		}
		// the tags on every report (docs/plans/event-tags.md) — indexed
		// server-side as one filter per tag; the console does the shape work
		// (lowercase, its pattern, its cap), this only lists them
		if (tags.length > 0) {
			entry.tags = tags;
		}
		// a failed request's trace id — indexed server-side, links the report
		// to the backend errors of the same request
		if (error.request && error.request.traceId) {
			entry.traceId = error.request.traceId;
		}
		
		shrink(entry);
		
		seen[key] = entry;
		queue.push(entry);
		// stamps entry.extra.snapshotId only if a snapshot is actually
		// uploaded — so a dropped capture leaves no dangling VIEW button
		// and does not burn the per-page budget
		maybeSnapshot(entry);
		schedule();
	}
	
	/** per-report diagnostics + user context + breadcrumbs + request */
	function buildExtra(error) {
		var merged = diagnostics();
		
		try {
			if (typeof config.context === 'function') {
				var context = config.context();
				for (var key in context) {
					merged[key] = context[key];
				}
			}
		} catch (ignored) {}
		
		if (error.cause) {
			merged.cause = error.cause;
		}
		if (error.request) {
			merged.request = error.request;
		}
		if (config.breadcrumbs && breadcrumbs.length) {
			merged.breadcrumbs = breadcrumbs.slice();
		}
		
		if (error.extra) {
			for (var extraKey in error.extra) {
				merged[extraKey] = error.extra[extraKey];
			}
		}
		
		// secrets dropped, e-mails masked (domain kept), username fields
		// anonymized — the console scrubs again server-side as a backstop
		return scrubBag(merged, 0);
	}
	
	function diagnostics() {
		var extra = {pageId: pageId};
		try {
			extra.online = navigator.onLine !== false;
			if (navigator.connection && navigator.connection.effectiveType) {
				extra.connection = navigator.connection.effectiveType;
			}
			extra.visibility = document.visibilityState || '';
			extra.sinceLoadMs = sinceLoad();
			extra.viewport = window.innerWidth + 'x' + window.innerHeight;
			extra.dpr = window.devicePixelRatio || 1;
			if (window.screen) {
				extra.screen = screen.width + 'x' + screen.height;
			}
			extra.lang = navigator.language || '';
			if (document.referrer) {
				extra.referrer = scrub(document.referrer, 300);
			}
			// the spec'd automation admission — Selenium, Puppeteer and
			// Playwright (and the AI browsing agents built on them) set it by
			// default. Only ever sent as true: absence is the common case and
			// claims nothing. The console lifts it into the indexed `flags`
			// field (Console\Error\Row), where the issue panel facets it.
			if (navigator.webdriver === true) {
				extra.webdriver = true;
			}
		} catch (ignored) {}
		return extra;
	}
	
	// resource-timing entries kept per page — raised from the browser default
	// (250) at init so the unloaded-script diff below survives asset-heavy
	// pages, and the diff's own honesty cap: at this count entries may have
	// been dropped again, and a MISSING entry proves nothing anymore
	var RESOURCE_BUFFER = 1000;
	
	function raiseResourceBuffer() {
		try {
			if (window.performance && performance.setResourceTimingBufferSize) {
				performance.setResourceTimingBufferSize(RESOURCE_BUFFER);
			}
		} catch (ignored) {}
	}
	
	/** External <script src> urls the browser never even TRIED to fetch: in
		the DOM, but absent from resource timing. A script that failed LOUDLY
		gets an entry and an error event (onResourceError breadcrumbs those) —
		no entry at all is the silent-skip signature of bots that execute the
		inline scripts of a page without loading its external files, which is
		what a "jQuery is not defined" from a plain-Chrome UA usually is. Null
		means "no verdict" (API missing, page still parsing, buffer overflow),
		never an empty claim. */
	function unloadedScripts() {
		try {
			if (!window.performance || !performance.getEntriesByType
				|| !document.querySelectorAll) {
				return null;
			}
			// while the HTML is still parsing, later script tags are not in
			// the DOM yet and earlier ones are legitimately in flight — any
			// answer now would be a guess
			if (document.readyState === 'loading') {
				return null;
			}
			var entries = performance.getEntriesByType('resource');
			if (!entries || entries.length >= RESOURCE_BUFFER) {
				return null;
			}
			var loaded = {};
			for (var i = 0; i < entries.length; i++) {
				loaded[entries[i].name] = true;
			}
			var scripts = document.querySelectorAll('script[src]');
			var missing = [];
			for (var s = 0; s < scripts.length && missing.length < 10; s++) {
				// the src PROPERTY, already resolved absolute — resource
				// entry names are absolute too, so they compare exactly
				var src = String(scripts[s].src || '');
				if (!/^https?:/i.test(src) || loaded[src]) {
					continue;
				}
				missing.push(scrub(src, 200));
			}
			return missing;
		} catch (ignored) {
			return null;
		}
	}
	
	/** Stamp the unloaded-script diff onto every batch entry that lacks one —
		at FLUSH time, not report time: a report may fire mid-load, while the
		flush runs flushDelay later (or at pagehide), when a script that was
		going to load has. One diff serves the whole batch. readyState travels
		along so the reader can judge a page that was still loading. */
	function stampScripts(batch) {
		try {
			var missing;
			for (var i = 0; i < batch.length; i++) {
				var extra = batch[i].extra;
				if (!extra || extra.scriptsNotLoaded !== undefined) {
					continue;
				}
				if (missing === undefined) {
					missing = unloadedScripts();
				}
				if (missing && missing.length) {
					extra.scriptsNotLoaded = missing;
					extra.readyState = String(document.readyState || '');
				}
				if (failedScripts.length && extra.scriptsFailed === undefined) {
					extra.scriptsFailed = failedScripts.slice();
				}
			}
		} catch (ignored) {}
	}
	
	/** flattened error.cause chain, bounded */
	function causeChain(error) {
		var parts = [];
		try {
			var cause = error && error.cause;
			var depth = 0;
			while (cause && depth < 3) {
				if (cause instanceof Error) {
					parts.push((cause.name || 'Error') + ': ' + truncate(cause.message || '', 200));
					cause = cause.cause;
				} else {
					parts.push(truncate(stringifyReason(cause), 200));
					break;
				}
				depth++;
			}
		} catch (ignored) {}
		return parts.join(' <- ');
	}
	
	function stringifyReason(reason) {
		if (reason === null || reason === undefined) {
			return 'unhandled rejection: ' + String(reason);
		}
		if (typeof reason === 'string') {
			return reason;
		}
		// an Error (empty message included) keeps its class as the label —
		// never JSON.stringify it: Error fields are non-enumerable -> '{}'.
		// duck-type, not instanceof, so a cross-realm error (iframe, worker,
		// wrapped lib) is still recognised
		if (reason instanceof Error
			|| (typeof reason.stack === 'string' && typeof reason.name === 'string')) {
			return reason.message
				? (reason.name || 'Error') + ': ' + reason.message
				: (reason.name || 'Error');
		}
		if (typeof reason.message === 'string' && reason.message) {
			return reason.message;
		}
		// a plain object: report its shape (keys), never its values — a
		// rejection payload routinely carries tokens/PII, and the message
		// is transmitted and indexed unscrubbed
		try {
			var keys = Object.keys(reason).slice(0, 10).join(', ');
			return keys ? 'rejected object {' + truncate(keys, 200) + '}' : 'rejected object';
		} catch (ignored) {
			return 'rejected object';
		}
	}
	
	function crumb(type, data) {
		try {
			if (!config || !config.breadcrumbs) {
				return;
			}
			
			var entry = {t: sinceLoad(), type: type};
			for (var key in data) {
				if (data[key] !== undefined && data[key] !== '') {
					entry[key] = data[key];
				}
			}
			
			breadcrumbs.push(entry);
			if (breadcrumbs.length > config.maxBreadcrumbs) {
				breadcrumbs.shift();
			}
		} catch (ignored) {}
	}
	
	function instrumentClicks() {
		// anonymous listener, so addEventListener cannot dedupe it for us
		if (clicksInstrumented) {
			return;
		}
		clicksInstrumented = true;
		document.addEventListener('click', function (event) {
			try {
				var target = event.target;
				if (target && target.nodeType === 3) {
					target = target.parentNode; // text node
				}
				if (target && target.tagName) {
					crumb('click', {sel: selectorFor(target)});
				}
			} catch (ignored) {}
		}, true);
	}
	
	function instrumentNav() {
		try {
			// history.pushState is REPLACED here and the listeners below are
			// anonymous, so a second init() wraps the wrapper and registers a
			// second pair: every navigation then records two identical crumbs
			// and halves the usable trail inside the 20-slot ring. The fetch,
			// xhr and console wrappers have carried a guard all along; these
			// did not, and a WordPress site where the plugin and a theme
			// snippet both call init() is not hypothetical.
			//
			// A flag rather than a marker on pushState: the listeners go on
			// first, and a browser without history.pushState would never
			// reach the marker at all.
			if (navInstrumented) {
				return;
			}
			navInstrumented = true;
			
			var record = function () {
				crumb('nav', {url: scrub(location.href, 200)});
			};
			window.addEventListener('popstate', record);
			window.addEventListener('hashchange', record);
			
			if (window.history && history.pushState) {
				var push = history.pushState;
				history.pushState = function () {
					var result = push.apply(this, arguments);
					record();
					return result;
				};
				var replace = history.replaceState;
				history.replaceState = function () {
					var result = replace.apply(this, arguments);
					record();
					return result;
				};
			}
		} catch (ignored) {}
	}
	
	function instrumentConsole() {
		try {
			var levels = ['error', 'warn'];
			for (var i = 0; i < levels.length; i++) {
				(function (level) {
					var original = console[level];
					if (!original || original.__ovosConsole) {
						return;
					}
					console[level] = function () {
						try {
							crumb('console', {level: level, msg: truncate(formatArgs(arguments), 200)});
						} catch (ignored) {}
						return original.apply(console, arguments);
					};
					console[level].__ovosConsole = true;
				})(levels[i]);
			}
		} catch (ignored) {}
	}
	
	/** console.* arguments as one breadcrumb line, scrubbed on the way in.
		The object branch has to scrub BEFORE it stringifies: scrubBag judges
		by KEY, and once JSON.stringify has run there are no keys left to
		judge — so console.error('login failed', await res.json()) used to
		store the whole body, access_token and all. The server backstop is
		key-based too and never re-reads a breadcrumb string, so nothing
		downstream caught it either. stringifyReason() refuses to serialise a
		rejection value for the same reason. */
	function formatArgs(args) {
		var parts = [];
		for (var i = 0; i < args.length && i < 3; i++) {
			var value = args[i];
			if (typeof value === 'string') {
				parts.push(scrubBag(value, 0));
			} else if (value instanceof Error) {
				parts.push(value.name + ': ' + scrubBag(value.message, 0));
			} else {
				try {
					parts.push(JSON.stringify(scrubBag(value, 0)));
				} catch (circular) {
					parts.push(String(value));
				}
			}
		}
		return parts.join(' ');
	}
	
	/** short ancestor-path selector — never element text or HTML */
	function selectorFor(element) {
		var parts = [];
		var node = element;
		var depth = 0;
		while (node && node.tagName && depth < 3) {
			var part = node.tagName.toLowerCase();
			if (node.id) {
				parts.unshift(part + '#' + node.id);
				break; // an id anchors the path well enough
			}
			if (typeof node.className === 'string' && node.className) {
				var classes = node.className.split(/\s+/).filter(Boolean).slice(0, 2);
				if (classes.length) {
					part += '.' + classes.join('.');
				}
			}
			parts.unshift(part);
			node = node.parentNode;
			depth++;
		}
		return truncate(parts.join(' > '), 200);
	}
	
	function instrumentFetch() {
		try {
			if (!window.fetch || window.fetch.__ovosConsole) {
				return;
			}
			
			var original = window.fetch;
			var wrapped = function () {
				var args = arguments;
				var info = null;
				try {
					var input = args[0];
					info = {
						method: String((args[1] && args[1].method) || (input && input.method) || 'GET').toUpperCase(),
						url: String((input && input.url) || input || ''),
						// a rejected fetch has no stack — capture the call site now
						stack: callSite(),
						started: sinceLoad(),
					};
					// never trace our own beacon/export traffic
					if (isOwnTraffic(info.url)) {
						info = null;
					}
				} catch (ignored) {}
				
				// backend correlation: hand the request a traceparent the
				// server-side sender picks up; any hiccup while patching the
				// args falls back to the untouched call
				var patched = null;
				try {
					if (info && config && config.trace && traceEligible(info.url)) {
						patched = injectTrace(args[0], args[1]);
						if (patched) {
							info.traceId = patched.traceId;
						}
					}
				} catch (ignored) {
					patched = null;
				}
				
				var result = patched
					? original.call(this, patched.input, patched.init)
					: original.apply(this, args);
				if (!info || !result || !result.then) {
					return result;
				}
				
				return result.then(function (response) {
					finishRequest(info, response && response.status || 0);
					return response;
				}, function (error) {
					finishRequest(info, 0);
					tagError(error, info);
					throw error;
				});
			};
			wrapped.__ovosConsole = true;
			window.fetch = wrapped;
		} catch (ignored) {}
	}
	
	function instrumentXhr() {
		try {
			if (!window.XMLHttpRequest) {
				return;
			}
			var proto = XMLHttpRequest.prototype;
			if (!proto.open || proto.open.__ovosConsole) {
				return;
			}
			
			var open = proto.open;
			var send = proto.send;
			var setHeader = proto.setRequestHeader;
			
			proto.open = function (method, url) {
				try {
					this.__ovosConsole = {
						method: String(method || 'GET').toUpperCase(),
						url: String(url || ''),
					};
				} catch (ignored) {}
				return open.apply(this, arguments);
			};
			proto.open.__ovosConsole = true;
			
			// remember an app-set traceparent: XHR COMBINES repeated headers,
			// so injecting a second value would corrupt the app's own tracing
			proto.setRequestHeader = function (name, value) {
				try {
					if (this.__ovosConsole && String(name).toLowerCase() === 'traceparent') {
						this.__ovosConsole.traceparent = String(value || '');
					}
				} catch (ignored) {}
				return setHeader.apply(this, arguments);
			};
			proto.setRequestHeader.__ovosConsole = true;
			
			proto.send = function () {
				var xhr = this;
				try {
					var info = xhr.__ovosConsole;
					if (info && isOwnTraffic(info.url) === false) {
						info.started = sinceLoad();
						if (config.trace && traceEligible(info.url)) {
							if (info.traceparent) {
								// the app's own tracer decided — reuse its id
								info.traceId = traceparentId(info.traceparent);
							} else {
								try {
									var trace = newTraceparent();
									setHeader.call(xhr, 'traceparent', trace.header);
									info.traceId = trace.traceId;
								} catch (ignored) {}
							}
						}
						xhr.addEventListener('loadend', function () {
							requestCrumb('xhr', info, xhr.status, sinceLoad() - info.started);
						});
					}
				} catch (ignored) {}
				return send.apply(this, arguments);
			};
		} catch (ignored) {}
	}
	
	function finishRequest(info, status) {
		try {
			info.status = status;
			info.durationMs = sinceLoad() - info.started;
			requestCrumb('fetch', info, status, info.durationMs);
		} catch (ignored) {}
	}
	
	/** the fetch/xhr trail entry — method/url/status only, never the
		response body: it routinely carries tokens/PII and scrub() only
		redacts url query params */
	function requestCrumb(type, info, status, durMs) {
		var data = {
			method: info.method,
			url: scrub(info.url, 200),
			status: status,
			durMs: durMs,
		};
		if (info.traceId) {
			data.traceId = info.traceId;
		}
		crumb(type, data);
	}
	
	/** attach the request to the error object the rejection will surface */
	function tagError(error, info) {
		try {
			if (error && typeof error === 'object') {
				error.__ovosConsoleRequest = {
					method: info.method,
					url: scrub(info.url, 500),
					status: info.status || 0,
					durationMs: info.durationMs || 0,
					callStack: info.stack,
				};
				if (info.traceId) {
					error.__ovosConsoleRequest.traceId = info.traceId;
				}
			}
		} catch (ignored) {}
	}
	
	/** call-site stack, minus this helper and the wrapper frame */
	function callSite() {
		try {
			var lines = String(new Error().stack || '').split('\n');
			if (lines[0] && /^\s*Error/.test(lines[0])) {
				lines = lines.slice(1); // V8 prefixes the message line
			}
			return truncate(lines.slice(2).join('\n'), 2000);
		} catch (ignored) {
			return '';
		}
	}
	
	/**
	 * Capture a DOM snapshot off the error path and, once it is actually
	 * uploaded, stamp its id onto `entry` so the error links to it. Reserves
	 * the per-page budget up front but returns it if the capture is dropped,
	 * so an oversized page does not silently consume the one allowed snapshot.
	 */
	function maybeSnapshot(entry) {
		try {
			// snapshots upload to the console's origin-gated endpoint — an
			// OTLP-only setup (no url/key) has nowhere to put them
			if (!config.snapshot || !config.url || !config.key
				|| snapshotsSent >= config.snapshotPerPage
				|| !document.documentElement || !document.documentElement.cloneNode
				|| !window.fetch || !window.Blob) {
				return;
			}
			snapshotsSent++;
			
			var id = randomHex(16);
			// serialization must never slow the error path — defer it
			setTimeout(function () {
				captureSnapshot(id, entry);
			}, 0);
		} catch (ignored) {}
	}
	
	/** hand the budget back so a later error on this page can still snapshot */
	function dropSnapshot() {
		if (snapshotsSent > 0) {
			snapshotsSent--;
		}
	}
	
	function captureSnapshot(id, entry) {
		try {
			var clone = document.documentElement.cloneNode(true);
			sanitizeSnapshot(clone);
			
			// opt-in: fold the page's styling into the clone so the snapshot
			// renders styled in the sandboxed viewer (which cannot pull the
			// site's cross-origin/hotlink-gated/rotated assets). The remote
			// pass is async (CORS fetch of unreadable sheets) — the capture
			// continues in its callback.
			if (config.snapshotStyles) {
				var used = inlineStylesheets(clone);
				inlineRemoteStylesheets(clone, used, function () {
					finishSnapshot(id, entry, clone);
				});
				return;
			}
			
			finishSnapshot(id, entry, clone);
		} catch (ignored) {
			dropSnapshot();
		}
	}
	
	function finishSnapshot(id, entry, clone) {
		try {
			var htmlText = '<!doctype html>\n' + clone.outerHTML;
			if (htmlText.length > 3000000) {
				dropSnapshot(); // pathological page — not worth the upload
				return;
			}
			uploadSnapshot(id, htmlText, entry);
		} catch (ignored) {
			dropSnapshot();
		}
	}
	
	/**
	 * Masks the clone in place: no scripts, no inline handlers, no
	 * server-rendered form values, PII areas blanked. Typed input values
	 * never reach the clone — cloneNode copies attributes, not live state.
	 */
	function sanitizeSnapshot(clone) {
		var i;
		
		var risky = clone.querySelectorAll('script, noscript, iframe');
		for (i = risky.length - 1; i >= 0; i--) {
			risky[i].parentNode.removeChild(risky[i]);
		}
		
		var all = clone.querySelectorAll('*');
		for (i = 0; i < all.length; i++) {
			var element = all[i];
			var attributes = element.attributes;
			for (var a = attributes.length - 1; a >= 0; a--) {
				if (attributes[a].name.indexOf('on') === 0) {
					element.removeAttribute(attributes[a].name);
				}
			}
			if (element.tagName === 'INPUT' && element.getAttribute('value')) {
				element.setAttribute('value', '***');
			} else if (element.tagName === 'TEXTAREA' && element.textContent) {
				element.textContent = '***';
			}
		}
		
		var selectors = ['[data-console-mask]'].concat(config.snapshotMask || []);
		for (i = 0; i < selectors.length; i++) {
			try {
				var masked = clone.querySelectorAll(selectors[i]);
				for (var m = 0; m < masked.length; m++) {
					masked[m].textContent = '***';
				}
			} catch (badSelector) {}
		}
		
		// resolve relative urls (images, and any stylesheet left as a <link>)
		// when viewed on the console host — pages carrying their own <base>
		// already resolve correctly and must not have it overridden
		try {
			var head = clone.querySelector('head');
			if (head && !clone.querySelector('base')) {
				var base = document.createElement('base');
				base.setAttribute('href', location.href.split('#')[0]);
				head.insertBefore(base, head.firstChild);
			}
		} catch (ignored) {}
	}
	
	/**
	 * Serialized cssRules of a live sheet, or null when unreadable/empty.
	 * Same-origin @import rules are expanded in place (the sandboxed viewer
	 * could not fetch them), their media condition preserved as an @media
	 * wrapper; layer()/supports() imports stay verbatim — expansion would
	 * lose their semantics. Depth-capped against import chains.
	 */
	function sheetCssText(sheet, depth) {
		var rules;
		try {
			rules = sheet.cssRules; // cross-origin -> SecurityError
		} catch (crossOrigin) {
			return null;
		}
		if (!rules || !rules.length) {
			return null;
		}
		var css = '';
		for (var r = 0; r < rules.length; r++) {
			var rule = rules[r];
			// CSSRule.IMPORT_RULE — plain imports only (no layer/supports)
			if (rule.type === 3 && rule.styleSheet && (depth || 0) < 4
				&& !rule.layerName && !rule.supportsText) {
				var imported = sheetCssText(rule.styleSheet, (depth || 0) + 1);
				if (imported !== null) {
					// inner urls resolve against the IMPORTED sheet's own base
					imported = absolutizeCssUrls(imported,
						rule.styleSheet.href || sheet.href || document.baseURI || location.href);
					var condition = rule.media && rule.media.mediaText;
					css += condition
						? '@media ' + condition + ' {\n' + imported + '}\n'
						: imported;
					continue;
				}
			}
			css += rule.cssText + '\n';
		}
		return css;
	}
	
	/** replace a clone <link> with an inline <style> (media kept) */
	function linkToStyle(link, css) {
		var style = document.createElement('style');
		var media = link.getAttribute('media');
		if (media) {
			style.setAttribute('media', media);
		}
		style.textContent = css;
		link.parentNode.replaceChild(style, link);
	}
	
	/**
	 * Makes the clone's styling self-contained (shared CSS budget, fully
	 * guarded — best-effort, never fails the capture). Returns the budget
	 * bytes used, so the async remote pass continues the same accounting.
	 *
	 * 1. <style> elements whose rules live only in the CSSOM — CSS-in-JS
	 *    libraries in production inject via insertRule(), leaving the node
	 *    EMPTY, so the clone would carry no styling at all — get their rules
	 *    re-serialized into text. Must run before step 3: it pairs live and
	 *    clone <style> lists by index, which folding <link>s would break.
	 * 2. document.adoptedStyleSheets (constructable sheets) have no DOM node
	 *    at all — serialized into one <style> appended at the end of body,
	 *    where they land in cascade order (after all document sheets).
	 * 3. Same-origin <link rel=stylesheet> are replaced with inline <style>
	 *    carrying the sheet's rules; a sheet whose cssRules throws (cross-
	 *    origin) stays a <link> for inlineRemoteStylesheets to try.
	 *
	 * url()/@import targets are absolutized against each sheet's own base:
	 * once inlined into the snapshot, a relative url() would otherwise
	 * resolve against the viewer's base and break.
	 */
	function inlineStylesheets(clone) {
		var inlined = 0;
		try {
			if (!window.URL) {
				return 0; // no absolute-url resolution — leave everything as is
			}
			
			var pageBase = document.baseURI || location.href;
			var budget = config.snapshotStyleMaxBytes;
			var i;
			var css;
			
			// 1. CSSOM-only <style> rules (live and clone lists are index-
			// aligned — the clone is a deep copy, nothing reordered yet)
			var liveStyles = document.querySelectorAll('style');
			var cloneStyles = clone.querySelectorAll('style');
			for (i = 0; i < liveStyles.length && i < cloneStyles.length; i++) {
				var node = cloneStyles[i];
				var liveSheet = liveStyles[i].sheet;
				// only rebuild nodes whose text carries no rules — a populated
				// <style> already travels with the clone as authored
				if (!liveSheet || liveSheet.disabled
					|| /\S/.test(node.textContent || '')) {
					continue;
				}
				css = sheetCssText(liveSheet, 0);
				if (css === null) {
					continue;
				}
				css = absolutizeCssUrls(css, pageBase);
				if (inlined + css.length > budget) {
					continue;
				}
				inlined += css.length;
				node.textContent = css;
			}
			
			// 2. adopted (constructable) sheets — no DOM node, cascade last
			try {
				var adoptedSheets = document.adoptedStyleSheets;
				var adopted = '';
				for (i = 0; adoptedSheets && i < adoptedSheets.length; i++) {
					if (adoptedSheets[i].disabled) {
						continue;
					}
					css = sheetCssText(adoptedSheets[i], 0);
					if (css !== null) {
						adopted += css;
					}
				}
				if (adopted) {
					adopted = absolutizeCssUrls(adopted, pageBase);
					if (inlined + adopted.length <= budget) {
						inlined += adopted.length;
						var tail = document.createElement('style');
						tail.textContent = adopted;
						(clone.querySelector('body') || clone).appendChild(tail);
					}
				}
			} catch (noAdopted) {}
			
			// 3. same-origin <link> stylesheets -> inline <style>
			var byHref = {};
			var sheets = document.styleSheets;
			for (var s = 0; s < sheets.length; s++) {
				if (sheets[s] && sheets[s].href) {
					byHref[sheets[s].href] = sheets[s];
				}
			}
			
			var links = clone.querySelectorAll('link[rel~="stylesheet"]');
			var done = {};
			
			for (i = 0; i < links.length; i++) {
				var link = links[i];
				var raw = link.getAttribute('href');
				if (!raw) {
					continue;
				}
				
				// hrefs resolve against the page's base (it may carry <base>)
				var href;
				try {
					href = new URL(raw, pageBase).href;
				} catch (badUrl) {
					continue;
				}
				
				var sheet = byHref[href];
				if (!sheet || sheet.disabled || done[href]) {
					continue; // a duplicate <link> must not double the CSS
				}
				
				css = sheetCssText(sheet, 0);
				if (css === null) {
					continue;
				}
				css = absolutizeCssUrls(css, href);
				
				if (inlined + css.length > budget) {
					continue; // over budget — leave this one as a <link>
				}
				inlined += css.length;
				done[href] = true;
				
				linkToStyle(link, css);
			}
		} catch (ignored) {}
		return inlined;
	}
	
	/**
	 * Second, async pass over the <link>s the CSSOM could not read: many
	 * CDNs serve CSS with open CORS, so a plain fetch (from HTTP cache —
	 * the page loaded these sheets moments ago) recovers e.g. Google Fonts
	 * or jsdelivr styles. Hard-capped at 1500ms so the snapshot upload —
	 * and the entry.extra.snapshotId stamp — stays inside the 2000ms report
	 * flush window; whatever has not settled stays a <link>. Links whose
	 * live sheet is readable or disabled are the sync pass's deliberate
	 * decisions (budget, alternate stylesheets) and are not second-guessed.
	 */
	function inlineRemoteStylesheets(clone, used, done) {
		var finished = false;
		var timer = null;
		var finish = function () {
			if (!finished) {
				finished = true;
				if (timer) {
					clearTimeout(timer);
				}
				done();
			}
		};
		
		try {
			if (!window.URL || !window.fetch || !window.Promise) {
				finish();
				return;
			}
			
			var links = clone.querySelectorAll('link[rel~="stylesheet"]');
			if (!links.length) {
				finish();
				return;
			}
			
			var pageBase = document.baseURI || location.href;
			var budget = config.snapshotStyleMaxBytes;
			var pendingCount = links.length;
			var fetched = {};
			var settle = function () {
				if (--pendingCount === 0) {
					finish();
				}
			};
			
			var byHref = {};
			var sheets = document.styleSheets;
			for (var s = 0; s < sheets.length; s++) {
				if (sheets[s] && sheets[s].href) {
					byHref[sheets[s].href] = sheets[s];
				}
			}
			
			timer = setTimeout(finish, 1500);
			
			var fetchOne = function (link) {
				var href;
				try {
					href = new URL(link.getAttribute('href') || '', pageBase).href;
				} catch (badUrl) {
					settle();
					return;
				}
				if (!/^https?:/i.test(href) || fetched[href]) {
					settle();
					return;
				}
				
				var live = byHref[href];
				if (live) {
					if (live.disabled) {
						settle();
						return;
					}
					var readable = true;
					try {
						void live.cssRules;
					} catch (crossOrigin) {
						readable = false;
					}
					if (readable) {
						settle(); // sync pass owned this sheet's decision
						return;
					}
				}
				fetched[href] = true;
				
				fetch(href, {mode: 'cors', cache: 'force-cache'}).then(function (res) {
					if (!res.ok
						|| (res.headers.get('content-type') || '').indexOf('css') === -1) {
						throw 0;
					}
					return res.text().then(function (text) {
						if (finished) {
							return; // too late — the snapshot already uploaded
						}
						var css = absolutizeCssUrls(text, res.url || href);
						if (used + css.length <= budget) {
							used += css.length;
							linkToStyle(link, css);
						}
						settle();
					});
				}).catch(settle);
			};
			
			for (var i = 0; i < links.length; i++) {
				fetchOne(links[i]);
			}
		} catch (ignored) {
			finish();
		}
	}
	
	/** true when the target needs no rewrite (already absolute or inline) */
	function isAbsoluteCssTarget(target) {
		return !target || /^(data:|blob:|https?:|\/\/|#)/i.test(target);
	}
	
	/**
	 * Rewrite relative url() and @import "…" targets in cssText to absolute
	 * (the url() form of @import is covered by the url() pass)
	 */
	function absolutizeCssUrls(css, base) {
		return css
			.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g, function (whole, quote, path) {
				var target = path.replace(/^\s+|\s+$/g, '');
				if (isAbsoluteCssTarget(target)) {
					return whole;
				}
				try {
					return 'url(' + quote + new URL(target, base).href + quote + ')';
				} catch (badUrl) {
					return whole;
				}
			})
			.replace(/(@import\s+)(['"])([^'"]+)\2/g, function (whole, lead, quote, path) {
				var target = path.replace(/^\s+|\s+$/g, '');
				if (isAbsoluteCssTarget(target)) {
					return whole;
				}
				try {
					return lead + quote + new URL(target, base).href + quote;
				} catch (badUrl) {
					return whole;
				}
			});
	}
	
	/**
	 * Gzip via CompressionStream where available, then POST as
	 * application/octet-stream — the page is alive at error time, so the
	 * CORS preflight this triggers is fine (snapshots never ride the beacon).
	 */
	function uploadSnapshot(id, htmlText, entry) {
		try {
			var endpoint = config.url + '/api/v1/ingest/snapshot/'
				+ encodeURIComponent(config.key) + '?id=' + id;
			var raw = new Blob([htmlText]);
			
			var post = function (blob, enc) {
				if (blob.size > config.snapshotMaxBytes) {
					dropSnapshot(); // still oversized after compression — give up
					return;
				}
				// link the error to the snapshot only now that we are sending
				// it — a report never advertises a snapshot that was dropped
				entry.extra.snapshotId = id;
				fetch(endpoint + (enc ? '&enc=' + enc : ''), {
					method: 'POST',
					body: blob,
					headers: {'Content-Type': 'application/octet-stream'},
				}).catch(function () {});
			};
			
			if (window.CompressionStream && window.Response && raw.stream) {
				new Response(raw.stream().pipeThrough(new CompressionStream('gzip'))).blob()
					.then(function (gzipped) {
						post(gzipped, 'gzip');
					}, function () {
						post(raw, '');
					});
			} else {
				post(raw, '');
			}
		} catch (ignored) {}
	}
	
	function isIgnored(message) {
		for (var i = 0; i < config.ignore.length; i++) {
			var rule = config.ignore[i];
			if (rule instanceof RegExp ? rule.test(message) : message.indexOf(rule) !== -1) {
				return true;
			}
		}
		return false;
	}
	
	/** webpack's lazy-chunk failures: the JS-chunk runtime rejects with
		ChunkLoadError (named so since webpack 4.29), the CSS-chunk runtimes
		(mini-css-extract, webpack's native CSS) throw a plain Error whose
		message carries the same shape — "Loading CSS chunk 7 failed.
		(/css/x.css)". Matched loosely and case-insensitively: a message
		quoting that exact phrase is talking about the same failure. */
	var CHUNK_FAILURE = /Loading (?:CSS )?chunk \S+ failed/i;
	function isChunkFailure(name, message) {
		return name === 'ChunkLoadError' || CHUNK_FAILURE.test(String(message || ''));
	}
	
	/** resource urls the page neither loads nor controls: browser extensions
		(Safari 16.4+ masks their frames as webkit-masked-url:), and scripts
		in-app browsers inject via their native bridge — iabjs: (Meta's Android
		webview), gsa: (Google iOS app), webviewprogressproxy: (older iOS
		webviews). Used by onResourceError only — JS error reports go through
		the isFirstParty allowlist instead, which drops these schemes anyway
		(they are not http). */
	function isInjectedUrl(url) {
		return /^(?:(?:chrome|moz|safari|safari-web|ms-browser)-extension|webkit-masked-url|iabjs|gsa|webviewprogressproxy):/.test(url || '');
	}
	
	/** the page's own origin — the scripts we care about are the ones we serve
		from here. Falls back to protocol+host on ancient browsers lacking
		location.origin. */
	function firstPartyOrigin() {
		try {
			return location.origin || (location.protocol + '//' + location.host);
		} catch (ignored) {
			return '';
		}
	}
	
	/** true when the error is attributable to code WE put on the page — the only
		errors we report. Evidence is a first-party source in the filename or ANY
		stack frame:
		  - a same-origin .js resource (one of our bundles), or
		  - the same-origin document URL at line > 1: an inline <script> in our
		    server-rendered HTML. In-app browsers inject their native bridges
		    (Meta's window.webkit.*, Chrome iOS's __gCrWeb) as SINGLE-LINE user
		    scripts also attributed to the document URL — but those always report
		    :1:col, while our markup is not minified and every inline script sits
		    far below line 1. Line 1 therefore stays dropped. (A site that minifies
		    its HTML onto one line loses inline reports — same as before this rule,
		    never noisier.)
		A blob:/data: url is NOT first-party evidence: a blob inherits the origin of
		whatever created it in our page, so an extension, an injected in-app bridge
		or a GTM-injected tag all mint blob:<our-origin>/… — the origin is the
		creating context's, not proof WE authored the code (we ship no blob/data
		scripts). It is skipped (matched as a whole so the http(s) url embedded in a
		blob: url is not mistaken for a real script frame); a genuine first-party
		eval still leaves a real .js or inline-document frame in the same stack,
		which the rules above catch.
		Everything else running in our page is someone else's code and is dropped:
		browser extensions (extension: / webkit-masked-url: — not http, so never
		matched), injected native bridges (line 1), obfuscated blob/data payloads
		(origin ≠ authorship), cross-origin / CDN third parties (different origin,
		no matter the line), and reason-less rejections (no source at all). This is
		an ALLOWLIST: a new injected-noise variant needs no client change, it simply
		never matches a first-party source.
		`line` carries the error event's lineno for the bare `filename` (stack
		frames carry their own :line:col). */
	function isFirstParty(filename, stack, line) {
		var origin = firstPartyOrigin();
		var sources = String(filename || '');
		if (sources && line) {
			// let the document-url rule below see the event's line number the
			// same way it sees a stack frame's
			sources += ':' + line;
		}
		sources += '\n' + String(stack || '');
		var re = /(?:blob|data):[^\s'"()]+|https?:\/\/[^\s'"()]+/gi;
		var match;
		while ((match = re.exec(sources))) {
			var url = match[0];
			if (/^(?:blob|data):/i.test(url)) {
				// NOT first-party evidence: a blob inherits the origin of whatever
				// created it in our page, so extensions, injected in-app bridges and
				// GTM-injected tags all mint blob:<our-origin>/… — origin is the
				// creating context's, not proof WE authored it (we ship no blob/data
				// scripts). Matched as a whole so the http(s) url embedded in a blob:
				// url is not taken for a real script frame, then skipped; a genuine
				// first-party eval still leaves a real .js/inline-document frame in
				// the same stack, which the checks below catch.
				continue;
			}
			if (!origin || url.indexOf(origin + '/') !== 0) {
				continue; // someone else's origin — never ours
			}
			// a loaded script resource (.js) of ours. Strip a trailing :line:col
			// and any ?query/#hash before the extension test.
			if (/\.m?js$/i.test(url.replace(/:\d+(?::\d+)?$/, '').split(/[?#]/)[0])) {
				return true;
			}
			// the document URL below line 1 — an inline <script> in our HTML
			var frameLine = /:(\d+)(?::\d+)?$/.exec(url);
			if (frameLine && parseInt(frameLine[1], 10) > 1) {
				return true;
			}
		}
		return false;
	}
	
	/** a failed fetch is ours when it targets our own backend — a relative url
		is same-origin by definition — or when its call-site stack (captured at
		fetch() time, see instrumentFetch) names one of our scripts. A third-party
		SDK's failed call to its own backend matches neither and is dropped. */
	function isFirstPartyRequest(request) {
		var url = String(request.url || '');
		// no scheme and no leading // — relative, resolves against our origin
		if (!/^(?:https?:)?\/\//i.test(url)) {
			return true;
		}
		var origin = firstPartyOrigin();
		if (origin && (url === origin || url.indexOf(origin + '/') === 0)) {
			return true;
		}
		return isFirstParty('', request.callStack);
	}
	
	/** truncate + redact sensitive query-param values, mask e-mails and
		username params, redact token-shaped path segments and any
		caller-supplied patterns */
	/* A path segment is a secret, not a slug, when it has no word structure and
		carries the character mix a generated token does. A slug is words joined
		by - or _, lower case, at most the odd year; a token is one long run of
		mixed case and digits, a uuid, a JWT, or a long hex string. Erring
		towards redaction on the ambiguous ones: a leaked reset token costs more
		than an unreadable URI.
		
		A cache-busted STATIC ASSET is the exception, and not an ambiguous one.
		Every bundler names its output after a content hash —
		base_bf6051fdf10449dbde8945baf61cdf14.1785056998.js (this CMS),
		main.<md5>.js (webpack), index-DkL9mQxZ8vB2nR4tY7wA.js (vite) — and each
		trips a rule below on its 32-character or mixed-case run. Redacting them
		protected nothing: the browser fetched the file with no credential and
		every CDN on the way holds a copy. It cost the `file` field, which is
		what a JS error is read from — 273 leadersnet occurrences stored
		".../[redacted]?group=true", unable to say WHICH bundle threw. A
		one-time credential in a path is a bare segment (/invite/<token>,
		/reset-password/<jwt>); it does not end in .js. */
	var ASSET_PATH = /\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|less|map|wasm|woff2?|ttf|otf|eot|svg|png|jpe?g|gif|webp|avif|ico|bmp|mp3|mp4|webm|ogg|wav)$/i;
	function looksSecret(segment) {
		// before the asset rule: a uuid and a bare hex run hold no dot, so only
		// a JWT could end in something that reads like an extension, and a JWT
		// stays a JWT
		if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(segment)
			|| /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)
			|| /^[0-9a-f]{24,}$/i.test(segment)) {
			return true;
		}
		if (ASSET_PATH.test(segment)) {
			return false;
		}
		if (segment.length < 24) {
			return false;
		}
		var runs = segment.split(/[-_.]+/);
		var longest = 0;
		for (var i = 0; i < runs.length; i++) {
			longest = Math.max(longest, runs[i].length);
		}
		var digits = /[0-9]/.test(segment);
		// one long mixed-case run with digits, or a very long single run
		return (digits && /[A-Z]/.test(segment) && longest >= 16)
			|| (digits && longest >= 32);
	}
	
	function scrub(value, max) {
		value = truncate(value, max || 500);
		try {
			value = value.replace(SCRUB_PARAMS, '$1[redacted]');
			// e-mail values in any remaining param or path segment (domain
			// kept), then username-named params down to their masked groups
			value = maskEmails(value);
			value = value.replace(SCRUB_USER_PARAMS, function (match, prefix, name) {
				return prefix + maskName(name);
			});
			value = value.replace(SCRUB_PATH, function (match, slash, segment) {
				return looksSecret(segment) ? slash + '[redacted]' : match;
			});
			if (config && config.scrub) {
				for (var i = 0; i < config.scrub.length; i++) {
					// force a global match — a caller's plain /re/ would else
					// redact only the first occurrence
					value = value.replace(globalize(config.scrub[i]), '[redacted]');
				}
			}
		} catch (ignored) {}
		return value;
	}
	
	/** a RegExp with the global flag guaranteed (cached on the source regex) */
	function globalize(pattern) {
		if (!(pattern instanceof RegExp) || pattern.global) {
			return pattern;
		}
		if (!pattern.__ovosGlobal) {
			pattern.__ovosGlobal = new RegExp(pattern.source, pattern.flags + 'g');
		}
		return pattern.__ovosGlobal;
	}
	
	/** extra bag (and nested request bags): secret-named keys dropped,
		e-mail values masked (domain kept), username keys masked to their
		groups (maskName) */
	function scrubBag(bag, depth) {
		try {
			if (typeof bag === 'string') {
				return maskEmails(bag);
			}
			if (bag === null || typeof bag !== 'object') {
				return bag;
			}
			if (depth >= 6) {
				return '[redacted]';
			}
			if (Array.isArray(bag)) {
				var list = [];
				for (var i = 0; i < bag.length; i++) {
					list.push(scrubBag(bag[i], depth + 1));
				}
				return list;
			}
			var out = {};
			for (var key in bag) {
				var value = bag[key];
				if (SCRUB_KEYS.test(key)) {
					// dropped wholesale — even when the value is an object
					out[key] = '[redacted]';
				} else if (value !== null && typeof value === 'object') {
					out[key] = scrubBag(value, depth + 1);
				} else if (typeof value === 'string') {
					var masked = maskEmails(value);
					// a one-character local part masks to itself and an already-
					// masked address no longer looks like one — both still count
					// as "the e-mail rule handled this", or the username rule
					// below would chew the mask and drop the domain
					out[key] = masked === value && !EMAIL_PLAIN.test(value)
						&& !MASKED_EMAIL.test(value) && USER_KEYS.test(key)
						? maskName(value) : masked;
				} else {
					out[key] = value;
				}
			}
			return out;
		} catch (ignored) {
			// best-effort: an unreadable bag is dropped, never sent raw
			return null;
		}
	}
	
	/** every e-mail in the value -> maskName(local part) + the domain kept:
		the mask says how long the address was (john.doe@x.com -> j***.***@x.com).
		Idempotent — a masked local part never ends in a run of address
		characters, so at most a single revealed character re-matches, and
		maskName maps a single character onto itself */
	function maskEmails(value) {
		return value.replace(EMAIL_VALUE, function (match, local, at, domain) {
			return maskName(local) + at + domain;
		});
	}
	
	/** every MASK_GROUP-th character kept, the rest starred (bob -> b**,
		marcin -> m***i*): the mask is as long as the value it replaced, and
		past MASK_MAX it states the real length instead ("[200]") — a login
		field holding thousands of characters is someone trying something.
		Masking a mask is a no-op; the server-side backstop scrubs an
		already-scrubbed report again */
	function maskName(value) {
		if (MASKED_CUT.test(value)) {
			return value;
		}
		
		var cut = Math.min(value.length, MASK_MAX);
		var masked = '';
		for (var index = 0; index < cut; index++) {
			masked += index % MASK_GROUP === 0 ? value.charAt(index) : '*';
		}
		
		return value.length > cut ? masked + '[' + value.length + ']' : masked;
	}
	
	/** host-aware path of a request url — the grouping key for failed calls.
		Token-shaped segments are redacted: they leak, and they also splinter
		grouping (every /orders/<uuid> would be its own issue). */
	function urlPath(url) {
		try {
			var a = document.createElement('a');
			a.href = url;
			// keep the host when it is not ours, so third-party endpoints stay apart
			var path = (a.host && a.host !== location.host ? a.host : '') + a.pathname;
			return path.replace(SCRUB_PATH, function (match, slash, segment) {
				return looksSecret(segment) ? slash + '[redacted]' : match;
			});
		} catch (ignored) {
			return truncate(String(url).split('?')[0], 200);
		}
	}
	
	function sinceLoad() {
		try {
			if (window.performance && performance.now) {
				return Math.round(performance.now());
			}
		} catch (ignored) {}
		return Date.now() - loadStart;
	}
	
	/** length hex chars; all-zero is forbidden for W3C trace ids */
	function randomHex(length) {
		var hex = '';
		try {
			if (window.crypto && crypto.getRandomValues) {
				var bytes = new Uint8Array(length / 2);
				crypto.getRandomValues(bytes);
				for (var i = 0; i < bytes.length; i++) {
					hex += (bytes[i] + 256).toString(16).slice(1);
				}
			}
		} catch (ignored) {
			hex = '';
		}
		while (hex.length < length) {
			hex += Math.random().toString(16).slice(2);
		}
		hex = hex.slice(0, length);
		return /[1-9a-f]/.test(hex) ? hex : '1' + hex.slice(1);
	}
	
	/** a fresh W3C traceparent — flags 00: we correlate, we do not trace */
	function newTraceparent() {
		var traceId = randomHex(32);
		return {header: '00-' + traceId + '-' + randomHex(16) + '-00', traceId: traceId};
	}
	
	/** the 32-hex trace id of a traceparent header, '' when malformed */
	function traceparentId(header) {
		var parsed = /^[0-9a-f]{2}-([0-9a-f]{32})-/.exec(String(header || '').toLowerCase());
		return parsed ? parsed[1] : '';
	}
	
	/** the client's own beacon/export requests — never breadcrumbed,
		never tagged, never traced (a reporting loop must be impossible) */
	function isOwnTraffic(url) {
		try {
			if (!config) {
				return false;
			}
			if (config.url && url.indexOf(config.url) === 0) {
				return true;
			}
			if (config.otlp && url.indexOf(config.otlp) === 0) {
				return true;
			}
		} catch (ignored) {}
		return false;
	}
	
	/** should this request carry a traceparent? Same-origin always (no CORS
		involved); other hosts only when listed in traceOrigins, because the
		header is not CORS-safelisted — it would add preflights the target
		must answer with Access-Control-Allow-Headers: traceparent */
	function traceEligible(url) {
		try {
			var a = document.createElement('a');
			a.href = url;
			// the scheme must match too: http->https on the same host is
			// cross-origin, and the header would force a preflight there
			if (!a.host || (a.host === location.host
				&& (!a.protocol || a.protocol === location.protocol))) {
				return true;
			}
			var origins = config.traceOrigins;
			for (var i = 0; origins && i < origins.length; i++) {
				var origin = origins[i];
				if (origin instanceof RegExp ? origin.test(url) : String(url).indexOf(origin) === 0) {
					return true;
				}
			}
		} catch (ignored) {}
		return false;
	}
	
	/** fetch args with a traceparent header added — {input, init, traceId},
		or null when the header cannot be placed safely (the caller then
		sends the request untouched). An app-set traceparent (its own OTEL
		SDK) is honored: reused for the report, never overwritten. */
	function injectTrace(input, init) {
		var existing = headerValue(init && init.headers, 'traceparent')
			|| (input && typeof input === 'object' && input.headers
				&& typeof input.headers.get === 'function'
				&& input.headers.get('traceparent')) || '';
		if (existing) {
			var existingId = traceparentId(existing);
			return existingId ? {input: input, init: init, traceId: existingId} : null;
		}
		
		var trace = newTraceparent();
		
		var patched = {};
		for (var key in init || {}) {
			patched[key] = init[key];
		}
		
		if (init && init.headers) {
			patched.headers = withHeader(init.headers, trace.header);
		} else if (input && typeof input === 'object' && input.headers) {
			// init.headers REPLACES a Request's own headers wholesale —
			// copy them all before adding ours
			patched.headers = withHeader(input.headers, trace.header);
		} else {
			patched.headers = {traceparent: trace.header};
		}
		
		return patched.headers ? {input: input, init: patched, traceId: trace.traceId} : null;
	}
	
	/** copy of a HeadersInit with traceparent set — Headers instance, entry
		array or plain object; null for shapes we do not understand */
	function withHeader(headers, value) {
		try {
			if (typeof Headers === 'function' && headers instanceof Headers) {
				var copy = new Headers(headers);
				copy.set('traceparent', value);
				return copy;
			}
			if (Array.isArray(headers)) {
				return headers.concat([['traceparent', value]]);
			}
			if (headers && typeof headers === 'object' && typeof headers.get !== 'function') {
				var plain = {};
				for (var key in headers) {
					plain[key] = headers[key];
				}
				plain.traceparent = value;
				return plain;
			}
		} catch (ignored) {}
		return null;
	}
	
	/** case-insensitive header lookup across the HeadersInit shapes */
	function headerValue(headers, name) {
		try {
			if (!headers) {
				return '';
			}
			if (typeof headers.get === 'function') {
				return String(headers.get(name) || '');
			}
			if (Array.isArray(headers)) {
				for (var i = 0; i < headers.length; i++) {
					if (String(headers[i] && headers[i][0]).toLowerCase() === name) {
						return String(headers[i][1] || '');
					}
				}
				return '';
			}
			for (var key in headers) {
				if (key.toLowerCase() === name) {
					return String(headers[key] || '');
				}
			}
		} catch (ignored) {}
		return '';
	}
	
	/** drop breadcrumbs before the batch trim ever has to drop whole reports */
	function shrink(entry) {
		try {
			if (JSON.stringify(entry).length > 10000 && entry.extra.breadcrumbs) {
				entry.extra.breadcrumbs = entry.extra.breadcrumbs.slice(-5);
				if (JSON.stringify(entry).length > 10000) {
					delete entry.extra.breadcrumbs;
				}
			}
		} catch (ignored) {}
	}
	
	function truncate(value, max) {
		value = String(value == null ? '' : value);
		return value.length > max ? value.slice(0, max) : value;
	}
	
	/**
	 * The tags option as the list the console reads: an array's strings, or
	 * one string split on commas, semicolons and whitespace — trimmed, empties
	 * dropped, at most 10 (the console's own cap per event)
	 */
	function normalizeTags(value) {
		var list = Array.isArray(value)
			? value
			: (typeof value === 'string' ? value.split(/[,;\s]+/) : []);
		var result = [];
		for (var i = 0; i < list.length && result.length < 10; i++) {
			if (typeof list[i] !== 'string' && typeof list[i] !== 'number') {
				continue;
			}
			var tag = String(list[i]).trim();
			if (tag !== '') {
				result.push(tag);
			}
		}
		return result;
	}
	
	/** named, so a second init() cannot register a second copy of it */
	function onVisibilityChange() {
		if (document.visibilityState === 'hidden') {
			flush();
		}
	}
	
	function schedule() {
		if (!flushTimer) {
			flushTimer = setTimeout(flush, config.flushDelay);
		}
	}
	
	/** Entries that did not fit this body, put back at the FRONT so they keep
		their order and go out next — with a flush scheduled for them, since
		the one that trimmed them has already taken the queue. A single report
		bigger than the cap is never trimmed (the loops stop at length > 1), so
		this cannot spin. */
	function requeue(entries) {
		if (entries.length === 0) {
			return;
		}
		queue = entries.concat(queue);
		schedule();
	}
	
	// syslog priority -> OTLP severityNumber band (higher = more severe
	// there); the console maps the bands back to 2/3/4/6/7 — 0/1 collapse
	// into critical and 5 into info on the round trip
	var OTLP_SEVERITY = {0: 21, 1: 21, 2: 21, 3: 17, 4: 13, 5: 9, 6: 9, 7: 5};
	var OTLP_SEVERITY_TEXT = {
		0: 'EMERGENCY', 1: 'ALERT', 2: 'CRITICAL', 3: 'ERROR',
		4: 'WARNING', 5: 'NOTICE', 6: 'INFO', 7: 'DEBUG',
	};
	
	/** POST one OTLP/JSON logs export — application/json via fetch
		(sendBeacon cannot carry that type cross-origin), keepalive so a
		pagehide flush survives */
	function sendOtlp(body) {
		if (!window.fetch) {
			return;
		}
		var headers = {'Content-Type': 'application/json'};
		for (var key in config.otlpHeaders || {}) {
			headers[key] = String(config.otlpHeaders[key]);
		}
		fetch(config.otlp, {
			method: 'POST',
			body: body,
			headers: headers,
			// the keepalive quota rejects bodies over 64 KiB outright — a
			// single oversized record sends without it (still delivered from
			// a live page, lost only when the page unloads mid-send)
			keepalive: body.length <= 60000,
		}).catch(function () {});
	}
	
	/** report entries -> ExportLogsServiceRequest. The webjs-tagged
		resource is what makes a console behind the collector ingest these
		as type js (browser grouping, page host, extra.col). */
	function toOtlp(batch) {
		var records = [];
		for (var i = 0; i < batch.length; i++) {
			records.push(otlpRecord(batch[i]));
		}
		
		var resource = [
			attr('telemetry.sdk.name', 'ovos-console-client'),
			attr('telemetry.sdk.language', 'webjs'),
			attr('service.name', String(location.host || '')),
		];
		if (config.release) {
			resource.push(attr('service.version', truncate(config.release, 64)));
		}
		if (config.environment) {
			resource.push(attr('deployment.environment.name',
				truncate(config.environment, 64)));
		}
		
		return {resourceLogs: [{
			resource: {attributes: resource.filter(Boolean)},
			scopeLogs: [{
				scope: {name: 'ovos-console-client'},
				logRecords: records,
			}],
		}]};
	}
	
	function otlpRecord(entry) {
		var attributes = [
			attr('exception.type', entry.name || 'Error'),
			attr('url.full', entry.url),
		];
		if (entry.stack) {
			attributes.push(attr('exception.stacktrace', entry.stack));
		}
		if (entry.file) {
			attributes.push(attr('code.file.path', entry.file));
		}
		if (entry.line) {
			attributes.push(attr('code.line.number', entry.line));
		}
		if (entry.col) {
			attributes.push(attr('code.column.number', entry.col));
		}
		try {
			if (navigator.userAgent) {
				attributes.push(attr('user_agent.original', truncate(navigator.userAgent, 500)));
			}
		} catch (ignored) {}
		if (entry.count > 1) {
			// the js path's dedup counter slot (extra.client_count)
			attributes.push(attr('client_count', entry.count));
		}
		
		// extra fields become one attribute each — unmapped attributes spill
		// into the console's context.extra verbatim, so pageId, breadcrumbs,
		// request and snapshotId land exactly where the js endpoint puts them
		for (var key in entry.extra || {}) {
			attributes.push(attr(key, entry.extra[key]));
		}
		
		var record = {
			// string math — ms * 1e6 overflows JS integer precision
			timeUnixNano: String(entry.timestamp) + '000000',
			severityNumber: OTLP_SEVERITY[entry.priority] || 17,
			severityText: OTLP_SEVERITY_TEXT[entry.priority] || 'ERROR',
			body: {stringValue: entry.message},
			attributes: attributes.filter(Boolean),
		};
		if (entry.traceId) {
			record.traceId = entry.traceId;
		}
		
		return record;
	}
	
	/** OTLP KeyValue via anyValue — null (filtered out) when not encodable */
	function attr(key, value) {
		var encoded = anyValue(value, 0);
		return encoded ? {key: key, value: encoded} : null;
	}
	
	/** JS value -> OTLP AnyValue (depth-capped; unsupported shapes and
		empty wrappers return null and the attribute is skipped) */
	function anyValue(value, depth) {
		try {
			if (value === null || value === undefined) {
				return null;
			}
			var type = typeof value;
			if (type === 'string') {
				// 8000 matches the report()-side stack cap — the widest
				// string a report legitimately carries
				return {stringValue: truncate(value, 8000)};
			}
			if (type === 'boolean') {
				return {boolValue: value};
			}
			if (type === 'number') {
				if (!isFinite(value)) {
					return {stringValue: String(value)};
				}
				return value % 1 === 0 && Math.abs(value) <= 9007199254740991
					? {intValue: String(value)}
					: {doubleValue: value};
			}
			if (depth >= 4) {
				return {stringValue: truncate(String(value), 200)};
			}
			if (Array.isArray(value)) {
				var values = [];
				for (var i = 0; i < value.length && i < 50; i++) {
					var item = anyValue(value[i], depth + 1);
					if (item) {
						values.push(item);
					}
				}
				return {arrayValue: {values: values}};
			}
			if (type === 'object') {
				var pairs = [];
				for (var key in value) {
					var wrapped = anyValue(value[key], depth + 1);
					if (wrapped) {
						pairs.push({key: key, value: wrapped});
					}
				}
				return {kvlistValue: {values: pairs}};
			}
		} catch (ignored) {}
		return null;
	}
	
	function flush() {
		try {
			clearTimeout(flushTimer);
			flushTimer = null;
			
			if (!config || queue.length === 0) {
				return;
			}
			
			var batch = queue;
			queue = [];
			
			// both transports: the diff belongs to every report of this page
			stampScripts(batch);
			
			// Entries trimmed to make the body fit go BACK on the queue. They
			// used to be dropped on the floor, and seen[] and uniqueSent had
			// already counted them — so a report that did not fit could never
			// be sent again for that page load, and a later re-throw of the
			// same error only incremented a count nobody would ever receive.
			var deferred = [];
			
			if (config.otlp) {
				// trim against the FINAL body: the OTLP envelope inflates
				// entries well past their report size, and a keepalive fetch
				// hard-fails over the ~64 KiB quota instead of degrading
				var otlpBody = JSON.stringify(toOtlp(batch));
				while (otlpBody.length > config.maxBytes && batch.length > 1) {
					deferred.unshift(batch.pop());
					otlpBody = JSON.stringify(toOtlp(batch));
				}
				requeue(deferred);
				sendOtlp(otlpBody);
				return;
			}
			
			var body = JSON.stringify(batch);
			while (body.length > config.maxBytes && batch.length > 1) {
				deferred.unshift(batch.pop());
				body = JSON.stringify(batch);
			}
			requeue(deferred);
			
			var endpoint = config.url + '/api/v1/ingest/js/' + encodeURIComponent(config.key);
			
			// text/plain keeps it a "simple" request: no CORS preflight,
			// sendBeacon-compatible; the server decodes the body regardless
			if (navigator.sendBeacon
				&& navigator.sendBeacon(endpoint, new Blob([body], {type: 'text/plain'}))) {
				return;
			}
			
			if (window.fetch) {
				fetch(endpoint, {
					method: 'POST',
					body: body,
					headers: {'Content-Type': 'text/plain'},
					// same quota guard sendOtlp() uses: keepalive rejects a
					// body over ~64 KiB OUTRIGHT rather than degrading, and
					// this line is only reached because sendBeacon already
					// refused for that very reason — so insisting on keepalive
					// threw the report away on a page that was still alive
					keepalive: body.length <= 60000,
				}).catch(function () {});
			}
		} catch (ignored) {}
	}
	
	// Async-loader stub takeover (docs/CLIENT.md): when a page loaded this
	// file async, an inline stub is already on ovosConsole — buffering
	// events and holding the init() options. Detach its blind listeners,
	// publish the real API over the shim, then init with the recorded
	// options; init() ends by draining the buffers. No task boundary exists
	// between removeEventListener and init()'s addEventListener, so no
	// event slips between them and none is seen twice. Synchronous
	// includes have no stub — nothing changes for them.
	var stub = window.ovosConsole && window.ovosConsole.stub;
	
	window.ovosConsole = {
		init: init,
		captureException: captureException,
		captureMessage: captureMessage,
		flush: flush,
		// capability marker: this build drains the async-loader stub. Loaders
		// that must work against older consoles too (ovos-play) probe it
		// onload — absent means a pre-drain client swallowed the stub and
		// never initialised, so such loaders fall back to init()ing directly.
		stubAware: true,
	};
	
	if (stub) {
		try {
			if (stub.capture) {
				window.removeEventListener('error', stub.capture, true);
				window.removeEventListener('unhandledrejection', stub.capture);
			}
			pendingEvents = stub.events || null;
			pendingCalls = stub.calls || null;
			if (stub.options) {
				init(stub.options);
			}
		} catch (ignored) { /* never break the host page */ }
	}
})();
