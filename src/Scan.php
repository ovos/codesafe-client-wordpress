<?php
declare(strict_types=1);
// phpcs:disable WordPress.WP.AlternativeFunctions -- a read-only walk of the site's own tree (scandir, stat, md5_file, a few hundred bytes read per candidate): WP_Filesystem exists for WRITES through FTP credentials and has nothing to offer a shutdown-time read; nothing here ever writes

namespace Ovos\Codesafe;

use Closure;
use Generator;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Prepend;

use function apply_filters;
use function array_diff;
use function array_filter;
use function array_flip;
use function array_intersect;
use function array_key_exists;
use function array_keys;
use function array_pop;
use function array_search;
use function array_slice;
use function array_splice;
use function array_sum;
use function array_unshift;
use function array_unique;
use function array_values;
use function basename;
use function bin2hex;
use function class_exists;
use function count;
use function defined;
use function did_action;
use function dirname;
use function end;
use function explode;
use function fclose;
use function file_get_contents;
use function fileperms;
use function filesize;
use function fopen;
use function fread;
use function function_exists;
use function get_blog_option;
use function get_bloginfo;
use function get_current_blog_id;
use function get_locale;
use function get_option;
use function get_plugins;
use function get_site_option;
use function get_sites;
use function get_theme_root;
use function gmdate;
use function home_url;
use function implode;
use function in_array;
use function ini_get;
use function is_admin;
use function is_array;
use function is_dir;
use function is_file;
use function is_link;
use function is_multisite;
use function is_string;
use function json_validate;
use function ltrim;
use function max;
use function md5_file;
use function method_exists;
use function microtime;
use function min;
use function preg_match;
use function preg_quote;
use function preg_replace;
use function preg_split;
use function random_bytes;
use function readlink;
use function realpath;
use function round;
use function rtrim;
use function sanitize_text_field;
use function scandir;
use function sort;
use function stat;
use function str_contains;
use function str_replace;
use function str_starts_with;
use function stripcslashes;
use function strlen;
use function strpos;
use function substr_count;
use function strrpos;
use function strtolower;
use function strtr;
use function substr;
use function sys_get_temp_dir;
use function time;
use function token_get_all;
use function trim;
use function var_export;
use function wp_doing_cron;
use function wp_get_environment_type;
use function wp_get_upload_dir;
use function wp_parse_url;
use function wp_unslash;

use const ABSPATH;
use const DIRECTORY_SEPARATOR;
use const PHP_FLOAT_MAX;
use const PHP_INT_MAX;
use const PHP_URL_HOST;
use const PHP_VERSION;
use const PREG_OFFSET_CAPTURE;
use const SCANDIR_SORT_NONE;
use const SORT_STRING;
use const T_ABSTRACT;
use const T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG;
use const T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG;
use const T_ARRAY;
use const T_AS;
use const T_ATTRIBUTE;
use const T_BAD_CHARACTER;
use const T_BOOL_CAST;
use const T_BOOLEAN_AND;
use const T_BOOLEAN_OR;
use const T_CATCH;
use const T_CLASS;
use const T_CLOSE_TAG;
use const T_COALESCE;
use const T_COMMENT;
use const T_CONCAT_EQUAL;
use const T_CONST;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_CURLY_OPEN;
use const T_DECLARE;
use const T_DIR;
use const T_DNUMBER;
use const T_DOC_COMMENT;
use const T_DOLLAR_OPEN_CURLY_BRACES;
use const T_DOUBLE_ARROW;
use const T_DOUBLE_CAST;
use const T_DOUBLE_COLON;
use const T_ELSEIF;
use const T_EMPTY;
use const T_ENCAPSED_AND_WHITESPACE;
use const T_END_HEREDOC;
use const T_ENUM;
use const T_EVAL;
use const T_EXIT;
use const T_FILE;
use const T_FINAL;
use const T_FN;
use const T_FOR;
use const T_FOREACH;
use const T_FUNCTION;
use const T_HALT_COMPILER;
use const T_IF;
use const T_INCLUDE;
use const T_INCLUDE_ONCE;
use const T_INLINE_HTML;
use const T_INT_CAST;
use const T_INTERFACE;
use const T_ISSET;
use const T_LINE;
use const T_LIST;
use const T_LNUMBER;
use const T_LOGICAL_AND;
use const T_LOGICAL_OR;
use const T_MATCH;
use const T_NAME_FULLY_QUALIFIED;
use const T_NAME_QUALIFIED;
use const T_NAME_RELATIVE;
use const T_NAMESPACE;
use const T_NEW;
use const T_NULLSAFE_OBJECT_OPERATOR;
use const T_OBJECT_OPERATOR;
use const T_OPEN_TAG;
use const T_READONLY;
use const T_REQUIRE;
use const T_REQUIRE_ONCE;
use const T_RETURN;
use const T_START_HEREDOC;
use const T_STATIC;
use const T_STRING;
use const T_SWITCH;
use const T_TRAIT;
use const T_UNSET;
use const T_USE;
use const T_VARIABLE;
use const T_WHILE;
use const T_WHITESPACE;

/**
 * Integrity scan — the static half of finding the file nobody shipped.
 *
 * Every other sensor in this plugin needs the foreign file to DO something
 * after the plugin is installed: throw (Sender::sourceFor), be saved through
 * the editor (Security), be activated (Inventory). A shell dropped before the
 * plugin arrived, used once and left behind, does none of that. This class
 * asks the tree directly — is there executable code where none belongs, an
 * image that opens with `<?php`, a directive that makes images execute, a
 * drop-in whose owner is not installed, a core or plugin file that is not
 * what wordpress.org shipped (Checksums) — and the database beside it
 * (Database) — and answers with paths, never with contents.
 *
 * READS ONLY. Never writes, deletes, renames or quarantines: a wrong guess
 * must cost a second look, not a file. Never touches .htaccess. Never
 * follows a symlink. Never descends into a plugin-owned data directory
 * (backups can be gigabytes) — the directory itself is the finding.
 *
 * CHUNKED: the walk keeps its whole position in an array (a stack of
 * pending directories, counters, findings so far) that the runner persists
 * between requests, so a shutdown hook can spend 500 ms per request and a
 * button press a few seconds, and both resume where they stopped. Phases
 * run in order of expected value — the root, then uploads, then wp-content
 * itself — so an interrupted pass has already shipped the urgent part. A
 * checksum list that still has to be fetched can YIELD a chunk: the
 * directory goes back on the stack and the next request pays for the fetch.
 * The two walks that can grow without end — the document root's folders, a
 * second application among them, and wp-content/cache — are BOUNDED in
 * depth and in names per pass (limit()), and say where they stopped.
 *
 * WHERE NO LIST VOUCHES — a theme, a premium plugin, a must-use plugin, a
 * folder of the document root, wp-config.php, a cache — a file is read for
 * what a backdoor looks like and honest code does not (codeVerdict(),
 * inspectPackage()): Database's code markers in the shapes that run them.
 *
 * PRECISION FIRST: a scanner that names something innocent gets switched
 * off, which is worse than one that is late. Every heuristic here carries
 * its known false positive and how it is held down (the `index.php` stubs
 * plugins write into uploads, Wordfence's and AIOS's root files, managed
 * hosts' drop-ins, the data files plugins keep under PHP names, this
 * plugin's own store). The tier on a finding is a PROPOSAL; the console
 * decides.
 */
class Scan
{
	public const TIER_URGENT = 'urgent';
	
	public const TIER_HIGH = 'high';
	
	public const TIER_INFO = 'info';
	
	public const TIERS = [self::TIER_URGENT, self::TIER_HIGH, self::TIER_INFO];
	
	public const AREAS = ['root', 'uploads', 'content', 'plugins', 'core', 'themes', Database::AREA];
	
	/**
	 * Findings carried in full; past this the report counts them per tier.
	 * Urgent-first phase order means the cap eats the least interesting end.
	 */
	public const MAX_FINDINGS = 200;
	
	protected const MAX_PATH = 512;
	
	public const MAX_DETAIL = 160;
	
	/** sites activeAnywhere() reads on a network; past them "active" is not knowable */
	public const SITES_MAX = 100;
	
	protected const MAX_SKIPPED = 50;
	
	protected const MAX_DIRECTIVES_PER_FILE = 10;
	
	/** the polish detectors (dir_changed, owner_anomaly, symlink_outside) each stop listing here */
	protected const MAX_PER_POLISH = 20;
	
	/**
	 * The first block of a media-shaped file — enough to see the `<?php`
	 * that a favicon.ico shell puts behind a few bytes of decoy
	 */
	protected const HEAD_BYTES = 1024;
	
	protected const STUB_BYTES = 256;
	
	/** the plugin's own store files are read whole up to this: the queue and the seen list are capped well below it */
	protected const STORE_BYTES = 1048576;
	
	/** a PHP-named data file is read whole up to this to judge it; a larger one is not judged data (the executed-file judge reads the same) */
	public const DATA_BYTES = 262144;
	
	/**
	 * A PHP file read for its code shapes, or judged as data where no list
	 * vouches for it, is read up to this; past it the file is named
	 * oversize_php. The tokenizer reads it in slices (slices()), so the limit
	 * costs read time, never a token array of the whole file
	 */
	protected const CODE_BYTES = 4194304;
	
	/** the source the tokenizer reads at once (slices()), and the tokens a slice without a statement's end may hold before it is cut */
	protected const SLICE_BYTES = 32768;
	
	protected const SLICE_TOKENS = 8192;
	
	/** the tokens a slice grows to rather than cut a runner's call, and past which it cuts and hands the next slice the call's head (cut()) */
	protected const CALL_TOKENS = 32768;
	
	/** a PHP file larger than this is judged only after the pass is checkpointed with it named (checkpoint()) */
	protected const CHECKPOINT_BYTES = 262144;
	
	/**
	 * The bounded walks (limit()): how many levels below its top a walk
	 * descends and how many names it reads per pass. The document root's
	 * folders reach a second application — a shell sits a level or two down
	 * (images/, .well-known/), not twenty — and a page cache holds a page
	 * per URL, a hundred thousand on a large site, mirroring the URLs'
	 * depth. Past either, the directory is named in scan.skipped
	 */
	protected const ROOT_DEPTH = 6;
	
	protected const ROOT_ENTRIES = 20000;
	
	protected const CACHE_DEPTH = 16;
	
	protected const CACHE_ENTRIES = 50000;
	
	/** how long the database phase waits for a WP-Cron or admin request before any loaded one will do */
	protected const DATABASE_WAIT = 86400;
	
	protected const DIRECTIVE_BYTES = 65536;
	
	protected const MIN_POLYGLOT_SIZE = 5;
	
	/** a directory changed after its newest file inside this window is worth dating */
	protected const RECENT_CHANGE = 30 * 86400;
	
	/**
	 * Checksum lists fetched per chunk before the walk yields to the next
	 * request: a shutdown chunk pays for one, a button round for a few
	 */
	protected const FETCHES_BACKGROUND = 1;
	
	protected const FETCHES_MANUAL = 3;
	
	/**
	 * Executable-shaped: the PHP family plus what Apache may hand to PHP or
	 * SSI. `.php.` inside the name counts too — `shell.php.jpg` executes
	 * wherever AddHandler (not SetHandler) maps .php.
	 */
	protected const EXECUTABLE = '~\.(?:ph(?:p\d?|tml|ar)|inc|shtml)(?:\.|$)~i';
	
	/**
	 * Media-shaped names probed for a PHP opener. Binary formats everywhere;
	 * text formats only under uploads, where a `.txt` opening with `<?php`
	 * has no honest explanation (a plugin's test fixture might).
	 */
	protected const MEDIA = ['ico', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'pdf', 'svg'];
	
	protected const MEDIA_TEXT = ['txt', 'log', 'csv'];
	
	protected const DIRECTIVE_FILES = ['.htaccess', '.user.ini', 'php.ini'];
	
	/**
	 * Dotfile PHP that developer tooling ships inside packages — a code-style
	 * config is not a hidden shell, and vendored plugins carry them by the
	 * dozen
	 */
	protected const HIDDEN_TOOLING = '~^\.(?:php-cs-fixer|php_cs|phpstorm\.meta|phpunit|phpcs|phpmd|phplint|phpstan|psalm)~i';
	
	/**
	 * WordPress 6.5+ writes translations as PHP (`<locale>.l10n.php`, or
	 * `<textdomain>-<locale>.l10n.php`) under wp-content/languages — core's own
	 * executable-shaped data files, loaded only by name for a requested locale
	 */
	protected const TRANSLATION = '~\.l10n\.php$~';
	
	/**
	 * Never descended: version control (thousands of objects, and its
	 * presence in the docroot is its own posture line) and node_modules
	 */
	protected const SKIP_DIRS = ['.git', '.svn', '.hg', 'node_modules'];
	
	/**
	 * wp-content directories skipped whole: core's own upgrade staging (the
	 * cache is walked, bounded: inspectCacheExecutable())
	 */
	protected const CONTENT_SKIP = ['upgrade', 'upgrade-temp-backup'];
	
	/**
	 * Directories a package keeps images, fonts, styles, media and
	 * translations in, by name at any depth of a theme, a plugin, a
	 * must-use plugin or a folder of the document root: code that runs
	 * there, among more ASSET_FILES than PHP, stands where its package keeps
	 * none (asset_php). The name alone is no proof — a PSR-4 `Css/`
	 * namespace, a view's `icons/`, a theme's `inc/css/` generators hold PHP
	 * and nothing else — and the data files honest packages keep among their
	 * assets — a build's `*.asset.php`, a `.l10n.php` translation, a guarded
	 * settings array — return literals and run nothing
	 */
	protected const ASSET_DIRS = ['images', 'image', 'img', 'imgs', 'icons', 'fonts', 'webfonts', 'css', 'scss',
		'sass', 'less', 'svg', 'sounds', 'audio', 'video', 'videos', 'languages', 'lang', 'langs'];
	
	/** what an asset folder holds: images, fonts, styles, scripts, translations, media */
	protected const ASSET_FILES = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'ico', 'bmp', 'woff', 'woff2', 'ttf',
		'eot', 'otf', 'css', 'scss', 'sass', 'less', 'map', 'js', 'mjs', 'mo', 'po', 'pot', 'json', 'mp3', 'mp4', 'webm',
		'ogg', 'wav'];
	
	/** WordPress's translation functions: they hand a string back, or echo it, and run nothing else */
	protected const I18N = ['__', '_e', '_x', '_ex', '_n', '_nx', '_n_noop', '_nx_noop', 'esc_html__', 'esc_html_e', 'esc_html_x',
		'esc_attr__', 'esc_attr_e', 'esc_attr_x'];
	
	/**
	 * Functions only WordPress defines, none of them PHP's: the hooks, the
	 * registrations (PHP's own register_shutdown_function and
	 * register_tick_function left out), the wp_ and esc_ families, the
	 * translation functions
	 */
	protected const WORDPRESS_CALLS = '~^(?:add_(?:action|filter|shortcode|theme_support|image_size|menu_page|submenu_page|meta_box)|remove_(?:action|filter)|do_action|apply_filters|register_(?!shutdown_function$|tick_function$)\w+|wp_\w+|esc_\w+|__|_e)$~';
	
	/** the calls data may make (dataOnly()): a guard's defined(), json_decode() of a literal, the translation functions */
	protected const DATA_CALLS = ['defined', 'json_decode', ...self::I18N];
	
	/** the tokens data is made of (dataOnly()), besides the names, a guard's exit and the parentheses */
	protected const DATA_TOKENS = [T_VARIABLE, T_CONSTANT_ENCAPSED_STRING, T_LNUMBER, T_DNUMBER, T_ARRAY, T_RETURN, T_IF, T_EXIT,
		T_BOOLEAN_OR, T_LOGICAL_OR, T_BOOLEAN_AND, T_LOGICAL_AND, T_COALESCE, T_DIR, T_FILE, T_LINE, T_START_HEREDOC,
		T_ENCAPSED_AND_WHITESPACE, T_END_HEREDOC, T_DOUBLE_ARROW, '!', '{', '}', '=', ';', '[', ']', ',', ')', '-', '+', '*', '/',
		'%', '|', '&', T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG, T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG, '~', '.', '?', ':'];
	
	/** PHP's request input: what a remote caller writes */
	protected const REQUEST_INPUT = ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_SERVER', '$_FILES'];
	
	/**
	 * The fields of $_SERVER a request writes, besides its headers (HTTP_*):
	 * the query string, the URI and its path info, PHP_SELF, the body's
	 * type, argv (the query string again where register_argc_argv is on).
	 * SCRIPT_NAME, SCRIPT_FILENAME, DOCUMENT_ROOT and SERVER_NAME are the
	 * server's own: the request picks a script, it writes no content there
	 */
	protected const SERVER_INPUT = ['QUERY_STRING', 'REQUEST_URI', 'PATH_INFO', 'ORIG_PATH_INFO', 'PATH_TRANSLATED', 'PHP_SELF',
		'CONTENT_TYPE', 'argv', 'REDIRECT_URL', 'REDIRECT_QUERY_STRING', 'UNENCODED_URL'];
	
	/** the functions that hand over the request without a superglobal's name */
	protected const INPUT_FUNCTIONS = ['getallheaders', 'apache_request_headers', 'filter_input', 'filter_input_array'];
	
	/**
	 * The functions that call a callable they are handed, by the position of
	 * that argument: request input there runs whatever the caller names, a
	 * literal there that names a runner hands it the other arguments
	 */
	protected const CALLABLES = [
		'call_user_func' => 0, 'call_user_func_array' => 0, 'forward_static_call' => 0, 'forward_static_call_array' => 0,
		'array_map' => 0, 'array_filter' => 1, 'array_walk' => 1, 'array_walk_recursive' => 1, 'array_reduce' => 1,
		'usort' => 1, 'uasort' => 1, 'uksort' => 1, 'preg_replace_callback' => 1, 'iterator_apply' => 1,
		'register_shutdown_function' => 0, 'register_tick_function' => 0, 'header_register_callback' => 0, 'ob_start' => 0,
		'set_error_handler' => 0, 'set_exception_handler' => 0, 'spl_autoload_register' => 0,
	];
	
	/**
	 * The arguments a callback's parameters come from, by position, per
	 * function of CALLABLES (null: every argument after the callable): what
	 * request input must stand in for a callback that runs its parameter to
	 * run it (callback()). The others hand their callback the output, an
	 * error or a class name
	 */
	protected const CALLBACK_DATA = [
		'call_user_func' => null, 'call_user_func_array' => [1], 'forward_static_call' => null, 'forward_static_call_array' => [1],
		'array_map' => null, 'array_filter' => [0], 'array_walk' => [0, 2], 'array_walk_recursive' => [0, 2], 'array_reduce' => [0, 2],
		'usort' => [0], 'uasort' => [0], 'uksort' => [0], 'preg_replace_callback' => [2], 'iterator_apply' => [0, 2],
		'register_shutdown_function' => null, 'register_tick_function' => null,
	];
	
	/** what makes request input fit for a command, a path or a name: an escaper, a sanitizer, a number */
	protected const SANITIZERS = ['escapeshellarg', 'escapeshellcmd', 'sanitize_key', 'sanitize_text_field', 'sanitize_file_name',
		'sanitize_title', 'sanitize_user', 'sanitize_email', 'absint', 'intval', 'floatval', 'boolval', 'basename', 'esc_attr',
		'esc_html', 'esc_url', 'esc_sql', 'preg_quote', 'urlencode', 'rawurlencode', 'md5', 'sha1', 'hash'];
	
	/** the decoders a file's obfuscation uses beside the ones an option's value would (Database::CODE_DECODERS) */
	protected const DECODERS = ['strrev', 'hex2bin', 'gzdecode', 'urldecode', 'rawurldecode', 'convert_uudecode', 'bzdecompress'];
	
	/**
	 * The stream wrappers an include reaches beyond the site's own files
	 * through. phar:// is left out: vendored libraries ship phar stubs that
	 * include their own archive, and a phar an intruder uploaded is named by
	 * its upload path or its media extension
	 */
	protected const STREAMS = '~^(?:https?|ftps?|php|data|expect|glob|zlib|zip|rar|ogg|compress\.(?:zlib|bzip2)|ssh2\.\w+)://|^data:~i';
	
	/** a template engine's compiled file by its compiler's own mark: Twig's class, Blade's path trailer, Smarty's header */
	protected const COMPILED = '~\bclass __TwigTemplate_[0-9a-f]{16,}\b|/\*\*PATH .{1,512}? ENDPATH\*\*/|^<\?php\s*/\*\s*Smarty version~';
	
	/** what W3 Total Cache writes behind its four-byte expiry into every object and database cache file */
	protected const W3TC_GUARD = '<?php exit; ?>';
	
	/**
	 * wp-content/cache directories a plugin fills with PHP that runs, by
	 * design: Docket Cache's object files rebuild objects, Autoptimize's gzip
	 * wrappers send its files. Read for code shapes alone while their plugin
	 * is installed; without it they hold strangers
	 */
	protected const CACHE_WRITERS = [
		'docket-cache' => ['docket-cache'],
		'autoptimize' => ['autoptimize'],
	];
	
	/**
	 * A "Silence is golden." index.php — the stub WordPress and half its
	 * plugins write into directories to stop listings — for a PHP built
	 * without the tokenizer (stubShaped()): an opener, `//` and block comments,
	 * a closer only at the very end. Stricter than PHP on purpose: a `//`
	 * comment ends at CR or LF and holds no `?>`, and no `#` line passes, since
	 * an attribute starts the same way
	 */
	protected const STUB_STRICT = '~^\s*<\?php(?:\s|//(?:[^\r\n?]|\?(?!>))*+|/\*.*?\*/)*+(?:\?>\s*)?$~s';
	
	/**
	 * Drop-ins and other wp-content files WordPress or a plugin writes, and
	 * the plugins that write them. A file here with none of its owners
	 * installed is a stranger wearing a known name.
	 */
	protected const CONTENT_OWNERS = [
		'advanced-cache.php' => ['wp-super-cache', 'w3-total-cache', 'wp-rocket', 'litespeed-cache',
			'wp-fastest-cache', 'hummingbird-performance', 'breeze', 'cache-enabler', 'comet-cache',
			'swift-performance', 'swift-performance-lite', 'nitropack', 'flying-press', 'wp-optimize',
			'sg-cachepress', 'powered-cache', 'hyper-cache', 'simple-cache', 'surge',
			'wp-cloudflare-page-cache', 'seraphinite-accelerator', 'speed-booster-pack'],
		'object-cache.php' => ['redis-cache', 'w3-total-cache', 'litespeed-cache', 'memcached',
			'memcached-redux', 'object-cache-pro', 'wp-redis', 'sqlite-object-cache', 'docket-cache',
			'powered-cache', 'apcu-manager', 'relay-cache', 'wp-spider-cache', 'hummingbird-performance'],
		'db.php' => ['query-monitor', 'ludicrousdb', 'hyperdb', 'w3-total-cache',
			'sqlite-database-integration', 'wp-db-driver'],
		'wp-cache-config.php' => ['wp-super-cache'],
		// the fallback Autoptimize copies into wp-content for requests its cache no longer holds
		'autoptimize_404_handler.php' => ['autoptimize'],
	];
	
	/**
	 * wp-content directories a plugin (or theme) owns and fills with its own
	 * PHP-named data and logs. Never descended; owner installed → listed,
	 * owner missing → a finding.
	 */
	protected const WRITER_DIRS = [
		'wflogs' => ['wordfence'],
		'wfcache' => ['wordfence'],
		'w3tc-config' => ['w3-total-cache'],
		'wp-rocket-config' => ['wp-rocket'],
		'litespeed' => ['litespeed-cache'],
		'sucuri' => ['sucuri-scanner'],
		'nfwlog' => ['ninjafirewall'],
		'wp-cloudflare-super-page-cache' => ['wp-cloudflare-page-cache'],
		'bps-backup' => ['bulletproof-security'],
		'aiowps_backups' => ['all-in-one-wp-security-and-firewall'],
		'backups-dup-lite' => ['duplicator'],
		'backups-dup-pro' => ['duplicator-pro'],
		'ai1wm-backups' => ['all-in-one-wp-migration'],
		'updraft' => ['updraftplus'],
		'wpvividbackups' => ['wpvivid-backuprestore'],
		'wp-security-audit-log' => ['wp-security-audit-log'],
		'ithemes-security' => ['better-wp-security', 'ithemes-security-pro'],
		'siteground-optimizer-assets' => ['sg-cachepress'],
		'smush-webp' => ['wp-smushit', 'wp-smush-pro'],
		'ewww' => ['ewww-image-optimizer'],
		'et-cache' => ['theme:Divi', 'theme:Extra'],
		'backup-db' => ['wp-db-backup'],
	];
	
	/**
	 * Uploads directories a plugin fills with PHP-named data it includes
	 * later: Ultimate Addons' (and ConvertPlug's) icon sets as charmap.php.
	 * Walked like the rest of uploads: a file there that is data only, with an
	 * owner installed, is listed; anything else is URGENT like any PHP under
	 * uploads. Owners match whatever the directory's casing
	 */
	protected const UPLOAD_WRITERS = [
		'smile_fonts' => ['Ultimate_VC_Addons', 'convertplug'],
	];
	
	/**
	 * The uploads folders a template engine compiles into, by the plugins
	 * whose code puts it there: WPML's Twig cache (WPML_Cache_Directory, the
	 * uploads root's cache/wpml, `twig` below it), which WooCommerce
	 * Multilingual ships too
	 */
	protected const UPLOAD_COMPILERS = [
		'cache/wpml/twig' => ['sitepress-multilingual-cms', 'woocommerce-multilingual'],
	];
	
	/**
	 * PHP files a plugin legitimately puts in the document ROOT (the
	 * executed-file watch, Entries, asks the same question): Wordfence's
	 * firewall prepend, and the bootstrap AIOS writes for its firewall and
	 * leaves behind, stripped, when the firewall is turned off
	 */
	public const ROOT_OWNERS = [
		'wordfence-waf.php' => ['wordfence'],
		'aios-bootstrap.php' => ['all-in-one-wp-security-and-firewall'],
	];
	
	/**
	 * The security plugins whose presence answers a posture question — a
	 * login rate limit, a second factor, an upload scanner — by slug among
	 * the ACTIVE plugins. The console prints the gap where none is found:
	 * these are commodity features the plugin deliberately does not
	 * re-implement.
	 */
	protected const PROTECTION = [
		'login_protection' => ['limit-login-attempts-reloaded', 'wordfence', 'better-wp-security', 'ithemes-security-pro',
			'all-in-one-wp-security-and-firewall', 'wp-cerber', 'loginizer', 'wp-simple-firewall', 'ninjafirewall',
			'sucuri-scanner', 'login-lockdown', 'wp-limit-login-attempts', 'limit-login-attempts', 'malcare-security',
			'security-malware-firewall', 'defender-security'],
		'two_factor' => ['two-factor', 'wp-2fa', 'miniorange-2-factor-authentication', 'google-authenticator',
			'two-factor-authentication', 'duo-wordpress', 'wordfence', 'better-wp-security', 'ithemes-security-pro',
			'all-in-one-wp-security-and-firewall', 'wp-simple-firewall', 'defender-security'],
		'upload_scanner' => ['wordfence', 'ninjafirewall', 'wp-cerber', 'sucuri-scanner', 'malcare-security',
			'wp-simple-firewall', 'security-malware-firewall', 'defender-security', 'antivirus', 'gotmls'],
	];
	
	/**
	 * Area roots for the pass in progress — set from the state on every
	 * advance() so the helpers can classify without threading the array
	 *
	 * @var array<string, string>
	 */
	protected array $roots = [];
	
	protected ?string $host = null;
	
	protected ?Checksums $sums = null;
	
	/** @var array{store: string, stub: string, legacy: string}|null */
	protected ?array $store = null;
	
	/** @var array<string, array<string, string>> installedSlugs() by root */
	protected array $slugs = [];
	
	/** the core list for this request, loaded once; false = unavailable this pass */
	protected array|false|null $coreList = null;
	
	/** @var ?array{uploads: string, temp: list<string>, owned: list<string>} places(), once per request */
	protected ?array $places = null;
	
	/**
	 * Handed the file about to be judged — {area, path, size} — before a
	 * large one is (checkpoint()), and before the database's checks, and
	 * null once it is: the runner keeps the name in an option of its own, so
	 * a chunk that dies there leaves it behind and nothing of the pass is
	 * written for it
	 */
	public ?Closure $checkpoint = null;
	
	/** when this chunk's budget runs out (advance()): visit() and recheck() stop between files at it */
	protected float $deadline = PHP_FLOAT_MAX;
	
	protected int $fetchLimit = self::FETCHES_BACKGROUND;
	
	public function __construct(
		protected Config $config,
	)
	{
	}
	
	/**
	 * A fresh pass: the phase list, empty counters, no position yet — and
	 * the plugin versions the checksum lists are keyed by, and where the last
	 * pass's bounded walks and content pages stopped
	 *
	 * @param array<string, int|string> $resume the last pass's resume_next
	 */
	public function start(
		string $mode,
		array $resume = [],
	): array
	{
		$roots = $this->roots();
		
		$phases = [['root', $roots['root'], true, ['bound' => 'root', 'depth' => 0]]];
		
		if($roots['uploads'] !== '' && is_dir($roots['uploads']))
		{
			$phases[] = ['uploads', $roots['uploads'], true, []];
		}
		
		$phases[] = ['content', $roots['content'], false, []];
		
		if(is_dir($roots['mu']))
		{
			$phases[] = ['content', $roots['mu'], true, ['mu' => true]];
		}
		
		$phases[] = ['plugins', $roots['plugins'], true, []];
		$phases[] = ['core', $roots['root'] . '/wp-admin', true, []];
		$phases[] = ['core', $roots['root'] . '/wp-includes', true, []];
		$phases[] = ['themes', $roots['themes'], true, []];
		$phases[] = ['recheck', '', false, []];
		$phases[] = [Database::AREA, '', false, []];
		$phases[] = ['posture', '', false, []];
		
		$areas = [];
		
		foreach(self::AREAS as $area)
		{
			$areas[$area] = [
				'root' => match($area)
				{
					'uploads' => $roots['uploads'],
					'content' => $roots['content'],
					'plugins' => $roots['plugins'],
					'themes' => $roots['themes'],
					Database::AREA => '',
					default => $roots['root'],
				},
				'files' => 0,
				'dirs' => 0,
				'executable' => 0,
				'bytes' => 0,
				'probed' => 0,
				'verified' => 0,
				'modified' => 0,
				'foreign' => 0,
				'missing' => 0,
			];
		}
		
		return [
			'id' => bin2hex(random_bytes(8)),
			'mode' => $mode,
			'started' => time(),
			'elapsed' => 0,
			'chunks' => 0,
			'roots' => $roots,
			'phases' => $phases,
			'phase' => 0,
			'opened' => false,
			'stack' => [],
			'yield' => false,
			// each bounded walk's ledger this pass (bounded()), where the last pass stopped and where this one does
			'bounded' => [],
			'resume' => $resume,
			'resume_next' => [],
			// files a chunk died judging: named once, never judged again this pass
			'poisoned' => [],
			// the files this pass found something in inside a bounded walk, by path, and the earlier ones judged again (recheck())
			'recheck_next' => [],
			'recheck_at' => 0,
			'rechecked' => 0,
			'config_read' => false,
			'areas' => $areas,
			'findings' => [],
			'counts' => [self::TIER_URGENT => 0, self::TIER_HIGH => 0, self::TIER_INFO => 0],
			'truncated' => [self::TIER_URGENT => 0, self::TIER_HIGH => 0, self::TIER_INFO => 0],
			'polish' => ['dir_changed' => 0, 'owner_anomaly' => 0, 'symlink_outside' => 0],
			'skipped' => [],
			'unreadable' => 0,
			'symlinks' => 0,
			'vcs' => [],
			'uploads_htaccess' => false,
			'uploads_php_denied' => false,
			'versions' => $this->pluginVersions(),
			'core_version' => Inventory::version((string)get_bloginfo('version')),
			'locale' => function_exists('get_locale') ? (string)get_locale() : 'en_US',
			'checksums' => [
				'core' => 'pending',
				'core_locale' => '',
				'plugins' => [],
			],
			'posture' => null,
			'done' => false,
		];
	}
	
	/**
	 * Spend up to $budgetMs on the pass and hand the position back. A
	 * directory is the unit of work: the budget is checked between
	 * directories, so one enormous flat directory may overrun it once. A
	 * checksum list the chunk may not fetch any more YIELDS: the directory
	 * goes back on the stack and the next request continues there.
	 */
	public function advance(
		array $state,
		int $budgetMs,
	): array
	{
		$this->roots = $state['roots'];
		$this->fetchLimit = ($state['mode'] ?? '') === 'manual' ? self::FETCHES_MANUAL : self::FETCHES_BACKGROUND;
		$this->sums ??= new Checksums(($state['mode'] ?? '') === 'manual' ? 4 : 2);
		$this->sums->fetches = 0;
		$this->coreList = null;
		$this->places = null;
		
		// a pass the last version stored lacks what this one keeps beside it
		$state += ['bounded' => [], 'resume' => [], 'resume_next' => [], 'poisoned' => [], 'config_read' => false,
			'recheck_next' => [], 'recheck_at' => 0, 'rechecked' => 0];
		$begun = microtime(true);
		$deadline = $begun + $budgetMs / 1000;
		$this->deadline = $deadline;
		$state['chunks']++;
		$state['yield'] = false;
		
		if(isset($state['judging']))
		{
			// the last chunk died judging this: it is named, and passed over from here on
			$judging = (array)$state['judging'];
			$area = (string)($judging['area'] ?? '');
			unset($state['judging']);
			$state['poisoned'][] = (string)($judging['path'] ?? '');
			$this->finding($state, isset($state['areas'][$area]) ? $area : 'root', (string)($judging['path'] ?? ''), 'scan_crash', self::TIER_HIGH,
				'the scan died judging this; read it by hand', isset($judging['size']) ? ['size' => (int)$judging['size']] : []);
		}
		
		while($state['done'] === false && microtime(true) < $deadline)
		{
			if($state['phase'] >= count($state['phases']))
			{
				$state['done'] = true;
				$state['resume_next'] = $this->resumeNext($state);
				
				break;
			}
			
			[$area, $dir, $recursive, $flags] = $state['phases'][$state['phase']];
			
			if($area === 'posture')
			{
				$this->posture($state);
				$state['phase']++;
				
				continue;
			}
			
			if($area === Database::AREA)
			{
				if($this->databaseReady($state) === false)
				{
					break;
				}
				
				if(in_array('checks', $state['poisoned'], true) === false)
				{
					$this->mark(['area' => Database::AREA, 'path' => 'checks']);
					$this->database($state);
					// they ran: a chunk that dies later blames them not
					$this->mark(null);
				}
				
				$state['phase']++;
				
				continue;
			}
			
			if($area === 'recheck')
			{
				if($this->recheck($state) === false)
				{
					break;
				}
				
				$state['phase']++;
				
				continue;
			}
			
			// the areas the core list vouches for wait for it — one fetch,
			// once per month, and never past this chunk's fetch budget
			if(in_array($area, ['root', 'core', 'themes'], true) && $this->ensureCore($state) === false)
			{
				break;
			}
			
			if($state['opened'] === false)
			{
				$state['stack'] = is_dir($dir)
					? [[$area, $dir, $flags + ['recursive' => $recursive]]]
					: [];
				$state['opened'] = true;
			}
			
			if($state['stack'] === [])
			{
				$state['phase']++;
				$state['opened'] = false;
				
				continue;
			}
			
			[$area, $dir, $flags] = array_pop($state['stack']);
			
			$this->visit($state, $area, $dir, $flags);
			
			if($state['yield'])
			{
				$state['yield'] = false;
				
				break;
			}
		}
		
		$state['elapsed'] += (int)round((microtime(true) - $begun) * 1000);
		
		return $state;
	}
	
	/**
	 * A human-readable position for a progress line: the phase's area and
	 * the files counted so far
	 */
	public static function progress(
		array $state,
	): array
	{
		$phase = $state['phases'][$state['phase']] ?? null;
		$files = 0;
		
		foreach($state['areas'] as $area)
		{
			$files += (int)$area['files'];
		}
		
		return [
			'area' => $phase === null ? '' : (string)$phase[0],
			'files' => $files,
			'findings' => count($state['findings']),
		];
	}
	
	/**
	 * The report — what the console ingests and what wp-admin shows. Area
	 * roots are absolute (the console already knows server paths from
	 * every error's context.dir); finding paths are relative to their area.
	 */
	public function report(
		array $state,
		string $client,
	): array
	{
		$areas = [];
		$files = 0;
		$dirs = 0;
		
		foreach($state['areas'] as $area => $stats)
		{
			$entry = ['root' => $this->clean((string)$stats['root'])];
			
			foreach($stats as $key => $value)
			{
				if($key !== 'root')
				{
					$entry[$key] = (int)$value;
				}
			}
			
			// the area's findings made and not listed (finding(), database()), beside scan.truncated's tiers; 0 when none were
			$entry['truncated'] ??= 0;
			$areas[$area] = $entry;
			$files += (int)$stats['files'];
			$dirs += (int)$stats['dirs'];
		}
		
		$verified = [];
		$unavailable = [];
		
		foreach((array)($state['checksums']['plugins'] ?? []) as $slug => $word)
		{
			if($word === 'verified')
			{
				$verified[] = (string)$slug;
			}
			elseif($word === 'unavailable')
			{
				$unavailable[] = (string)$slug;
			}
		}
		
		$core = (string)($state['checksums']['core'] ?? 'skipped');
		
		$report = [
			'v' => 1,
			'type' => 'files',
			'platform' => 'wordpress',
			'core' => Inventory::version((string)get_bloginfo('version')),
			'php' => Inventory::version(PHP_VERSION),
			'client' => $client,
			'scan' => [
				'id' => (string)$state['id'],
				'mode' => (string)$state['mode'],
				'started' => (int)$state['started'],
				'finished' => time(),
				'duration' => (int)$state['elapsed'],
				'chunks' => (int)$state['chunks'],
				'complete' => (bool)$state['done'],
				'files' => $files,
				'dirs' => $dirs,
				'unreadable' => (int)$state['unreadable'],
				'symlinks' => (int)$state['symlinks'],
				'skipped' => $state['skipped'],
				'counts' => $state['counts'],
				'truncated' => $state['truncated'],
				'bounded' => $this->boundedReport($state),
				'rechecked' => (int)($state['rechecked'] ?? 0),
			],
			'checksums' => [
				'core' => $core === 'pending' ? 'skipped' : $core,
				'core_locale' => (string)($state['checksums']['core_locale'] ?? ''),
				'plugins_verified' => $verified,
				'plugins_unavailable' => $unavailable,
			],
			'areas' => $areas,
			'findings' => $state['findings'],
			'posture' => $state['posture'] ?? [],
		];
		
		$release = $this->config->release();
		
		if($release !== '')
		{
			$report['release'] = $release;
		}
		
		$environment = $this->config->environment();
		
		if($environment !== '')
		{
			$report['environment'] = $environment;
		}
		
		return $report;
	}
	
	/**
	 * The bounded walks for the report: per walk the names read and the limit,
	 * the depth limit and the directories past it, where the pass started
	 * (`from`, '' = the top) and where the next one will (`next`, '' = the
	 * walk reached its end), paths relative to the walk's top
	 *
	 * @return array<string, array{read: int, limit: int, depth: int, deep: int, from: string, next: string}>
	 */
	protected function boundedReport(
		array $state,
	): array
	{
		$report = [];
		$next = $this->resumeNext($state);
		
		foreach((array)($state['bounded'] ?? []) as $bound => $walk)
		{
			if(is_array($walk))
			{
				$report[$bound] = [
					'read' => (int)$walk['read'],
					'limit' => (int)$walk['limit'],
					'depth' => (int)$walk['depth'],
					'deep' => (int)$walk['deep'],
					'from' => $this->clean((string)$walk['from']),
					'next' => $this->clean((string)($next[$bound] ?? '')),
				];
			}
		}
		
		return $report;
	}
	
	/**
	 * One directory: files inspected, subdirectories pushed. The root area
	 * walks its folders too, bounded, leaving wp-admin, wp-includes and
	 * wp-content's roots to their phases; the wp-content top level classifies
	 * each subdirectory instead of descending blindly. A plugin's top
	 * directory first makes sure its checksum list is known — or yields the
	 * chunk to fetch it next time. A bounded walk reads its directories in
	 * name order, counts the names it reads, stops at its limits and resumes
	 * where the last pass stopped (bounded()); what it finds is kept for the
	 * passes it will not reach (keep(), recheck()). Before a large file is
	 * judged it is named to the checkpoint (checkpoint()), and a file a dead
	 * chunk left named is passed over (advance()). Past the chunk's deadline
	 * the directory goes back on the walk with the names it has judged
	 */
	protected function visit(
		array &$state,
		string $area,
		string $dir,
		array $flags,
	): void
	{
		if($area === 'plugins' && dirname($dir) === $this->roots['plugins']
			&& $this->ensurePlugin($state, basename($dir)) === false)
		{
			$state['stack'][] = [$area, $dir, $flags];
			$state['yield'] = true;
			
			return;
		}
		
		$bound = (string)($flags['bound'] ?? '');
		$depth = (int)($flags['depth'] ?? 0);
		
		if($bound !== '' && $this->bounded($state, $bound)['stopped'])
		{
			return;
		}
		
		if($area === 'root' && $dir === $this->roots['root'])
		{
			$this->inspectConfig($state);
		}
		
		$entries = @scandir($dir, SCANDIR_SORT_NONE);
		
		if($entries === false)
		{
			$state['unreadable']++;
			
			return;
		}
		
		if($bound !== '')
		{
			// the order a resumed pass finds its place by, the same on every file system
			sort($entries, SORT_STRING);
		}
		
		// a directory walked again after a dead chunk: what that chunk judged is in the pass already
		$done = array_flip((array)($flags['done'] ?? []));
		
		if(isset($flags['done']) === false)
		{
			$state['areas'][$area]['dirs']++;
		}
		
		unset($flags['done']);
		$top = $area === 'content' && $dir === $this->roots['content'];
		$recursive = (bool)($flags['recursive'] ?? false);
		// the root's own top level is read whole, as it always was; below it, and in the cache, every name counts
		$counted = $bound === 'cache' || ($bound === 'root' && $depth > 0);
		// an asset folder is named for assets and holds one, and everything below it is in it
		$asset = $flags['asset'] ?? (in_array(strtolower(basename($dir)), self::ASSET_DIRS, true) && $this->holdsAssets($entries) ? $dir : null);
		$names = [];
		$newest = 0;
		$owners = [];
		
		$progress = false;
		
		foreach($entries as $name)
		{
			if($name === '.' || $name === '..')
			{
				continue;
			}
			
			// a chunk keeps to its deadline between files: the directory goes back on the walk with the names it has judged
			if($progress && microtime(true) >= $this->deadline)
			{
				$state['stack'][] = [$area, $dir, $flags + ['done' => array_keys($names)]];
				$state['yield'] = true;
				
				return;
			}
			
			$path = $dir . '/' . $name;
			$names[$name] = true;
			
			if(isset($done[$name]) || in_array($path, $state['poisoned'], true))
			{
				continue;
			}
			
			$progress = true;
			
			// read by the last pass when it stood before the place that pass stopped after
			$known = false;
			
			if($counted)
			{
				$walk = $this->bounded($state, $bound);
				
				if($walk['passed'] === false)
				{
					$known = true;
					$state['bounded'][$bound]['passed'] = $this->relative($path, $walk['top']) === $walk['from'];
				}
				elseif($walk['read'] >= $walk['limit'])
				{
					$this->boundReached($state, $bound, $area, $dir);
					
					break;
				}
				else
				{
					$state['bounded'][$bound]['read']++;
					$state['bounded'][$bound]['last'] = $this->relative($path, $walk['top']);
				}
			}
			
			$before = array_sum($state['counts']);
			
			if(@is_link($path))
			{
				if($known === false)
				{
					$this->inspectSymlink($state, $area, $path);
				}
				
				if($counted && array_sum($state['counts']) > $before)
				{
					$this->keep($state, 'link', $area, $path, []);
				}
				
				continue;
			}
			
			if(@is_dir($path))
			{
				if(in_array($name, self::SKIP_DIRS, true))
				{
					// the posture's line is the document root's own: a nested checkout is skipped and named
					if($area === 'root' && $depth === 0 && $name !== 'node_modules')
					{
						$state['vcs'][] = $name;
					}
					
					$this->skip($state, $area, $path);
					
					continue;
				}
				
				if($top)
				{
					$this->classifyContentDir($state, $path, $name);
					
					continue;
				}
				
				if($recursive === false || ($area === 'root' && $this->walkedElsewhere($path, $name, $depth)))
				{
					continue;
				}
				
				$child = $flags;
				
				if($name[0] === '.')
				{
					$child['hidden'] = true;
				}
				
				if($asset !== null)
				{
					$child['asset'] = $asset;
				}
				
				if($bound !== '')
				{
					$child['depth'] = $depth + 1;
					
					// past the walk's depth the directory is named, not read
					if($child['depth'] > $this->bounded($state, $bound)['depth'])
					{
						$state['bounded'][$bound]['deep']++;
						$this->skip($state, $area, $path);
						
						continue;
					}
				}
				
				$state['stack'][] = [$area, $path, $child];
				
				continue;
			}
			
			if($known)
			{
				continue;
			}
			
			$large = $this->checkpoint($area, $path);
			$stat = $this->inspect($state, $area, $path, $name, $flags + ['asset' => $asset]);
			
			if($large)
			{
				// judged: a chunk that dies from here on has no file to blame
				$this->mark(null);
			}
			
			// what a bounded walk finds is read again by a later pass that does not reach it
			if($counted && array_sum($state['counts']) > $before)
			{
				$this->keep($state, 'file', $area, $path, $flags + ['asset' => $asset]);
			}
			
			if($stat !== null)
			{
				$newest = max($newest, (int)$stat['mtime']);
				$owners[(int)$stat['uid']][] = $name;
			}
		}
		
		$this->missing($state, $area, $dir, $names);
		$this->dirChanged($state, $area, $dir, $newest, count($owners) > 0);
		
		// a second application's folders and a cache are written by the web server by design
		if($bound === '' || ($bound === 'root' && $depth === 0))
		{
			$this->ownerAnomaly($state, $area, $dir, $owners);
		}
	}
	
	/**
	 * Names an executable-shaped file larger than `checkpoint_bytes` to the
	 * checkpoint before it is judged — area, path and size, nothing of the
	 * pass, a small write — and says so; the caller clears the name once the
	 * file is judged (mark(null)). A chunk that dies on the file — out of
	 * memory, out of time — leaves the name with the runner, and the next
	 * chunk, resumed from the pass as the last chunk began it, names the file
	 * scan_crash and passes over it (advance(), visit()); a chunk that dies
	 * on a later file blames none
	 */
	protected function checkpoint(
		string $area,
		string $path,
	): bool
	{
		$size = $this->checkpoint !== null && preg_match(self::EXECUTABLE, basename($path)) === 1 ? @filesize($path) : false;
		
		if($size === false || $size <= $this->limit('checkpoint_bytes'))
		{
			return false;
		}
		
		$this->mark(['area' => $area, 'path' => $path, 'size' => $size]);
		
		return true;
	}
	
	/** hands the checkpoint what is about to be judged, null once it is */
	protected function mark(
		?array $judging,
	): void
	{
		if($this->checkpoint !== null)
		{
			($this->checkpoint)($judging);
		}
	}
	
	/**
	 * A file or link this pass found something in inside a bounded walk, kept
	 * by path with the flags it was judged with: the next pass reads it again
	 * when its walk does not reach it (recheck()). Twice the report's cap at
	 * most
	 */
	protected function keep(
		array &$state,
		string $kind,
		string $area,
		string $path,
		array $flags,
	): void
	{
		if(isset($state['recheck_next'][$path]) || count($state['recheck_next']) < 2 * self::MAX_FINDINGS)
		{
			$state['recheck_next'][$path] = [$kind, $area, $path, $flags];
		}
	}
	
	/**
	 * The files and links earlier passes found something in inside a bounded
	 * walk (resume `recheck`), read again before the database unless this
	 * pass found the same one already: a pass whose walk stops before them,
	 * or resumes past them, still reports every finding it knows — the
	 * console takes what a complete report leaves out for gone — and one gone
	 * or cleaned since drops out. Each read counts in `rechecked`, not in its
	 * area's files, and a file that still draws a finding is kept for the
	 * next pass. False when the chunk's deadline stops it, its place kept
	 */
	protected function recheck(
		array &$state,
	): bool
	{
		$entries = array_values((array)($state['resume']['recheck'] ?? []));
		$from = (int)($state['recheck_at'] ?? 0);
		
		for($at = $from; isset($entries[$at]); $at++)
		{
			if($at > $from && microtime(true) >= $this->deadline)
			{
				$state['recheck_at'] = $at;
				
				return false;
			}
			
			// the resume points are the stored pass's, read as data
			[$kind, $area, $path, $flags] = array_values((array)$entries[$at]) + ['', '', '', []];
			$area = (string)$area;
			$path = (string)$path;
			
			if(isset($state['areas'][$area]) === false || isset($state['recheck_next'][$path]) || in_array($path, $state['poisoned'], true))
			{
				continue;
			}
			
			$before = array_sum($state['counts']);
			$files = $state['areas'][$area]['files'];
			
			if($kind === 'link' && @is_link($path))
			{
				$this->inspectSymlink($state, $area, $path);
			}
			elseif($kind === 'file' && @is_link($path) === false && @is_file($path))
			{
				$large = $this->checkpoint($area, $path);
				$this->inspect($state, $area, $path, basename($path), (array)$flags);
				
				if($large)
				{
					$this->mark(null);
				}
			}
			else
			{
				continue;
			}
			
			$state['areas'][$area]['files'] = $files;
			$state['rechecked']++;
			
			if(array_sum($state['counts']) > $before)
			{
				$this->keep($state, (string)$kind, $area, $path, (array)$flags);
			}
		}
		
		$state['recheck_at'] = count($entries);
		
		return true;
	}
	
	/**
	 * A bounded walk's ledger for this pass, opened on first use: the names
	 * read and the limit, the depth limit and the directories past it, the
	 * place the last pass stopped after (`from`, relative to the walk's top)
	 * and whether this pass has passed it yet, the last name read, whether the
	 * walk stopped
	 *
	 * @return array{read: int, limit: int, depth: int, deep: int, from: string, passed: bool, last: string, stopped: bool, top: string}
	 */
	protected function bounded(
		array &$state,
		string $bound,
	): array
	{
		if(is_array($state['bounded'][$bound] ?? null) === false)
		{
			$from = (string)($state['resume'][$bound] ?? '');
			$state['bounded'][$bound] = [
				'read' => 0,
				'limit' => $this->limit($bound . '_entries'),
				'depth' => $this->limit($bound . '_depth'),
				'deep' => 0,
				'from' => $from,
				'passed' => $from === '',
				'last' => '',
				'stopped' => false,
				'top' => $bound === 'cache' ? $this->roots['content'] . '/cache' : $this->roots['root'],
			];
		}
		
		return $state['bounded'][$bound];
	}
	
	/**
	 * Where each bounded walk hands over to the next pass: the last name it
	 * read when it stopped, '' when it reached its end — or never found the
	 * place it was to resume after, the tree having changed — so the next
	 * pass starts over
	 *
	 * @return array<string, string>
	 */
	protected function resumeNext(
		array $state,
	): array
	{
		$next = (array)($state['resume_next'] ?? []);
		$next['recheck'] = array_values((array)($state['recheck_next'] ?? []));
		
		foreach((array)($state['bounded'] ?? []) as $bound => $walk)
		{
			if(is_array($walk))
			{
				$next[$bound] = $walk['stopped'] ? (string)$walk['last'] : '';
			}
		}
		
		return $next;
	}
	
	/**
	 * Whether a directory's names hold at least one asset (ASSET_FILES) —
	 * however many PHP files and listing stubs stand beside it
	 *
	 * @param list<string> $entries
	 */
	protected function holdsAssets(
		array $entries,
	): bool
	{
		foreach($entries as $name)
		{
			if(in_array(self::extension(strtolower($name)), self::ASSET_FILES, true))
			{
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * A folder of the document root another phase walks: core's two at its
	 * top, wp-content and the plugin, theme, upload and must-use roots
	 * wherever they stand
	 */
	protected function walkedElsewhere(
		string $path,
		string $name,
		int $depth,
	): bool
	{
		return ($depth === 0 && in_array($name, ['wp-admin', 'wp-includes'], true))
			|| in_array($path, [$this->roots['content'], $this->roots['plugins'], $this->roots['themes'],
				$this->roots['uploads'], $this->roots['mu']], true);
	}
	
	/**
	 * A bounded walk out of names: it stops for this pass, and the directory
	 * it stopped in is named first in scan.skipped — ahead of anything a
	 * full list would otherwise keep it from
	 */
	protected function boundReached(
		array &$state,
		string $bound,
		string $area,
		string $dir,
	): void
	{
		$state['bounded'][$bound]['stopped'] = true;
		
		array_unshift($state['skipped'], $area . ':' . $this->clean($this->relative($dir, (string)$state['areas'][$area]['root'])));
		$state['skipped'] = array_slice($state['skipped'], 0, self::MAX_SKIPPED);
	}
	
	/** a walk bound by name (ROOT_DEPTH, ROOT_ENTRIES, CACHE_DEPTH, CACHE_ENTRIES, CODE_BYTES, CHECKPOINT_BYTES) */
	protected function limit(
		string $name,
	): int
	{
		return match($name)
		{
			'root_depth' => self::ROOT_DEPTH,
			'root_entries' => self::ROOT_ENTRIES,
			'cache_depth' => self::CACHE_DEPTH,
			'cache_entries' => self::CACHE_ENTRIES,
			'code_bytes' => self::CODE_BYTES,
			'checkpoint_bytes' => self::CHECKPOINT_BYTES,
			default => PHP_INT_MAX,
		};
	}
	
	/**
	 * A wp-content subdirectory: the four areas walked on their own are
	 * skipped here, upgrade staging is skipped whole, the cache is walked
	 * bounded and judged by what caches write, a plugin-owned data directory
	 * is one finding and never descended, anything else is walked as content
	 * — where executable code is a stranger.
	 */
	protected function classifyContentDir(
		array &$state,
		string $path,
		string $name,
	): void
	{
		if(in_array($path, [$this->roots['plugins'], $this->roots['themes'],
			$this->roots['uploads'], $this->roots['mu']], true))
		{
			return;
		}
		
		if(in_array($name, self::CONTENT_SKIP, true))
		{
			$this->skip($state, 'content', $path);
			
			return;
		}
		
		if($name === 'cache')
		{
			$state['stack'][] = ['content', $path, ['recursive' => true, 'bound' => 'cache', 'depth' => 0]];
			
			return;
		}
		
		if(isset(self::WRITER_DIRS[$name]))
		{
			$owner = $this->installedOwner(self::WRITER_DIRS[$name]);
			
			$this->finding($state, 'content', $path,
				$owner !== null ? 'writer_dir' : 'writer_dir_orphan',
				$owner !== null ? self::TIER_INFO : self::TIER_HIGH,
				$owner !== null
					? 'owned by ' . $owner . ', not scanned'
					: 'owner not installed: ' . implode(', ', self::WRITER_DIRS[$name]));
			
			return;
		}
		
		$flags = ['recursive' => true];
		
		if($name[0] === '.')
		{
			$flags['hidden'] = true;
		}
		
		$state['stack'][] = ['content', $path, $flags];
	}
	
	/**
	 * One file: counted, then shape-checked — executable names by area,
	 * directive files by content, media names for a PHP opener. Answers the
	 * stat so the directory can date itself and compare owners.
	 *
	 * @return array{size: int, mtime: int, uid: int}|null
	 */
	protected function inspect(
		array &$state,
		string $area,
		string $path,
		string $name,
		array $flags,
	): ?array
	{
		$lower = strtolower($name);
		
		// a cache holds pages by the thousand: only a name that can run, or point PHP elsewhere, is worth a stat
		if(($flags['bound'] ?? '') === 'cache' && preg_match(self::EXECUTABLE, $name) !== 1
			&& in_array($lower, self::DIRECTIVE_FILES, true) === false && in_array(self::extension($lower), self::MEDIA, true) === false)
		{
			$state['areas'][$area]['files']++;
			
			return null;
		}
		
		$stat = @stat($path);
		$size = $stat !== false ? (int)$stat['size'] : 0;
		$mtime = $stat !== false ? (int)$stat['mtime'] : 0;
		$uid = $stat !== false ? (int)$stat['uid'] : 0;
		
		$state['areas'][$area]['files']++;
		$state['areas'][$area]['bytes'] += $size;
		
		$meta = ['size' => $size, 'mtime' => $mtime];
		$answer = $stat === false ? null : ['size' => $size, 'mtime' => $mtime, 'uid' => $uid];
		
		if(preg_match(self::EXECUTABLE, $name) === 1)
		{
			$state['areas'][$area]['executable']++;
			
			$this->inspectExecutable($state, $area, $path, $name, $size, $flags, $meta);
			
			return $answer;
		}
		
		if(in_array($lower, self::DIRECTIVE_FILES, true))
		{
			$this->inspectDirectives($state, $area, $path, $meta);
			
			return $answer;
		}
		
		$this->inspectPolyglot($state, $area, $path, $lower, $size, $meta);
		
		return $answer;
	}
	
	/**
	 * Executable-shaped, judged by where it stands. Hidden anywhere is a
	 * finding; under uploads anything but a listing stub is; at the root's
	 * top anything core did not ship is, deeper its shapes are; at the
	 * wp-content top level a drop-in is judged by its owner and anything else
	 * is a stranger; in plugins and core the checksum list is the judge where
	 * one exists, and where none does — themes, premium plugins — the shapes
	 * are (inspectPackage()).
	 */
	protected function inspectExecutable(
		array &$state,
		string $area,
		string $path,
		string $name,
		int $size,
		array $flags,
		array $meta,
	): void
	{
		if(($flags['hidden'] ?? false) === true || $name[0] === '.')
		{
			// a dotfile wordpress.org's list ships with the plugin is the plugin's, whatever it is named
			if($area === 'plugins' && $this->listedInPlugin($state, $path, $meta))
			{
				return;
			}
			
			if(preg_match(self::HIDDEN_TOOLING, $name) !== 1)
			{
				$this->finding($state, $area, $path, 'hidden_php', self::TIER_HIGH, '', $meta);
			}
			
			return;
		}
		
		switch($area)
		{
			case 'uploads':
				if($this->isStub($path, $size) === false)
				{
					$this->inspectUploadsPhp($state, $path, $size, $meta);
				}
				
				return;
			
			case 'root':
				if(dirname($path) !== $this->roots['root'])
				{
					// a folder of the document root: a second application's code is no finding for being code
					$this->inspectPackage($state, $area, $path, $name, $size, $meta, $this->roots['root'], $flags['asset'] ?? null);
					
					return;
				}
				
				if($name === 'wp-config.php')
				{
					// read whole as the file WordPress loads (inspectConfig())
					return;
				}
				
				if(in_array($name, Sender::CORE_ROOT_FILES, true))
				{
					// compared when listed; wp-config.php is core's own root file
					// the list never carries, and nothing else can stand here
					// without being root_php already
					$this->verify($state, $area, $path, $name, $meta, 'core', null, false);
					
					return;
				}
				
				$owner = isset(self::ROOT_OWNERS[$name])
					? $this->installedOwner(self::ROOT_OWNERS[$name])
					: null;
				
				$this->finding($state, $area, $path,
					$owner !== null ? 'root_php_owned' : 'root_php',
					$owner !== null ? self::TIER_INFO : self::TIER_URGENT,
					$owner !== null ? 'owned by ' . $owner : '', $meta);
				
				return;
			
			case 'content':
				$this->inspectContentExecutable($state, $path, $name, $size, $flags, $meta);
				
				return;
			
			case 'core':
				$this->verify($state, $area, $path, $this->relative($path, $this->roots['root']), $meta, 'core');
				
				return;
			
			case 'plugins':
				$this->verifyInside($state, $path, $name, $size, $meta, $flags['asset'] ?? null);
				
				return;
				
			case 'themes':
				// no list vouches for a theme: wp.org has no theme checksums, and
				// the core list's bundled themes are the VERSIONS shipped with that
				// core release, which the theme updater has long since replaced
				$this->inspectPackage($state, $area, $path, $name, $size, $meta, $this->packageBase($path, $this->roots['themes']),
					$flags['asset'] ?? null);
				
				return;
			
			default:
				return;
		}
	}
	
	protected function inspectContentExecutable(
		array &$state,
		string $path,
		string $name,
		int $size,
		array $flags,
		array $meta,
	): void
	{
		$parent = dirname($path);
		
		if(($flags['bound'] ?? '') === 'cache')
		{
			$this->inspectCacheExecutable($state, $path, $size, $meta);
			
			return;
		}
		
		if(($flags['mu'] ?? false) === true)
		{
			// only the top level of mu-plugins is loaded and listed; deeper
			// files are its includes, and no list vouches for either
			if($parent === $this->roots['mu'])
			{
				if($this->ownMuPlugin($state, $path, $name, $size, $meta))
				{
					return;
				}
				
				$this->finding($state, 'content', $path, 'mu_plugin', self::TIER_INFO, '', $meta);
			}
			
			$this->inspectPackage($state, 'content', $path, $name, $size, $meta, $this->packageBase($path, $this->roots['mu']),
				$flags['asset'] ?? null);
			
			return;
		}
		
		$store = $this->storePaths();
		
		if(in_array($parent, [$this->normalize($store['store']), $this->normalize($store['stub']), $this->normalize($store['legacy'])], true))
		{
			$this->inspectStoreFile($state, $path, $name, $parent, $size, $meta);
			
			return;
		}
		
		if($parent !== $this->roots['content'])
		{
			// core's PHP translation files live under languages/ and its
			// plugins/ and themes/ subdirectories, named for their text domain
			// and locale, and return literals; anything else executable there,
			// or a translation's name over code, is a stranger
			$translation = str_starts_with($path, $this->roots['content'] . '/languages/')
				&& preg_match(self::TRANSLATION, $name) === 1
				&& $this->translationData($path, $size);
			
			if($translation === false && $this->isStub($path, $size) === false)
			{
				$this->stranger($state, 'content', $path, $size, 'content_php', self::TIER_HIGH, $meta);
			}
			
			return;
		}
		
		if($name === 'index.php' && $this->isStub($path, $size))
		{
			return;
		}
		
		if(isset(self::CONTENT_OWNERS[$name]))
		{
			$owner = $this->installedOwner(self::CONTENT_OWNERS[$name]);
			
			if($owner !== null)
			{
				$this->finding($state, 'content', $path, 'dropin', self::TIER_INFO,
					'owned by ' . $owner, $meta);
				// an owner's name is no proof of the code under it, and a drop-in runs on every request
				$this->inspectCode($state, 'content', $path, $meta);
				
				return;
			}
			
			// managed hosts drop their own object-cache.php with a vendor
			// header and no plugin behind it; a header is not proof, but a
			// drop-in WITHOUT one and without an owner is the stranger
			$this->finding($state, 'content', $path,
				$this->looksVendored($path) ? 'dropin' : 'dropin_orphan',
				$this->looksVendored($path) ? self::TIER_INFO : self::TIER_HIGH,
				'no installed owner', $meta);
			$this->inspectCode($state, 'content', $path, $meta);
			
			return;
		}
		
		if(in_array($name, Sender::CONTENT_DROPINS, true))
		{
			// install.php runs core's installer hooks and has no business on
			// a live site; the rest (maintenance, error pages, sunrise) are
			// hand-written by design and only listed
			$this->finding($state, 'content', $path, 'dropin',
				$name === 'install.php' ? self::TIER_HIGH : self::TIER_INFO,
				$name === 'install.php' ? 'install drop-in on a live site' : '', $meta);
			$this->inspectCode($state, 'content', $path, $meta);
				
			return;
		}
		
		$this->stranger($state, 'content', $path, $size, 'content_php', self::TIER_HIGH, $meta);
	}
	
	/**
	 * PHP under uploads that is no stub: listed when it stops before any code
	 * runs, when it is a known writer's data file with its owner installed, or
	 * a template its owner's engine compiled there (UPLOAD_COMPILERS) that
	 * declares and runs nothing when requested, read for the code shapes all
	 * the same; URGENT otherwise
	 */
	protected function inspectUploadsPhp(
		array &$state,
		string $path,
		int $size,
		array $meta,
	): void
	{
		$compiler = $this->uploadCompiler($path);
		
		if($compiler !== null && $size <= $this->limit('code_bytes'))
		{
			$source = (string)$this->head($path, $this->limit('code_bytes'));
			
			if(preg_match(self::COMPILED, $source) === 1 && self::runsOnRequest($source) === false)
			{
				if($this->inspectCode($state, 'uploads', $path, $meta, $source) === false)
				{
					$this->finding($state, 'uploads', $path, 'uploads_php_owned', self::TIER_INFO,
						'owned by ' . $compiler . ', a compiled template', $meta);
				}
				
				return;
			}
		}
		
		$top = explode('/', $this->relative($path, $this->roots['uploads']), 2)[0];
		$owner = isset(self::UPLOAD_WRITERS[$top]) ? $this->installedOwner(self::UPLOAD_WRITERS[$top]) : null;
		
		if($owner !== null && $size <= self::DATA_BYTES && self::dataOnly((string)$this->head($path, self::DATA_BYTES)))
		{
			$this->finding($state, 'uploads', $path, 'uploads_php_owned', self::TIER_INFO,
				'owned by ' . $owner . ', data only', $meta);
				
			return;
		}
		
		$this->stranger($state, 'uploads', $path, $size, 'uploads_php', self::TIER_URGENT, $meta);
	}
	
	/**
	 * PHP where none belongs: the stranger's finding, or inert_php INFO when the
	 * file stops before any code runs — the data files W3 Total Cache and AIOS
	 * keep under PHP names behind an exit or __halt_compiler() — or, in
	 * wp-content, holds data alone: the guarded configs Breeze, WP-Optimize
	 * and Cache Enabler keep beside the cache. Under uploads data is still
	 * PHP where none belongs, unless its writer is known (inspectUploadsPhp())
	 */
	protected function stranger(
		array &$state,
		string $area,
		string $path,
		int $size,
		string $detector,
		string $tier,
		array $meta,
	): void
	{
		$head = $size <= self::DATA_BYTES ? (string)$this->head($path, self::DATA_BYTES) : '';
		
		if($head !== '' && self::inert($head))
		{
			$this->finding($state, $area, $path, 'inert_php', self::TIER_INFO, 'stops before any code runs', $meta);
			
			return;
		}
		
		if($head !== '' && $area === 'content' && self::dataOnly($head))
		{
			$this->finding($state, $area, $path, 'inert_php', self::TIER_INFO, 'data only, runs no code', $meta);
			
			return;
		}
		
		$this->finding($state, $area, $path, $detector, $tier, '', $meta);
	}
	
	/**
	 * The plugin's own store as Adapter::storePaths() names it, read once per
	 * request
	 *
	 * @return array{store: string, stub: string, legacy: string}
	 */
	protected function storePaths(): array
	{
		return $this->store ??= Adapter::storePaths();
	}
	
	/**
	 * A PHP file in one of the plugin's store directories, judged by what the
	 * plugin writes there: its prepend stub byte for byte (PHP may run it on
	 * every request), the data files by their exit guard and JSON body, a
	 * listing stub as anywhere. Any other PHP there is a stranger
	 */
	protected function inspectStoreFile(
		array &$state,
		string $path,
		string $name,
		string $parent,
		int $size,
		array $meta,
	): void
	{
		$store = $this->storePaths()['store'];
		$content = $size > self::STORE_BYTES ? null : $this->head($path, self::STORE_BYTES);
		
		// the stub by the names it has in this directory: a configuration may still name an earlier one
		$names = $parent === $this->normalize($this->storePaths()['legacy']) ? [Prepend::LEGACY_STUB] : Prepend::STUB_NAMES;
		if(in_array($name, $names, true) && $content !== null)
		{
			// beside the data the stub runs against __DIR__; elsewhere it names the data's directory
			$expression = $parent === $this->normalize($store) ? '__DIR__' : var_export($store, true);
			
			if($content === Prepend::stubText(Prepend::source(), $expression))
			{
				$state['areas']['content']['verified']++;
				
				return;
			}
			
			if(str_contains($content, Prepend::STUB_MARKER))
			{
				$this->finding($state, 'content', $path, 'store_modified', self::TIER_URGENT,
					'the plugin\'s prepend stub is not what it writes', $meta);
					
				return;
			}
		}
		elseif(in_array($name, [Prepend::CONSENT, Prepend::QUEUE, Prepend::ENTRIES, Prepend::SEEN], true))
		{
			if($content !== null && str_starts_with($content, Prepend::GUARD) && json_validate(substr($content, strlen(Prepend::GUARD))))
			{
				$state['areas']['content']['verified']++;
				
				return;
			}
			
			$this->finding($state, 'content', $path, 'store_modified', self::TIER_HIGH,
				'the plugin\'s data file lacks its exit guard or JSON body', $meta);
				
			return;
		}
		elseif($name === 'index.php' && $this->isStub($path, $size))
		{
			return;
		}
		
		$this->finding($state, 'content', $path, 'content_php', self::TIER_HIGH, '', $meta);
	}
	
	/**
	 * The plugin's early stage in mu-plugins: true when judged here — silent
	 * when it is byte for byte what ensureMuPlugin() writes, URGENT when it
	 * carries the marker and differs, since it runs on every request — false
	 * for any other file, which is listed like every mu-plugin
	 */
	protected function ownMuPlugin(
		array &$state,
		string $path,
		string $name,
		int $size,
		array $meta,
	): bool
	{
		if($name !== Prepend::MU_PLUGIN || $size > self::STORE_BYTES)
		{
			return false;
		}
		
		$content = $this->head($path, self::STORE_BYTES);
		
		if($content === null || str_contains($content, Prepend::MU_MARKER) === false)
		{
			return false;
		}
		
		if($content === Prepend::muPluginText(Prepend::source(), var_export($this->storePaths()['store'], true)))
		{
			$state['areas']['content']['verified']++;
			
			return true;
		}
		
		$this->finding($state, 'content', $path, 'store_modified', self::TIER_URGENT,
			'the plugin\'s mu-plugin is not what it writes', $meta);
			
		return true;
	}
	
	/**
	 * A file under a root wordpress.org vouches for, against a list: listed
	 * and equal → verified; listed and different → MODIFIED; not listed →
	 * FOREIGN — the two verdicts with authority behind them. With no list
	 * this pass, nothing is said.
	 *
	 * @param string $key the list's own path for the file
	 * @param string $kind core|plugin|theme — the detector family and its tier
	 * @param array<string, string|list<string>>|null $list the plugin's own list; null = core's
	 */
	protected function verify(
		array &$state,
		string $area,
		string $path,
		string $key,
		array $meta,
		string $kind,
		?array $list = null,
		bool $foreignIsFinding = true,
	): void
	{
		$list ??= $this->coreList($state);
		
		if(is_array($list) === false)
		{
			// no list this pass: core's own files are still read for the shapes no release ships
			if($kind === 'core')
			{
				$this->inspectCode($state, $area, $path, $meta);
			}
			
			return;
		}
		
		$tier = $kind === 'core' ? self::TIER_URGENT : self::TIER_HIGH;
		
		if(isset($list[$key]) === false)
		{
			if($foreignIsFinding === false)
			{
				return;
			}
			
			$state['areas'][$area]['foreign']++;
			
			$this->finding($state, $area, $path, $kind . '_foreign', $tier,
				'not in the wordpress.org list for this version', $meta);
			
			return;
		}
		
		$md5 = @md5_file($path);
		
		if($md5 === false)
		{
			return;
		}
		
		if(Checksums::matches($list, $key, $md5))
		{
			$state['areas'][$area]['verified']++;
			
			return;
		}
		
		$state['areas'][$area]['modified']++;
		
		$this->finding($state, $area, $path, $kind . '_modified', $tier,
			'md5 differs from the wordpress.org list for this version', $meta);
	}
	
	/**
	 * A file inside a plugin directory, against the plugin's own wp.org list
	 * where one exists. A single-file plugin (hello.php) has no directory to
	 * key a list by and updates apart from core, and a premium or custom
	 * plugin has no list: both are read for the shapes no list vouches for
	 * (inspectPackage()).
	 */
	protected function verifyInside(
		array &$state,
		string $path,
		string $name,
		int $size,
		array $meta,
		?string $asset = null,
	): void
	{
		$relative = $this->relative($path, $this->roots['plugins']);
		$slash = strpos($relative, '/');
		
		if($slash === false)
		{
			$this->inspectPackage($state, 'plugins', $path, $name, $size, $meta, $this->roots['plugins'], $asset);
			
			return;
		}
		
		$slug = substr($relative, 0, $slash);
		$list = ($state['checksums']['plugins'][$slug] ?? '') === 'verified'
			? $this->sums?->plugin($slug, (string)($state['versions'][$slug] ?? ''))
			: null;
		
		if($list === null)
		{
			$this->inspectPackage($state, 'plugins', $path, $name, $size, $meta, $this->roots['plugins'] . '/' . $slug, $asset);
			
			return;
		}
		
		$this->verify($state, 'plugins', $path, substr($relative, $slash + 1), $meta, 'plugin', $list);
	}
	
	/** whether a file is one the plugin's wordpress.org list names, byte for byte: counted verified when it is */
	protected function listedInPlugin(
		array &$state,
		string $path,
		array $meta,
	): bool
	{
		$relative = $this->relative($path, $this->roots['plugins']);
		$slash = strpos($relative, '/');
		$slug = $slash === false ? '' : substr($relative, 0, $slash);
		$list = $slug !== '' && ($state['checksums']['plugins'][$slug] ?? '') === 'verified'
			? $this->sums?->plugin($slug, (string)($state['versions'][$slug] ?? ''))
			: null;
		$md5 = $list === null ? false : @md5_file($path);
		
		if($md5 === false || Checksums::matches((array)$list, substr($relative, $slash + 1), $md5) === false)
		{
			return false;
		}
		
		$state['areas']['plugins']['verified']++;
		
		return true;
	}
	
	/**
	 * A PHP file no list vouches for — a theme's, a plugin's wordpress.org
	 * never had, a must-use plugin's, a folder of the document root's — held
	 * against what a backdoor looks like and honest code does not, one
	 * finding at most: its code shapes (codeVerdict()); code where its
	 * package keeps assets or translations (asset_php); a core entry file's
	 * name where no WordPress stands (mimic_core: the wp-login.php in a
	 * theme). A stub, an exit first and literal data run no code. An `.inc`
	 * is not judged: it runs only when a PHP file includes it, and vendored
	 * code sniffers ship their bad-code fixtures under that extension
	 *
	 * @param string $base the package's own directory, below which an asset folder counts
	 * @param ?string $asset the asset folder the file stands in, at any depth (visit())
	 */
	protected function inspectPackage(
		array &$state,
		string $area,
		string $path,
		string $name,
		int $size,
		array $meta,
		string $base,
		?string $asset = null,
	): void
	{
		$lower = strtolower($name);
		
		if(self::extension($lower) === 'inc' || $this->isStub($path, $size))
		{
			return;
		}
		
		$source = (string)$this->head($path, $this->limit('code_bytes'));
		
		if($this->inspectCode($state, $area, $path, $meta, $source))
		{
			return;
		}
		
		// the asset folder counts below the package's own directory, never as it
		$folder = $asset !== null && str_starts_with($asset, $base . '/') ? basename($asset) : null;
		
		// past code_bytes the file cannot be read whole, and a guess is no finding
		if($folder !== null && $size <= $this->limit('code_bytes') && self::runsOnRequest($source))
		{
			$this->finding($state, $area, $path, 'asset_php', self::TIER_HIGH,
				'code in ' . $folder . '/, among its assets', $meta);
			
			return;
		}
		
		// core's own entry files, by their wp- names: xmlrpc.php names a class file in many a library
		if(str_starts_with($lower, 'wp-') && in_array($lower, Sender::CORE_ROOT_FILES, true) && $this->wordpressRoot(dirname($path)) === false)
		{
			$this->finding($state, $area, $path, 'mimic_core', self::TIER_HIGH,
				'named like core\'s ' . $lower . ' where no WordPress stands', $meta);
		}
	}
	
	/**
	 * A file no list vouches for, read for its code shapes alone
	 * (codeVerdict()): true when it drew a finding. A file larger than
	 * `code_bytes` is read that far and listed as oversize_php, since the
	 * rest goes unjudged
	 */
	protected function inspectCode(
		array &$state,
		string $area,
		string $path,
		array $meta,
		?string $source = null,
	): bool
	{
		$size = (int)($meta['size'] ?? 0);
		
		if($size > $this->limit('code_bytes'))
		{
			$this->finding($state, $area, $path, 'oversize_php', self::TIER_INFO,
				'read the first ' . $this->limit('code_bytes') . ' of ' . $size . ' bytes; the rest is not judged', $meta);
		}
		
		$verdict = self::codeVerdict($source ?? (string)$this->head($path, $this->limit('code_bytes')), $this->places());
		
		if($verdict === null)
		{
			return false;
		}
		
		[$detector, $tier, $detail, $line] = $verdict;
		
		$this->finding($state, $area, $path, $detector, $tier, $detail, $meta + ['line' => $line]);
		
		return true;
	}
	
	/**
	 * PHP under wp-content/cache, judged by what writes there. Caching
	 * plugins write data under PHP names: an exit or a die first (WP Super
	 * Cache's pages, metas and debug log, LiteSpeed's guards), the same
	 * behind W3 Total Cache's four-byte expiry, no PHP at all (its JSON blog
	 * map), returned literals (Breeze); template engines write compiled
	 * templates (Twig, Blade, Smarty), a few plugins code by design
	 * (CACHE_WRITERS). Code shapes are reported wherever they stand, any
	 * other code is cache_php
	 */
	protected function inspectCacheExecutable(
		array &$state,
		string $path,
		int $size,
		array $meta,
	): void
	{
		if($this->isStub($path, $size))
		{
			return;
		}
		
		$first = (string)$this->head($path, self::DIRECTIVE_BYTES);
		
		// the first statement decides, after any header comment: a cached page is read no further than its guard
		if(self::inert($first) || (strlen($first) > 4 && str_starts_with(substr($first, 4), self::W3TC_GUARD)))
		{
			return;
		}
		
		$source = $size > self::DIRECTIVE_BYTES ? (string)$this->head($path, $this->limit('code_bytes')) : $first;
		
		// no opener at all is output, never code; literals returned run nothing
		if($size <= $this->limit('code_bytes') && (str_contains($source, '<?') === false || self::dataOnly($source)))
		{
			return;
		}
		
		if($this->inspectCode($state, 'content', $path, $meta, $source)
			|| preg_match(self::COMPILED, $source) === 1 || $this->cacheWriter($path) !== null)
		{
			return;
		}
		
		$this->finding($state, 'content', $path, 'cache_php', self::TIER_HIGH, 'code where caches keep data', $meta);
	}
	
	/** the installed plugin whose engine compiles into the uploads folder that holds $path (UPLOAD_COMPILERS), or null */
	protected function uploadCompiler(
		string $path,
	): ?string
	{
		$relative = $this->relative($path, $this->roots['uploads']);
		
		foreach(self::UPLOAD_COMPILERS as $folder => $owners)
		{
			if(str_starts_with($relative, $folder . '/'))
			{
				return $this->installedOwner($owners);
			}
		}
		
		return null;
	}
	
	/** the installed plugin whose cache directory holds $path by design (CACHE_WRITERS), or null */
	protected function cacheWriter(
		string $path,
	): ?string
	{
		$top = explode('/', $this->relative($path, $this->roots['content'] . '/cache'), 2)[0];
		
		return isset(self::CACHE_WRITERS[$top]) ? $this->installedOwner(self::CACHE_WRITERS[$top]) : null;
	}
	
	/**
	 * Whether a translation file holds what WordPress writes there: literals
	 * returned. One past `code_bytes` is held to its code shapes alone
	 */
	protected function translationData(
		string $path,
		int $size,
	): bool
	{
		$source = (string)$this->head($path, $this->limit('code_bytes'));
		
		return $size <= $this->limit('code_bytes') ? self::dataOnly($source) : self::codeVerdict($source, $this->places()) === null;
	}
	
	/**
	 * The wp-config.php WordPress loads, read whole for code an intruder adds
	 * to it: the file every request runs before any plugin, and one no list
	 * can vouch for. Once per pass, when the walk opens the root
	 */
	protected function inspectConfig(
		array &$state,
	): void
	{
		if(($state['config_read'] ?? false) === true)
		{
			return;
		}
		
		$state['config_read'] = true;
		$config = $this->loadedConfig($this->roots['root']);
		
		if($config === null)
		{
			return;
		}
		
		$stat = @stat($config);
		$meta = $stat === false ? [] : ['size' => (int)$stat['size'], 'mtime' => (int)$stat['mtime']];
		// nothing under uploads belongs in the file every request runs first, however it is named
		$verdict = self::codeVerdict((string)$this->head($config, $this->limit('code_bytes')), ['strict' => true] + $this->places());
		
		if($verdict !== null)
		{
			[$detector, $tier, $detail, $line] = $verdict;
			
			$this->finding($state, 'root', $config, $detector, $tier, $detail, $meta + ['line' => $line]);
		}
	}
	
	/**
	 * The wp-config.php wp-load.php requires: ABSPATH's own, else the one a
	 * level up — unless a wp-settings.php beside it there says it belongs to
	 * another install, which WordPress then never loads
	 */
	protected function loadedConfig(
		string $root,
	): ?string
	{
		if(is_file($root . '/wp-config.php'))
		{
			return $root . '/wp-config.php';
		}
		
		$parent = $this->normalize(dirname($root));
		
		return is_file($parent . '/wp-config.php') && is_file($parent . '/wp-settings.php') === false
			? $parent . '/wp-config.php'
			: null;
	}
	
	/** the first folder below a root a file stands in — its package — or the root itself for a file at its top */
	protected function packageBase(
		string $path,
		string $root,
	): string
	{
		$relative = $this->relative($path, $root);
		$slash = strpos($relative, '/');
		
		return $slash === false || $relative === $path ? $root : $root . '/' . substr($relative, 0, $slash);
	}
	
	/** whether a directory is a WordPress install's root: its wp-settings.php and wp-includes/version.php, files, beside it */
	protected function wordpressRoot(
		string $dir,
	): bool
	{
		return is_file($dir . '/wp-settings.php') && is_file($dir . '/wp-includes/version.php');
	}
	
	/**
	 * Where an include reaches what no install keeps its code in: the uploads
	 * root and the temp directories, lowercase with forward slashes, a prefix
	 * too short to mean anything left out; and the uploads folders whose
	 * writer is installed (UPLOAD_WRITERS), whose PHP that plugin includes
	 *
	 * @return array{uploads: string, temp: list<string>, owned: list<string>}
	 */
	protected function places(): array
	{
		if($this->places !== null)
		{
			return $this->places;
		}
		
		$temp = [];
		
		foreach([sys_get_temp_dir(), (string)ini_get('upload_tmp_dir')] as $dir)
		{
			$dir = strtolower($this->normalize($dir));
			
			if(strlen($dir) > 4)
			{
				$temp[] = $dir;
			}
		}
		
		$owned = [];
		
		foreach(self::UPLOAD_WRITERS as $folder => $owners)
		{
			if($this->installedOwner($owners) !== null)
			{
				$owned[] = strtolower($folder);
			}
		}
		
		return $this->places = ['uploads' => strtolower($this->roots['uploads'] ?? ''), 'temp' => $temp, 'owned' => $owned];
	}
	
	/**
	 * The listed files a directory should hold but does not — counted per
	 * area, never listed: hosts strip readmes, and a missing file is not an
	 * intrusion. Only directories a list speaks for.
	 *
	 * @param array<string, true> $names the entries seen in the directory
	 */
	protected function missing(
		array &$state,
		string $area,
		string $dir,
		array $names,
	): void
	{
		$list = null;
		$directory = '';
		
		// the core list speaks for the root's top level alone, never for a folder in it
		if($area === 'core' || ($area === 'root' && $dir === $this->roots['root']))
		{
			$list = $this->coreList($state);
			$directory = $area === 'root' ? '' : $this->relative($dir, $this->roots['root']);
		}
		elseif($area === 'plugins')
		{
			$relative = $this->relative($dir, $this->roots['plugins']);
			$slug = explode('/', $relative, 2)[0];
			
			if($relative !== $slug || $dir !== $this->roots['plugins'])
			{
				if(($state['checksums']['plugins'][$slug] ?? '') === 'verified')
				{
					$list = $this->sums?->plugin($slug, (string)($state['versions'][$slug] ?? ''));
					$directory = $relative === $slug ? '' : substr($relative, strlen($slug) + 1);
				}
			}
		}
		
		if(is_array($list) === false)
		{
			return;
		}
		
		foreach(Checksums::expected($list, $directory) as $name)
		{
			if(isset($names[$name]) === false)
			{
				$state['areas'][$area]['missing']++;
			}
		}
	}
	
	/**
	 * A directory changed after its newest file: something was deleted
	 * or renamed here recently (the shell the attacker removed, dated).
	 * Uploads and the root itself only (an application in a folder of the
	 * root rewrites its own), the last thirty days only, info.
	 */
	protected function dirChanged(
		array &$state,
		string $area,
		string $dir,
		int $newest,
		bool $hasFiles,
	): void
	{
		if(($area !== 'uploads' && ($area !== 'root' || $dir !== $this->roots['root'])) || $hasFiles === false
			|| $state['polish']['dir_changed'] >= self::MAX_PER_POLISH)
		{
			return;
		}
		
		$stat = @stat($dir);
		$changed = $stat === false ? 0 : (int)$stat['mtime'];
		
		if($changed > $newest + 60 && $changed > time() - self::RECENT_CHANGE)
		{
			$state['polish']['dir_changed']++;
			
			$this->finding($state, $area, $dir === (string)$state['areas'][$area]['root'] ? $dir . '/.' : $dir, 'dir_changed', self::TIER_INFO,
				'directory changed ' . gmdate('Y-m-d H:i', $changed) . ', newest file ' . gmdate('Y-m-d H:i', $newest)
				. ' — something was removed or renamed here', ['mtime' => $changed]);
		}
	}
	
	/**
	 * A file whose owner differs from its directory's siblings: the
	 * web server wrote among the deploy user's files. Silent on Windows and
	 * on shared hosting, where everything is one uid.
	 *
	 * @param array<int, list<string>> $owners uid → file names
	 */
	protected function ownerAnomaly(
		array &$state,
		string $area,
		string $dir,
		array $owners,
	): void
	{
		if(DIRECTORY_SEPARATOR === '\\' || count($owners) < 2
			|| $state['polish']['owner_anomaly'] >= self::MAX_PER_POLISH)
		{
			return;
		}
		
		$total = 0;
		$majority = 0;
		$majorityUid = 0;
		
		foreach($owners as $uid => $names)
		{
			$total += count($names);
			
			if(count($names) > $majority)
			{
				$majority = count($names);
				$majorityUid = $uid;
			}
		}
		
		if($total < 3)
		{
			return;
		}
		
		foreach($owners as $uid => $names)
		{
			if($uid === $majorityUid)
			{
				continue;
			}
			
			foreach($names as $name)
			{
				if($state['polish']['owner_anomaly'] >= self::MAX_PER_POLISH)
				{
					return;
				}
				
				$state['polish']['owner_anomaly']++;
				
				$this->finding($state, $area, $dir . '/' . $name, 'owner_anomaly', self::TIER_HIGH,
					'owned by uid ' . $uid . ' among files owned by uid ' . $majorityUid);
			}
		}
	}
	
	/**
	 * A symlink is counted, never followed; one that leaves the site
	 * (another vhost's tree, /etc) is the symlink attack and a finding
	 */
	protected function inspectSymlink(
		array &$state,
		string $area,
		string $path,
	): void
	{
		$state['symlinks']++;
		
		$target = @readlink($path);
		
		if($target === false || $state['polish']['symlink_outside'] >= self::MAX_PER_POLISH)
		{
			return;
		}
		
		$absolute = str_starts_with($target, '/') || preg_match('~^[A-Za-z]:[\\\\/]~', $target) === 1
			? $target
			: dirname($path) . '/' . $target;
		$resolved = @realpath($absolute);
		$resolved = $this->normalize($resolved === false ? $absolute : $resolved);
		
		foreach(['root', 'content', 'uploads'] as $root)
		{
			$prefix = $this->roots[$root];
			
			if($prefix !== '' && ($resolved === $prefix || str_starts_with($resolved, $prefix . '/')))
			{
				return;
			}
		}
		
		$state['polish']['symlink_outside']++;
		
		$this->finding($state, $area, $path, 'symlink_outside', self::TIER_HIGH,
			'symlink leaving the site → ' . $resolved);
	}
	
	/**
	 * A media-shaped name whose first block carries a PHP opener — the
	 * favicon shell, the `.jpg` behind an AddHandler
	 */
	protected function inspectPolyglot(
		array &$state,
		string $area,
		string $path,
		string $lower,
		int $size,
		array $meta,
	): void
	{
		if($size < self::MIN_POLYGLOT_SIZE)
		{
			return;
		}
		
		$extension = self::extension($lower);
		
		if(in_array($extension, self::MEDIA, true) === false
			&& ($area !== 'uploads' || in_array($extension, self::MEDIA_TEXT, true) === false))
		{
			return;
		}
		
		$state['areas'][$area]['probed']++;
		
		$head = $this->head($path, self::HEAD_BYTES);
		
		if($head !== null && self::opensPhp($head))
		{
			$this->finding($state, $area, $path, 'polyglot', self::TIER_URGENT,
				'PHP opener in a .' . $extension . ' file', $meta);
		}
	}
	
	/**
	 * .htaccess / .user.ini / php.ini: the directives that make a foreign
	 * file execute (a prepend, an image handler, engine on under uploads)
	 * or send visitors elsewhere. The finding names the directive, the file
	 * and the line — never the line's text.
	 */
	protected function inspectDirectives(
		array &$state,
		string $area,
		string $path,
		array $meta,
	): void
	{
		$content = @file_get_contents($path, false, null, 0, self::DIRECTIVE_BYTES);
		
		if(is_string($content) === false)
		{
			return;
		}
		
		$uploads = $area === 'uploads';
		
		if($uploads && dirname($path) === $this->roots['uploads'] && basename($path) === '.htaccess')
		{
			$state['uploads_htaccess'] = true;
			$state['uploads_php_denied'] = $this->deniesPhp($content);
		}
		
		$found = 0;
		
		foreach(preg_split('~\r\n|\r|\n~', $content) ?: [] as $index => $line)
		{
			$line = trim($line);
			
			if($line === '' || $line[0] === '#' || $line[0] === ';')
			{
				continue;
			}
			
			$verdict = $this->judgeDirective($line, $uploads);
			
			if($verdict === null)
			{
				continue;
			}
			
			[$detector, $tier, $detail] = $verdict;
			
			$this->finding($state, $area, $path, $detector, $tier, $detail,
				$meta + ['line' => $index + 1]);
			
			if(++$found >= self::MAX_DIRECTIVES_PER_FILE)
			{
				return;
			}
		}
	}
	
	/**
	 * One directive line → [detector, tier, detail] or null when harmless
	 *
	 * @return array{0: string, 1: string, 2: string}|null
	 */
	protected function judgeDirective(
		string $line,
		bool $uploads,
	): ?array
	{
		if(preg_match('~auto_(prepend|append)_file\s*(?:=|\s)\s*["\']?([^"\'\s;]*)~i', $line, $match) === 1)
		{
			$target = $match[2];
			
			if($target === '' || strtolower($target) === 'none')
			{
				return null;
			}
			
			$owner = $this->ownerOfPath($target);
			
			return $owner !== null
				? ['directive_owned', self::TIER_INFO, 'auto_' . strtolower($match[1]) . '_file owned by ' . $owner]
				: ['directive_prepend', self::TIER_URGENT, 'auto_' . strtolower($match[1]) . '_file → ' . basename($target)];
		}
		
		if(preg_match('~^(?:AddHandler|AddType)\s+(\S*php\S*)\s+(.+)$~i', $line, $match) === 1)
		{
			$foreign = [];
			
			foreach(preg_split('~\s+~', trim($match[2])) ?: [] as $extension)
			{
				if(preg_match('~^\.?(?:php\d?|phtml|phar)$~i', $extension) !== 1)
				{
					$foreign[] = $extension;
				}
			}
			
			return $foreign === []
				? null
				: ['handler_php_extension', self::TIER_URGENT, 'PHP handler for ' . implode(' ', $foreign)];
		}
		
		if(preg_match('~^SetHandler\s+\S*php~i', $line) === 1)
		{
			return ['set_handler_php', $uploads ? self::TIER_URGENT : self::TIER_HIGH, 'SetHandler to PHP'];
		}
		
		if($uploads && preg_match('~^php_(?:admin_)?flag\s+engine\s+on~i', $line) === 1)
		{
			return ['engine_on_uploads', self::TIER_URGENT, 'PHP engine switched on under uploads'];
		}
		
		if($uploads && preg_match('~^(?:Options\b.*\bExecCGI|AddHandler\s+cgi-script)~i', $line) === 1)
		{
			return ['cgi_uploads', self::TIER_HIGH, 'CGI execution under uploads'];
		}
		
		if(preg_match('~^(?:RewriteRule\s+\S+|Redirect(?:Match|Permanent|Temp)?\s+(?:\d{3}\s+)?\S+|ErrorDocument\s+\d{3})\s+["\']?https?://([^/\s"\']+)~i', $line, $match) === 1)
		{
			$host = strtolower($match[1]);
			
			if($this->isForeignHost($host))
			{
				return ['redirect_external', self::TIER_HIGH, 'redirect to ' . $host];
			}
		}
		
		return null;
	}
	
	/**
	 * Whether an uploads .htaccess denies PHP — engine off, or a php
	 * Files/FilesMatch block that denies or unsets the handler
	 */
	protected function deniesPhp(
		string $content,
	): bool
	{
		return preg_match('~php_(?:admin_)?flag\s+engine\s+off~i', $content) === 1
			|| preg_match('~<Files(?:Match)?\s+[^>]*php[^>]*>.*?(?:deny\s+from\s+all|Require\s+all\s+denied|SetHandler\s+(?:none|default-handler))~is', $content) === 1;
	}
	
	/**
	 * Whether this request may run the database phase. Its cron check asks
	 * which hooks have a listener, and a plugin adds its listeners while
	 * WordPress loads: a request that ended early (a language redirect that
	 * exits at setup_theme) has heard of none of them, so the phase waits for
	 * one that reached wp_loaded. It prefers a WP-Cron or admin request, where
	 * every plugin loads its listeners (some skip anonymous front-end
	 * visitors); the request is judged, never the pass: a manual pass is
	 * finished by whatever requests come after the button's. A site without
	 * either for a day runs it on the next loaded request, or the pass would
	 * never finish
	 */
	protected function databaseReady(
		array &$state,
	): bool
	{
		if(function_exists('did_action') && did_action('wp_loaded') === 0)
		{
			return false;
		}
		
		if((function_exists('wp_doing_cron') && wp_doing_cron())
			|| (function_exists('is_admin') && is_admin()))
		{
			return true;
		}
		
		$now = time();
		// a deferral dated ahead of the clock was planted in the stored pass: the wait starts now
		if(Clock::ahead((int)($state['database_deferred_since'] ?? $now), $now))
		{
			unset($state['database_deferred_since']);
		}
		$state['database_deferred_since'] ??= $now;
		
		return $now - (int)$state['database_deferred_since'] >= self::DATABASE_WAIT;
	}
	
	/**
	 * The database phase: the attacker's other filesystem, read by
	 * Database — every finding an id, an option name or a hook, never a
	 * name or a value
	 */
	protected function database(
		array &$state,
	): void
	{
		$result = (new Database($this->roots, (int)($state['resume']['posts'] ?? 0), (array)($state['resume']['posts_found'] ?? [])))->scan();
		$state['resume_next']['posts'] = (int)($result['stats']['posts_cursor'] ?? 0);
		$state['resume_next']['posts_found'] = (array)($result['posts'] ?? []);
		unset($result['stats']['posts_cursor']);
		
		// what the detectors' caps left out was found and not listed: the report says so
		foreach((array)($result['truncated'] ?? []) as $tier => $count)
		{
			if(isset($state['truncated'][$tier]))
			{
				$state['counts'][$tier] += (int)$count;
				$state['truncated'][$tier] += (int)$count;
				$state['areas'][Database::AREA]['truncated'] = ($state['areas'][Database::AREA]['truncated'] ?? 0) + (int)$count;
			}
		}
		
		foreach($result['findings'] as $finding)
		{
			$this->finding($state, Database::AREA, (string)$finding['path'], (string)$finding['detector'],
				(string)$finding['tier'], (string)($finding['detail'] ?? ''),
				isset($finding['mtime']) ? ['mtime' => (int)$finding['mtime']] : []);
		}
		
		foreach($result['stats'] as $key => $value)
		{
			$state['areas'][Database::AREA][$key] = (int)$value;
		}
	}
	
	/**
	 * The final phase: the site's posture, so the console's advice can say
	 * "and close the door" — plus the one live directive that no file scan
	 * sees, the ini's own auto_prepend_file
	 */
	protected function posture(
		array &$state,
	): void
	{
		$roots = $this->roots;
		$config = $this->configPath($roots['root']);
		$server = $this->server();
		$windows = DIRECTORY_SEPARATOR === '\\';
		
		$debug = defined('WP_DEBUG') && (bool)WP_DEBUG;
		$active = $this->activeSlugs();
		$debugLog = $this->debugLog($roots);
		
		$state['posture'] = [
			'server' => $server,
			'multisite' => function_exists('is_multisite') && is_multisite(),
			'environment' => function_exists('wp_get_environment_type') ? (string)wp_get_environment_type() : '',
			'file_edit_disabled' => defined('DISALLOW_FILE_EDIT') && (bool)DISALLOW_FILE_EDIT,
			'file_mods_disabled' => defined('DISALLOW_FILE_MODS') && (bool)DISALLOW_FILE_MODS,
			'debug' => $debug,
			'debug_display' => $debug && (defined('WP_DEBUG_DISPLAY') === false || (bool)WP_DEBUG_DISPLAY),
			'auto_update_core' => defined('WP_AUTO_UPDATE_CORE') ? $this->constantWord(WP_AUTO_UPDATE_CORE) : null,
			'updater_disabled' => defined('AUTOMATIC_UPDATER_DISABLED') && (bool)AUTOMATIC_UPDATER_DISABLED,
			'users_can_register' => (bool)get_option('users_can_register'),
			'default_role' => Inventory::slugOf((string)get_option('default_role')),
			'xmlrpc' => (bool)apply_filters('xmlrpc_enabled', true),
			'config_world_readable' => $config !== null && $windows === false ? $this->permits($config, 0004) : null,
			'uploads_world_writable' => $roots['uploads'] !== '' && $windows === false ? $this->permits($roots['uploads'], 0002) : null,
			'uploads_htaccess' => (bool)$state['uploads_htaccess'],
			'uploads_php_denied' => in_array($server, ['apache', 'litespeed'], true) ? (bool)$state['uploads_php_denied'] : null,
			'vcs_exposed' => $state['vcs'],
			'readme_html' => is_file($roots['root'] . '/readme.html'),
			'login_protection' => $this->protection('login_protection', $active),
			'two_factor' => $this->protection('two_factor', $active),
			'upload_scanner' => $this->protection('upload_scanner', $active),
			'debug_log' => $debugLog !== null,
			'ini' => [
				'auto_prepend_file' => $this->clean((string)ini_get('auto_prepend_file')),
				'auto_append_file' => $this->clean((string)ini_get('auto_append_file')),
				'user_ini_filename' => $this->clean((string)ini_get('user_ini.filename')),
				'open_basedir' => $this->clean((string)ini_get('open_basedir')),
				'disable_functions' => $this->clean((string)ini_get('disable_functions')),
				'display_errors' => $this->clean((string)ini_get('display_errors')),
				'expose_php' => (bool)ini_get('expose_php'),
				'allow_url_include' => (bool)ini_get('allow_url_include'),
				'opcache' => (bool)ini_get('opcache.enable'),
			],
		];
		
		if($debugLog !== null)
		{
			// WP_DEBUG_LOG on a production site: the log leaks paths, queries
			// and stack traces to anyone who asks for it by URL
			$stat = @stat($debugLog);
			
			$this->finding($state, str_starts_with($debugLog, $roots['content'] . '/') ? 'content' : 'root', $debugLog,
				'debug_log_public', self::TIER_HIGH,
				'WP_DEBUG_LOG writes a web-reachable file' . ($stat === false ? '' : ' (' . (int)round((int)$stat['size'] / 1024) . ' KB)'),
				$stat === false ? [] : ['size' => (int)$stat['size'], 'mtime' => (int)$stat['mtime']]);
		}
		
		foreach(['auto_prepend_file', 'auto_append_file'] as $key)
		{
			$target = trim((string)ini_get($key));
			
			if($target === '' || strtolower($target) === 'none')
			{
				continue;
			}
			
			$owner = $this->ownerOfPath($target);
			
			$this->finding($state, 'root', $this->normalize($target),
				$owner !== null ? 'ini_prepend_owned' : 'ini_prepend',
				$owner !== null ? self::TIER_INFO : self::TIER_URGENT,
				$key . ($owner !== null ? ' owned by ' . $owner : ' is live in php.ini'));
		}
	}
	
	/**
	 * The core list for this pass, fetched once the chunk's budget allows:
	 * true when the phase may go on (list known, or known to be
	 * unavailable), false when the chunk must yield for the fetch
	 */
	protected function ensureCore(
		array &$state,
	): bool
	{
		if(($state['checksums']['core'] ?? 'pending') !== 'pending')
		{
			return true;
		}
		
		$version = (string)$state['core_version'];
		$locale = (string)$state['locale'];
		
		if($this->sums === null || $version === '')
		{
			$state['checksums']['core'] = 'unavailable';
			
			return true;
		}
		
		if($this->sums->coreCached($version, $locale) === false && $this->sums->fetches >= $this->fetchLimit)
		{
			return false;
		}
		
		$list = $this->sums->core($version, $locale);
		$state['checksums']['core'] = $list === null ? 'unavailable' : 'verified';
		$state['checksums']['core_locale'] = $list === null ? '' : $locale;
		
		return true;
	}
	
	/**
	 * The core list, loaded once per request; false when this pass has none
	 */
	protected function coreList(
		array $state,
	): array|false
	{
		if($this->coreList !== null)
		{
			return $this->coreList;
		}
		
		if(($state['checksums']['core'] ?? '') !== 'verified' || $this->sums === null)
		{
			return $this->coreList = false;
		}
		
		$list = $this->sums->core((string)$state['core_version'],
			(string)(($state['checksums']['core_locale'] ?? '') !== '' ? $state['checksums']['core_locale'] : $state['locale']));
		
		return $this->coreList = $list ?? false;
	}
	
	/**
	 * A plugin's list: known (the state remembers verified/unavailable per
	 * slug), or fetched now within the chunk's budget — false when the
	 * chunk must yield for it. A plugin without a version header, or one
	 * wp.org never had, is simply unverified.
	 */
	protected function ensurePlugin(
		array &$state,
		string $slug,
	): bool
	{
		if(isset($state['checksums']['plugins'][$slug]))
		{
			return true;
		}
		
		$version = (string)($state['versions'][$slug] ?? '');
		
		if($this->sums === null || $version === '' || Inventory::slugOf($slug) !== $slug)
		{
			$state['checksums']['plugins'][$slug] = 'unavailable';
			
			return true;
		}
		
		if($this->sums->pluginCached($slug, $version) === false && $this->sums->fetches >= $this->fetchLimit)
		{
			return false;
		}
		
		$state['checksums']['plugins'][$slug] = $this->sums->plugin($slug, $version) === null ? 'unavailable' : 'verified';
		
		return true;
	}
	
	/**
	 * Every installed plugin's version by directory slug — the key wp.org's
	 * lists are kept under. A single-file plugin has no directory and is the
	 * core list's business (hello.php).
	 *
	 * @return array<string, string>
	 */
	public function pluginVersions(): array
	{
		if(function_exists('get_plugins') === false)
		{
			if(defined('ABSPATH') && is_file(ABSPATH . 'wp-admin/includes/plugin.php'))
			{
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			
			if(function_exists('get_plugins') === false)
			{
				return [];
			}
		}
		
		$versions = [];
		
		foreach((array)get_plugins() as $file => $headers)
		{
			$directory = dirname((string)$file);
			
			if($directory === '.' || $directory === '')
			{
				continue;
			}
			
			$versions[$directory] ??= Inventory::version((string)($headers['Version'] ?? ''));
		}
		
		return $versions;
	}
	
	/**
	 * Record one finding, or count it once the report is full. The path is
	 * relative to its area root (absolute when it stands outside, as an ini
	 * target may) and always cleaned: it is attacker-authored.
	 */
	protected function finding(
		array &$state,
		string $area,
		string $path,
		string $detector,
		string $tier,
		string $detail = '',
		array $meta = [],
	): void
	{
		$state['counts'][$tier]++;
		
		if(count($state['findings']) >= self::MAX_FINDINGS)
		{
			$victim = $this->outranked($state['findings'], $tier);
			
			if($victim === null)
			{
				$state['truncated'][$tier]++;
				$state['areas'][$area]['truncated'] = ($state['areas'][$area]['truncated'] ?? 0) + 1;
				
				return;
			}
			
			// the last listed finding of the lowest tier below this one gives up its place, counted where it was, by tier and by area
			$given = $state['findings'][$victim];
			$state['truncated'][$given['tier']]++;
			$state['areas'][$given['area']]['truncated'] = ($state['areas'][$given['area']]['truncated'] ?? 0) + 1;
			array_splice($state['findings'], $victim, 1);
		}
		
		$finding = [
			'detector' => $detector,
			'tier' => $tier,
			'area' => $area,
			// codesafe refuses a whole report over one path with a `..` segment, and an
			// intruder names a cron hook or an active plugin entry; either separator counts
			'path' => $this->clean((string)preg_replace('~(?<=^|[/\\\\])\.\.(?=$|[/\\\\])~', '%2E%2E',
				$this->relative($path, (string)$state['areas'][$area]['root']))),
		];
		
		if(isset($meta['size']))
		{
			$finding['size'] = (int)$meta['size'];
		}
		
		if(isset($meta['mtime']))
		{
			$finding['mtime'] = (int)$meta['mtime'];
		}
		
		if(isset($meta['line']))
		{
			$finding['line'] = (int)$meta['line'];
		}
		
		if($detail !== '')
		{
			$finding['detail'] = $this->clean($detail, self::MAX_DETAIL);
		}
		
		$state['findings'][] = $finding;
	}
	
	/**
	 * The index of the last listed finding of the lowest tier below $tier,
	 * or null when every listed finding ranks as high
	 *
	 * @param list<array<string, mixed>> $findings
	 */
	protected function outranked(
		array $findings,
		string $tier,
	): ?int
	{
		$rank = [self::TIER_INFO => 1, self::TIER_HIGH => 2, self::TIER_URGENT => 3];
		$victim = null;
		
		foreach($findings as $index => $finding)
		{
			$their = $rank[$finding['tier']] ?? 0;
			
			if($their < $rank[$tier] && ($victim === null || $their <= $rank[$findings[$victim]['tier']]))
			{
				$victim = $index;
			}
		}
		
		return $victim;
	}
	
	protected function skip(
		array &$state,
		string $area,
		string $path,
	): void
	{
		if(count($state['skipped']) < self::MAX_SKIPPED)
		{
			$state['skipped'][] = $area . ':'
				. $this->clean($this->relative($path, (string)$state['areas'][$area]['root']));
		}
	}
	
	/**
	 * The owners of a plugin-owned data directory under wp-content when none
	 * of them is installed; null when the name is no such directory or an
	 * owner is installed. The executed-file watch asks it for a file that ran
	 * inside one: what software the site no longer runs left behind
	 *
	 * @param array<string, string> $roots the area roots the caller judges against (roots())
	 * @return ?list<string>
	 */
	public function writerOwners(
		string $name,
		array $roots,
	): ?array
	{
		$owners = self::WRITER_DIRS[$name] ?? null;
		
		if($owners === null || $this->installedOwner($owners, $roots) !== null)
		{
			return null;
		}
		
		return $owners;
	}
	
	/**
	 * The first installed owner of a plugin-written path — plugin slugs, or
	 * `theme:<dir>` — as a label, or null; against the pass's roots unless
	 * the caller hands its own
	 *
	 * @param string[] $owners
	 * @param ?array<string, string> $roots
	 */
	protected function installedOwner(
		array $owners,
		?array $roots = null,
	): ?string
	{
		$roots ??= $this->roots;
		
		foreach($owners as $owner)
		{
			[$type, $slug] = str_contains($owner, ':') ? explode(':', $owner, 2) : ['plugin', $owner];
			$root = $type === 'theme' ? $roots['themes'] : $roots['plugins'];
			$installed = $this->installedSlugs($root)[strtolower($slug)] ?? null;
			
			if($slug !== '' && $installed !== null)
			{
				// named as the directory is named
				return $type === 'theme' ? 'theme:' . $installed : $installed;
			}
		}
		
		return null;
	}
	
	/**
	 * The directories under a plugins or themes root by their lowercase name,
	 * read once per request: an owner table names a plugin in one casing
	 * (Ultimate_VC_Addons) and the site's file system may be case-sensitive
	 *
	 * @return array<string, string> lowercase name → the directory's own name
	 */
	protected function installedSlugs(
		string $root,
	): array
	{
		if(isset($this->slugs[$root]))
		{
			return $this->slugs[$root];
		}
		
		$slugs = [];
		
		foreach(@scandir($root, SCANDIR_SORT_NONE) ?: [] as $entry)
		{
			if($entry !== '.' && $entry !== '..' && is_dir($root . '/' . $entry))
			{
				$slugs[strtolower($entry)] = $entry;
			}
		}
		
		return $this->slugs[$root] = $slugs;
	}
	
	/**
	 * Whether PHP stops before any code in $source runs: after the opener the
	 * first statement is __halt_compiler(), or an exit or die whose argument
	 * is a literal or nothing (an expression there runs before the exit).
	 * Read slice by slice (slices()): a long header comment is one token, and
	 * no first block of bytes decides. Without the tokenizer nothing is judged
	 * inert
	 */
	public static function inert(
		string $source,
	): bool
	{
		if(function_exists('token_get_all') === false)
		{
			return false;
		}
		
		$opened = false;
		$statement = [];
		
		foreach(self::slices($source) as $tokens)
		{
			foreach($tokens as [$id, $text])
			{
				if($opened === false)
				{
					if($id === T_INLINE_HTML && trim($text) === '')
					{
						continue;
					}
					
					if($id !== T_OPEN_TAG)
					{
						return false;
					}
					
					$opened = true;
					
					continue;
				}
				
				$statement[] = $id;
				
				if(count($statement) === 5)
				{
					break 2;
				}
			}
		}
		
		return ($statement[0] ?? null) === T_HALT_COMPILER
			|| (($statement[0] ?? null) === T_EXIT && self::exitsCleanly($statement, 0));
	}
	
	/**
	 * Whether the tokens from $at are an exit or die that runs nothing first —
	 * bare, empty or taking one literal, then the statement's end — or a bare
	 * `return`, which ends a requested file alike
	 *
	 * @param list<int|string> $ids token ids
	 */
	protected static function exitsCleanly(
		array $ids,
		int $at,
	): bool
	{
		$end = [';', T_CLOSE_TAG];
		$next = $ids[$at + 1] ?? null;
		
		return match($ids[$at] ?? null)
		{
			T_RETURN => in_array($next, $end, true),
			T_EXIT => in_array($next, $end, true)
				|| ($next === '(' && ($ids[$at + 2] ?? null) === ')' && in_array($ids[$at + 3] ?? null, $end, true))
				|| ($next === '(' && in_array($ids[$at + 2] ?? null, [T_LNUMBER, T_CONSTANT_ENCAPSED_STRING], true)
					&& ($ids[$at + 3] ?? null) === ')' && in_array($ids[$at + 4] ?? null, $end, true)),
			default => false,
		};
	}
	
	/**
	 * Whether $source only assigns or returns data: variables, strings,
	 * numbers, constants (PHP_INT_MAX, ABSPATH, __DIR__), heredocs, arrays and
	 * the arithmetic that combines them, behind an optional
	 * `defined('ABSPATH') || exit` guard in any of its spellings — nothing
	 * that can call or include code but the calls in DATA_CALLS. A `(` after
	 * a value would call it and is refused, after an operator it groups, so
	 * `$f('x')`, `'system'('id')` and `[$o, 'm']()` stay code, and so do a
	 * method, a static and an interpolated call. What Ultimate Addons writes
	 * into its icon sets' charmap.php, a build into `*.asset.php`, WordPress
	 * into `.l10n.php`, the i18n tools into a plugin's table of its scripts'
	 * strings, caching plugins into their config files. Read element by
	 * element (slices()), so a large array is never one token array. Without
	 * the tokenizer nothing is judged data
	 */
	public static function dataOnly(
		string $source,
	): bool
	{
		if(function_exists('token_get_all') === false)
		{
			return false;
		}
		
		// 0 before the opener, 1 inside PHP, 2 after the closer
		$phase = 0;
		$previous = null;
		$values = [T_VARIABLE, T_CONSTANT_ENCAPSED_STRING, T_LNUMBER, T_DNUMBER, T_DIR, T_FILE, T_LINE, T_END_HEREDOC,
			')', ']', '}', '"', 'constant'];
		
		foreach(self::slices($source, true) as $tokens)
		{
			foreach($tokens as $index => [$id, $text])
			{
				if($phase !== 1 && $id === T_INLINE_HTML && trim($text) === '')
				{
					continue;
				}
				
				if($phase !== 1)
				{
					if($phase === 2 || $id !== T_OPEN_TAG)
					{
						return false;
					}
					
					$phase = 1;
					
					continue;
				}
				
				if($id === T_CLOSE_TAG)
				{
					$phase = 2;
					
					continue;
				}
				
				$name = $id === T_STRING || $id === T_NAME_FULLY_QUALIFIED ? strtolower(ltrim($text, '\\')) : null;
				$next = $tokens[$index + 1][0] ?? null;
				$allowed = match(true)
				{
					$id === '(' => in_array($previous, [T_ARRAY, T_IF, T_EXIT, ...self::DATA_CALLS], true)
						|| in_array($previous, $values, true) === false,
					// a name is a call only where DATA_CALLS allows one, else a constant: never called, never a class
					$name !== null => in_array($name, self::DATA_CALLS, true) ? $next === '(' : $next !== '(' && $next !== T_DOUBLE_COLON,
					default => in_array($id, self::DATA_TOKENS, true),
				};
				
				if($allowed === false)
				{
					return false;
				}
				
				$previous = match(true)
				{
					$name !== null && in_array($name, self::DATA_CALLS, true) => $name,
					$name !== null => 'constant',
					default => $id,
				};
			}
		}
		
		return $phase !== 0;
	}
	
	/**
	 * What code in $source does that honest code does not, read with the
	 * tokenizer in Database's code markers, PHP's command functions and the
	 * functions that call what they are handed: request input reaching an
	 * executor or a command, called as a function or handed as the function
	 * another calls, run by backticks or included (request_exec — urgent, high
	 * where an escaper or a sanitizer wraps it or the code dispatches on it
	 * through its own object or a literal prefix); an include of a stream
	 * URL, of a file under uploads or in a temp directory, of a media file
	 * (include_foreign — urgent, high for a fixed PHP file under uploads
	 * outside wp-config.php, nothing for one in an uploads folder an installed
	 * plugin writes); a decoder's output or a stream's content fed to an
	 * executor or a command (eval_chain, high). The worst shape wins, the
	 * first of it names the line. A method of the same name
	 * (`$this->assert(`) or a function's definition is not PHP's own. A
	 * callback that runs its parameter, handed request input, is a runner
	 * (callback()); one named by a string resolves once the file defines it,
	 * before or after the call. Read slice by slice (slices()); a call cut
	 * past CALL_TOKENS whose verdict hangs on an argument's place is
	 * oversize_call (high) when the file draws no other verdict. Without the
	 * tokenizer nothing is judged
	 *
	 * @param array{uploads?: string, temp?: list<string>, owned?: list<string>, strict?: bool} $places places()
	 * @return ?array{0: string, 1: string, 2: string, 3: int} detector, tier, detail, line
	 */
	public static function codeVerdict(
		string $source,
		array $places = [],
	): ?array
	{
		if(function_exists('token_get_all') === false || self::suspect($source, $places) === false)
		{
			return null;
		}
		
		$found = null;
		$oversize = null;
		// the functions the file defines that run their parameter, and the calls that hand one request input before it is defined
		$context = ['runs' => [], 'pending' => [], 'shells' => 0];
		
		foreach(self::slices($source) as $label => $tokens)
		{
			// a slice never ends inside a string, so its backticks pair up within it
			$context['shells'] = 0;
			
			foreach($tokens as $index => [$id, , $line])
			{
				$name = $id === T_FUNCTION ? self::functionName($tokens, $index) : null;
				$sink = $name === null ? null : self::parameterSink($tokens, $index);
				
				if($sink !== null)
				{
					$context['runs'][$name] = $sink;
				}
				
				// a call made before the definition is judged now
				$verdict = $sink === null ? null : ($context['pending'][$name] ?? null);
				$verdict ??= self::shapeAt($tokens, $index, $places, $context);
				
				if($verdict === null)
				{
					continue;
				}
				
				$verdict[3] ??= $line;
				
				if($verdict[1] === self::TIER_URGENT)
				{
					return $verdict;
				}
				
				$found ??= $verdict;
			}
			
			if($label !== '')
			{
				$oversize ??= ['oversize_call', self::TIER_HIGH, ($label === ')' ? 'a call on a call' : 'a call to ' . $label . '()')
					. ' longer than the scan reads at once; read it by hand', (int)($tokens[count($tokens) - 1][2] ?? 1)];
			}
		}
		
		return $found ?? $oversize;
	}
	
	/**
	 * The shape that starts at the token at $index, or null
	 *
	 * @return ?array{0: string, 1: string, 2: string}
	 */
	protected static function shapeAt(
		array $tokens,
		int $index,
		array $places,
		array &$context,
	): ?array
	{
		$id = $tokens[$index][0];
		
		if($id === T_EVAL)
		{
			return self::fed($tokens, $index, 'eval', $context);
		}
		
		// the backtick that closes a shell command opens none
		if($id === '`')
		{
			return $context['shells']++ % 2 === 0 ? self::backticked($tokens, $index) : null;
		}
		
		if(in_array($id, [T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE], true))
		{
			return self::included($tokens, $index, $places);
		}
		
		$runner = self::runnerAt($tokens, $index);
		
		if($runner !== null)
		{
			return self::fed($tokens, $index, $runner, $context);
		}
		
		$input = self::inputAt($tokens, $index);
		
		return $input === null ? null : self::requestCalled($tokens, $index, $input);
	}
	
	/**
	 * Whether $source can hold a code shape at all, by pattern, before the
	 * tokenizer is paid for: a runner's call — a comment may stand before its
	 * parenthesis — beside request input or a decoder's call; request input
	 * called or in backticks; an include beside request input, a stream, an
	 * upload or temp path, an escaped byte or a quoted media file, however
	 * far apart.
	 * The comment group is unrolled, so no input makes PCRE backtrack, and a
	 * PCRE error reads as suspect: the tokenizer judges instead
	 *
	 * @param array{uploads?: string, temp?: list<string>} $places
	 */
	protected static function suspect(
		string $source,
		array $places = [],
	): bool
	{
		$comment = '(?:/\*[^*]*\*+(?:[^/*][^*]*\*+)*/\s*|(?://|#)[^\n]*\n\s*)*';
		$call = '\s*' . $comment . '\(';
		$input = self::matches('~\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\$GLOBALS\s*\[\s*[\'"]_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b'
			. '|php://input|\b(?:' . implode('|', self::INPUT_FUNCTIONS) . ')\s*\(~i', $source);
		
		if(self::matches('~\b(?:eval|' . implode('|', self::runners()) . ')' . $call . '~i', $source)
			&& ($input || self::matches('~\b(?:' . implode('|', self::decoders()) . ')' . $call . '|://|\bdata:~i', $source)))
		{
			return true;
		}
		
		if($input && (str_contains($source, '`') || self::matches('~[\])]\s*' . $comment . '\(~', $source)))
		{
			return true;
		}
		
		$where = [];
		
		foreach([(string)($places['uploads'] ?? ''), ...(array)($places['temp'] ?? [])] as $place)
		{
			if($place !== '')
			{
				$where[] = preg_quote($place, '~');
			}
		}
		
		// an include and what it may name, each anywhere, as a runner and its input: the tokenizer decides whether one names the other
		return self::matches('~\b(?:include|require)(?:_once)?\b~i', $source)
			&& self::matches('~\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\$GLOBALS|://|\bdata:'
			. '|\b(?:' . implode('|', self::INPUT_FUNCTIONS) . ')\b|wp-content/uploads|upload_dir|/tmp/|/shm/|temp_dir|\\\\[0-7]{3}|\\\\x[0-9a-f]{2}'
			. '|\.(?:' . implode('|', self::includeMedia()) . ')[\'"]|[\'"](?:' . implode('|', self::includeMedia()) . ')[\'"]'
			. ($where === [] ? '' : '|' . implode('|', $where)) . '~i', $source);
	}
	
	/** whether a pattern matches, a PCRE error counted as a match: the caller then reads the source itself */
	protected static function matches(
		string $pattern,
		string $subject,
	): bool
	{
		return preg_match($pattern, $subject) !== 0;
	}
	
	/**
	 * Whether $source does something of its own when the web server is asked
	 * for it by URL — what a file planted among a package's assets is for. An
	 * exit first, a first statement that exits unless WordPress defined its
	 * constant (`defined('ABSPATH') || exit`, `if(!defined('WPINC')) die;`, a
	 * bare `return` alike) while that exit runs nothing itself, literal data
	 * and declarations alone (a namespace, imports, classes, functions,
	 * constants) run nothing. Without the tokenizer anything runs
	 */
	public static function runsOnRequest(
		string $source,
	): bool
	{
		if(function_exists('token_get_all') === false)
		{
			return true;
		}
		
		if(self::inert($source) || self::dataOnly($source))
		{
			return false;
		}
		
		$ids = [];
		
		// the first statement's ids: a guard is the same few tokens in every spelling
		foreach(self::slices($source) as $tokens)
		{
			foreach($tokens as [$id, $text])
			{
				$ids[] = match(true)
				{
					$id === T_STRING || $id === T_NAME_FULLY_QUALIFIED => strtolower(ltrim($text, '\\')),
					$id === T_BOOLEAN_OR || $id === T_LOGICAL_OR => '||',
					default => $id,
				};
			}
			
			break;
		}
		
		$ids = array_slice($ids, (int)array_search(T_OPEN_TAG, $ids, true) + 1, 16);
		$guard = ['defined', '(', T_CONSTANT_ENCAPSED_STRING, ')'];
		
		foreach([[...$guard, '||'], [T_IF, '(', '!', ...$guard, ')'], [T_IF, '(', '!', ...$guard, ')', '{']] as $shape)
		{
			if(array_slice($ids, 0, count($shape)) === $shape && self::exitsCleanly($ids, count($shape)))
			{
				return false;
			}
		}
		
		return self::declaresOnly($source) === false;
	}
	
	/**
	 * Whether $source runs nothing alone at its top level: every statement
	 * there declares — a namespace, imports, declare(), constants, classes,
	 * interfaces, traits, enums and functions with their attributes, whose
	 * bodies run only when something calls them — up to a first statement
	 * that calls a function only WordPress defines (WORDPRESS_CALLS) and the
	 * file does not (definedNames()): requested by URL, without WordPress
	 * loaded, PHP stops at that call
	 */
	protected static function declaresOnly(
		string $source,
	): bool
	{
		$declarations = [T_NAMESPACE, T_USE, T_DECLARE, T_CONST, T_CLASS, T_INTERFACE, T_TRAIT, T_ENUM, T_FUNCTION,
			T_ABSTRACT, T_FINAL, T_READONLY, T_ATTRIBUTE];
		$depth = 0;
		$start = true;
		
		foreach(self::slices($source) as $tokens)
		{
			foreach($tokens as $index => [$id, $text])
			{
				if(in_array($id, [T_OPEN_TAG, T_CLOSE_TAG], true) || ($id === T_INLINE_HTML && $depth === 0 && $start))
				{
					continue;
				}
				
				if($depth === 0 && $start && in_array($id, $declarations, true) === false)
				{
					$name = strtolower(ltrim((string)$text, '\\'));
					
					// a function of that name the file defines or imports itself is the file's own, and runs
					return ($id === T_STRING || $id === T_NAME_FULLY_QUALIFIED)
						&& ($tokens[$index + 1][0] ?? null) === '('
						&& preg_match(self::WORDPRESS_CALLS, $name) === 1
						&& in_array($name, self::definedNames($source), true) === false;
				}
				
				$start = false;
				
				if(in_array($id, ['{', T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))
				{
					$depth++;
				}
				elseif($id === '}')
				{
					$depth--;
					// a declaration's body closed: the next token starts a statement
					$start = $depth === 0;
				}
				elseif($id === ';' && $depth === 0)
				{
					$start = true;
				}
			}
		}
		
		return true;
	}
	
	/**
	 * The names of the functions $source defines anywhere — PHP hoists them,
	 * so one defined after its call is there for it — and the names it
	 * imports anything as (`use function … as …`), lowercase
	 *
	 * @return list<string>
	 */
	protected static function definedNames(
		string $source,
	): array
	{
		$names = [];
		
		foreach(self::slices($source) as $tokens)
		{
			foreach($tokens as $index => [$id])
			{
				$name = match(true)
				{
					$id === T_FUNCTION => self::functionName($tokens, $index),
					$id === T_AS && ($tokens[$index + 1][0] ?? null) === T_STRING => strtolower($tokens[$index + 1][1]),
					default => null,
				};
				
				if($name !== null)
				{
					$names[] = $name;
				}
			}
		}
		
		return $names;
	}
	
	/**
	 * $source's significant tokens — comments and whitespace left out, each
	 * as [id, text, line] — in slices the tokenizer reads one at a time, so a
	 * dense file is never one token array: about SLICE_BYTES each, ending
	 * where cut() says — never inside a string, never inside a runner's call
	 * or an include's expression but past CALL_TOKENS, data element by
	 * element with $elements. The next slice is read from there in PHP mode,
	 * on the source's own lines. A cut inside a string or a comment the
	 * tokenizer read whole reads as one string or comment token, so a `;` the
	 * tokenizer saw is a real one. A slice cut inside a runner's call begins
	 * the next one with the open calls' heads, so what follows is read as
	 * their arguments, and is keyed by the call whose verdict the heads
	 * cannot carry (cut()'s label; '' for every other slice)
	 *
	 * @return Generator<string, list<array{0: int|string, 1: string, 2: int}>>
	 */
	protected static function slices(
		string $source,
		bool $elements = false,
	): Generator
	{
		$length = strlen($source);
		$start = 0;
		$line = 1;
		// the brackets the last slice was cut inside, past CALL_TOKENS
		$open = [];
		
		while($start < $length)
		{
			$prefix = $start === 0 ? '' : '<?php ';
			$size = self::SLICE_BYTES;
			
			while(true)
			{
				$end = min($length, $start + $size);
				$raw = token_get_all($prefix . substr($source, $start, $end - $start));
				$cut = $end >= $length ? ['at' => count($raw), 'open' => [], 'label' => ''] : self::cut($raw, $elements, $open);
				
				// the opener a later slice is given is no progress of its own
				if($cut !== null && $cut['at'] > ($prefix === '' ? 0 : 1))
				{
					break;
				}
				
				$size *= 2;
			}
			
			$tokens = [];
			
			// the heads of the calls the last slice was cut inside: what follows is their arguments
			foreach($open as [, $head])
			{
				foreach($head as [$id, $text])
				{
					$tokens[] = [$id, $text, $line];
				}
			}
			
			$consumed = 0;
			$at = $line;
			
			for($index = 0; $index < $cut['at']; $index++)
			{
				$token = $raw[$index];
				$consumed += strlen(is_array($token) ? $token[1] : $token);
				$at = is_array($token) ? $line + (int)$token[2] - 1 : $at;
				
				if(($index === 0 && $prefix !== '') || (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)))
				{
					continue;
				}
				
				$tokens[] = is_array($token) ? [$token[0], $token[1], $at] : [$token, $token, $at];
			}
			
			unset($raw);
			$consumed -= strlen($prefix);
			$line += substr_count($source, "\n", $start, $consumed);
			$start += $consumed;
			$open = $cut['open'];
			
			yield $cut['label'] => $tokens;
		}
	}
	
	/**
	 * Where a slice's tokens end (slices()): never inside a string, and but
	 * for data ($elements) never inside a runner's call (owner()) or an
	 * include's expression — after the last `;` outside every bracket, else
	 * after the last `;` or `,`, else, past SLICE_TOKENS, after the last
	 * operator; null while there is none and the slice may grow. A runner's
	 * call grows its slice up to CALL_TOKENS and past that is cut after its
	 * last operator anyway, handing the next slice the brackets open there
	 * (`open`: each [owner, the tokens its head is carried as, whether it is
	 * an include without parentheses]) and naming the outermost call whose
	 * verdict hangs on an argument's place (`label`: a function of
	 * CALLABLES, `)` for a call on a call), which its head cannot carry
	 *
	 * @param list<mixed> $raw token_get_all()'s
	 * @param list<array{0: string, 1: list<array{0: int|string, 1: string}>, 2: bool}> $open the brackets the last slice was cut inside
	 * @return ?array{at: int, open: list<array{0: string, 1: list<array{0: int|string, 1: string}>, 2: bool}>, label: string}
	 */
	protected static function cut(
		array $raw,
		bool $elements,
		array $open = [],
	): ?array
	{
		$read = self::read($raw, $elements, $open, count($raw));
		$cut = $elements ? $read['any'] : ($read['statement'] ?? $read['any']);
		
		if($cut !== null)
		{
			return ['at' => $cut, 'open' => [], 'label' => ''];
		}
		
		if(count($raw) <= self::SLICE_TOKENS)
		{
			return null;
		}
		
		if($elements || $read['owned'] === 0)
		{
			return ['at' => $read['operator'] ?? count($raw) - 1, 'open' => [], 'label' => ''];
		}
		
		if(count($raw) <= self::CALL_TOKENS)
		{
			return null;
		}
		
		$at = $read['forced'] ?? count($raw) - 1;
		// what is open where the cut falls, read again up to it: rare enough not to be kept on every operator
		$stack = self::read($raw, $elements, $open, $at)['stack'];
		$label = '';
		
		foreach($stack as [$owner])
		{
			if($owner === ')' || isset(self::CALLABLES[$owner]))
			{
				$label = $owner;
				
				break;
			}
		}
		
		return ['at' => $at, 'open' => $stack, 'label' => $label];
	}
	
	/**
	 * cut()'s reading of $raw's first $until tokens: the brackets open at
	 * the end (`stack`) and how many of them a runner's call or an include
	 * owns, and the places a slice may end — after the last `;` outside
	 * every bracket (`statement`), after the last `;` or `,` outside a
	 * runner's call and every string (`any`), after the last operator there
	 * (`operator`) and after the last operator outside every string
	 * (`forced`)
	 *
	 * @param list<array{0: string, 1: list<array{0: int|string, 1: string}>, 2: bool}> $open
	 * @return array{stack: list<array{0: string, 1: list<array{0: int|string, 1: string}>, 2: bool}>, owned: int, statement: ?int, any: ?int, operator: ?int, forced: ?int}
	 */
	protected static function read(
		array $raw,
		bool $elements,
		array $open,
		int $until,
	): array
	{
		$runners = array_flip(self::runners());
		$stack = $open;
		$owned = count(array_filter($open, static fn(array $entry): bool => $entry[0] !== ''));
		$quotes = [];
		$statement = null;
		$any = null;
		$operator = null;
		$forced = null;
		$lastId = null;
		$lastText = '';
		$beforeId = null;
		
		for($index = 0; $index < $until; $index++)
		{
			$token = $raw[$index];
			
			if(is_array($token))
			{
				[$id, $text] = $token;
				
				if($id === T_WHITESPACE || $id === T_COMMENT || $id === T_DOC_COMMENT)
				{
					continue;
				}
				
				// a name, a variable, a literal: only the next bracket asks for it
				if(isset(self::CUT_MARKS[$id]) === false)
				{
					$beforeId = $lastId;
					$lastId = $id;
					$lastText = $text;
					
					continue;
				}
			}
			else
			{
				$id = $text = $token;
			}
			
			if($id === T_START_HEREDOC || (($id === '"' || $id === '`') && end($quotes) !== $id))
			{
				$quotes[] = $id;
			}
			elseif($id === T_END_HEREDOC || $id === '"' || $id === '`')
			{
				array_pop($quotes);
			}
			elseif($quotes !== [])
			{
				// an interpolation's tokens stand inside the string: no place to cut
			}
			elseif($id === '[')
			{
				$stack[] = ['', [['[', '[']], false];
			}
			elseif($id === '(')
			{
				$owner = self::owner([$lastId, $lastText], [$beforeId, ''], $runners);
				$stack[] = [$owner, self::carried('(', $owner, [$lastId, $lastText], [$beforeId, '']), false];
				$owned += $owner === '' ? 0 : 1;
			}
			elseif($id === ')' || $id === ']' || $id === ';' || $id === ',' || $id === T_CLOSE_TAG)
			{
				// an include without parentheses ends with its expression
				while($stack !== [] && end($stack)[2])
				{
					array_pop($stack);
					$owned--;
				}
				
				if(($id === ')' || $id === ']') && $stack !== [])
				{
					$owned -= array_pop($stack)[0] === '' ? 0 : 1;
				}
				elseif(($id === ';' || $id === ',') && ($elements || $owned === 0))
				{
					$any = $index + 1;
					$statement = $id === ';' && $stack === [] ? $index + 1 : $statement;
				}
			}
			elseif($id === T_INCLUDE || $id === T_INCLUDE_ONCE || $id === T_REQUIRE || $id === T_REQUIRE_ONCE)
			{
				$stack[] = [strtolower($text), [[$id, $text]], true];
				$owned++;
			}
			
			if($quotes === [] && isset(self::CUT_AFTER[$id]))
			{
				$forced = $index + 1;
				$operator = $elements || $owned === 0 ? $index + 1 : $operator;
			}
			
			$beforeId = $lastId;
			$lastId = $id;
			$lastText = $text;
		}
		
		return ['stack' => $stack, 'owned' => $owned, 'statement' => $statement, 'any' => $any, 'operator' => $operator, 'forced' => $forced];
	}
	
	/**
	 * The runner whose call the `(` after $last opens, $before standing before
	 * that: eval, a runner by its name (no method, no definition), `)` for a
	 * call on what a call or a group returns; '' for any other parenthesis —
	 * an include's own entry holds its parenthesis (read())
	 *
	 * @param array{0: int|string|null, 1: string} $last
	 * @param array{0: int|string|null, 1: string} $before
	 * @param array<string, int> $runners runners(), flipped
	 */
	protected static function owner(
		array $last,
		array $before,
		array $runners,
	): string
	{
		[$id, $text] = $last;
		$name = strtolower(ltrim($text, '\\'));
		
		return match(true)
		{
			$id === T_EVAL => 'eval',
			($id === T_STRING || $id === T_NAME_FULLY_QUALIFIED) && self::called($before[0]) && isset($runners[$name]) => $name,
			$id === ')' => ')',
			default => '',
		};
	}
	
	/** whether a name after a token of $id is a function's call: no method, static, definition or constructor */
	protected static function called(
		int|string|null $id,
	): bool
	{
		return in_array($id, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_CONST, T_NEW], true) === false;
	}
	
	/**
	 * The tokens a bracket is carried into the next slice as (cut()): eval
	 * and a function by its name with their parenthesis — a decoder or a
	 * sanitizer still wraps what follows — and a bare bracket for the rest,
	 * an include's keyword being carried by its own entry; a call whose
	 * verdict hangs on an argument's place is carried bare, since the places
	 * before the cut are gone
	 *
	 * @param array{0: int|string|null, 1: string} $last
	 * @param array{0: int|string|null, 1: string} $before
	 * @return list<array{0: int|string, 1: string}>
	 */
	protected static function carried(
		string $bracket,
		string $owner,
		array $last,
		array $before,
	): array
	{
		$named = $last[0] === T_EVAL || (($last[0] === T_STRING || $last[0] === T_NAME_FULLY_QUALIFIED) && self::called($before[0]));
		
		return $bracket === '(' && $named && $owner !== ')' && isset(self::CALLABLES[$owner]) === false
			? [[$last[0], $last[1]], ['(', '(']]
			: [[$bracket, $bracket]];
	}
	
	/** the tokens read() looks at besides the one-character ones: strings' bounds, includes, the closing tag and CUT_AFTER's */
	protected const CUT_MARKS = [T_START_HEREDOC => 1, T_END_HEREDOC => 1, T_INCLUDE => 1, T_INCLUDE_ONCE => 1, T_REQUIRE => 1, T_REQUIRE_ONCE => 1,
		T_CLOSE_TAG => 1, T_DOUBLE_ARROW => 1, T_BOOLEAN_AND => 1, T_BOOLEAN_OR => 1, T_LOGICAL_AND => 1, T_LOGICAL_OR => 1, T_COALESCE => 1,
		T_CONCAT_EQUAL => 1];
	
	/** the tokens after which a slice cut past SLICE_TOKENS may end (cut()): an operator, an opening bracket, a separator */
	protected const CUT_AFTER = ['.' => 1, '+' => 1, '-' => 1, '*' => 1, '/' => 1, '%' => 1, '=' => 1, '?' => 1, ':' => 1, '(' => 1, '[' => 1,
		',' => 1, T_DOUBLE_ARROW => 1, T_BOOLEAN_AND => 1, T_BOOLEAN_OR => 1, T_LOGICAL_AND => 1, T_LOGICAL_OR => 1, T_COALESCE => 1, T_CONCAT_EQUAL => 1];
	
	/** the functions that run what they are given: Database's executors but eval (a language construct), PHP's commands, and the functions that call the callable they are handed (CALLABLES) */
	protected static function runners(): array
	{
		return [...self::literalRunners(), ...array_keys(self::CALLABLES)];
	}
	
	/** the runners a string may name: Database's executors but eval, which is no function, and PHP's commands */
	protected static function literalRunners(): array
	{
		$runners = Database::COMMANDS;
		
		foreach(Database::CODE_EXECUTORS as $marker)
		{
			if($marker !== 'eval(')
			{
				$runners[] = substr($marker, 0, -1);
			}
		}
		
		return $runners;
	}
	
	/** @return list<string> Database's decoders by name, and the ones a file's obfuscation uses beside them (DECODERS) */
	protected static function decoders(): array
	{
		$decoders = self::DECODERS;
		
		foreach(Database::CODE_DECODERS as $marker)
		{
			$decoders[] = substr($marker, 0, -1);
		}
		
		return $decoders;
	}
	
	/** the media an include has no honest reason to name: the probed media but SVG (themes inline their icons by include) and the text formats */
	protected static function includeMedia(): array
	{
		return [...array_diff(self::MEDIA, ['svg']), ...self::MEDIA_TEXT];
	}
	
	/** whether the token at $index calls one of PHP's own $names: followed by `(`, not a method, a static, a definition or a constructor */
	protected static function callsOneOf(
		array $tokens,
		int $index,
		array $names,
	): bool
	{
		[$id, $text] = $tokens[$index];
		
		return ($id === T_STRING || $id === T_NAME_FULLY_QUALIFIED)
			&& in_array(strtolower(ltrim($text, '\\')), $names, true)
			&& ($tokens[$index + 1][0] ?? null) === '('
			&& in_array($tokens[$index - 1][0] ?? null, [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_CONST, T_NEW], true) === false;
	}
	
	/**
	 * The runner a call at $index makes, or null: a runner by its name, or
	 * one a parenthesised concatenation of literals builds — `('sys' .
	 * 'tem')(…)` — at the group's closing parenthesis
	 */
	protected static function runnerAt(
		array $tokens,
		int $index,
	): ?string
	{
		[$id, $text] = $tokens[$index];
		
		if(self::callsOneOf($tokens, $index, self::runners()))
		{
			return strtolower(ltrim($text, '\\'));
		}
		
		if($id !== ')' || ($tokens[$index + 1][0] ?? null) !== '(')
		{
			return null;
		}
		
		$name = '';
		
		for($i = $index - 1; $i >= 0 && $tokens[$i][0] !== '('; $i--)
		{
			if($tokens[$i][0] === T_CONSTANT_ENCAPSED_STRING)
			{
				$name = self::literal($tokens[$i][1]) . $name;
			}
			elseif($tokens[$i][0] !== '.')
			{
				return null;
			}
		}
		
		$name = strtolower($name);
		
		return $i >= 0 && self::groups($tokens, $i) && in_array($name, self::literalRunners(), true) ? $name : null;
	}
	
	/**
	 * Whether the `(` at $index groups rather than calls or opens a
	 * construct: what stands before it is no callee, keyword or string
	 */
	protected static function groups(
		array $tokens,
		int $index,
	): bool
	{
		return in_array($tokens[$index - 1][0] ?? null, [T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED, T_NAME_RELATIVE, T_VARIABLE,
			T_CONSTANT_ENCAPSED_STRING, ')', ']', '}', '"', T_ARRAY, T_LIST, T_ISSET, T_EMPTY, T_UNSET, T_EVAL, T_EXIT, T_IF, T_ELSEIF,
			T_WHILE, T_FOR, T_FOREACH, T_SWITCH, T_MATCH, T_FUNCTION, T_FN, T_USE, T_CATCH, T_DECLARE, T_NEW, T_STATIC,
			T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE], true) === false;
	}
	
	/**
	 * Request input that begins at $index, as [label, the index of its last
	 * token]: a superglobal, $GLOBALS['_GET'] and its kin, the raw body
	 * (php://input), a function that hands over the request (INPUT_FUNCTIONS).
	 * Of $_SERVER only the request's own fields count (serverInput())
	 *
	 * @return ?array{0: string, 1: int}
	 */
	protected static function inputAt(
		array $tokens,
		int $index,
	): ?array
	{
		[$id, $text] = $tokens[$index];
		
		if($id === T_VARIABLE && $text === '$GLOBALS')
		{
			$key = ($tokens[$index + 1][0] ?? null) === '[' && ($tokens[$index + 2][0] ?? null) === T_CONSTANT_ENCAPSED_STRING
				&& ($tokens[$index + 3][0] ?? null) === ']' ? '$' . self::literal($tokens[$index + 2][1]) : '';
			
			if(in_array($key, self::REQUEST_INPUT, true) === false)
			{
				return null;
			}
			
			$label = '$GLOBALS[' . substr($key, 1) . ']';
			
			return $key === '$_SERVER' ? self::serverInput($tokens, $index + 3, $label) : [$label, $index + 3];
		}
		
		if($id === T_VARIABLE && in_array($text, self::REQUEST_INPUT, true))
		{
			return $text === '$_SERVER' ? self::serverInput($tokens, $index, $text) : [$text, $index];
		}
		
		if($id === T_CONSTANT_ENCAPSED_STRING && strtolower(self::literal($text)) === 'php://input')
		{
			return ['php://input', $index];
		}
		
		if(self::callsOneOf($tokens, $index, self::INPUT_FUNCTIONS))
		{
			$close = self::closing($tokens, $index + 1);
			
			return [strtolower(ltrim($text, '\\')) . '()', $close];
		}
		
		return null;
	}
	
	/**
	 * $_SERVER, ending at $at, as input: its request fields — the headers
	 * (HTTP_*) and SERVER_INPUT — and a key that is no literal, since it may
	 * be a header; null for the server's own fields (DOCUMENT_ROOT,
	 * SCRIPT_FILENAME, SERVER_NAME …)
	 *
	 * @return ?array{0: string, 1: int}
	 */
	protected static function serverInput(
		array $tokens,
		int $at,
		string $label,
	): ?array
	{
		$key = $tokens[$at + 2] ?? null;
		
		if(($tokens[$at + 1][0] ?? null) !== '[' || ($key[0] ?? null) !== T_CONSTANT_ENCAPSED_STRING || ($tokens[$at + 3][0] ?? null) !== ']')
		{
			return [$label, $at];
		}
		
		$name = self::literal($key[1]);
		
		return str_starts_with($name, 'HTTP_') || in_array($name, self::SERVER_INPUT, true) ? [$label . '[' . $name . ']', $at + 3] : null;
	}
	
	/** the index of the token closing the bracket at $open, or the last one */
	protected static function closing(
		array $tokens,
		int $open,
	): int
	{
		$depth = 0;
		
		for($i = $open; isset($tokens[$i]); $i++)
		{
			$id = $tokens[$i][0];
			$depth += in_array($id, ['(', '[', '{', T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true) ? 1 : (in_array($id, [')', ']', '}'], true) ? -1 : 0);
			
			if($depth === 0)
			{
				return $i;
			}
		}
		
		return count($tokens) - 1;
	}
	
	/**
	 * The arguments of the call whose `(` stands at $open, as index ranges
	 * [from, to], empty ones left out
	 *
	 * @return list<array{0: int, 1: int}>
	 */
	protected static function arguments(
		array $tokens,
		int $open,
	): array
	{
		$close = self::closing($tokens, $open);
		$arguments = [];
		$from = $open + 1;
		$depth = 0;
		
		for($i = $open + 1; $i < $close; $i++)
		{
			$id = $tokens[$i][0];
			$depth += in_array($id, ['(', '[', '{', T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true) ? 1 : (in_array($id, [')', ']', '}'], true) ? -1 : 0);
			
			if($depth === 0 && $id === ',')
			{
				$arguments[] = [$from, $i - 1];
				$from = $i + 1;
			}
		}
		
		$arguments[] = [$from, $close - 1];
		
		return array_values(array_filter($arguments, static fn(array $range): bool => $range[0] <= $range[1]));
	}
	
	/**
	 * The runner at $index judged by what it is given. A function that calls
	 * the callable it is handed (CALLABLES) is judged by that argument:
	 * request input as the callable is urgent, a dispatch on request input
	 * through the code's own object or a literal prefix high, a runner the
	 * literal names is fed the other arguments, and any other callable is
	 * read for what it does with its parameters (callback()). Any other
	 * runner is fed all of them (fedBy())
	 *
	 * @param array{runs: array<string, string>, pending: array<string, array>, shells: int} $context codeVerdict()'s
	 * @return ?array{0: string, 1: string, 2: string, 3?: int}
	 */
	protected static function fed(
		array $tokens,
		int $index,
		string $runner,
		array &$context = ['runs' => [], 'pending' => [], 'shells' => 0],
	): ?array
	{
		if(($tokens[$index + 1][0] ?? null) !== '(')
		{
			return null;
		}
		
		$arguments = self::arguments($tokens, $index + 1);
		$position = self::CALLABLES[$runner] ?? null;
		
		if($position === null)
		{
			return self::fedBy($tokens, $arguments, $runner . '()');
		}
		
		$callable = $arguments[$position] ?? null;
		
		if($callable === null)
		{
			return null;
		}
		
		$verdict = self::callableIn($tokens, $callable[0], $callable[1]);
		$all = $arguments;
		unset($arguments[$position]);
		
		return match(true)
		{
			$verdict === 'input' => ['request_exec', self::TIER_URGENT, 'request input handed to ' . $runner . '() as the function it calls'],
			$verdict === 'dispatch' => ['request_exec', self::TIER_HIGH, $runner . '() dispatches on request input'],
			$verdict !== null => self::fedBy($tokens, $arguments, $verdict . '() through ' . $runner . '()'),
			default => self::callback($tokens, $index, $runner, $all, $context),
		};
	}
	
	/**
	 * A callable that is neither request input nor a runner's name, read for
	 * what it does with its parameters: a closure or arrow function the code
	 * writes, or a string naming a function this file defines, whose
	 * parameter reaches a runner (parameterSink()) is fed the arguments its
	 * parameters come from (CALLBACK_DATA). A string naming a function the
	 * file has not defined yet waits in `pending` until it does
	 * (codeVerdict())
	 *
	 * @param list<array{0: int, 1: int}> $arguments the call's arguments by position, the callable's included
	 * @return ?array{0: string, 1: string, 2: string}
	 */
	protected static function callback(
		array $tokens,
		int $index,
		string $runner,
		array $arguments,
		array &$context,
	): ?array
	{
		if(array_key_exists($runner, self::CALLBACK_DATA) === false)
		{
			return null;
		}
		
		$position = self::CALLABLES[$runner];
		$feeds = self::CALLBACK_DATA[$runner];
		[$from, $to] = $arguments[$position];
		$data = [];
		
		foreach($arguments as $at => $range)
		{
			if($feeds === null ? $at > $position : in_array($at, $feeds, true))
			{
				$data[] = $range;
			}
		}
		
		$first = $tokens[$from][0] === T_STATIC ? ($tokens[$from + 1][0] ?? null) : $tokens[$from][0];
		
		if($first === T_FUNCTION || $first === T_FN)
		{
			$sink = self::parameterSink($tokens, $from);
			
			return $sink === null ? null : self::fedBy($tokens, $data, $sink . ' in ' . $runner . '()\'s callback');
		}
		
		if($from !== $to || $tokens[$from][0] !== T_CONSTANT_ENCAPSED_STRING)
		{
			return null;
		}
		
		$name = strtolower(ltrim(self::literal($tokens[$from][1]), '\\'));
		$verdict = self::fedBy($tokens, $data, $name . '() through ' . $runner . '()');
		
		if($verdict === null || isset($context['runs'][$name]))
		{
			return $verdict;
		}
		
		$context['pending'][$name] ??= [...$verdict, (int)$tokens[$index][2]];
		
		return null;
	}
	
	/** the name a `function` at $index defines, lowercase; null for a closure and for `use function` */
	protected static function functionName(
		array $tokens,
		int $index,
	): ?string
	{
		if(($tokens[$index - 1][0] ?? null) === T_USE)
		{
			return null;
		}
		
		$next = in_array($tokens[$index + 1][0] ?? null, ['&', T_AMPERSAND_FOLLOWED_BY_VAR_OR_VARARG, T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG], true)
			? $index + 2
			: $index + 1;
		
		return ($tokens[$next][0] ?? null) === T_STRING ? strtolower($tokens[$next][1]) : null;
	}
	
	/**
	 * What the function or closure whose `function`, `fn` or `static` stands
	 * at $at hands one of its parameters to (sinkOf()), or null. Its body is
	 * read within the slice it stands in
	 */
	protected static function parameterSink(
		array $tokens,
		int $at,
	): ?string
	{
		$open = $at;
		
		// past `static`, `&` and the name to the parameter list
		while(isset($tokens[$open]) && $tokens[$open][0] !== '(')
		{
			$open++;
		}
		
		if(isset($tokens[$open]) === false)
		{
			return null;
		}
		
		$close = self::closing($tokens, $open);
		$parameters = [];
		
		for($i = $open + 1; $i < $close; $i++)
		{
			if($tokens[$i][0] === T_VARIABLE)
			{
				$parameters[] = $tokens[$i][1];
			}
		}
		
		[$from, $to] = self::body($tokens, $close);
		
		for($i = $from; $parameters !== [] && $i < $to; $i++)
		{
			$sink = self::sinkOf($tokens, $i, $parameters);
			
			if($sink !== null)
			{
				return $sink;
			}
			
			// a shell command's tokens are its content: the backtick closing it opens none
			$i = $tokens[$i][0] === '`' ? self::quoteEnd($tokens, $i) : $i;
		}
		
		return null;
	}
	
	/**
	 * The body of a function whose parameter list closes at $close, as an
	 * index range [from, to): its braces, or an arrow function's expression
	 * up to the `,`, `;` or bracket that ends it; empty for an abstract one
	 *
	 * @return array{0: int, 1: int}
	 */
	protected static function body(
		array $tokens,
		int $close,
	): array
	{
		for($i = $close + 1; isset($tokens[$i]); $i++)
		{
			$id = $tokens[$i][0];
			
			if($id === '{')
			{
				return [$i + 1, self::closing($tokens, $i)];
			}
			
			if($id === ';')
			{
				return [$i, $i];
			}
			
			if($id === T_DOUBLE_ARROW)
			{
				return [$i + 1, self::expressionEnd($tokens, $i + 1)];
			}
		}
		
		return [count($tokens), count($tokens)];
	}
	
	/** the index of the `,`, `;`, `?>` or closing bracket that ends the expression starting at $from, or the slice's end */
	protected static function expressionEnd(
		array $tokens,
		int $from,
	): int
	{
		$depth = 0;
		
		for($i = $from; isset($tokens[$i]); $i++)
		{
			$id = $tokens[$i][0];
			
			if(in_array($id, ['(', '[', '{', T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true))
			{
				$depth++;
			}
			elseif(in_array($id, [')', ']', '}'], true) && --$depth < 0)
			{
				return $i;
			}
			elseif($depth === 0 && in_array($id, [',', ';', T_CLOSE_TAG], true))
			{
				return $i;
			}
		}
		
		return count($tokens);
	}
	
	/**
	 * What the token at $i hands one of $parameters to: eval(), an include,
	 * a shell command in backticks, a runner by its name — a function that
	 * calls a callable only with the parameter as that callable — or the
	 * parameter called itself; null for none
	 *
	 * @param list<string> $parameters the variables' names, `$` included
	 */
	protected static function sinkOf(
		array $tokens,
		int $i,
		array $parameters,
	): ?string
	{
		$id = $tokens[$i][0];
		
		if($id === T_VARIABLE && in_array($tokens[$i][1], $parameters, true) && ($tokens[$i + 1][0] ?? null) === '(')
		{
			return 'a call of its parameter';
		}
		
		[$sink, $ranges] = match(true)
		{
			$id === T_EVAL => ['eval()', self::arguments($tokens, $i + 1)],
			in_array($id, [T_INCLUDE, T_INCLUDE_ONCE, T_REQUIRE, T_REQUIRE_ONCE], true) => ['an include', [[$i + 1, self::expressionEnd($tokens, $i + 1) - 1]]],
			$id === '`' => ['a shell command in backticks', [[$i + 1, self::quoteEnd($tokens, $i) - 1]]],
			default => [null, []],
		};
		
		$runner = $sink === null ? self::runnerAt($tokens, $i) : null;
		
		if($runner !== null && ($tokens[$i + 1][0] ?? null) === '(')
		{
			$arguments = self::arguments($tokens, $i + 1);
			$sink = $runner . '()';
			$ranges = isset(self::CALLABLES[$runner]) ? array_values(array_filter([$arguments[self::CALLABLES[$runner]] ?? null])) : $arguments;
		}
		
		foreach($ranges as [$from, $to])
		{
			for($j = $from; $j <= $to; $j++)
			{
				if($tokens[$j][0] === T_VARIABLE && in_array($tokens[$j][1], $parameters, true))
				{
					return $sink;
				}
			}
		}
		
		return null;
	}
	
	/** the index of the backtick that closes the one at $open, or the slice's end */
	protected static function quoteEnd(
		array $tokens,
		int $open,
	): int
	{
		for($i = $open + 1; isset($tokens[$i]) && $tokens[$i][0] !== '`'; $i++)
		{
		}
		
		return $i;
	}
	
	/**
	 * What a callable argument between $from and $to is: request input alone
	 * ('input'), a literal naming a runner (its name), request input beside
	 * the code's own (`[$this, $_GET['a']]`, `'prefix_' . $_GET['a']`:
	 * 'dispatch'), or null. A closure the code writes is its own callable,
	 * whatever its body reads; what that body runs is read where it stands
	 */
	protected static function callableIn(
		array $tokens,
		int $from,
		int $to,
	): ?string
	{
		$first = $tokens[$from][0] === T_STATIC ? ($tokens[$from + 1][0] ?? null) : $tokens[$from][0];
		
		if($first === T_FUNCTION || $first === T_FN)
		{
			return null;
		}
		
		$input = self::inputAt($tokens, $from);
		$end = $input[1] ?? -1;
		
		// the input's own subscripts are still the input
		while($input !== null && ($tokens[$end + 1][0] ?? null) === '[')
		{
			$end = self::closing($tokens, $end + 1);
		}
		
		if($input !== null && $end >= $to)
		{
			return 'input';
		}
		
		$name = '';
		
		for($i = $from; $i <= $to; $i++)
		{
			if(self::inputAt($tokens, $i) !== null)
			{
				return 'dispatch';
			}
			
			$name = $tokens[$i][0] === T_CONSTANT_ENCAPSED_STRING ? $name . self::literal($tokens[$i][1]) : ($tokens[$i][0] === '.' ? $name : '-');
		}
		
		return in_array(strtolower($name), self::literalRunners(), true) ? strtolower($name) : null;
	}
	
	/**
	 * A runner judged by its arguments: request input in them is urgent,
	 * high where an escaper, a sanitizer or a cast wraps it (SANITIZERS); a
	 * decoder's call or a stream's content in them is eval_chain
	 *
	 * @param array<int, array{0: int, 1: int}> $arguments arguments()'s ranges
	 * @return ?array{0: string, 1: string, 2: string}
	 */
	protected static function fedBy(
		array $tokens,
		array $arguments,
		string $label,
	): ?array
	{
		$raw = null;
		$cleaned = null;
		$decoder = null;
		
		foreach($arguments as [$from, $to])
		{
			$callees = [];
			
			for($i = $from; $i <= $to; $i++)
			{
				[$id, $text] = $tokens[$i];
				
				if($id === '(')
				{
					$callees[] = in_array($tokens[$i - 1][0] ?? null, [T_STRING, T_NAME_FULLY_QUALIFIED], true) ? strtolower(ltrim($tokens[$i - 1][1], '\\')) : '';
					
					continue;
				}
				
				if($id === ')')
				{
					array_pop($callees);
					
					continue;
				}
				
				$input = self::inputAt($tokens, $i);
				
				if($input !== null)
				{
					$wrapper = array_values(array_intersect($callees, self::SANITIZERS))[0]
						?? (in_array($tokens[$i - 1][0] ?? null, [T_INT_CAST, T_DOUBLE_CAST, T_BOOL_CAST], true) ? 'a cast' : null);
					
					if($wrapper === null)
					{
						$raw ??= $input[0];
					}
					else
					{
						$cleaned ??= [$input[0], $wrapper];
					}
					
					$i = max($i, $input[1]);
					
					continue;
				}
				
				if(self::callsOneOf($tokens, $i, self::decoders()))
				{
					$decoder ??= strtolower(ltrim($text, '\\')) . '()';
				}
				elseif($id === T_CONSTANT_ENCAPSED_STRING && preg_match(self::STREAMS, self::literal($text), $match) === 1)
				{
					$decoder ??= 'a ' . rtrim(strtolower($match[0]), ':/') . ' stream';
				}
			}
		}
		
		return match(true)
		{
			$raw !== null => ['request_exec', self::TIER_URGENT, $label . ' fed by request input (' . $raw . ')'],
			$cleaned !== null => ['request_exec', self::TIER_HIGH, $label . ' fed by request input through ' . $cleaned[1] . ' (' . $cleaned[0] . ')'],
			$decoder !== null => ['eval_chain', self::TIER_HIGH, $label . ' fed by ' . $decoder],
			default => null,
		};
	}
	
	/**
	 * A shell command in backticks, opened at $index, fed by request input
	 *
	 * @return ?array{0: string, 1: string, 2: string}
	 */
	protected static function backticked(
		array $tokens,
		int $index,
	): ?array
	{
		for($i = $index + 1; isset($tokens[$i]) && $tokens[$i][0] !== '`'; $i++)
		{
			$input = self::inputAt($tokens, $i);
			
			if($input !== null)
			{
				return ['request_exec', self::TIER_URGENT, 'a shell command in backticks fed by request input (' . $input[0] . ')'];
			}
		}
		
		return null;
	}
	
	/**
	 * Request input at $index called as a function — `$_POST['f']($x)`,
	 * `($_POST['f'])($x)`, the one-line shell that needs no executor's name
	 *
	 * @param array{0: string, 1: int} $input inputAt()'s
	 * @return ?array{0: string, 1: string, 2: string}
	 */
	protected static function requestCalled(
		array $tokens,
		int $index,
		array $input,
	): ?array
	{
		$i = $input[1] + 1;
		$subscripts = 0;
		
		while(($tokens[$i][0] ?? null) === '[')
		{
			$i = self::closing($tokens, $i) + 1;
			$subscripts++;
		}
		
		// parentheses that only group the input close after it
		for($open = $index - 1; ($tokens[$open][0] ?? null) === '(' && self::groups($tokens, $open) && ($tokens[$i][0] ?? null) === ')'; $open--)
		{
			$i++;
		}
		
		return $subscripts > 0 && ($tokens[$i][0] ?? null) === '('
			? ['request_exec', self::TIER_URGENT, 'request input called as a function (' . $input[0] . ')']
			: null;
	}
	
	/**
	 * The include at $index judged by what its expression names: request
	 * input (request_exec); a stream URL, a path under uploads or in a temp
	 * directory, a media file (include_foreign). Literals are read as PHP
	 * reads them, escapes resolved, so an octal-spelled path is the path; a
	 * subscript's key names no path; the file's name is the literals that end
	 * the expression, however they are split. A fixed PHP file under uploads
	 * is high (urgent in wp-config.php, with `strict`), nothing in an uploads
	 * folder an installed plugin writes (`owned`)
	 *
	 * @param array{uploads?: string, temp?: list<string>, owned?: list<string>, strict?: bool} $places
	 * @return ?array{0: string, 1: string, 2: string}
	 */
	protected static function included(
		array $tokens,
		int $index,
		array $places,
	): ?array
	{
		$parts = [];
		$names = [];
		$input = null;
		$tail = '';
		$depth = 0;
		
		for($i = $index + 1; isset($tokens[$i]); $i++)
		{
			[$id, $text] = $tokens[$i];
			
			if($depth === 0 && in_array($id, [';', ',', T_CLOSE_TAG], true))
			{
				break;
			}
			
			if(in_array($id, ['(', '['], true))
			{
				$depth++;
				
				continue;
			}
			
			if(in_array($id, [')', ']'], true))
			{
				// `if(include 'x')`: the parenthesis closing round the include ends it
				if($depth-- === 0)
				{
					break;
				}
				
				continue;
			}
			
			// the quotes round an interpolated string and the concatenation say nothing of the path
			if($id === '"' || $id === '.')
			{
				continue;
			}
			
			$found = self::inputAt($tokens, $i);
			
			if($found !== null)
			{
				$input ??= $found[0];
				$i = max($i, $found[1]);
				
				continue;
			}
			
			if(($id === T_CONSTANT_ENCAPSED_STRING || $id === T_ENCAPSED_AND_WHITESPACE) && ($tokens[$i - 1][0] ?? null) !== '[')
			{
				$part = $id === T_CONSTANT_ENCAPSED_STRING ? self::literal($text) : stripcslashes($text);
				$parts[] = strtolower(str_replace('\\', '/', $part));
				$tail .= $part;
				
				continue;
			}
			
			$tail = '';
			
			if($id === T_STRING || $id === T_NAME_FULLY_QUALIFIED)
			{
				$names[] = strtolower(ltrim($text, '\\'));
			}
		}
		
		if($input !== null)
		{
			return ['request_exec', self::TIER_URGENT, 'include of request input (' . $input . ')'];
		}
		
		foreach($parts as $part)
		{
			if(preg_match(self::STREAMS, ltrim($part), $match) === 1)
			{
				return ['include_foreign', self::TIER_URGENT, 'include of a ' . rtrim($match[0], ':/') . ' stream'];
			}
		}
		
		$joined = implode('', $parts);
		$uploads = (string)($places['uploads'] ?? '');
		$after = null;
		
		foreach(['wp-content/uploads/', $uploads === '' ? null : $uploads . '/'] as $marker)
		{
			$at = $marker === null ? false : strpos($joined, $marker);
			$after ??= $at === false ? null : substr($joined, $at + strlen($marker));
		}
		
		if($after === null && array_intersect($names, ['wp_upload_dir', 'wp_get_upload_dir']) !== [])
		{
			$after = ltrim($joined, '/');
		}
		
		if($after !== null)
		{
			// a fixed PHP file a plugin keeps under uploads, unless wp-config.php includes it
			if(($places['strict'] ?? false) === false && preg_match('~/[^/]+\.php$~i', '/' . str_replace('\\', '/', $tail)) === 1)
			{
				return in_array(explode('/', ltrim($after, '/'), 2)[0], (array)($places['owned'] ?? []), true)
					? null
					: ['include_foreign', self::TIER_HIGH, 'include of a PHP file under uploads'];
			}
			
			return ['include_foreign', self::TIER_URGENT, 'include of a file under uploads'];
		}
		
		$temp = (array)($places['temp'] ?? []);
		
		foreach($parts as $part)
		{
			if(preg_match('~^(?:/tmp|/var/tmp|/dev/shm)/~', $part) === 1
				|| array_filter($temp, static fn(string $dir): bool => str_starts_with($part, $dir . '/')) !== [])
			{
				return ['include_foreign', self::TIER_URGENT, 'include of a file in a temp directory'];
			}
		}
		
		if(array_intersect($names, ['sys_get_temp_dir', 'get_temp_dir']) !== [])
		{
			return ['include_foreign', self::TIER_URGENT, 'include of a file in a temp directory'];
		}
		
		$extension = self::extension(strtolower($tail));
		
		return in_array($extension, self::includeMedia(), true)
			? ['include_foreign', self::TIER_URGENT, 'include of a .' . $extension . ' file']
			: null;
	}
	
	/** a quoted literal as PHP reads it: a single-quoted one knows two escapes, a double-quoted one C's */
	protected static function literal(
		string $token,
	): string
	{
		$token = ltrim($token, 'bB');
		$body = substr($token, 1, -1);
		
		return ($token[0] ?? '') === "'" ? strtr($body, ['\\\\' => '\\', "\\'" => "'"]) : stripcslashes($body);
	}
	
	/** the extension of a lowercase file name, '' for none */
	protected static function extension(
		string $lower,
	): string
	{
		$dot = strrpos($lower, '.');
		
		return $dot === false ? '' : substr($lower, $dot + 1);
	}
	
	/**
	 * Who owns an arbitrary path a directive points at: a file inside an
	 * installed plugin's directory, or a known root file whose plugin is
	 * installed (Wordfence's prepend), or this plugin's own prepend stub in
	 * its store directory (wp-content/ovos-codesafe/, or ovos-console/ under its
	 * first name) while the plugin is installed. Anything else is nobody's.
	 */
	protected function ownerOfPath(
		string $target,
	): ?string
	{
		$target = $this->normalize($target);
		$name = basename($target);
		
		// wp-content/ovos-console/ is the same directory under the plugin's first
		// name: its stub may still be what PHP prepends, and runs this plugin
		if((str_starts_with($target, $this->roots['content'] . '/ovos-codesafe/') || str_starts_with($target, $this->roots['content'] . '/ovos-console/'))
			&& (is_dir($this->roots['plugins'] . '/ovos-codesafe') || is_dir($this->roots['mu'] . '/ovos-codesafe')))
		{
			return 'plugin:ovos-codesafe';
		}
		
		if(isset(self::ROOT_OWNERS[$name]))
		{
			$owner = $this->installedOwner(self::ROOT_OWNERS[$name]);
			
			if($owner !== null)
			{
				return $owner;
			}
		}
		
		foreach(['plugins' => 'plugin', 'mu' => 'mu-plugin'] as $root => $type)
		{
			$prefix = $this->roots[$root] . '/';
			
			if(str_starts_with($target, $prefix))
			{
				$slug = explode('/', substr($target, strlen($prefix)), 2)[0];
				
				if($slug !== '' && (is_dir($prefix . $slug) || is_file($prefix . $slug)))
				{
					return $type . ':' . $slug;
				}
			}
		}
		
		return null;
	}
	
	/**
	 * Whether a redirect target leaves the site — hosts compared without a
	 * leading www., so a move between the two spellings is not a finding
	 */
	protected function isForeignHost(
		string $host,
	): bool
	{
		$this->host ??= $this->siteHost();
		
		$strip = static fn(string $value): string => preg_replace('~^www\.~', '', strtolower(explode(':', $value, 2)[0])) ?? '';
		
		return $this->host !== '' && $strip($host) !== $strip($this->host);
	}
	
	protected function siteHost(): string
	{
		if(function_exists('home_url') === false)
		{
			return '';
		}
		
		$host = wp_parse_url((string)home_url(), PHP_URL_HOST);
		
		return is_string($host) ? $host : '';
	}
	
	public function isStub(
		string $path,
		int $size,
	): bool
	{
		if($size === 0)
		{
			return true;
		}
		
		if($size > self::STUB_BYTES)
		{
			return false;
		}
		
		$head = $this->head($path, self::STUB_BYTES);
		
		return $head !== null && self::stubShaped($head);
	}
	
	/**
	 * Whether $source is a stub by what PHP would run: an opener, comments and
	 * whitespace, an optional closer with only whitespace after it. The
	 * tokenizer judges because a pattern cannot: PHP ends a `//` comment at a
	 * bare CR or at `?>`, and a `#[` line is an attribute
	 */
	public static function stubShaped(
		string $source,
		?bool $tokenizer = null,
	): bool
	{
		if(($tokenizer ?? function_exists('token_get_all')) === false)
		{
			return preg_match(self::STUB_STRICT, $source) === 1;
		}
		
		// 0 before the opener, 1 inside PHP, 2 after the closer
		$phase = 0;
		
		foreach(token_get_all($source) as $token)
		{
			$id = is_array($token) ? $token[0] : null;
			
			// whitespace around the PHP block is output, never code
			if($phase !== 1 && $id === T_INLINE_HTML && trim($token[1]) === '')
			{
				continue;
			}
			
			if($phase === 0 && $id === T_OPEN_TAG)
			{
				$phase = 1;
			}
			elseif($phase === 1 && $id === T_CLOSE_TAG)
			{
				$phase = 2;
			}
			elseif($phase !== 1 || in_array($id, [T_COMMENT, T_DOC_COMMENT, T_WHITESPACE], true) === false)
			{
				return false;
			}
		}
		
		return $phase !== 0;
	}
	
	/**
	 * Whether a media file's first block holds PHP that could run: an opener
	 * (`<?php` in any case before whitespace, or `<?=`) whose code up to the
	 * first closer has no byte PHP refuses. Such a byte fails the whole file's
	 * compile, so the `<?=` that compressed image data happens to contain is no
	 * shell. Without the tokenizer any opener counts
	 */
	public static function opensPhp(
		string $head,
		?bool $tokenizer = null,
	): bool
	{
		if(preg_match('~<\?(?:php(?=\s|$)|=)~i', $head, $match, PREG_OFFSET_CAPTURE) !== 1)
		{
			return false;
		}
		
		if(($tokenizer ?? function_exists('token_get_all')) === false)
		{
			return true;
		}
		
		$code = substr($head, $match[0][1]);
		$close = strpos($code, '?>');
		
		foreach(token_get_all($close === false ? $code : substr($code, 0, $close + 2)) as $token)
		{
			if(is_array($token) && $token[0] === T_BAD_CHARACTER)
			{
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * A drop-in that carries a vendor header — plugin headers, package
	 * tags, a copyright or licence line — in its first kilobyte
	 */
	protected function looksVendored(
		string $path,
	): bool
	{
		$head = $this->head($path, self::HEAD_BYTES);
		
		return $head !== null
			&& preg_match('~Plugin Name:|@package|@author|Copyright|License|Version:~i', $head) === 1;
	}
	
	protected function head(
		string $path,
		int $bytes,
	): ?string
	{
		$handle = @fopen($path, 'rb');
		
		if($handle === false)
		{
			return null;
		}
		
		$head = @fread($handle, $bytes);
		fclose($handle);
		
		return is_string($head) ? $head : null;
	}
	
	protected function permits(
		string $path,
		int $bit,
	): ?bool
	{
		$perms = @fileperms($path);
		
		return $perms === false ? null : ($perms & $bit) !== 0;
	}
	
	/**
	 * wp-config.php stands in ABSPATH or, by core's own convention, one
	 * level above it
	 */
	protected function configPath(
		string $root,
	): ?string
	{
		foreach([$root . '/wp-config.php', dirname($root) . '/wp-config.php'] as $candidate)
		{
			if(is_file($candidate))
			{
				return $candidate;
			}
		}
		
		return null;
	}
	
	/**
	 * The active plugins' slugs — directory names, or the file name of a
	 * single-file plugin — network-activated ones included. Those are the
	 * network's: activate_plugin() writes them with update_site_option(),
	 * into sitemeta, where the site's own get_option() never looks
	 *
	 * @return list<string>
	 */
	public function activeSlugs(): array
	{
		$files = (array)get_option('active_plugins', []);
		
		if(function_exists('is_multisite') && is_multisite())
		{
			foreach((array)get_site_option('active_sitewide_plugins', []) as $file => $time)
			{
				$files[] = $file;
			}
		}
		
		return self::slugsOf($files);
	}
	
	/**
	 * What the site runs: the plugins active on this site or network-wide,
	 * and on a network on any of its sites, by slug as activeSlugs()
	 * derives them; the themes as each site's stylesheet and template
	 * OPTIONS — get_stylesheet() is a per-request filter, the option is what
	 * the site runs. Null past SITES_MAX sites: not knowable at a bounded
	 * cost, and a plugin called not active must never be a guess. The
	 * network-active row is the current network's; the sites are every
	 * network's
	 *
	 * @return ?array{plugins: list<string>, themes: list<string>}
	 */
	public function activeAnywhere(): ?array
	{
		$plugins = $this->activeSlugs();
		$themes = [(string)get_option('stylesheet', ''), (string)get_option('template', '')];
		
		if(function_exists('is_multisite') && is_multisite())
		{
			// one more than the cap asked for, so a network past it reads as one
			$sites = (array)get_sites(['fields' => 'ids', 'number' => self::SITES_MAX + 1]);
			
			if(count($sites) > self::SITES_MAX)
			{
				return null;
			}
			
			$current = (int)get_current_blog_id();
			
			foreach($sites as $site)
			{
				$site = (int)$site;
				
				if($site === $current)
				{
					continue;
				}
				
				$plugins = [...$plugins, ...self::slugsOf((array)get_blog_option($site, 'active_plugins', []))];
				$themes[] = (string)get_blog_option($site, 'stylesheet', '');
				$themes[] = (string)get_blog_option($site, 'template', '');
			}
		}
		
		return [
			'plugins' => array_values(array_unique($plugins)),
			'themes' => array_values(array_unique(array_filter($themes, static fn(string $theme): bool => $theme !== ''))),
		];
	}
	
	/**
	 * Plugin files as WordPress lists them active (`akismet/akismet.php`,
	 * `hello.php`) as slugs: the directory, or a single file's name
	 *
	 * @param array<mixed> $files
	 * @return list<string>
	 */
	protected static function slugsOf(
		array $files,
	): array
	{
		$slugs = [];
		
		foreach($files as $file)
		{
			if(is_string($file) === false)
			{
				continue;
			}
			
			$directory = dirname($file);
			$slugs[] = $directory === '.' || $directory === '' ? basename($file, '.php') : $directory;
		}
		
		return $slugs;
	}
	
	/**
	 * The first active plugin that answers a protection question, '' when
	 * none does. Jetpack counts for the login question only with its
	 * Protect module on.
	 *
	 * @param list<string> $active
	 */
	protected function protection(
		string $kind,
		array $active,
	): string
	{
		foreach(self::PROTECTION[$kind] ?? [] as $slug)
		{
			if(in_array($slug, $active, true))
			{
				return $slug;
			}
		}
		
		if($kind === 'login_protection' && in_array('jetpack', $active, true)
			&& class_exists('Jetpack') && method_exists('Jetpack', 'is_module_active') && \Jetpack::is_module_active('protect'))
		{
			return 'jetpack';
		}
		
		return '';
	}
	
	/**
	 * The debug log's path when WP_DEBUG_LOG writes one UNDER the document
	 * root and the file exists — the leak; null when logging is off, the
	 * file is absent, or it lives outside the site where it belongs
	 */
	protected function debugLog(
		array $roots,
	): ?string
	{
		if(defined('WP_DEBUG_LOG') === false || (bool)WP_DEBUG_LOG === false)
		{
			return null;
		}
		
		$path = is_string(WP_DEBUG_LOG) && WP_DEBUG_LOG !== '' ? WP_DEBUG_LOG : $roots['content'] . '/debug.log';
		$path = $this->normalize($path);
		
		return is_file($path) && str_starts_with($path, $roots['root'] . '/') ? $path : null;
	}
	
	protected function server(): string
	{
		return self::serverOf(isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash((string)$_SERVER['SERVER_SOFTWARE'])) : '');
	}
	
	/** the web server SERVER_SOFTWARE names, in the posture's words: litespeed, apache, nginx, iis, caddy or unknown */
	public static function serverOf(
		string $software,
	): string
	{
		$software = strtolower($software);
		
		return match(true)
		{
			str_contains($software, 'litespeed') => 'litespeed',
			str_contains($software, 'apache') => 'apache',
			str_contains($software, 'nginx') => 'nginx',
			str_contains($software, 'microsoft-iis') => 'iis',
			str_contains($software, 'caddy') => 'caddy',
			default => 'unknown',
		};
	}
	
	protected function constantWord(
		mixed $value,
	): string
	{
		if($value === true)
		{
			return 'true';
		}
		
		if($value === false)
		{
			return 'false';
		}
		
		return $this->clean((string)$value, 32);
	}
	
	/**
	 * The area roots, normalised to forward slashes without a trailing one
	 *
	 * @return array<string, string>
	 */
	public function roots(): array
	{
		$root = $this->normalize((string)ABSPATH);
		$content = defined('WP_CONTENT_DIR') ? $this->normalize((string)WP_CONTENT_DIR) : $root . '/wp-content';
		
		return [
			'root' => $root,
			'content' => $content,
			'plugins' => defined('WP_PLUGIN_DIR') ? $this->normalize((string)WP_PLUGIN_DIR) : $content . '/plugins',
			'mu' => defined('WPMU_PLUGIN_DIR') ? $this->normalize((string)WPMU_PLUGIN_DIR) : $content . '/mu-plugins',
			'themes' => function_exists('get_theme_root') ? $this->normalize((string)get_theme_root()) : $content . '/themes',
			'uploads' => function_exists('wp_get_upload_dir')
				? $this->normalize((string)(wp_get_upload_dir()['basedir'] ?? ''))
				: '',
		];
	}
	
	protected function normalize(
		string $path,
	): string
	{
		return rtrim(str_replace('\\', '/', $path), '/');
	}
	
	protected function relative(
		string $path,
		string $root,
	): string
	{
		$path = $this->normalize($path);
		
		return $root !== '' && str_starts_with($path, $root . '/')
			? substr($path, strlen($root) + 1)
			: $path;
	}
	
	/**
	 * Attacker-authored text on its way to a report: control characters
	 * replaced, length capped
	 */
	protected function clean(
		string $value,
		int $max = self::MAX_PATH,
	): string
	{
		$value = (string)preg_replace('~[\x00-\x1f\x7f]~', '?', $value);
		
		return strlen($value) > $max ? substr($value, 0, $max) : $value;
	}
}
