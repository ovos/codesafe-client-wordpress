<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Database as PluginDatabase;
use Ovos\Codesafe\Scan;
use Ovos\Test;
use Ovos\Test\Internal;

use function add_action;
use function addcslashes;
use function addslashes;
use function array_column;
use function array_filter;
use function array_keys;
use function array_map;
use function array_slice;
use function array_values;
use function bin2hex;
use function count;
use function dirname;
use function explode;
use function file_put_contents;
use function in_array;
use function is_dir;
use function mkdir;
use function preg_match;
use function preg_match_all;
use function preg_replace_callback;
use function random_bytes;
use function range;
use function realpath;
use function rmdir;
use function scandir;
use function str_contains;
use function str_ends_with;
use function str_pad;
use function str_repeat;
use function str_replace;
use function str_starts_with;
use function strcmp;
use function stripcslashes;
use function stripslashes;
use function strlen;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;
use function usort;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;
use const STR_PAD_LEFT;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * The integrity scan's database detectors without WordPress: the shim's
 * _get_cron_array() and has_action() stand in for the site.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Database extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/**
	 * RULE: a scheduled hook nothing listens to is a cron_orphan that names
	 * its schedule and next run in the detail and carries no mtime, since the
	 * next run is no write and codesafe dates a row's mtime against attack
	 * waves; a hook with a listener is no finding. Falsify: pass the next run
	 * as the mtime — the console matches a schedule against a probing address.
	 */
	public function aCronOrphanCarriesNoDateAndNamesTheNextRun(): bool
	{
		$GLOBALS['wp']['cron'] = [1_792_500_000 => [
			'gone_plugin_cleanup' => ['abc' => ['schedule' => 'hourly']],
			'kept_hook' => ['def' => ['schedule' => 'daily']],
		]];
		add_action('kept_hook', 'strlen');
		
		$database = new class extends PluginDatabase
		{
			public function cronFindings(): array
			{
				$stats = ['cron_hooks' => 0];
				
				return $this->cron($stats);
			}
		};
		$findings = $database->cronFindings();
		
		return count($findings) === 1
			&& $findings[0]['detector'] === 'cron_orphan'
			&& $findings[0]['path'] === 'options/cron/gone_plugin_cleanup'
			&& isset($findings[0]['mtime']) === false
			&& str_contains($findings[0]['detail'], 'hourly, next 2026-10-20 12:40');
	}
	
	/**
	 * RULE: on a network a plugin activated network-wide is read from the
	 * network's options, where activate_plugin() writes it, so one whose path
	 * leaves the plugins directory is an active_plugin_missing finding like a
	 * site's own. Falsify: read active_sitewide_plugins with get_option() —
	 * the network's loader is never seen.
	 */
	public function aNetworkActivePluginIsCheckedLikeTheSitesOwn(): bool
	{
		$GLOBALS['wp']['multisite'] = true;
		$GLOBALS['wp']['site_options']['active_sitewide_plugins'] = ['../uploads/loader.php' => 1_792_500_000];
		
		$database = new class extends PluginDatabase
		{
			public function activeFindings(): array
			{
				$stats = [];
				
				return $this->activePlugins($stats);
			}
		};
		$findings = $database->activeFindings();
		
		return count($findings) === 1
			&& $findings[0]['detector'] === 'active_plugin_missing'
			&& $findings[0]['path'] === 'options/active_plugins/../uploads/loader.php';
	}
	
	/** a temp tree gone, files first */
	protected function remove(
		string $path,
	): void
	{
		foreach(is_dir($path) ? (array)scandir($path) : [] as $entry)
		{
			if($entry !== '.' && $entry !== '..')
			{
				is_dir($path . '/' . $entry) ? $this->remove($path . '/' . $entry) : unlink($path . '/' . $entry);
			}
		}
		
		if(is_dir($path))
		{
			rmdir($path);
		}
	}
	
	/**
	 * A $wpdb that answers a query with the rows of the table it names that
	 * its conditions keep: `IN` / `=` on post_status and post_type, `NOT IN` /
	 * `NOT LIKE '<prefix>%'` on option_name, and any of its `LIKE '%…%'`
	 * markers in the content or the value — the statement is the plugin's,
	 * the rows are the test's
	 *
	 * @param list<array<string, mixed>> $options option_name, option_value
	 * @param list<array<string, mixed>> $posts ID, post_type, post_status, post_content, post_modified_gmt
	 */
	protected function wpdb(
		array $options,
		array $posts,
	): object
	{
		return new class($options, $posts)
		{
			public string $options = 'wp_options';
			
			public string $posts = 'wp_posts';
			
			/** @var list<string> */
			public array $queries = [];
			
			public function __construct(
				protected array $optionRows,
				protected array $postRows,
			)
			{
			}
			
			public function esc_like(
				string $text,
			): string
			{
				return addcslashes($text, '_%\\');
			}
			
			/** %s quoted and slashed, %d an integer, as core's prepare() */
			public function prepare(
				string $query,
				mixed ...$args,
			): string
			{
				$index = 0;
				
				return (string)preg_replace_callback('~%[sd]~', static function(array $match) use (&$index, $args): string
				{
					$value = $args[$index++] ?? '';
					
					return $match[0] === '%d' ? (string)(int)$value : "'" . addslashes((string)$value) . "'";
				}, $query);
			}
			
			public function get_results(
				string $query,
				string $output = 'OBJECT',
			): array
			{
				$this->queries[] = $query;
				
				return $this->select($query);
			}
			
			public function get_var(
				string $query,
			): int
			{
				$this->queries[] = $query;
				
				return count($this->select($query));
			}
			
			/** the quoted values of `<column> <operator> (…)`, or of `<column> = '…'` for IN; null when the query has neither */
			protected function values(
				string $query,
				string $column,
				string $operator,
			): ?array
			{
				if(preg_match('~' . $column . ' ' . $operator . ' \(([^)]*)\)~', $query, $match) === 1)
				{
					preg_match_all("~'((?:[^'\\\\]|\\\\.)*)'~", $match[1], $values);
					
					return array_map('stripslashes', $values[1]);
				}
				
				if($operator === 'IN' && preg_match("~" . $column . " = '((?:[^'\\\\]|\\\\.)*)'~", $query, $match) === 1)
				{
					return [stripslashes($match[1])];
				}
				
				return null;
			}
			
			protected function select(
				string $query,
			): array
			{
				$posts = str_contains($query, 'FROM wp_posts');
				preg_match_all("~ LIKE '%((?:[^'\\\\]|\\\\.)*)%'~", $query, $likes);
				$markers = array_map(static fn(string $like): string => stripcslashes(stripslashes($like)), $likes[1]);
				$statuses = $this->values($query, 'post_status', 'IN');
				$types = $this->values($query, 'post_type', 'IN');
				$excluded = $this->values($query, 'option_name', 'NOT IN') ?? [];
				$prefix = preg_match("~option_name NOT LIKE '((?:[^'\\\\]|\\\\.)*)%'~", $query, $match) === 1 ? stripcslashes(stripslashes($match[1])) : null;
				$after = preg_match('~ID > (\\d+)~', $query, $match) === 1 ? (int)$match[1] : null;
				$ids = preg_match('~ID IN \(([\\d, ]+)\)~', $query, $match) === 1 ? array_map('intval', explode(',', $match[1])) : null;
				$rows = [];
				
				foreach($posts ? $this->postRows : $this->optionRows as $row)
				{
					$text = (string)($posts ? $row['post_content'] : $row['option_value']);
					$marked = $markers === [];
					
					foreach($markers as $marker)
					{
						$marked = $marked || str_contains($text, $marker);
					}
					
					$kept = $marked && ($posts
						? ($statuses === null || in_array($row['post_status'], $statuses, true)) && ($types === null || in_array($row['post_type'], $types, true))
						: in_array($row['option_name'], $excluded, true) === false && ($prefix === null || str_starts_with($row['option_name'], $prefix) === false));
					
					if($kept && ($after === null || (int)$row['ID'] > $after) && ($ids === null || in_array((int)$row['ID'], $ids, true)))
					{
						$rows[] = $posts ? $row : ['option_name' => $row['option_name'], 'len' => strlen($text)];
					}
				}
				
				if(str_contains($query, 'ORDER BY post_modified_gmt DESC'))
				{
					usort($rows, static fn(array $a, array $b): int => strcmp($b['post_modified_gmt'], $a['post_modified_gmt']));
				}
				elseif(str_contains($query, 'ORDER BY ID ASC'))
				{
					usort($rows, static fn(array $a, array $b): int => $a['ID'] <=> $b['ID']);
				}
				
				return preg_match('~LIMIT (\\d+)~', $query, $match) === 1 ? array_slice($rows, 0, (int)$match[1]) : $rows;
			}
		};
	}
	
	/**
	 * RULE: content is read in every status a person or a renderer reaches —
	 * published, draft, pending review, private and scheduled — and a finding
	 * names the status when it is not published; trash, revisions and
	 * auto-drafts are not read, and the count the report carries is over the
	 * same statuses. Falsify: read published rows only (the scheduled
	 * injection waits unread for its date); read every status (the trashed
	 * post and the revision are reported).
	 */
	public function contentIsReadInEveryStatusARendererReaches(): bool
	{
		$script = '<p>x</p><script src="https://evil.example/s.js"></script>';
		$posts = [];
		
		foreach(['publish' => 1, 'draft' => 2, 'pending' => 3, 'private' => 4, 'future' => 5, 'trash' => 6, 'auto-draft' => 7, 'inherit' => 8] as $status => $id)
		{
			$posts[] = ['ID' => $id, 'post_type' => $status === 'inherit' ? 'revision' : 'post', 'post_status' => $status,
				'post_content' => $script, 'post_modified_gmt' => '2026-10-01 10:00:00'];
		}
		
		$GLOBALS['wpdb'] = $this->wpdb([], $posts);
		$database = new class extends PluginDatabase
		{
			public function contentFindings(
				array &$stats,
			): array
			{
				return $this->content($stats);
			}
		};
		$stats = ['posts_scanned' => 0];
		$details = array_column($database->contentFindings($stats), 'detail', 'path');
		unset($GLOBALS['wpdb']);
		
		return array_keys($details) === ['posts/1', 'posts/2', 'posts/3', 'posts/4', 'posts/5']
			&& $details['posts/1'] === 'script from evil.example'
			&& $details['posts/2'] === 'draft: script from evil.example'
			&& $details['posts/3'] === 'pending review: script from evil.example'
			&& $details['posts/4'] === 'private: script from evil.example'
			&& $details['posts/5'] === 'scheduled: script from evil.example'
			&& $stats['posts_scanned'] === 5;
	}
	
	/**
	 * RULE: content is read newest first and, beside that, onward from where
	 * the last pass stopped by id, so a row the newest ones crowd out is read
	 * by a later pass: the cursor the scan hands on moves through the rows
	 * and starts over once it reaches the end. A synced pattern and a block
	 * theme's navigation menu are content too. Falsify: read the newest rows
	 * alone (the old injected post is never read); keep the cursor where it
	 * was (every pass reads the same rows).
	 */
	public function contentIsPagedAcrossPasses(): bool
	{
		$embed = '<iframe src="https://www.youtube.com/embed/x"></iframe>';
		$posts = [];
		
		foreach(range(1, 250) as $id)
		{
			// the injected post is the oldest: the newest rows crowd it out
			$posts[] = ['ID' => $id, 'post_type' => 'post', 'post_status' => 'publish',
				'post_content' => $id === 150 ? '<script src="https://evil.example/s.js"></script>' : $embed,
				'post_modified_gmt' => $id === 150 ? '2001-01-01 00:00:00' : '2026-10-' . str_pad((string)(1 + $id % 28), 2, '0', STR_PAD_LEFT) . ' 10:00:00'];
		}
		
		$posts[] = ['ID' => 900, 'post_type' => 'wp_block', 'post_status' => 'publish', 'post_content' => '<script src="https://evil.example/b.js"></script>', 'post_modified_gmt' => '2026-10-30 10:00:00'];
		$posts[] = ['ID' => 901, 'post_type' => 'wp_navigation', 'post_status' => 'publish', 'post_content' => '<script src="https://evil.example/n.js"></script>', 'post_modified_gmt' => '2026-10-30 10:00:00'];
		$GLOBALS['wpdb'] = $this->wpdb([], $posts);
		$database = new class extends PluginDatabase
		{
			public function contentFindings(
				array &$stats,
				int $cursor,
			): array
			{
				$this->cursor = $cursor;
				
				return $this->content($stats);
			}
		};
		$passes = [];
		$cursor = 0;
		
		foreach(range(1, 4) as $pass)
		{
			$stats = ['posts_scanned' => 0];
			$details = array_column($database->contentFindings($stats, $cursor), 'detail', 'path');
			$cursor = (int)($stats['posts_cursor'] ?? -1);
			$passes[] = [$details, $cursor];
		}
		
		unset($GLOBALS['wpdb']);
		
		return isset($passes[0][0]['posts/150']) === false
			&& ($passes[1][0]['posts/150'] ?? '') === 'script from evil.example'
			&& ($passes[0][0]['posts/900'] ?? '') === 'synced pattern: script from evil.example'
			&& ($passes[0][0]['posts/901'] ?? '') === 'navigation menu: script from evil.example'
			&& $passes[0][1] === 100
			&& $passes[1][1] === 200
			&& $passes[2][1] === 0
			&& $passes[3][1] === 100;
	}
	
	/**
	 * RULE: the posts the last pass reported are read again first, whatever
	 * the newest rows and the cursor bring, so a post a pass found stays
	 * listed while it carries the injection — a complete report that leaves
	 * it out says it is gone — and drops out once cleaned; past the cap the
	 * findings left out are counted as truncated, never dropped unsaid.
	 * Falsify: read only the newest rows and the cursor (the post found last
	 * time drops out while the cursor is past it); read it after the others
	 * (the cap cuts it); cut at the cap silently (the left-out findings are
	 * not counted).
	 */
	public function whatTheLastPassFoundIsReadFirst(): bool
	{
		$embed = '<iframe src="https://www.youtube.com/embed/x"></iframe>';
		$script = '<script src="https://evil.example/s.js"></script>';
		$posts = [];
		
		foreach(range(1, 250) as $id)
		{
			$posts[$id] = ['ID' => $id, 'post_type' => 'post', 'post_status' => 'publish', 'post_content' => $id === 150 ? $script : $embed,
				'post_modified_gmt' => $id === 150 ? '2001-01-01 00:00:00' : '2026-10-' . str_pad((string)(1 + $id % 28), 2, '0', STR_PAD_LEFT) . ' 10:00:00'];
		}
		
		$database = new class extends PluginDatabase
		{
			public function pass(
				array &$stats,
				int $cursor,
				array $known,
			): array
			{
				$this->cursor = $cursor;
				$this->known = $known;
				$this->found = [];
				$this->truncated = [Scan::TIER_URGENT => 0, Scan::TIER_HIGH => 0, Scan::TIER_INFO => 0];
				
				return ['findings' => array_column($this->content($stats), 'detail', 'path'), 'found' => $this->found, 'truncated' => $this->truncated];
			}
		};
		$passes = [];
		$cursor = 0;
		$known = [];
		
		foreach(range(1, 4) as $pass)
		{
			if($pass === 4)
			{
				$posts[150]['post_content'] = $embed;
			}
			
			$GLOBALS['wpdb'] = $this->wpdb([], array_values($posts));
			$stats = ['posts_scanned' => 0];
			$read = $database->pass($stats, $cursor, $known);
			$cursor = (int)($stats['posts_cursor'] ?? -1);
			$known = $read['found'];
			$passes[] = $read;
		}
		
		// twenty-five injected posts among the newest besides the one found before: that one and nineteen listed, six counted
		foreach([...range(1, 25), 150] as $id)
		{
			$posts[$id]['post_content'] = $script;
		}
		
		$GLOBALS['wpdb'] = $this->wpdb([], array_values($posts));
		$stats = ['posts_scanned' => 0];
		$capped = $database->pass($stats, 0, [150]);
		unset($GLOBALS['wpdb']);
		
		return isset($passes[0]['findings']['posts/150']) === false
			&& isset($passes[1]['findings']['posts/150'])
			&& $passes[1]['found'] === [150]
			&& isset($passes[2]['findings']['posts/150'])
			&& isset($passes[3]['findings']['posts/150']) === false
			&& $passes[3]['found'] === []
			&& count($capped['findings']) === 20
			&& isset($capped['findings']['posts/150'])
			&& $capped['truncated'] === [Scan::TIER_URGENT => 0, Scan::TIER_HIGH => 6, Scan::TIER_INFO => 0];
	}
	
	/**
	 * RULE: the option rows past the option check's cap are counted, the
	 * twenty longest listed. Falsify: read one page alone (the rows past it
	 * are dropped unsaid).
	 */
	public function optionsPastTheCapAreCounted(): bool
	{
		$rows = [];
		
		foreach(range(1, 25) as $index)
		{
			$rows[] = ['option_name' => 'agency_' . $index, 'option_value' => str_repeat('x', $index) . 'eval(base64_decode('];
		}
		
		$GLOBALS['wpdb'] = $this->wpdb($rows, []);
		$database = new class extends PluginDatabase
		{
			/** @return array{0: int, 1: array<string, int>} */
			public function codeRows(): array
			{
				$stats = ['options_scanned' => 0];
				
				return [count($this->optionCode($stats)), $this->truncated];
			}
		};
		[$listed, $truncated] = $database->codeRows();
		unset($GLOBALS['wpdb']);
		
		return $listed === 20 && $truncated === [Scan::TIER_URGENT => 0, Scan::TIER_HIGH => 5, Scan::TIER_INFO => 0];
	}
	
	/**
	 * RULE: of the rows under the plugin's prefix only the ones the plugin
	 * writes are left out of the option-code check; any other ovos_codesafe…
	 * row carrying code markers is option_code like any option. Falsify:
	 * exclude the prefix (the planted row hides behind the plugin's name).
	 */
	public function onlyThePluginsOwnOptionsAreLeftOut(): bool
	{
		$code = "<?php eval(\$_POST['x']);";
		$GLOBALS['wpdb'] = $this->wpdb([
			['option_name' => 'ovos_codesafe_payload', 'option_value' => $code],
			['option_name' => 'ovos_codesafe_scan', 'option_value' => 'a report naming eval(x).php'],
			['option_name' => 'ovos_codesafe', 'option_value' => 'eval('],
			['option_name' => 'widget_x', 'option_value' => $code],
			['option_name' => 'clean', 'option_value' => 'nothing'],
		], []);
		$database = new class extends PluginDatabase
		{
			public function optionFindings(
				array &$stats,
			): array
			{
				return $this->optionCode($stats);
			}
		};
		$stats = ['options_scanned' => 0];
		$paths = array_column($database->optionFindings($stats), 'path');
		unset($GLOBALS['wpdb']);
		
		return $paths === ['options/ovos_codesafe_payload', 'options/widget_x'];
	}
	
	/**
	 * RULE: a scheduled hook WITH a listener is judged by the file that
	 * defined the listener: a closure, a function, a static method by string
	 * and by array, an instance method and an invokable from a file under
	 * uploads are cron_listener_foreign (urgent, dated by the file); one from
	 * a file outside every installed component — a folder under plugins/
	 * that is no installed plugin among them — is high; a closure from
	 * eval()'d code is urgent; a method only __call or __callStatic answers,
	 * either alone, is judged by its class's file. PHP's own function as the listener is
	 * cron_listener_builtin: urgent for system() and its kin, high for one
	 * that writes, unserializes or calls what it is handed, info for any
	 * other. A listener that names nothing PHP can find is
	 * cron_listener_unresolved (info). A listener in an installed plugin (a
	 * folder one heads, or a single file),
	 * core's wp-includes, a drop-in, a theme in a registered theme directory
	 * or a Composer vendor tree beside the site is no finding, a hook nobody
	 * listens to is still cron_orphan, and twenty-five such leftovers ahead
	 * of the foreign listeners crowd none of them out — twenty leftovers
	 * listed, the other six counted as truncated.
	 * Falsify: skip every hook with a listener (none is reported); resolve
	 * closures only (the method forms pass); drop the guard (the unresolvable
	 * listener throws the detector away); give up on a method Reflection
	 * cannot name (the __call proxy under uploads passes); take any folder
	 * under plugins/ for a plugin (the shared library passes); share one cap between leftovers and
	 * listeners (the foreign ones are cut); know plugins alone as components
	 * (the vendor, theme, drop-in and core listeners are reported); drop
	 * the leftovers past the cap unsaid (truncated reads 0); take
	 * __call alone for a proxy (the class only __callStatic answers is
	 * unresolved); read a single file under plugins/ as nobody's (the
	 * single-file plugin's listener is reported).
	 */
	public function aCronListenerIsJudgedByTheFileThatDefinedIt(): bool
	{
		$base = str_replace('\\', '/', (string)realpath(sys_get_temp_dir())) . '/ovos-cron-' . uniqid();
		$roots = [
			'root' => $base . '/site',
			'content' => $base . '/site/wp-content',
			'plugins' => $base . '/site/wp-content/plugins',
			'mu' => $base . '/site/wp-content/mu-plugins',
			'themes' => $base . '/site/wp-content/themes',
			'uploads' => $base . '/site/wp-content/uploads',
		];
		$space = 'CronFixture' . bin2hex(random_bytes(4));
		$files = [
			$roots['uploads'] . '/2024/01/cb.php' => "<?php\nnamespace {$space}\\Up;\nfunction planted(): void {}\nclass Job\n{\n"
				. "\tpublic static function run(): void {}\n\tpublic function go(): void {}\n\tpublic function __invoke(): void {}\n}\nreturn static function(): void {};\n",
			$base . '/elsewhere/cb.php' => "<?php\nnamespace {$space}\\Away;\nfunction stray(): void {}\n",
			$roots['uploads'] . '/2024/01/proxy.php' => "<?php\nnamespace {$space}\\Proxy;\nclass Proxy\n{\n"
				. "\tpublic function __call(string \$name, array \$args): void {}\n\tpublic static function __callStatic(string \$name, array \$args): void {}\n}\n",
			$roots['uploads'] . '/2024/01/static-proxy.php' => "<?php\nnamespace {$space}\\Proxy;\nclass StaticProxy\n{\n"
				. "\tpublic static function __callStatic(string \$name, array \$args): void {}\n}\n",
			$roots['plugins'] . '/.shared-lib/jobs.php' => "<?php\nnamespace {$space}\\Lib;\nfunction job(): void {}\n",
			$roots['plugins'] . '/hello.php' => "<?php\n/* Plugin Name: Hello */\nnamespace {$space}\\Hello;\nfunction hello(): void {}\n",
			$roots['plugins'] . '/honest/honest.php' => "<?php\n/* Plugin Name: Honest */\nnamespace {$space}\\Home;\nfunction honest(): void {}\n",
			$roots['root'] . '/wp-includes/cron-core.php' => "<?php\nnamespace {$space}\\Core;\nfunction core(): void {}\n",
			$roots['content'] . '/object-cache.php' => "<?php\nnamespace {$space}\\Dropin;\nfunction cached(): void {}\n",
			$base . '/themes-extra/agency/functions.php' => "<?php\nnamespace {$space}\\Theme;\nfunction themed(): void {}\n",
			$base . '/vendor/composer/installed.json' => '{"packages": []}',
			$base . '/vendor/acme/jobs/src/jobs.php' => "<?php\nnamespace {$space}\\Vendored;\nfunction vendored(): void {}\n",
		];
		
		foreach($files as $path => $source)
		{
			if(is_dir(dirname($path)) === false)
			{
				mkdir(dirname($path), 0700, true);
			}
			
			file_put_contents($path, $source);
		}
		
		$closure = require $roots['uploads'] . '/2024/01/cb.php';
		require $roots['uploads'] . '/2024/01/proxy.php';
		require $roots['uploads'] . '/2024/01/static-proxy.php';
		
		foreach(array_keys($files) as $path)
		{
			if(str_ends_with($path, '.php') && str_contains($path, '/uploads/') === false)
			{
				require $path;
			}
		}
		
		$GLOBALS['wp_theme_directories'] = [$base . '/themes-extra'];
		$job = $space . '\\Up\\Job';
		$listeners = [
			'h_closure' => $closure,
			'h_function' => $space . '\\Up\\planted',
			'h_static' => $job . '::run',
			'h_array' => [$job, 'run'],
			'h_method' => [new $job, 'go'],
			'h_invokable' => new $job,
			'h_stray' => $space . '\\Away\\stray',
			'h_system' => 'system',
			'h_call_user_func' => 'call_user_func',
			'h_file_put_contents' => 'file_put_contents',
			'h_strlen' => 'strlen',
			'h_proxy_call' => [new ($space . '\\Proxy\\Proxy'), 'run'],
			'h_proxy_static' => $space . '\\Proxy\\Proxy::run',
			'h_proxy_static_only' => $space . '\\Proxy\\StaticProxy::run',
			'h_shared_lib' => $space . '\\Lib\\job',
			'h_eval' => eval('return static function(): void {};'),
			'h_honest' => $space . '\\Home\\honest',
			'h_single' => $space . '\\Hello\\hello',
			'h_core' => $space . '\\Core\\core',
			'h_dropin' => $space . '\\Dropin\\cached',
			'h_theme' => $space . '\\Theme\\themed',
			'h_vendor' => $space . '\\Vendored\\vendored',
			'h_missing' => $space . '\\nowhere',
		];
		$hooks = ['h_orphan' => ['k' => ['schedule' => 'hourly']]];
		
		// leftovers ahead of every listener, more than one detector's cap
		foreach(range(1, 25) as $gone)
		{
			$hooks['gone_' . $gone] = ['k' => ['schedule' => 'daily']];
		}
		
		foreach($listeners as $hook => $listener)
		{
			$hooks[$hook] = ['k' => ['schedule' => 'hourly']];
			add_action($hook, $listener);
			$GLOBALS['wp_filter'][$hook] = (object)['callbacks' => [10 => ['id' => ['function' => $listener, 'accepted_args' => 1]]]];
		}
		
		$GLOBALS['wp']['cron'] = [1_792_500_000 => $hooks];
		$database = new class($roots) extends PluginDatabase
		{
			public function cronFindings(): array
			{
				$stats = ['cron_hooks' => 0];
				
				return $this->cron($stats);
			}
			
			/** @return array<string, int> */
			public function cut(): array
			{
				return $this->truncated;
			}
		};
		$found = [];
		$dated = [];
		
		try
		{
			foreach($database->cronFindings() as $finding)
			{
				$found[$finding['path']] = $finding['detector'] . ' ' . $finding['tier'];
				$dated[$finding['path']] = isset($finding['mtime']);
			}
		}
		finally
		{
			// a detector that throws leaves no tree behind
			$this->remove($base);
			unset($GLOBALS['wp_theme_directories']);
		}
		
		$orphans = count(array_filter($found, static fn(string $verdict): bool => $verdict === 'cron_orphan info'));
		
		$urgent = 'cron_listener_foreign urgent';
		
		return ($found['options/cron/h_closure'] ?? '') === $urgent
			&& ($found['options/cron/h_function'] ?? '') === $urgent
			&& ($found['options/cron/h_static'] ?? '') === $urgent
			&& ($found['options/cron/h_array'] ?? '') === $urgent
			&& ($found['options/cron/h_method'] ?? '') === $urgent
			&& ($found['options/cron/h_invokable'] ?? '') === $urgent
			&& ($found['options/cron/h_stray'] ?? '') === 'cron_listener_foreign high'
			&& ($found['options/cron/h_system'] ?? '') === 'cron_listener_builtin urgent'
			&& ($found['options/cron/h_call_user_func'] ?? '') === 'cron_listener_builtin high'
			&& ($found['options/cron/h_file_put_contents'] ?? '') === 'cron_listener_builtin high'
			&& ($found['options/cron/h_strlen'] ?? '') === 'cron_listener_builtin info'
			&& ($found['options/cron/h_proxy_call'] ?? '') === $urgent
			&& ($found['options/cron/h_proxy_static'] ?? '') === $urgent
			&& ($found['options/cron/h_proxy_static_only'] ?? '') === $urgent
			&& ($found['options/cron/h_shared_lib'] ?? '') === 'cron_listener_foreign high'
			&& ($found['options/cron/h_missing'] ?? '') === 'cron_listener_unresolved info'
			&& ($found['options/cron/h_eval'] ?? '') === $urgent
			&& ($found['options/cron/h_orphan'] ?? '') === 'cron_orphan info'
			&& isset($found['options/cron/h_honest']) === false
			&& isset($found['options/cron/h_single']) === false
			&& isset($found['options/cron/h_core']) === false
			&& isset($found['options/cron/h_dropin']) === false
			&& isset($found['options/cron/h_theme']) === false
			&& isset($found['options/cron/h_vendor']) === false
			&& $orphans === 20
			&& $database->cut() === [Scan::TIER_URGENT => 0, Scan::TIER_HIGH => 0, Scan::TIER_INFO => 6]
			&& $dated['options/cron/h_closure']
			&& $dated['options/cron/h_orphan'] === false;
	}
}
