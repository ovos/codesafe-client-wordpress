<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use Ovos\Codesafe\Shield\Prepend;
use Throwable;

use function add_filter;
use function constant;
use function defined;
use function in_array;
use function is_object;
use function is_string;
use function rtrim;
use function sanitize_text_field;
use function str_contains;
use function str_replace;
use function str_starts_with;
use function wp_unslash;

use const PHP_INT_MIN;

/**
 * WordPress's update working directories, closed to the web where the server
 * reads .htaccess (Apache, LiteSpeed). WP_Upgrader::unpack_package() empties
 * wp-content/upgrade/ and unzips each package below it, where the copy of core
 * or of a plugin stays reachable over HTTP until the update ends; the
 * rollback then parks the version it replaces in
 * wp-content/upgrade-temp-backup/plugins|themes/<slug>, as reachable and
 * still vulnerable. The upgrader reads both through the filesystem alone. On
 * pre_unzip_file — upgrade/ emptied, nothing extracted, nothing parked yet —
 * a deny .htaccess and an index.php go into both, the second made when it is
 * missing, through WordPress's own filesystem, so every package of a run
 * finds them again. WordPress's weekly cleanup empties upgrade-temp-backup/,
 * these two with the rest; the next update writes them again before it parks
 * anything. A file by either name this plugin did not write is never touched
 * — WordPress 7.1.4 and later keep an index.php in upgrade/ and write their
 * own before the filter runs — and nothing here can stop an update. Only a
 * server known to ignore .htaccess (nginx, IIS, Caddy) is skipped: there the
 * Shield's guard before WordPress is what closes them (Prepend::guard()).
 * pre_unzip_file exists from WordPress 6.4; on an older one nothing is
 * written. OpenLiteSpeed reads a new .htaccess only after a restart unless
 * its auto-load is on.
 */
final class UpgradeDir
{
	/** what both files carry: only a file with it is ever rewritten */
	public const MARKER = 'ovos codesafe: the update working directory is never served';
	
	/** Apache 2.4's word, and 2.2's where mod_authz_core is missing */
	public const HTACCESS = '# ' . self::MARKER . "\n"
		. "<IfModule mod_authz_core.c>\n"
		. "\tRequire all denied\n"
		. "</IfModule>\n"
		. "<IfModule !mod_authz_core.c>\n"
		. "\tOrder deny,allow\n"
		. "\tDeny from all\n"
		. "</IfModule>\n";
	
	/** the directory's listing, where its .htaccess is not read (AllowOverride None) */
	public const INDEX = "<?php\n// " . self::MARKER . "\n";
	
	/**
	 * The servers that read .htaccess, in Scan::serverOf()'s words, and the
	 * word for none named: WP-CLI has no SERVER_SOFTWARE, and on a server
	 * that ignores the file it is inert
	 */
	public const SERVERS = ['apache', 'litespeed', 'unknown'];
	
	/**
	 * @param ?string $software the web server's SERVER_SOFTWARE; null reads this request's
	 */
	public function __construct(
		protected ?string $software = null,
	)
	{
	}
	
	/** first on the hook: a filter that extracts by itself would open the window before this one ran */
	public function register(): void
	{
		add_filter('pre_unzip_file', [$this, 'close'], PHP_INT_MIN, 3);
	}
	
	/**
	 * pre_unzip_file: the two files written into wp-content/upgrade/ when the
	 * package unpacks below it, and the filter's value handed back as it came.
	 * Never throws
	 */
	public function close(
		mixed $result,
		mixed $file = '',
		mixed $to = '',
	): mixed
	{
		try
		{
			$filesystem = $GLOBALS['wp_filesystem'] ?? null;
			if(is_string($to) && is_object($filesystem) && $this->mayReadHtaccess())
			{
				$this->write($filesystem, $to);
			}
		}
		catch(Throwable)
		{
			// the update goes on as WordPress started it
		}
		
		return $result;
	}
	
	/**
	 * The two files in each update working directory (Prepend::UPGRADE_DIRS)
	 * when $to lies below upgrade/, spelled as the filesystem spells the
	 * content directory (an FTP root is not this PHP's); a directory missing
	 * is made as WordPress makes it. The paths written, below the content
	 * directory
	 *
	 * @param object $filesystem WordPress's WP_Filesystem_Base
	 * @return list<string>
	 */
	public function write(
		object $filesystem,
		string $to,
	): array
	{
		$content = rtrim((string)$filesystem->wp_content_dir(), '/\\');
		if($content === '')
		{
			return [];
		}
		$upgrade = $content . '/upgrade/';
		// compared with forward slashes: WP_CONTENT_DIR on Windows mixes the two
		if(str_starts_with(rtrim(str_replace('\\', '/', $to), '/') . '/', str_replace('\\', '/', $upgrade)) === false)
		{
			return [];
		}
		$written = [];
		foreach(Prepend::UPGRADE_DIRS as $dir)
		{
			$path = $content . '/' . $dir;
			// upgrade-temp-backup/ exists only once WordPress parked a copy: made before it parks the first
			if($filesystem->is_dir($path) === false
				&& $filesystem->mkdir($path, defined('FS_CHMOD_DIR') ? constant('FS_CHMOD_DIR') : false) === false)
			{
				continue;
			}
			foreach(['.htaccess' => self::HTACCESS, 'index.php' => self::INDEX] as $name => $text)
			{
				if($this->place($filesystem, $path . '/' . $name, $text))
				{
					$written[] = $dir . '/' . $name;
				}
			}
		}
		
		return $written;
	}
	
	/** one file, written unless it is there as wanted already, unreadable, or not this plugin's */
	protected function place(
		object $filesystem,
		string $path,
		string $text,
	): bool
	{
		if($filesystem->exists($path))
		{
			$existing = $filesystem->get_contents($path);
			if(is_string($existing) === false || $existing === $text || str_contains($existing, self::MARKER) === false)
			{
				return false;
			}
		}
		
		return $filesystem->put_contents($path, $text, defined('FS_CHMOD_FILE') ? constant('FS_CHMOD_FILE') : false) === true;
	}
	
	/** whether the web server may read .htaccess — false only for one the scan's posture names that does not */
	protected function mayReadHtaccess(): bool
	{
		$software = $this->software ?? (isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash((string)$_SERVER['SERVER_SOFTWARE'])) : '');
		
		return in_array(Scan::serverOf($software), self::SERVERS, true);
	}
}
