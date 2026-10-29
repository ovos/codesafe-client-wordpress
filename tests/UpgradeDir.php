<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Scan;
use Ovos\Codesafe\UpgradeDir as BaseUpgradeDir;
use Ovos\Test;
use Ovos\Test\Internal;
use RuntimeException;
use WP_Error;

use function apply_filters;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function in_array;
use function is_dir;
use function is_file;
use function mkdir;
use function realpath;
use function rmdir;
use function scandir;
use function str_replace;
use function sys_get_temp_dir;
use function uniqid;
use function unlink;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;
use const PHP_INT_MIN;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * WordPress's update working directory closed to the web on a server that
 * reads .htaccess: on pre_unzip_file, after WP_Upgrader::unpack_package()
 * emptied wp-content/upgrade/ and before anything is extracted, a deny
 * .htaccess and an index.php go into it through WordPress's filesystem. The
 * unpack is played here as WordPress before 7.1.4 runs it (7.1.4 keeps an
 * index.php): the directory emptied whole, the package's folders made, the
 * filter, the extraction.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class UpgradeDir extends Test
{
	protected const string APACHE = 'Apache/2.4.62 (Win64) OpenSSL/3.1.3 PHP/8.5.8';
	
	protected string $content;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		$dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-upgrade-dir-' . uniqid();
		mkdir($dir . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'upgrade', 0700, true);
		$this->content = str_replace('\\', '/', (string)realpath($dir)) . '/wp-content';
		$GLOBALS['wp_filesystem'] = $this->filesystem();
	}
	
	#[Internal]
	public function finalize(): void
	{
		unset($GLOBALS['wp_filesystem']);
		$this->remove(dirname($this->content));
	}
	
	/**
	 * RULE: the two files are in wp-content/upgrade/ before the package's
	 * first file is extracted, the extraction goes on, and the filter's null
	 * goes back as it came — WordPress extracts as it would have. Falsify:
	 * return anything but the incoming value — the update stops, or another
	 * plugin's extraction is overridden.
	 */
	public function theWorkingDirectoryIsClosedBeforeAnythingIsExtracted(): bool
	{
		// that the filter runs before extraction is WordPress's order, played by unpack(), not asserted here
		[$pre, $closed, $extracted] = $this->unpack(new BaseUpgradeDir(self::APACHE), 'wordpress-7.1.4-a1b2c3');
		
		return $pre === null && $closed && $extracted
			&& file_get_contents($this->content . '/upgrade/.htaccess') === BaseUpgradeDir::HTACCESS
			&& file_get_contents($this->content . '/upgrade/index.php') === BaseUpgradeDir::INDEX;
	}
	
	/**
	 * RULE: WordPress empties the directory again for every package of a
	 * run; each one finds the files again, and files already as wanted are
	 * not written twice. Falsify: remember within the request that they were
	 * written — the second package of a bulk update unpacks into an open
	 * directory.
	 */
	public function everyPackageOfARunFindsTheFilesAgain(): bool
	{
		$guard = new BaseUpgradeDir(self::APACHE);
		$this->unpack($guard, 'akismet-a1b2c3');
		[, $closed] = $this->unpack($guard, 'contact-form-7-d4e5f6');
		
		return $closed
			&& $guard->write($this->filesystem(), $this->content . '/upgrade/hello-dolly-g7h8i9') === [];
	}
	
	/**
	 * RULE: only a package unpacked below wp-content/upgrade/, and only where
	 * the server may read .htaccess: Apache, LiteSpeed, and a server nobody
	 * named (WP-CLI has no SERVER_SOFTWARE; where the file is ignored it is
	 * inert). nginx, IIS and Caddy, which ignore it, get nothing in either
	 * directory, nor does an extraction elsewhere or a directory merely
	 * starting with the name. Falsify: skip the unknown server — an update
	 * run from WP-CLI on Apache stages into an open directory; drop the
	 * server check — nginx sites get files that do nothing; compare without
	 * the trailing slash — upgraded/ counts as the working directory.
	 */
	public function onlyBelowTheUpgradeDirectoryAndOnlyWhereHtaccessIsRead(): bool
	{
		$nginx = $this->unpack(new BaseUpgradeDir('nginx/1.27.0'), 'akismet-a1b2c3')[1];
		$iis = $this->unpack(new BaseUpgradeDir('Microsoft-IIS/10.0'), 'akismet-a1b2c3')[1];
		$caddy = $this->unpack(new BaseUpgradeDir('Caddy'), 'akismet-a1b2c3')[1];
		$untouched = is_dir($this->content . '/upgrade-temp-backup') === false;
		$unknown = $this->unpack(new BaseUpgradeDir(''), 'akismet-a1b2c3')[1];
		$litespeed = $this->unpack(new BaseUpgradeDir('LiteSpeed'), 'akismet-a1b2c3')[1];
		$this->emptied();
		$guard = new BaseUpgradeDir(self::APACHE);
		$filesystem = $this->filesystem();
		
		return $nginx === false && $iis === false && $caddy === false && $untouched
			&& $unknown === true && $litespeed === true
			&& $guard->write($filesystem, $this->content . '/plugins/akismet') === []
			&& $guard->write($filesystem, $this->content . '/upgraded/akismet') === []
			&& is_file($this->content . '/upgrade/.htaccess') === false
			&& Scan::serverOf(self::APACHE) === 'apache' && Scan::serverOf('LiteSpeed') === 'litespeed'
			&& Scan::serverOf('nginx/1.27.0') === 'nginx' && Scan::serverOf('') === 'unknown';
	}
	
	/**
	 * RULE: wp-content/upgrade-temp-backup/ gets the same two files on the
	 * same pass — made when WordPress has not made it yet — before the
	 * rollback parks the version it replaces there; WordPress's weekly
	 * cleanup empties it, and the next update writes them again before it
	 * parks anything. Falsify: write upgrade/ alone — a parked copy of a
	 * vulnerable plugin is served; or never make the directory — the first
	 * update of a site parks its copy into an open one.
	 */
	public function theParkingDirectoryIsClosedBeforeAnythingIsParked(): bool
	{
		$parking = $this->content . '/upgrade-temp-backup/';
		$guard = new BaseUpgradeDir(self::APACHE);
		$fresh = is_dir($parking) === false;
		$this->unpack($guard, 'akismet-a1b2c3');
		$made = $this->closed($parking);
		// WordPress's rollback parks the old copy, its weekly cleanup then empties the directory
		mkdir($parking . 'plugins/akismet', 0700, true);
		$this->remove($parking . '.htaccess');
		$this->remove($parking . 'index.php');
		$this->remove($parking . 'plugins');
		$this->unpack($guard, 'contact-form-7-d4e5f6');
		
		return $fresh && $made && $this->closed($parking);
	}
	
	/**
	 * RULE: a .htaccess or an index.php this plugin did not write stays as it
	 * is, in either directory; one it wrote earlier with other words is
	 * brought to the current ones. Falsify: write over whatever is there — a
	 * host's own rules in the directory are lost.
	 */
	public function aFileThisPluginDidNotWriteIsNeverTouched(): bool
	{
		$upgrade = $this->content . '/upgrade/';
		$parking = $this->content . '/upgrade-temp-backup/';
		mkdir($parking, 0700, true);
		foreach([$upgrade, $parking] as $dir)
		{
			file_put_contents($dir . '.htaccess', "Options -Indexes\n");
			file_put_contents($dir . 'index.php', "<?php // Silence is golden.\n");
		}
		$foreign = (new BaseUpgradeDir(self::APACHE))->write($this->filesystem(), $upgrade . 'akismet-a1b2c3');
		$kept = true;
		foreach([$upgrade, $parking] as $dir)
		{
			$kept = $kept && file_get_contents($dir . '.htaccess') === "Options -Indexes\n"
				&& file_get_contents($dir . 'index.php') === "<?php // Silence is golden.\n";
		}
		file_put_contents($parking . '.htaccess', '# ' . BaseUpgradeDir::MARKER . "\nDeny from all\n");
		$older = (new BaseUpgradeDir(self::APACHE))->write($this->filesystem(), $upgrade . 'akismet-a1b2c3');
		
		return $foreign === [] && $kept
			&& $older === ['upgrade-temp-backup/.htaccess']
			&& file_get_contents($parking . '.htaccess') === BaseUpgradeDir::HTACCESS
			&& file_get_contents($upgrade . '.htaccess') === "Options -Indexes\n";
	}
	
	/**
	 * RULE: whatever the filter is handed goes back as it came — an earlier
	 * filter's true or WP_Error, and the null when the filesystem throws or
	 * WordPress has none — and no throw reaches the upgrader. Falsify: drop
	 * the catch — a filesystem that fails stops the update.
	 */
	public function theFiltersValueIsHandedBackAsItCame(): bool
	{
		$guard = new BaseUpgradeDir(self::APACHE);
		$to = $this->content . '/upgrade/akismet-a1b2c3';
		$error = new WP_Error('incompatible_archive');
		$handed = $guard->close(true, '', $to) === true && $guard->close($error, '', $to) === $error;
		$GLOBALS['wp_filesystem'] = $this->filesystem(true);
		$thrown = $guard->close(null, '', $to);
		unset($GLOBALS['wp_filesystem']);
		$missing = $guard->close(null, '', $to);
		
		return $handed && $thrown === null && $missing === null;
	}
	
	/** first on pre_unzip_file, with the three arguments it reads */
	public function itIsHookedFirstOnPreUnzipFile(): bool
	{
		$guard = new BaseUpgradeDir(self::APACHE);
		$guard->register();
		
		return in_array(['pre_unzip_file', [$guard, 'close'], PHP_INT_MIN, 3], $GLOBALS['wp']['hooked'], true);
	}
	
	// ---- helpers --------------------------------------------------------------
	
	/**
	 * One package unpacked as WP_Upgrader::unpack_package() and unzip_file()
	 * do it: the directory emptied, the package's folders made, the filter,
	 * then a file extracted. The filter's answer, whether the deny .htaccess
	 * was there before the extraction, and whether the extraction happened
	 *
	 * @return array{0: mixed, 1: bool, 2: bool}
	 */
	protected function unpack(
		BaseUpgradeDir $guard,
		string $name,
	): array
	{
		$this->emptied();
		$working = $this->content . '/upgrade/' . $name;
		mkdir($working . '/wordpress/wp-admin', 0700, true);
		$GLOBALS['wp']['filters']['pre_unzip_file'] = [[$guard, 'close']];
		$pre = apply_filters('pre_unzip_file', null, $this->content . '/upgrade/' . $name . '.zip', $working, [$working . '/wordpress'], 1024.0);
		$closed = is_file($this->content . '/upgrade/.htaccess') && file_get_contents($this->content . '/upgrade/.htaccess') === BaseUpgradeDir::HTACCESS;
		$extracted = file_put_contents($working . '/wordpress/wp-admin/setup-config.php', "<?php\n") !== false;
		
		return [$pre, $closed, $extracted];
	}
	
	/** whether a directory holds the plugin's two files as it writes them */
	protected function closed(
		string $dir,
	): bool
	{
		return is_file($dir . '.htaccess') && file_get_contents($dir . '.htaccess') === BaseUpgradeDir::HTACCESS
			&& is_file($dir . 'index.php') && file_get_contents($dir . 'index.php') === BaseUpgradeDir::INDEX;
	}
	
	/** wp-content/upgrade/ emptied, every entry, as unpack_package() starts */
	protected function emptied(): void
	{
		$upgrade = $this->content . '/upgrade';
		foreach(scandir($upgrade) ?: [] as $name)
		{
			if($name !== '.' && $name !== '..')
			{
				$this->remove($upgrade . '/' . $name);
			}
		}
	}
	
	/**
	 * WP_Filesystem_Direct's surface the class uses, over the temp content
	 * directory, spelled as WordPress spells it (a trailing slash); with
	 * $throws every call fails as a broken FTP connection would
	 */
	protected function filesystem(
		bool $throws = false,
	): object
	{
		return new class($this->content, $throws)
		{
			public function __construct(
				protected string $content,
				protected bool $throws,
			)
			{
			}
			
			public function wp_content_dir(): string
			{
				return $this->content . '/';
			}
			
			public function is_dir(
				string $path,
			): bool
			{
				$this->fail();
				
				return is_dir($path);
			}
			
			public function mkdir(
				string $path,
				mixed $chmod = false,
			): bool
			{
				$this->fail();
				
				return @mkdir($path, 0700);
			}
			
			public function exists(
				string $path,
			): bool
			{
				$this->fail();
				
				return is_file($path) || is_dir($path);
			}
			
			public function get_contents(
				string $path,
			): string|false
			{
				$this->fail();
				
				return @file_get_contents($path);
			}
			
			public function put_contents(
				string $path,
				string $contents,
				mixed $mode = false,
			): bool
			{
				$this->fail();
				
				return @file_put_contents($path, $contents) !== false;
			}
			
			protected function fail(): void
			{
				if($this->throws)
				{
					throw new RuntimeException('the connection dropped');
				}
			}
		};
	}
	
	/** a temp directory and everything under it */
	protected function remove(
		string $path,
	): void
	{
		if(is_dir($path) === false)
		{
			if(is_file($path))
			{
				unlink($path);
			}
			
			return;
		}
		foreach(scandir($path) ?: [] as $name)
		{
			if($name !== '.' && $name !== '..')
			{
				$this->remove($path . '/' . $name);
			}
		}
		rmdir($path);
	}
}
