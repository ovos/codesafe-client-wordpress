<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Lifecycle as BaseLifecycle;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Test;
use Ovos\Test\Internal;

use function addcslashes;
use function array_merge;
use function count;
use function escapeshellarg;
use function exec;
use function file_get_contents;
use function file_put_contents;
use function glob;
use function implode;
use function in_array;
use function is_dir;
use function is_file;
use function mkdir;
use function preg_match_all;
use function rmdir;
use function scandir;
use function str_contains;
use function str_replace;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;
use const PHP_BINARY;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php';

/**
 * M16 of the 2026-10-03 security audit: a deactivated plugin's prepend layer
 * kept blocking and recording, and an uninstall left the store (visitor
 * addresses and user agents in its queues) and half the options behind.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Lifecycle extends Test
{
	protected const string RULES = 'shield-cdcdcdcdcdcdcdcdcdcdcdcd.json';
	
	protected string $dir;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		$this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-lifecycle-' . uniqid();
		mkdir($this->dir, 0700, true);
		(new Store($this->dir . DIRECTORY_SEPARATOR . self::RULES, ''))->write(Ruleset::fromPayload([
			'contract' => 1,
			'dialect' => 're2-2026',
			'project' => 'harness',
			'rules' => [['id' => 7, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'ua', 'op' => 'contains',
				'value' => 'zz-bot', 'ci' => true, 'mode' => 'proven', 'expires_at' => null]],
		], time())->toRecord());
		Prepend::writeConsent($this->dir, ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => 'p:', 'root' => '/srv/wp',
			'entries' => true, 'rules' => self::RULES]);
		unset($GLOBALS['wpdb']);
	}
	
	#[Internal]
	public function finalize(): void
	{
		unset($GLOBALS['wpdb']);
		if(is_dir($this->dir) === false)
		{
			return;
		}
		foreach(scandir($this->dir) ?: [] as $name)
		{
			if($name !== '.' && $name !== '..')
			{
				unlink($this->dir . DIRECTORY_SEPARATOR . $name);
			}
		}
		rmdir($this->dir);
	}
	
	/**
	 * Deactivated, the layer judges and records nothing from the next request
	 * on — the ruleset's name and the prefix kept for a reactivation
	 */
	public function aDisabledConsentStopsTheLayer(): bool
	{
		$server = ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/', 'HTTP_USER_AGENT' => 'zz-bot', 'REMOTE_ADDR' => '203.0.113.9'];
		$before = Prepend::judge($this->dir, $server);
		$written = BaseLifecycle::disable($this->dir);
		$consent = Prepend::consent($this->dir);
		
		return $before !== null
			&& $written === true
			&& Prepend::judge($this->dir, $server) === null
			&& $consent['detect'] === false
			&& $consent['entries'] === false
			&& $consent['rules'] === self::RULES
			&& $consent['prefix'] === 'p:';
	}
	
	/** nothing in PHP's configuration names the stub: every file goes, and the directory */
	public function uninstallRemovesTheStoreWhole(): bool
	{
		$this->fill();
		$gone = BaseLifecycle::removeStore($this->dir, '');
		
		return $gone === true && is_dir($this->dir) === false;
	}
	
	/**
	 * PHP still prepends the stub: removing it would fail every request, so it
	 * stays — rewritten to do nothing and to say what to do — and every other
	 * file goes; the same when the configuration cannot be known (WP-CLI)
	 */
	public function aStubPhpStillPrependsStaysInert(): bool
	{
		$this->fill();
		$stub = $this->dir . DIRECTORY_SEPARATOR . Prepend::STUB;
		$gone = BaseLifecycle::removeStore($this->dir, $stub);
		$left = $this->names();
		$output = [];
		exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($stub) . ' 2>&1', $output, $status);
		$kept = $gone === false
			&& file_get_contents($stub) === BaseLifecycle::INERT_STUB
			&& $status === 0 && $output === [];
		$this->fill();
		$cli = BaseLifecycle::removeStore($this->dir, null, true);
		
		return $kept
			&& $left === [Prepend::STUB]
			&& $cli === false
			&& is_file($stub)
			&& is_file($this->dir . DIRECTORY_SEPARATOR . Prepend::QUEUE) === false;
	}
	
	/** every option and named transient through WordPress, the suffixed transients by prefix */
	public function uninstallForgetsEveryOptionAndTransient(): bool
	{
		foreach(BaseLifecycle::OPTIONS as $option)
		{
			$GLOBALS['wp']['options'][$option] = 'x';
		}
		$GLOBALS['wp']['options']['blogname'] = 'kept';
		foreach(BaseLifecycle::TRANSIENTS as $transient)
		{
			$GLOBALS['wp']['transients'][$transient] = 1;
		}
		$GLOBALS['wpdb'] = new class
		{
			public string $options = 'wp_options';
			
			public array $queries = [];
			
			public function esc_like(string $text): string
			{
				return addcslashes($text, '_%\\');
			}
			
			public function prepare(string $query, string ...$arguments): string
			{
				return str_replace('%s', "'" . $arguments[0] . "'", $query);
			}
			
			public function query(string $query): int
			{
				$this->queries[] = $query;
				
				return 1;
			}
		};
		BaseLifecycle::forget();
		$queries = implode("\n", $GLOBALS['wpdb']->queries);
		
		return $GLOBALS['wp']['options'] === ['blogname' => 'kept']
			&& $GLOBALS['wp']['transients'] === []
			&& str_contains($queries, "'\\_transient\\_ovos\\_codesafe\\_sums\\_%'")
			&& str_contains($queries, "'\\_transient\\_timeout\\_ovos\\_codesafe\\_authfail\\_%'")
			&& count($GLOBALS['wpdb']->queries) === 4;
	}
	
	/**
	 * Every `ovos_codesafe_…` name the plugin's code spells is an option or a
	 * transient the uninstall removes, or a name that stores nothing (a hook,
	 * a filter, a nonce action, an error code, a global): a new option that
	 * is not added to Lifecycle fails here, not on a customer's site
	 */
	public function everyStoredNameInTheCodeIsOnTheUninstallList(): bool
	{
		$storesNothing = ['ovos_codesafe_sslverify', 'ovos_codesafe_sslverify_wporg', 'ovos_codesafe_test',
			'ovos_codesafe_unsigned', 'ovos_codesafe_version', 'ovos_codesafe_shield_prepend', 'ovos_codesafe_'];
		$known = array_merge(BaseLifecycle::OPTIONS, BaseLifecycle::TRANSIENTS, $storesNothing);
		$src = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src';
		$files = array_merge(glob($src . DIRECTORY_SEPARATOR . '*.php') ?: [], glob($src . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . '*.php') ?: []);
		foreach($files as $file)
		{
			preg_match_all("~'(ovos_codesafe_[a-z0-9_]*)'~", (string)file_get_contents($file), $matches);
			foreach($matches[1] as $name)
			{
				$prefixed = false;
				foreach(BaseLifecycle::TRANSIENT_PREFIXES as $prefix)
				{
					$prefixed = $prefixed || $name === $prefix;
				}
				if(in_array($name, $known, true) === false && $prefixed === false)
				{
					return false;
				}
			}
		}
		
		return true;
	}
	
	/** the store as a running site leaves it: stub, deny files, consent, ruleset, queue, the watch's lists */
	protected function fill(): void
	{
		if(is_dir($this->dir) === false)
		{
			mkdir($this->dir, 0700, true);
		}
		Prepend::writeConsent($this->dir, ['detect' => true, 'enforce' => true, 'kill' => false, 'prefix' => '', 'rules' => self::RULES]);
		Prepend::ensureStub($this->dir);
		Prepend::queue($this->dir, ['shield_block', 'm', ['rule' => 7]], ['ip' => '203.0.113.9', 'ua' => 'zz-bot']);
		Prepend::writeKnown($this->dir, '6.8', '1.0.3', []);
		file_put_contents($this->dir . DIRECTORY_SEPARATOR . self::RULES, '{}');
		file_put_contents($this->dir . DIRECTORY_SEPARATOR . '.htaccess', "Require all denied\n");
		file_put_contents($this->dir . DIRECTORY_SEPARATOR . 'index.php', "<?php\n");
	}
	
	/** the names in the store directory, dot files included */
	protected function names(): array
	{
		$names = [];
		foreach(scandir($this->dir) ?: [] as $name)
		{
			if($name !== '.' && $name !== '..')
			{
				$names[] = $name;
			}
		}
		
		return $names;
	}
}
