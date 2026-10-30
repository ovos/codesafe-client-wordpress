<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Test;
use Ovos\Test\Exception\SkipException;
use Ovos\Test\Internal;

use function apcu_enabled;
use function file_get_contents;
use function function_exists;
use function is_dir;
use function mkdir;
use function rmdir;
use function scandir;
use function str_contains;
use function strtoupper;
use function sys_get_temp_dir;
use function time;
use function uniqid;
use function unlink;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';
// the kernel file holds Ruleset and Store beside Kernel, so no class-per-file
// autoloader finds them: the layer's own require brings it
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Adapter.php';

/**
 * The sealed store across the plugin's two layers: the adapter pulls the
 * ruleset with the project key and its kernel seals the record under
 * Kernel::sealKey() of that key; the prepend layer, which holds no API key,
 * reads the record with the seal key the adapter writes into the consent and
 * with the same platform modules. A record nobody sealed under that key is
 * judged by neither layer, and the settings page never calls it live.
 *
 * The adapter's store is APCu here (no WP_CONTENT_DIR in the test process),
 * under a prefix of its own per test, the home URL's hash; the layer reads
 * the same entry through the prefix the consent carries.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class ShieldSeal extends Test
{
	/** project keys in codesafe's shape, 64 hex like a seal key: the consent file holds the seal key, never one of these */
	protected const string KEY = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90';
	
	protected const string OTHER_KEY = '0f9e8d7c6b5a49382716f5e4d3c2b1a00f9e8d7c6b5a49382716f5e4d3c2b1a0';
	
	protected const string BOT = 'zz-seal-bot/1.0';
	
	protected const array RULE = ['id' => 7, 'origin' => 'manual', 'finding' => '', 'cve' => '', 'field' => 'ua', 'op' => 'contains',
		'value' => 'zz-seal-bot', 'ci' => true, 'mode' => 'block', 'expires_at' => null];
	
	protected string $dir;
	
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
		$this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'ovos-shield-seal-' . uniqid();
		mkdir($this->dir, 0700, true);
		// the adapter's APCu prefix is the home URL's hash: one of its own per test
		$GLOBALS['wp']['options']['home'] = 'https://seal-' . uniqid() . '.invalid';
		$this->connect(self::KEY);
	}
	
	#[Internal]
	public function finalize(): void
	{
		wp_shim_reset();
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
	 * RULE: the prepend layer judges the ruleset the adapter's own kernel
	 * pulled: the record is sealed under Kernel::sealKey() of the project key,
	 * the consent the adapter writes carries that seal key, and the layer
	 * reads with the adapter's platform modules. Falsify: build the layer's
	 * kernel without the consent's seal key — it reads no store and the
	 * exploit reaches WordPress; build it with other modules, or leave the
	 * seal out of the consent — the adapter's record is refused the same way.
	 */
	public function theLayerJudgesTheRecordTheAdapterSealed(): bool
	{
		$adapter = $this->adapter();
		$this->door([self::RULE]);
		$pulled = $adapter->kernel()->pull($adapter->consent());
		Prepend::writeConsent($this->dir, Adapter::consentOf(new Config()));
		$judged = Prepend::judge($this->dir, $this->bot());
		
		return $pulled === Kernel::PULL_FRESH
			&& ($judged['verdict'] ?? null)?->isBlock() === true && $judged['verdict']->rule['id'] === 7;
	}
	
	/**
	 * RULE: a record not sealed under the project key — planted without a
	 * seal, or sealed under another key — is judged by neither layer, while
	 * the same rules sealed under the key are judged by both. Falsify: read
	 * the record without the seal check — the planted rules decide in both
	 * layers; build the layer's kernel without the seal key — the sealed
	 * rules are not judged before WordPress.
	 */
	public function aRecordNotSealedUnderTheKeyIsJudgedByNeitherLayer(): bool
	{
		Prepend::writeConsent($this->dir, Adapter::consentOf(new Config()));
		$ruleset = $this->ruleset([self::RULE]);
		$unsealed = $ruleset->toRecord(Kernel::sealKey(self::KEY));
		unset($unsealed['seal']);
		$judged = [];
		foreach([$unsealed, $ruleset->toRecord(Kernel::sealKey(self::OTHER_KEY)), $ruleset->toRecord(Kernel::sealKey(self::KEY))] as $record)
		{
			$this->adapter()->kernel()->store()->write($record);
			$judged[] = [Prepend::judge($this->dir, $this->bot()) !== null, $this->adapterBlocks()];
		}
		
		return $judged === [[false, false], [false, false], [true, true]];
	}
	
	/**
	 * RULE: the consent carries Kernel::sealKey() of the project key and never
	 * the key: rewritten when the key changes (a settings save, a Connect, a
	 * constant: syncPrepend() compares on every request), left alone while it
	 * does not, '' while the site is not connected, and kept by the REST
	 * prefix's own write at init. Falsify: write the API key — it lies in a
	 * file under wp-content; leave the seal out of the comparison — a new key
	 * never reaches the layer, which then refuses every record the adapter
	 * seals under it.
	 */
	public function aKeyChangeRewritesTheSealInTheConsent(): bool
	{
		$path = $this->dir . DIRECTORY_SEPARATOR . Prepend::CONSENT;
		$first = Prepend::writeConsent($this->dir, Adapter::consentOf(new Config()));
		$sealed = Prepend::consent($this->dir)['seal'] ?? null;
		$files = (string)file_get_contents($path);
		$same = Prepend::writeConsent($this->dir, Adapter::consentOf(new Config()));
		$this->connect(self::OTHER_KEY);
		$changed = Prepend::writeConsent($this->dir, Adapter::consentOf(new Config()));
		$files .= (string)file_get_contents($path);
		$prefixed = Prepend::writeRestPrefix($this->dir, 'api');
		$resealed = Prepend::consent($this->dir)['seal'] ?? null;
		$this->connect('');
		$cleared = Prepend::writeConsent($this->dir, Adapter::consentOf(new Config()));
		
		return $first && $sealed === Kernel::sealKey(self::KEY)
			&& $same === false
			&& $changed && $prefixed && $resealed === Kernel::sealKey(self::OTHER_KEY)
			&& $cleared && (Prepend::consent($this->dir)['seal'] ?? null) === ''
			&& str_contains($files, self::KEY) === false && str_contains($files, self::OTHER_KEY) === false;
	}
	
	/**
	 * RULE: a consent the previous version wrote has no seal: it reads as ''
	 * (as does a seal off its shape), and the layer judges nothing and does not
	 * fail, whether it reads the file or is handed the old consent; once the
	 * adapter rewrote the consent, the layer judges. Falsify: read the seal
	 * without its default — the old file fails the layer; take any string — a
	 * hand-edited value reaches the kernel.
	 */
	public function anOldConsentWithoutASealJudgesNothingAndDoesNotFail(): bool
	{
		$adapter = $this->adapter();
		$this->door([self::RULE]);
		$adapter->kernel()->pull($adapter->consent());
		$current = Adapter::consentOf(new Config());
		$old = $current + ['rules' => 'shield-abababababababababababab.json', 'rest_prefix' => 'wp-json'];
		unset($old['seal']);
		$path = $this->dir . DIRECTORY_SEPARATOR . Prepend::CONSENT;
		Prepend::write($path, $old + ['written_at' => time()]);
		$read = Prepend::consent($this->dir);
		$judged = Prepend::judge($this->dir, $this->bot());
		$handed = Prepend::judge($this->dir, $this->bot(), consent: $old);
		$shapes = [];
		foreach([123, 'abc', strtoupper(Kernel::sealKey(self::KEY)), Kernel::sealKey(self::KEY) . '0', ['x']] as $seal)
		{
			Prepend::write($path, ['seal' => $seal] + $old);
			$shapes[] = Prepend::consent($this->dir)['seal'] ?? null;
		}
		$rewritten = Prepend::writeConsent($this->dir, $current);
		$after = Prepend::judge($this->dir, $this->bot());
		
		return ($read['seal'] ?? null) === '' && $judged === null && $handed === null
			&& $shapes === ['', '', '', '', '']
			&& $rewritten === true && ($after['verdict'] ?? null)?->isBlock() === true;
	}
	
	/**
	 * RULE: the settings page's Shield line reads the store as the kernel
	 * judges by it: a record not sealed under the site's key, and the
	 * stand-in the pull writes in its place while the door does not answer,
	 * are no live rules; the record sealed under the key is. Falsify: count
	 * the raw record's rules — a planted ruleset shows as live while nothing
	 * judges by it, an empty one as "0 rules live".
	 */
	public function statusNeverCallsARecordNotSealedUnderTheKeyLive(): bool
	{
		$ruleset = $this->ruleset([self::RULE, ['id' => 8, 'value' => 'zz-other-bot', 'mode' => 'observe'] + self::RULE]);
		$store = $this->adapter()->kernel()->store();
		$store->write($ruleset->toRecord(Kernel::sealKey(self::OTHER_KEY)));
		$planted = $this->adapter()->status();
		$GLOBALS['wp']['get_status'] = 503;
		$adapter = $this->adapter();
		$pulled = $adapter->kernel()->pull($adapter->consent());
		$standIn = $this->adapter()->status();
		$store->write($ruleset->toRecord(Kernel::sealKey(self::KEY)));
		$sealed = $this->adapter()->status();
		
		return str_contains($planted, 'live') === false && str_contains($planted, 'not sealed under this site')
			&& $pulled === Kernel::PULL_FAILED && str_contains($standIn, 'live') === false && str_contains($standIn, 'not sealed under this site')
			&& str_contains($sealed, '2 rules live, 1 of them set to BLOCK');
	}
	
	/**
	 * RULE: a consent file the plugin could not rewrite (root-owned, a
	 * read-only filesystem) is said on the settings page's Shield line: one
	 * still sealed for the key before a rotation — the early layers read no
	 * rules — and one whose switches lag behind the page's; a current one
	 * adds nothing. Falsify: read status() off the store alone — the line
	 * says the rules are live while the layers before WordPress judge by no
	 * rules, or by a blocking box the owner unticked.
	 */
	public function aConsentThePluginCouldNotRewriteIsSaidOnTheShieldLine(): bool
	{
		$store = $this->adapter()->kernel()->store();
		$store->write($this->ruleset([self::RULE])->toRecord(Kernel::sealKey(self::KEY)));
		$current = Adapter::consentOf(new Config());
		Prepend::writeConsent($this->dir, $current);
		$fresh = $this->adapter()->status($this->dir);
		// the key rotated: the store is sealed again under the new key, the consent file stays as it was
		$this->connect(self::OTHER_KEY);
		$store->write($this->ruleset([self::RULE])->toRecord(Kernel::sealKey(self::OTHER_KEY)));
		$rotated = $this->adapter()->status($this->dir);
		// the key is current, the blocking box is not
		Prepend::writeConsent($this->dir, ['enforce' => false] + Adapter::consentOf(new Config()));
		$lagging = $this->adapter()->status($this->dir);
		
		return str_contains($fresh, '1 rule live') && str_contains($fresh, 'WARNING') === false
			&& str_contains($rotated, '1 rule live') && str_contains($rotated, 'WARNING')
			&& str_contains($rotated, 'cannot read the rules') && str_contains($rotated, $this->dir)
			&& str_contains($lagging, 'WARNING') && str_contains($lagging, 'cannot read the rules') === false
			&& str_contains($lagging, $this->dir);
	}
	
	/**
	 * RULE: a request the early layer cannot read the store for — none yet,
	 * or a consent sealed for another key — is left to the adapter whole: not
	 * marked judged, so plugins_loaded judges it instead of only tallying,
	 * and no pull is forced, so a stale consent does not make every request
	 * ask codesafe. Falsify: judge it with no ruleset — the request is marked
	 * judged and passes both layers, and the kernel forces a pull each time.
	 */
	public function aRequestTheLayerCannotReadTheStoreForIsLeftToTheAdapter(): bool
	{
		$adapter = $this->adapter();
		$this->door([self::RULE]);
		$adapter->kernel()->pull($adapter->consent());
		Prepend::writeConsent($this->dir, ['seal' => Kernel::sealKey(self::OTHER_KEY)] + Adapter::consentOf(new Config()));
		$ran = null;
		$judged = Prepend::judge($this->dir, $this->bot(), [], [], null, null, $ran);
		$mu = null;
		Prepend::judge($this->dir, $this->bot(), [], [], null, null, $mu, wordpress: true);
		
		return $judged === null && $ran === false && $mu === false
			&& $this->adapter()->kernel()->store()->pullForced() === false
			&& $this->adapterBlocks();
	}
	
	// ---- helpers --------------------------------------------------------------
	
	/** the site's settings as the settings page saves them, connected under $key ('' for none) */
	protected function connect(
		string $key,
	): void
	{
		$GLOBALS['wp']['options'][Config::OPTION] = ['enabled' => true, 'url' => 'https://codesafe.invalid', 'api_key' => $key,
			'shield_detect' => true, 'shield_enforce' => true];
	}
	
	/** the adapter as the plugin builds it, its kernel's store on APCu; a fresh one reads the store again */
	protected function adapter(): Adapter
	{
		if(function_exists('apcu_enabled') === false || apcu_enabled() === false)
		{
			throw new SkipException('APCu is not enabled for this SAPI (apc.enable_cli).');
		}
		
		return new Adapter(new Config(), new Sender(new Config()));
	}
	
	/** what codesafe's door answers the pull: these rules, 200 */
	protected function door(
		array $rules,
	): void
	{
		$GLOBALS['wp']['get_status'] = 200;
		$GLOBALS['wp']['get_headers'] = [];
		$GLOBALS['wp']['api'] = ['contract' => Ruleset::CONTRACT, 'dialect' => Ruleset::DIALECT, 'project' => 'harness', 'rules' => $rules];
	}
	
	/** the rules as the adapter's kernel keeps them: pulled with WordPress's module */
	protected function ruleset(
		array $rules,
	): Ruleset
	{
		return Ruleset::fromPayload(['contract' => Ruleset::CONTRACT, 'dialect' => Ruleset::DIALECT, 'project' => 'harness', 'rules' => $rules],
			time(), platforms: Prepend::platforms());
	}
	
	/** the bot's request to the front page, anonymous */
	protected function bot(): array
	{
		return ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/', 'HTTP_USER_AGENT' => self::BOT, 'REMOTE_ADDR' => '203.0.113.9'];
	}
	
	/** whether the adapter's own judge at plugins_loaded refuses the bot's request */
	protected function adapterBlocks(): bool
	{
		$anonymous = ['authed' => false, 'user' => '', 'can' => null, 'nonce' => null, 'known' => true];
		
		return $this->adapter()->judgeRequest([$this->bot(), [], [], [], []], $anonymous, '203.0.113.9', 'wp-json')?->isBlock() === true;
	}
}
