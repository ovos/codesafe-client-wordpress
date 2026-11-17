<?php
declare(strict_types=1);

/**
 * The Shield adapter in a process of its own, where a class can be declared
 * that the harness's one process already holds, and a constant defined that
 * it must never see. OVOS_ADAPTER_STAGE carries a JSON of the scratch
 * directory and the mode:
 *
 * - `marked` (php-cgi, since judge() does nothing on the CLI): Prepend::MARK
 *   defined and two reports stashed, as the prepend layer leaves an observed
 *   request, then judge() at plugins_loaded;
 * - `older-kernel`: the plugin's Kernel.php loaded with rejudge() cut out, as
 *   a kernel older than the adapter is (another plugin's php-library, loaded
 *   first), then a REST request whose token the kernel cannot tell, held and
 *   settled: refused once WordPress has an anonymous caller, observed when
 *   settled at shutdown;
 * - `older-prepend`: an older Prepend, without claimAll() —
 *   claim() answering the one stashed report — and the adapter claiming twice.
 *
 * Prints what reached the Sender, or the kernel's reporter, as JSON.
 *
 * Under tests/files/, so the runner never takes it for a test.
 */

namespace Tests\Files;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Kernel;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Codesafe\Shield\Ruleset;
use Ovos\Codesafe\Shield\Store;
use Ovos\Codesafe\Shield\Verdict;

use function class_exists;
use function define;
use function dirname;
use function file_get_contents;
use function file_put_contents;
use function getenv;
use function getmypid;
use function is_file;
use function json_decode;
use function json_encode;
use function method_exists;
use function preg_replace;
use function spl_autoload_register;
use function str_replace;
use function str_starts_with;
use function substr;
use function time;
use function unlink;

use const DIRECTORY_SEPARATOR;

$given = json_decode((string)getenv('OVOS_ADAPTER_STAGE'), true);
$src = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR;

if($given['mode'] === 'older-kernel')
{
	// an older kernel: every class, no rejudge()
	$older = $given['dir'] . DIRECTORY_SEPARATOR . 'older-kernel-' . getmypid() . '.php';
	file_put_contents($older, (string)preg_replace('~\t/\*\*\n(?:\t \*[^\n]*\n)*\t \*/\n\tpublic function rejudge\(.*?\n\t\}\n~s', '',
		(string)file_get_contents($src . 'Shield' . DIRECTORY_SEPARATOR . 'Kernel.php'), 1));
	require $older;
	unlink($older);
}
if($given['mode'] === 'older-prepend')
{
	require __DIR__ . DIRECTORY_SEPARATOR . 'older-prepend.file.php';
}

spl_autoload_register(static function(string $class) use ($src): void
{
	$file = $src . str_replace('\\', '/', substr($class, 14)) . '.php';
	if(str_starts_with($class, 'Ovos\\Codesafe\\') && is_file($file))
	{
		require $file;
	}
});

require __DIR__ . DIRECTORY_SEPARATOR . 'wordpress.file.php';
// the kernel is one multi-class file: its Store and Ruleset have no file of their own to autoload
if(class_exists(Kernel::class, false) === false)
{
	require $src . 'Shield' . DIRECTORY_SEPARATOR . 'Kernel.php';
}

// the switches on, without the options table
$config = new class extends Config
{
	public function __construct()
	{
	}
	
	public function enabled(): bool
	{
		return true;
	}
	
	public function url(): string
	{
		return 'https://console.invalid';
	}
	
	public function apiKey(): string
	{
		return 'stage-key';
	}
	
	public function shieldDetect(): bool
	{
		return true;
	}
	
	public function shieldEnforce(): bool
	{
		return true;
	}
	
	public function shieldKill(): bool
	{
		return false;
	}
};
// what the Sender is handed, as [kind, extra]
$sender = new class extends Sender
{
	public array $said = [];
	
	public function __construct()
	{
	}
	
	public function reportRefusal(
		string $kind,
		string $message = '',
		array $extra = [],
		array $context = [],
		?int $priority = null,
	): void
	{
		$this->said[] = [$kind, $extra];
	}
	
	public function clientIp(): string
	{
		return '203.0.113.9';
	}
};
$reports = [];
$store = new Store($given['dir'] . DIRECTORY_SEPARATOR . 'shield-stage-' . getmypid() . '.json', '');
// rule 21 refuses an anonymous caller on the REST route
$store->write(Ruleset::fromPayload(['contract' => 1, 'dialect' => 're2-2026', 'project' => 'stage', 'rules' => [
	['id' => 21, 'kind' => 'vpatch', 'origin' => 'finding', 'finding' => '', 'cve' => '', 'mode' => 'block', 'expires_at' => null, 'who' => 'anonymous',
		'conditions' => [['target' => 'path', 'test' => 'prefix', 'value' => '/wp-json/fx/v1/']]],
]], time())->toRecord(Kernel::sealKey('stage-key')));
$kernel = new Kernel('', '', $store, static fn(): array => ['status' => 0, 'headers' => [], 'body' => ''],
	static function(
		string $kind,
		string $message,
		array $extra,
	) use (&$reports): void
	{
		$reports[] = [$kind, $extra['rule'] ?? 0];
	}, sealKey: Kernel::sealKey('stage-key'));
$adapter = new Adapter($config, $sender, $kernel);

if($given['mode'] === 'marked')
{
	define('CODESAFE_STORE_DIR', $given['dir']);
	define(Prepend::MARK, true);
	$GLOBALS[Prepend::STASH] = ['verdict' => new Verdict(Verdict::OBSERVE), 'reports' => [
		[Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /x.php', ['rule' => 8]],
		[Verdict::KIND_OBSERVE, 'shield rule 9 observed GET /x.php', ['rule' => 9]],
	], 'claimed' => false];
	$adapter->judge();
	echo json_encode(['said' => $sender->said, 'claimed' => $GLOBALS[Prepend::STASH]['claimed']]);
}
elseif($given['mode'] === 'older-kernel')
{
	$request = [['HTTP_AUTHORIZATION' => 'Bearer forged', 'REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/wp-json/fx/v1/save', 'HTTP_USER_AGENT' => 'fx/2.1',
		'REMOTE_ADDR' => '203.0.113.9'], [], [], [], []];
	$unknown = Adapter::caller($request[0], [], [], false, true);
	$anonymous = ['authed' => false, 'user' => '', 'can' => static fn(string $capability): bool => false, 'nonce' => null, 'known' => true];
	$held = $adapter->judgeRequest($request, $unknown, '203.0.113.9', 'wp-json');
	$adapter->judgeAgain(null, $anonymous);
	$refused = $reports;
	$reports = [];
	$adapter->judgeRequest($request, $unknown, '203.0.113.9', 'wp-json');
	$adapter->settleHeld();
	echo json_encode(['rejudge' => method_exists(Kernel::class, 'rejudge'), 'held' => $held === null, 'refused' => $refused, 'settled' => $reports]);
}
else
{
	$GLOBALS[Prepend::STASH] = ['report' => [Verdict::KIND_OBSERVE, 'shield rule 8 observed GET /x.php', ['rule' => 8]], 'claimed' => false];
	$first = $adapter->sendClaimed();
	$again = $adapter->sendClaimed();
	echo json_encode(['claimAll' => method_exists(Prepend::class, 'claimAll'), 'sent' => [$first, $again], 'said' => $sender->said]);
}
if(is_file($store->file))
{
	unlink($store->file);
}
