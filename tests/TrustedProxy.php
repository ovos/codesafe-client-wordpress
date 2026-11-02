<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Scan;
use Ovos\Codesafe\ScanRunner;
use Ovos\Codesafe\Sender;
use Ovos\Codesafe\Settings;
use Ovos\Codesafe\Shield\Adapter;
use Ovos\Codesafe\Shield\Prepend;
use Ovos\Test;
use Ovos\Test\Internal;

use function count;
use function define;
use function defined;
use function implode;
use function in_array;
use function str_contains;
use function wp_shim_reset;

use const DIRECTORY_SEPARATOR;

require_once __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'wordpress.file.php';

/**
 * M5 of the 2026-10-03 security audit, the sender's side: behind Cloudflare
 * every report named the edge as the visitor, and codesafe could export a
 * CDN address. Opt-in: a header and the proxy ranges it may be taken from;
 * REMOTE_ADDR otherwise, whatever headers arrive. The rule itself is
 * Shield\Prepend::clientIp (Tests\Prepend pins it); here the settings and
 * the Sender's use of them.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class TrustedProxy extends Test
{
	#[Internal]
	public function prepare(): void
	{
		wp_shim_reset();
	}
	
	/** `cloudflare` stands for the bundled list; anything that is no address or range is dropped */
	public function theRangesReadCloudflareAndDropWhatIsNoRange(): bool
	{
		$GLOBALS['wp']['options']['ovos_codesafe'] = ['trusted_proxies' => 'cloudflare, 10.0.0.0/8; 192.0.2.1 example.com 999.1/x'];
		$ranges = (new Config())->trustedProxies();
		
		return in_array('173.245.48.0/20', $ranges, true)
			&& in_array('2606:4700::/32', $ranges, true)
			&& in_array('10.0.0.0/8', $ranges, true)
			&& in_array('192.0.2.1', $ranges, true)
			&& in_array('example.com', $ranges, true) === false
			&& count($ranges) === count(Config::CLOUDFLARE) + 2;
	}
	
	public function aHeaderNameThatIsNoHeaderNameIsNone(): bool
	{
		$GLOBALS['wp']['options']['ovos_codesafe'] = ['trusted_proxy_header' => "X-Real-IP\r\nEvil: 1"];
		
		return (new Config())->trustedProxyHeader() === '';
	}
	
	/**
	 * The Sender's row: the visitor behind a trusted edge, the connecting
	 * address when the header comes from anywhere else or nothing is named
	 */
	public function theSenderNamesTheVisitorOnlyBehindATrustedProxy(): bool
	{
		$saved = $_SERVER;
		try
		{
			$_SERVER = ['REMOTE_ADDR' => '173.245.48.7', 'HTTP_CF_CONNECTING_IP' => '198.51.100.23'];
			$none = (new Sender(new Config()))->clientIp();
			$GLOBALS['wp']['options']['ovos_codesafe'] = ['trusted_proxy_header' => 'CF-Connecting-IP', 'trusted_proxies' => 'cloudflare'];
			$edge = (new Sender(new Config()))->clientIp();
			$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
			$spoof = (new Sender(new Config()))->clientIp();
		}
		finally
		{
			$_SERVER = $saved;
		}
		
		return $none === '173.245.48.7'
			&& $edge === '198.51.100.23'
			&& $spoof === '203.0.113.9';
	}
	
	/**
	 * RULE: a range wider than any one network is refused: an IPv4 range
	 * needs a prefix of /8 or more, an IPv6 one /16 or more, and a range over
	 * the blocks that carry IPv4 inside IPv6 (::ffff:0:0/96, 64:ff9b::/96) is
	 * measured as the IPv4 range it holds, /104 or more. Cloudflare's
	 * published ranges, the private ones and single addresses pass.
	 * Falsify: keep every token shaped like a range — 0.0.0.0/0 trusts the
	 * header from any client, and every visitor names their own address; or
	 * measure IPv6 alone — ::ffff:0:0/96 trusts every IPv4 visitor on a
	 * dual-stack socket.
	 */
	public function aRangeWiderThanAnyNetworkIsRefused(): bool
	{
		// ::fe00:0:0/87 reaches into ::ffff:0:0/96 through the seven bits it fixes of the eleventh byte
		$refused = ['0.0.0.0/0', '::/0', '1.0.0.0/7', '2000::/3', '2a00::/15', '::ffff:0:0/96', '::ffff:10.0.0.0/103',
			'64:ff9b::/96', '::/16', '::fe00:0:0/87'];
		$kept = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '2a00::/16', 'fd12:3456:789a::/48', '::ffff:10.0.0.0/104',
			'192.0.2.1', '2001:db8::1'];
		$GLOBALS['wp']['options']['ovos_codesafe'] = ['trusted_proxies' => implode(', ', [...$refused, ...$kept]) . ' cloudflare'];
		$config = new Config();
		
		return $config->trustedProxies() === [...$kept, ...Config::CLOUDFLARE]
			&& $config->refusedProxies() === $refused;
	}
	
	/**
	 * RULE: a range inside the unique-local fc00::/7 or the link-local
	 * fe80::/10 passes whatever its length: no internet visitor's address
	 * comes from them, and internal Docker or Kubernetes proxies use them. A
	 * range that reaches past either block is measured like any other, and
	 * wide routable ranges stay refused.
	 * Falsify: drop the exemption — fd00::/8 behind an internal proxy names
	 * the proxy for every visitor; or let a range that only overlaps a block
	 * pass — fc00::/6 also holds f800::/7.
	 */
	public function aNonRoutableIpv6RangePassesWhateverItsLength(): bool
	{
		$refused = ['::/0', '2000::/3', '::ffff:0:0/96', 'fc00::/6', 'fe80::/9'];
		$kept = ['fc00::/7', 'fd00::/8', 'fe80::/10', 'fd12:3456:789a::/48', 'fe80::/64'];
		$GLOBALS['wp']['options']['ovos_codesafe'] = ['trusted_proxies' => implode(' ', [...$refused, ...$kept])];
		$config = new Config();
		
		return $config->trustedProxies() === $kept
			&& $config->refusedProxies() === $refused;
	}
	
	/**
	 * RULE: the refusal holds whatever the value came from: the stored option
	 * an intruder wrote, a wp-config constant, the main site's value a
	 * subsite reads, the settings form. The form saves what is left and says
	 * why with a notice; the page says it too while the option or the
	 * constant still names the range.
	 * Falsify: check the form alone — a constant or a planted option is
	 * honoured, and nothing on the page says so.
	 */
	public function aWideRangeIsRefusedFromEverySource(): bool
	{
		if(defined('TESTS_TRUSTED_PROXIES_WIDE') === false)
		{
			define('TESTS_TRUSTED_PROXIES_WIDE', '0.0.0.0/0, 10.0.0.0/8');
		}
		$constant = new class extends Config
		{
			public function constantName(
				string $key,
			): string
			{
				return $key === 'trusted_proxies' ? 'TESTS_TRUSTED_PROXIES_WIDE' : parent::constantName($key);
			}
		};
		$fromConstant = $constant->trustedProxies() === ['10.0.0.0/8'] && $constant->refusedProxies() === ['0.0.0.0/0'];
		
		$GLOBALS['wp']['options']['ovos_codesafe'] = ['trusted_proxies' => '::/0 192.168.0.0/16'];
		$stored = new Config();
		$fromOption = $stored->trustedProxies() === ['192.168.0.0/16'] && $stored->refusedProxies() === ['::/0'];
		$settings = $this->settings($stored);
		$line = $settings->proxyRefusal($stored->refusedProxies());
		
		$saved = $settings->sanitize(['trusted_proxies' => '0.0.0.0/0, cloudflare; 10.0.0.0/8']);
		$clean = $settings->sanitize(['trusted_proxies' => 'cloudflare 10.0.0.0/8']);
		// a field the constant locks keeps its stored value on save, and the page, not the save, speaks of it
		$locked = $this->settings($constant);
		$kept = $locked->sanitize(['trusted_proxies' => '10.0.0.0/8']);
		// a network's subsite reads the main site's value, refused the same way
		$GLOBALS['wp']['multisite'] = true;
		$GLOBALS['wp']['main_site'] = false;
		$GLOBALS['wp']['blog_options'][1]['ovos_codesafe'] = ['trusted_proxies' => '0.0.0.0/1 10.0.0.0/8'];
		$subsite = new Config();
		$fromMain = $subsite->trustedProxies() === ['10.0.0.0/8'] && $subsite->refusedProxies() === ['0.0.0.0/1'];
		$GLOBALS['wp']['multisite'] = false;
		$GLOBALS['wp']['main_site'] = true;
		
		return $fromConstant && $fromOption && $fromMain
			&& $kept['trusted_proxies'] === '::/0 192.168.0.0/16' && $locked->notices === []
			&& str_contains($line, '::/0')
			&& $settings->proxyRefusal([]) === ''
			&& $saved['trusted_proxies'] === 'cloudflare, 10.0.0.0/8'
			&& count($settings->notices) === 1
			&& $settings->notices[0][0] === 'trusted_proxies'
			&& str_contains($settings->notices[0][1], '0.0.0.0/0')
			&& $clean['trusted_proxies'] === 'cloudflare 10.0.0.0/8';
	}
	
	/**
	 * RULE: a planted all-address range is used nowhere: the Sender names the
	 * connecting address, and the consent the layer before WordPress reads
	 * carries no range, so the layer names it too; a narrow range around the
	 * connecting address still reads the header.
	 * Falsify: refuse it at the form alone — the planted option still lets
	 * every visitor pick the address the reports and rate rules name.
	 */
	public function aPlantedAllAddressRangeNamesTheConnectingAddress(): bool
	{
		$saved = $_SERVER;
		try
		{
			$_SERVER = ['REMOTE_ADDR' => '203.0.113.9', 'HTTP_X_FORWARDED_FOR' => '198.51.100.23'];
			$GLOBALS['wp']['options']['ovos_codesafe'] = ['trusted_proxy_header' => 'X-Forwarded-For', 'trusted_proxies' => '0.0.0.0/0, ::/0'];
			$sender = (new Sender(new Config()))->clientIp();
			$consent = Adapter::consentOf(new Config());
			$layer = Prepend::clientIp($_SERVER, $consent['proxy_header'], $consent['proxies']);
			$GLOBALS['wp']['options']['ovos_codesafe']['trusted_proxies'] = '203.0.113.0/24';
			$named = (new Sender(new Config()))->clientIp();
		}
		finally
		{
			$_SERVER = $saved;
		}
		
		return $sender === '203.0.113.9'
			&& $consent['proxies'] === []
			&& $layer === '203.0.113.9'
			&& $named === '198.51.100.23';
	}
	
	/**
	 * Settings over $config whose notices the test reads
	 *
	 * @return Settings&object{notices: list<array{0: string, 1: string}>}
	 */
	protected function settings(
		Config $config,
	): Settings
	{
		return new class($config, new Sender($config), '/srv/wp/wp-content/plugins/ovos-codesafe/ovos-codesafe.php',
			new ScanRunner($config, new Scan($config))) extends Settings
		{
			/** @var list<array{0: string, 1: string}> */
			public array $notices = [];
			
			protected function notice(
				string $code,
				string $message,
			): void
			{
				$this->notices[] = [$code, $message];
			}
		};
	}
}
