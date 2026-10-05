<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Sender;
use Ovos\Test;
use Ovos\Test\Internal;

use function count;
use function in_array;
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
}
