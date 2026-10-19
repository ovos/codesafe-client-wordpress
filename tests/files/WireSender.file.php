<?php
declare(strict_types=1);

namespace Tests\Files;

use Ovos\Codesafe\Config;
use Ovos\Codesafe\Payload;
use Ovos\Codesafe\Sender;

/**
 * The Sender with its one piece of I/O replaced — php://input is empty under
 * the CLI — and its protected request path reachable. No sanitizing code is
 * copied: buildRequest() (Redactor::scrub over $_POST, Body::redact over the
 * body, the header allowlist), decorate() and encode() are the plugin's own.
 * buildContext() itself cannot run here: under the CLI it takes its argv
 * branch, so wire() assembles the web branch's request-carrying part (uri,
 * referer, request) from the same methods — url() and buildRequest().
 */
final class WireSender extends Sender
{
	public function __construct(
		Config $config,
		protected string $rawBody,
	)
	{
		parent::__construct($config);
	}
	
	/**
	 * The error JSON as flush() would post it, for one message and its extra
	 */
	public function wire(
		array $extra = [],
		string $message = 'G3 sanitizer harness',
	): string
	{
		$payload = $this->decorate(Payload::fromMessage($message, 3, $extra), [
			'type' => 'http',
			'entry' => 'web',
			'context' => [
				'uri' => $this->url('REQUEST_URI'),
				'referer' => $this->url('HTTP_REFERER'),
				'request' => $this->buildRequest(),
			],
		]);
		
		return $this->encode([$payload]);
	}
	
	protected function readBody(
		string $contentType,
	): string
	{
		return $this->rawBody;
	}
}
