<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function bin2hex;
use function count;
use function explode;
use function preg_match;
use function random_bytes;
use function sanitize_text_field;
use function strtolower;
use function trim;
use function wp_unslash;

/**
 * Request-scoped trace correlation id — standalone port of the
 * php-library Ovos\Http\Trace.
 *
 * One id per request: the trace id of an inbound W3C traceparent
 * header when the caller is instrumented (OTEL SDKs, service meshes),
 * a generated 32-hex id otherwise. The console indexes it as trace_id,
 * so every report of one request correlates — across services when
 * the header propagates.
 */
final class Trace
{
	protected static ?string $id = null;
	
	/**
	 * The request's trace id, memoized — inbound traceparent wins,
	 * otherwise generated once
	 */
	public static function id(): string
	{
		if(self::$id === null)
		{
			// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotValidated -- validated by the strict hex grammar in fromTraceparent()
			$header = isset($_SERVER['HTTP_TRACEPARENT'])
				? sanitize_text_field(wp_unslash((string)$_SERVER['HTTP_TRACEPARENT']))
				: '';
			// phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotValidated
			
			self::$id = self::fromTraceparent($header) ?? bin2hex(random_bytes(16));
		}
		
		return self::$id;
	}
	
	/**
	 * The trace id of a W3C traceparent header
	 * ("00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>"),
	 * or null when the header is absent or malformed
	 */
	public static function fromTraceparent(
		string $header,
	): ?string
	{
		$parts = explode('-', strtolower(trim($header)));
		if(count($parts) < 4)
		{
			return null;
		}
		
		[$version, $traceId, $parentId, $flags] = $parts;
		
		if(preg_match('~^[0-9a-f]{2}$~', $version) !== 1
			|| $version === 'ff' // forbidden by the spec
			|| preg_match('~^[0-9a-f]{32}$~', $traceId) !== 1
			|| $traceId === '00000000000000000000000000000000'
			|| preg_match('~^[0-9a-f]{16}$~', $parentId) !== 1
			|| $parentId === '0000000000000000'
			|| preg_match('~^[0-9a-f]{2}$~', $flags) !== 1)
		{
			return null;
		}
		
		return $traceId;
	}
	
	/**
	 * Drops the memoized id — a new one is derived on the next id() call
	 */
	public static function reset(): void
	{
		self::$id = null;
	}
}
