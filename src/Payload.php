<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use ErrorException;
use Throwable;

use function get_class;
use function gmdate;
use function preg_match;
use function strpos;
use function substr;

/**
 * Maps throwables and last-error fatals onto the error console v1 payload
 * (see ovos/console docs/API.V1.md) — standalone port of the php-library
 * Ovos\Service\Console\Payload.
 */
final class Payload
{
	/**
	 * Syslog priority (0-7) for a throwable; ErrorException severity
	 * is mapped onto the classic error levels
	 */
	public static function priorityFor(
		Throwable $event,
	): int
	{
		if($event instanceof ErrorException)
		{
			return self::severityPriority($event->getSeverity());
		}
		
		return 3; // any other uncaught throwable = error
	}
	
	public static function severityPriority(
		int $severity,
	): int
	{
		return match($severity)
		{
			E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR,
			E_USER_ERROR, E_RECOVERABLE_ERROR => 2, // critical
			E_WARNING, E_CORE_WARNING, E_COMPILE_WARNING,
			E_USER_WARNING => 4, // warning
			E_NOTICE, E_USER_NOTICE => 5, // notice
			E_DEPRECATED, E_USER_DEPRECATED => 6, // info
			default => 3, // error
		};
	}
	
	/**
	 * Exception chain as v1 events, outermost first
	 */
	public static function events(
		Throwable $event,
	): array
	{
		$events = [];
		$previous = false;
		
		do
		{
			$events[] = [
				'message' => $event->getMessage(),
				'className' => get_class($event),
				'file' => $event->getFile(),
				'line' => $event->getLine(),
				'backtrace' => $event->getTraceAsString(),
				'previous' => $previous,
			];
			
			$previous = true;
		}
		while(($event = $event->getPrevious()) !== null);
		
		return $events;
	}
	
	/**
	 * Complete v1 error object (context is added by the Sender)
	 */
	public static function fromThrowable(
		Throwable $event,
		?int $priority = null,
		array $extra = [],
	): array
	{
		return [
			'v' => 1,
			'priority' => $priority ?? self::priorityFor($event),
			'timestamp' => gmdate('c'),
			'message' => $event->getMessage(),
			'events' => self::events($event),
			'extra' => $extra,
		];
	}
	
	public static function fromMessage(
		string $message,
		int $priority = 5,
		array $extra = [],
	): array
	{
		return [
			'v' => 1,
			'priority' => $priority,
			'timestamp' => gmdate('c'),
			'message' => $message,
			'events' => [],
			'extra' => $extra,
		];
	}
	
	/**
	 * error_get_last() fatal from the shutdown handler — uncaught
	 * exceptions land here too, their class and backtrace are parsed
	 * out of the fatal message PHP composes
	 */
	public static function fromFatal(
		array $error,
	): array
	{
		$message = (string)($error['message'] ?? '');
		$className = 'FatalError';
		$backtrace = '';
		
		if(preg_match('/^Uncaught ([\w\\\\]+)[: ]/', $message, $match) === 1)
		{
			$className = $match[1];
		}
		
		$pos = strpos($message, "\nStack trace:\n");
		
		if($pos !== false)
		{
			$backtrace = substr($message, $pos + 14);
			$message = substr($message, 0, $pos);
		}
		
		return [
			'v' => 1,
			'priority' => self::severityPriority((int)($error['type'] ?? E_ERROR)),
			'timestamp' => gmdate('c'),
			'message' => $message,
			'events' => [
				[
					'message' => $message,
					'className' => $className,
					'file' => (string)($error['file'] ?? ''),
					'line' => (int)($error['line'] ?? 0),
					'backtrace' => $backtrace,
					'previous' => false,
				],
			],
			'extra' => [],
		];
	}
}
