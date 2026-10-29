<?php
declare(strict_types=1);

namespace Ovos\Codesafe;

use function add_action;
use function array_keys;
use function array_merge;
use function array_unique;
use function implode;
use function in_array;
use function is_array;
use function is_bool;
use function sort;
use function trim;

/**
 * The sensor's own words about itself: codesafe relies on this plugin to see
 * the site, so a change of the plugin's settings is told as a security
 * event of its own — which keys changed, which switches went off or on,
 * never a value: not a URL, not a key, not an address. A site pointed at
 * another console tells the old one first, synchronously, since the
 * shutdown queue would post to the new one (Sender::tell). The goodbye a
 * deactivation says is Lifecycle's.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
final class Sensors
{
	/** the deactivation's last word (Lifecycle::goodbye) */
	public const KIND_GOODBYE = 'sensor_goodbye';
	
	/** a change of this plugin's settings */
	public const KIND_SETTINGS = 'sensor_settings';
	
	public function __construct(
		protected Config $config,
		protected Sender $sender,
	)
	{
	}
	
	/** core's update_option_{option} fires only on a real change, with the old and the new value */
	public function register(): void
	{
		add_action('update_option_' . Config::OPTION, [$this, 'settingsChanged'], 10, 2);
	}
	
	/**
	 * The settings changed: the keys whose value differs, in name order, the
	 * boolean switches sorted into off and on; nothing for no change
	 */
	public function settingsChanged(
		mixed $old,
		mixed $new,
	): void
	{
		if(is_array($old) === false || is_array($new) === false)
		{
			return;
		}
		// core fires after the option changed: the cache drops the old values, so the queue posts to the NEW console with the new key
		$this->config->refresh();
		$keys = array_unique(array_merge(array_keys(Config::DEFAULTS), array_keys($old), array_keys($new)));
		sort($keys);
		$changed = [];
		$off = [];
		$on = [];
		foreach($keys as $key)
		{
			$key = (string)$key;
			$default = Config::DEFAULTS[$key] ?? null;
			$before = $old[$key] ?? $default;
			$after = $new[$key] ?? $default;
			if(self::same($before, $after, is_bool($default)))
			{
				continue;
			}
			$changed[] = $key;
			if(is_bool($default))
			{
				if((bool)$after)
				{
					$on[] = $key;
				}
				else
				{
					$off[] = $key;
				}
			}
		}
		if($changed === [])
		{
			return;
		}
		$message = 'settings changed: ' . implode(', ', $changed);
		$extra = ['action' => 'settings_changed', 'changed' => $changed, 'off' => $off, 'on' => $on];
		// no request on it: the request that saved the form carries the form, key and URL included
		$this->sender->reportRefusal(self::KIND_SETTINGS, $message, $extra, Sender::withoutRequest());
		
		// pointed away: the console this site reported to hears it now, with the key it knew
		$oldUrl = trim((string)($old['url'] ?? ''));
		$oldKey = trim((string)($old['api_key'] ?? ''));
		if((in_array('url', $changed, true) || in_array('api_key', $changed, true)) && $oldUrl !== '' && $oldKey !== '')
		{
			$this->sender->tell($oldUrl, $oldKey, self::KIND_SETTINGS, $message, $extra);
		}
	}
	
	/** whether a value is unchanged: a switch by its truth, anything else by its text */
	protected static function same(
		mixed $before,
		mixed $after,
		bool $switch,
	): bool
	{
		if($switch)
		{
			return (bool)$before === (bool)$after;
		}
		
		return (string)(is_array($before) ? implode(',', $before) : $before) === (string)(is_array($after) ? implode(',', $after) : $after);
	}
}
