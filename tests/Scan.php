<?php
declare(strict_types=1);

namespace Tests;

use Ovos\Codesafe\Scan as PluginScan;
use Ovos\Test;

/**
 * The integrity scan's judges without WordPress: whether a file is a
 * "silence is golden" stub, and whether a media file's head holds PHP that
 * could run — each as PHP itself would read the bytes.
 *
 * @author Marcin Gil <mg@ovos.at>
 */
class Scan extends Test
{
	/**
	 * RULE: a stub is what the tokenizer reads as an opener, comments and
	 * whitespace, and an optional closer — a `//` comment ended by a bare CR,
	 * a closer inside a comment followed by HTML, and a `#[` attribute line
	 * are code; the core form, a block comment with CR line ends and a closer
	 * at the end are stubs. Without the tokenizer the strict pattern rejects
	 * all four bypasses and the `#` form too. Falsify: the old pattern
	 * (`(?://|#)[^\n]*`) — every bypass passes as a stub and goes unreported.
	 */
	public function aStubIsWhatTheTokenizerSaysItIs(): bool
	{
		$bypasses = [
			"<?php\r// Silence\rsystem(\$_GET['c']);\r",
			"<?php // x ?><script>alert(1)</script>",
			"<?php\n#[A] function f(){system('id');} f();\n",
			"<?php\n// fine\n?>\n<?php system('id');",
		];
		$stubs = [
			"<?php\n// Silence is golden.\n",
			"<?php\r/*Silence is Golden*/\r?>",
			"<?php // x ?>\n",
			"\n<?php\n/** nothing */\n?>\n\n",
			'<?php',
		];
		
		foreach($bypasses as $source)
		{
			if(PluginScan::stubShaped($source) || PluginScan::stubShaped($source, tokenizer: false))
			{
				return false;
			}
		}
		
		foreach($stubs as $source)
		{
			if(PluginScan::stubShaped($source) === false || PluginScan::stubShaped($source, tokenizer: false) === false)
			{
				return false;
			}
		}
		
		// the strict fallback refuses a # line the tokenizer reads as a comment
		return PluginScan::stubShaped("<?php\n# Silence is golden.\n")
			&& PluginScan::stubShaped("<?php\n# Silence is golden.\n", tokenizer: false) === false
			&& PluginScan::stubShaped("<?= 'x';") === false
			&& PluginScan::stubShaped('silence') === false;
	}
	
	/**
	 * RULE: a media file holds PHP only where an opener's code up to its
	 * closer has no byte PHP refuses: the `<?=` inside a PNG's compressed
	 * data (followed by 0x03) is none, a GIF carrying `<?php system()`, an
	 * echo-tag backtick shell and an upper-case `<?PHP` are; `<?xml` and
	 * `<?phpinfo` open nothing. Without the tokenizer any opener counts.
	 * Falsify: the substring rule — the PNG is reported URGENT; a
	 * case-sensitive `<?php` — the upper-case shell passes.
	 */
	public function aCompressedImageIsNoPolyglot(): bool
	{
		$png = "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00+\x00\x00\x00+\x08\x06\x00\x00\x00IDATx\x9c<?=\x03r\x16t\x1e\xff\x00\x10abc";
		$shells = [
			"GIF89a\x01\x00\x01\x00<?php system(\$_GET['c']); ?>\x00\x00;",
			"\xff\xd8\xff\xe0<?=`id`?>\xff\xd9",
			"\xff\xd8\xff\xe0<?PHP system('id');",
		];
		
		foreach($shells as $head)
		{
			if(PluginScan::opensPhp($head) === false || PluginScan::opensPhp($head, tokenizer: false) === false)
			{
				return false;
			}
		}
		
		return PluginScan::opensPhp($png) === false
			&& PluginScan::opensPhp($png, tokenizer: false)
			&& PluginScan::opensPhp('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>') === false
			&& PluginScan::opensPhp('<?phpinfo') === false
			&& PluginScan::opensPhp("\x89PNG\r\n\x1a\nIDAT\x00\x01") === false;
	}
}
