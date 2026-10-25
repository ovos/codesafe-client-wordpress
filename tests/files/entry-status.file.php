<?php
declare(strict_types=1);

/**
 * One request of its own for the executed-file watch: the layer records a
 * stranger, the request answers a status, and the shutdown function the
 * layer registered writes that status onto the record.
 *
 *   php tests/files/entry-status.file.php <store dir> <site root> <relative path> <status>
 */
require dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'src' . DIRECTORY_SEPARATOR . 'Shield' . DIRECTORY_SEPARATOR . 'Prepend.php';

use Ovos\Codesafe\Shield\Prepend;

[, $dir, $root, $relative, $status] = $argv;

Prepend::entry($dir, [
	'SCRIPT_FILENAME' => $root . '/' . $relative,
	'REQUEST_URI' => '/' . $relative,
	'REQUEST_METHOD' => 'GET',
	'REMOTE_ADDR' => '203.0.113.9',
], ['root' => $root, 'entries' => true]);

// what the file that ran would have answered
http_response_code((int)$status);
