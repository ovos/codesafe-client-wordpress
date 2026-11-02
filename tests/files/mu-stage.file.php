<?php
declare(strict_types=1);

/**
 * WordPress up to its must-use plugins, for Tests\ShieldLoginCookie through
 * php-cgi: the shim's functions and classes, the state the test wrote
 * (CODESAFE_MU_STATE: the site options, the user meta, the users table,
 * wp-config's constants, the site root, the mu-plugin), a users table behind
 * $wpdb, ABSPATH, then the mu-plugin. What the request leaves for
 * plugins_loaded is printed: whether an early layer judged and passed it
 * (Prepend::JUDGED), stashed a verdict (Prepend::MARK), that verdict, and
 * how many times the users table was read.
 *
 * Under tests/files/, so the runner never takes it for a test.
 */
$state = json_decode((string)file_get_contents((string)getenv('CODESAFE_MU_STATE')), true);
require __DIR__ . DIRECTORY_SEPARATOR . 'wordpress.file.php';
$GLOBALS['wp']['options'] = $state['options'];
$GLOBALS['wp']['user_meta'] = $state['user_meta'];
foreach($state['constants'] as $name => $value)
{
	define($name, $value);
}
// the users table as the check reads it: a prepared lookup by login
$GLOBALS['wpdb'] = new class($state['users'])
{
	public string $users = 'wp_users';
	
	public string $last_error = '';
	
	public int $queries = 0;
	
	public function __construct(
		protected array $rows,
	)
	{
	}
	
	public function prepare(
		string $query,
		mixed ...$arguments,
	): array
	{
		return [$query, $arguments];
	}
	
	public function get_row(
		array $prepared,
	): ?object
	{
		$this->queries++;
		$row = $this->rows[$prepared[1][0] ?? ''] ?? null;
		
		return $row === null ? null : (object)['ID' => (string)$row[0], 'user_pass' => $row[1]];
	}
};
define('ABSPATH', $state['root'] . '/');
include $state['mu_plugin'];
$stash = $GLOBALS['ovos_codesafe_shield_prepend'] ?? null;
echo json_encode([
	'plugins' => true,
	'judged' => defined('CODESAFE_SHIELD_JUDGED'),
	'mark' => defined('CODESAFE_SHIELD_PREPENDED'),
	'stash' => is_array($stash) ? $stash['verdict']->outcome : null,
	'queries' => $GLOBALS['wpdb']->queries,
]);
