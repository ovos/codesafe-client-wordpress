<?php
declare(strict_types=1);

defined('WP_UNINSTALL_PLUGIN') || exit;

if(is_multisite())
{
	foreach(get_sites(['fields' => 'ids']) as $ovosCodesafeSiteId)
	{
		switch_to_blog((int)$ovosCodesafeSiteId);
		delete_option('ovos_codesafe');
		delete_option('ovos_codesafe_inventory');
		delete_option('ovos_codesafe_inventory_dirty');
		delete_option('ovos_codesafe_announced_release');
		delete_option('ovos_codesafe_scan');
		delete_option('ovos_codesafe_scan_lock');
		restore_current_blog();
	}
	
	return;
}

delete_option('ovos_codesafe');
delete_option('ovos_codesafe_inventory');
delete_option('ovos_codesafe_inventory_dirty');
delete_option('ovos_codesafe_announced_release');
delete_option('ovos_codesafe_scan');
delete_option('ovos_codesafe_scan_lock');
