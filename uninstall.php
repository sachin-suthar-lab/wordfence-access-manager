<?php
/**
 * Uninstall: removes only this plugin's own options and cron events.
 *
 * Helper-created allowlist entries are already removed from Wordfence on
 * deactivation (WFAM_Plugin::deactivate()), which WordPress always runs
 * before uninstall. Wordfence's own data and settings are not touched.
 *
 * @package Wordfence_Access_Manager
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'wfam_allowlist' );
delete_option( 'wfam_audit' );
delete_option( 'wfam_next_expiry' );
wp_clear_scheduled_hook( 'wfam_purge_expired' );
wp_clear_scheduled_hook( 'wfam_expire_due' );
