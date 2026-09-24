<?php
/**
 * Uninstall: removes only this plugin's own options and cron event.
 *
 * Wordfence data is deliberately left untouched — IPs added through the
 * helper stay in the Wordfence allowlist and must be reviewed/removed in
 * Wordfence → Firewall → All Firewall Options if no longer wanted.
 *
 * @package Wordfence_Access_Manager
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

delete_option( 'wfam_allowlist' );
delete_option( 'wfam_audit' );
wp_clear_scheduled_hook( 'wfam_purge_expired' );
