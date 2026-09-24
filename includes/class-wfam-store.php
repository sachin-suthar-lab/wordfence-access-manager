<?php
/**
 * Plugin-owned storage: the registry of allowlist entries added through this
 * helper, and the audit log. Both are plain non-autoloaded options, so the
 * plugin needs no custom tables.
 *
 * The registry is what makes "Remove" safe: only IPs recorded here can be
 * removed from the Wordfence allowlist by this plugin, so entries an admin
 * added directly in Wordfence are never touched.
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

class WFAM_Store {

	const REGISTRY_OPTION = 'wfam_allowlist';
	const AUDIT_OPTION    = 'wfam_audit';
	const AUDIT_MAX       = 200;

	/**
	 * Allowed expiry choices (key => seconds, 0 = never).
	 *
	 * @return array<string, int>
	 */
	public static function expiry_choices() {
		return array(
			'7'     => 7 * DAY_IN_SECONDS,
			'30'    => 30 * DAY_IN_SECONDS,
			'never' => 0,
		);
	}

	/**
	 * Helper-added allowlist entries, keyed by canonical IP.
	 *
	 * @return array<string, array{ip:string, note:string, added_by:int, added_by_name:string, added_at:int, expires_at:int}>
	 */
	public static function registry() {
		$registry = get_option( self::REGISTRY_OPTION, array() );
		return is_array( $registry ) ? $registry : array();
	}

	/**
	 * Records that this helper added $ip to the Wordfence allowlist.
	 *
	 * @param string $ip         Canonical IP.
	 * @param string $note       Sanitized admin note.
	 * @param int    $expires_at Unix timestamp, 0 = never.
	 * @return array The stored entry.
	 */
	public static function add_entry( $ip, $note, $expires_at ) {
		$user     = wp_get_current_user();
		$registry = self::registry();

		$registry[ $ip ] = array(
			'ip'            => $ip,
			'note'          => $note,
			'added_by'      => (int) $user->ID,
			'added_by_name' => $user->ID ? $user->display_name : '',
			'added_at'      => time(),
			'expires_at'    => (int) $expires_at,
		);

		update_option( self::REGISTRY_OPTION, $registry, false );
		return $registry[ $ip ];
	}

	/**
	 * Forgets a helper-added entry (does not touch Wordfence).
	 *
	 * @param string $ip Canonical IP.
	 * @return void
	 */
	public static function remove_entry( $ip ) {
		$registry = self::registry();
		if ( isset( $registry[ $ip ] ) ) {
			unset( $registry[ $ip ] );
			update_option( self::REGISTRY_OPTION, $registry, false );
		}
	}

	/**
	 * Appends an audit record (who, what, which IP, when) and keeps only the
	 * most recent AUDIT_MAX entries.
	 *
	 * Also fires `wfam_audit` so another logger (e.g. WP Activity
	 * Log) can pick the event up without changes here.
	 *
	 * @param string $action  Machine name, e.g. 'unblock', 'allowlist_add'.
	 * @param string $ip      IP acted on.
	 * @param string $details Short human-readable detail.
	 * @return void
	 */
	public static function audit( $action, $ip, $details = '' ) {
		$user  = wp_get_current_user();
		$entry = array(
			'time'       => time(),
			'user_id'    => (int) $user->ID,
			'user_login' => $user->ID ? $user->user_login : 'wp-cron',
			'action'     => $action,
			'ip'         => $ip,
			'details'    => $details,
		);

		$log = get_option( self::AUDIT_OPTION, array() );
		$log = is_array( $log ) ? $log : array();
		array_unshift( $log, $entry );
		update_option( self::AUDIT_OPTION, array_slice( $log, 0, self::AUDIT_MAX ), false );

		/**
		 * Fires after the helper records an audit entry.
		 *
		 * @param array $entry time, user_id, user_login, action, ip, details.
		 */
		do_action( 'wfam_audit', $entry );
	}

	/**
	 * Most recent audit entries.
	 *
	 * @param int $limit Max entries.
	 * @return array[]
	 */
	public static function recent_audit( $limit = 20 ) {
		$log = get_option( self::AUDIT_OPTION, array() );
		return is_array( $log ) ? array_slice( $log, 0, $limit ) : array();
	}
}
