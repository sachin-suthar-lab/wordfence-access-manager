<?php
/**
 * Plugin-owned storage: the registry of TEMPORARY allowlist entries added
 * through this helper, and the audit log. Plain options, no custom tables.
 *
 * The registry is what makes removal safe: only IPs recorded here are ever
 * removed from the Wordfence allowlist by this plugin, so entries an admin
 * added directly in Wordfence are never touched.
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

class WFAM_Store {

	const REGISTRY_OPTION = 'wfam_allowlist';
	const AUDIT_OPTION    = 'wfam_audit';

	/**
	 * Autoloaded int: timestamp of the earliest helper allowlist expiry (0 =
	 * none). Lets every request check "is anything due?" without a query.
	 */
	const NEXT_EXPIRY_OPTION = 'wfam_next_expiry';

	const AUDIT_MAX = 200;

	/** Shortest custom allowlist period. */
	const MIN_SECONDS = 300;

	/**
	 * Preset allowlist periods (key => seconds). There is deliberately no
	 * "never": every helper allowlist entry expires.
	 *
	 * @return array<string, int>
	 */
	public static function expiry_presets() {
		return array(
			'1h'  => HOUR_IN_SECONDS,
			'4h'  => 4 * HOUR_IN_SECONDS,
			'24h' => DAY_IN_SECONDS,
			'7d'  => 7 * DAY_IN_SECONDS,
		);
	}

	/**
	 * Longest allowed custom period (default 30 days).
	 *
	 * @return int Seconds.
	 */
	public static function max_seconds() {
		/**
		 * Filters the longest temporary allowlist period an admin can choose.
		 *
		 * @param int $seconds Default 30 days.
		 */
		return max( self::MIN_SECONDS, (int) apply_filters( 'wfam_max_allowlist_seconds', 30 * DAY_IN_SECONDS ) );
	}

	/**
	 * Resolves the admin's expiry choice to a unix timestamp.
	 *
	 * @param string $choice    Preset key or 'custom'.
	 * @param int    $custom_ts Unix timestamp for 'custom'.
	 * @return int|WP_Error
	 */
	public static function resolve_expiry( $choice, $custom_ts = 0 ) {
		$presets = self::expiry_presets();
		if ( isset( $presets[ $choice ] ) ) {
			return time() + $presets[ $choice ];
		}

		if ( 'custom' !== $choice ) {
			return new WP_Error( 'wfam_bad_expiry', __( 'Choose how long the IP should stay allowlisted.', 'wordfence-access-manager' ) );
		}

		$custom_ts = (int) $custom_ts;
		if ( $custom_ts < time() + self::MIN_SECONDS ) {
			return new WP_Error( 'wfam_bad_expiry', __( 'The custom expiry must be at least 5 minutes in the future.', 'wordfence-access-manager' ) );
		}
		if ( $custom_ts > time() + self::max_seconds() ) {
			return new WP_Error(
				'wfam_bad_expiry',
				/* translators: %d: number of days. */
				sprintf( __( 'The custom expiry cannot be more than %d days away.', 'wordfence-access-manager' ), (int) floor( self::max_seconds() / DAY_IN_SECONDS ) )
			);
		}

		return $custom_ts;
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
	 * @param int    $expires_at Unix timestamp.
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

		self::save( $registry );
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
			self::save( $registry );
		}
	}

	/**
	 * Saves the registry and refreshes the "next expiry" marker.
	 *
	 * @param array $registry Registry.
	 * @return void
	 */
	private static function save( array $registry ) {
		update_option( self::REGISTRY_OPTION, $registry, false );

		$next = 0;
		foreach ( $registry as $entry ) {
			$ts = (int) $entry['expires_at'];
			if ( $ts > 0 && ( 0 === $next || $ts < $next ) ) {
				$next = $ts;
			}
		}
		update_option( self::NEXT_EXPIRY_OPTION, $next, true );
	}

	/**
	 * Earliest pending expiry (0 = none). Autoloaded, so free to read.
	 *
	 * @return int
	 */
	public static function next_expiry() {
		return (int) get_option( self::NEXT_EXPIRY_OPTION, 0 );
	}

	/**
	 * Appends an audit record (who, what, which IP, when) and keeps only the
	 * most recent AUDIT_MAX entries.
	 *
	 * Also fires `wfam_audit` so another logger (e.g. WP Activity
	 * Log) can pick the event up without changes here.
	 *
	 * @param string $action  Machine name, e.g. 'unblock', 'unblock_allowlist'.
	 * @param string $ip      IP acted on.
	 * @param string $details Short human-readable detail.
	 * @return void
	 */
	public static function audit( $action, $ip, $details = '' ) {
		$user  = wp_get_current_user();
		$entry = array(
			'time'       => time(),
			'user_id'    => (int) $user->ID,
			'user_login' => $user->ID ? $user->user_login : 'system',
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
