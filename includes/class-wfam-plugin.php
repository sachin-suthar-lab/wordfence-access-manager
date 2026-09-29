<?php
/**
 * Bootstrap, temporary-allowlist expiry, and the shared operations (unblock,
 * unblock + temporary allowlist, remove) used by the AJAX handlers and cron.
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

class WFAM_Plugin {

	/** Hourly safety-net sweep. */
	const CRON_HOOK = 'wfam_purge_expired';

	/** Single event scheduled at the next expiry time. */
	const DUE_HOOK = 'wfam_expire_due';

	/** Short lock so concurrent requests don't purge at the same time. */
	const PURGE_LOCK = 'wfam_purging';

	/**
	 * Registers hooks. Wordfence availability is only checked inside hooks,
	 * because Wordfence loads after this plugin (alphabetical order).
	 *
	 * @return void
	 */
	public static function init() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'purge_expired' ) );
		add_action( self::DUE_HOOK, array( __CLASS__, 'purge_expired' ) );
		add_action( 'init', array( __CLASS__, 'maybe_purge_due' ), 20 );
		add_action( 'admin_init', array( __CLASS__, 'ensure_cron' ) );
		add_action( 'admin_notices', array( __CLASS__, 'unavailable_notice' ) );

		if ( is_admin() ) {
			WFAM_Admin::init();
		}
	}

	/**
	 * Activation: schedule the hourly sweep and the next due expiry.
	 *
	 * @return void
	 */
	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
		self::schedule_due_event();
	}

	/**
	 * Deactivation: stop the cron events AND remove every helper-created
	 * allowlist entry from Wordfence, because once the plugin is inactive
	 * nothing would expire them (they would silently become permanent).
	 *
	 * @return void
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
		wp_clear_scheduled_hook( self::DUE_HOOK );

		if ( ! WFAM_Wordfence::is_available() ) {
			return; // Registry kept; entries are removed on re-activation once due.
		}
		foreach ( array_keys( WFAM_Store::registry() ) as $ip ) {
			self::remove_allowlisted_ip( $ip, 'deactivated' );
		}
	}

	/**
	 * Re-schedules the cron events if they went missing.
	 *
	 * @return void
	 */
	public static function ensure_cron() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
		if ( WFAM_Store::next_expiry() && ! wp_next_scheduled( self::DUE_HOOK ) ) {
			self::schedule_due_event();
		}
	}

	/**
	 * Runs on every request (init): if a helper allowlist entry is due, remove
	 * it now. Costs one autoloaded option read when nothing is due, and makes
	 * expiry happen on time even when WP-Cron is disabled or delayed.
	 *
	 * @return void
	 */
	public static function maybe_purge_due() {
		$next = WFAM_Store::next_expiry();
		if ( $next > 0 && $next <= time() ) {
			self::purge_expired();
		}
	}

	/**
	 * Shows why the helper is inactive when Wordfence is missing or its API
	 * has changed. Only on the dashboard, plugins screen and our own screen.
	 *
	 * @return void
	 */
	public static function unavailable_notice() {
		if ( ! current_user_can( 'manage_options' ) || WFAM_Wordfence::is_available() ) {
			return;
		}

		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		$ids    = array_filter( array( 'dashboard', 'plugins', WFAM_Admin::$hook_suffix ) );
		if ( $screen && ! in_array( $screen->id, $ids, true ) ) {
			return;
		}

		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s</p><p><code>%3$s</code></p></div>',
			esc_html__( 'Wordfence Access Manager is inactive.', 'wordfence-access-manager' ),
			esc_html__( 'Wordfence is not active, or this Wordfence version does not provide the functions the helper needs. No actions are available until this is resolved.', 'wordfence-access-manager' ),
			esc_html( implode( ', ', WFAM_Wordfence::missing_requirements() ) )
		);
	}

	/**
	 * Ends one IP's login lockout (Wordfence unlock + counter reset) and syncs
	 * the firewall. Does not allowlist.
	 *
	 * @param string $ip Canonical IP.
	 * @return array{synced:bool}
	 */
	public static function unblock_ip( $ip ) {
		WFAM_Wordfence::unlock( $ip );
		$synced = WFAM_Wordfence::sync_firewall();

		WFAM_Store::audit( 'unblock', $ip, $synced ? '' : 'firewall sync deferred to next request' );

		return array( 'synced' => $synced );
	}

	/**
	 * Ends the lockout and allowlists the IP until $expires_at.
	 *
	 * - Not covered by any allowlist entry: added via Wordfence and recorded as
	 *   helper-owned with the expiry.
	 * - Already helper-owned: the expiry is replaced with the new one.
	 * - Covered by an entry the admin added in Wordfence: nothing is added or
	 *   recorded (so the helper can never remove that entry); only unlocked.
	 *
	 * @param string $ip         Canonical public IP.
	 * @param string $note       Sanitized note.
	 * @param int    $expires_at Unix timestamp (validated by WFAM_Store::resolve_expiry()).
	 * @return array{status:string, synced:bool}|WP_Error status: 'added' | 'extended' | 'exists'.
	 */
	public static function unblock_and_allowlist( $ip, $note, $expires_at ) {
		WFAM_Wordfence::unlock( $ip );

		$registry = WFAM_Store::registry();
		if ( isset( $registry[ $ip ] ) && WFAM_Wordfence::is_allowlisted( $ip ) ) {
			$status = 'extended';
		} else {
			$status = WFAM_Wordfence::add_to_allowlist( $ip );
		}

		if ( is_wp_error( $status ) ) {
			WFAM_Wordfence::sync_firewall();
			WFAM_Store::audit( 'unblock', $ip, 'allowlist step failed: ' . $status->get_error_message() );
			return $status;
		}

		if ( 'exists' !== $status ) {
			WFAM_Store::add_entry( $ip, $note, $expires_at );
			self::schedule_due_event();
		}

		$synced = WFAM_Wordfence::sync_firewall();

		$details = ( 'exists' === $status )
			? 'already covered by an existing Wordfence allowlist entry; not added'
			: sprintf( 'until %s UTC%s', gmdate( 'Y-m-d H:i', $expires_at ), '' !== $note ? '; note: ' . $note : '' );
		if ( ! $synced ) {
			$details .= '; firewall sync deferred to next request';
		}
		WFAM_Store::audit( 'extended' === $status ? 'allowlist_extended' : 'unblock_allowlist', $ip, $details );

		return array(
			'status' => $status,
			'synced' => $synced,
		);
	}

	/**
	 * Removes a helper-added IP from the Wordfence allowlist and forgets it.
	 * Refuses IPs the helper did not add.
	 *
	 * @param string $ip     Canonical IP.
	 * @param string $reason 'manual' | 'expired' | 'deactivated' (for the audit log).
	 * @return array{removed:bool, synced:bool}|WP_Error
	 */
	public static function remove_allowlisted_ip( $ip, $reason = 'manual' ) {
		$registry = WFAM_Store::registry();
		if ( ! isset( $registry[ $ip ] ) ) {
			return new WP_Error( 'wfam_not_owned', __( 'This IP was not added through this helper, so it can only be removed from the Wordfence settings screen.', 'wordfence-access-manager' ) );
		}

		// False here just means someone already removed it in Wordfence.
		$removed = WFAM_Wordfence::remove_from_allowlist( $ip );
		WFAM_Store::remove_entry( $ip );
		self::schedule_due_event();
		$synced = WFAM_Wordfence::sync_firewall();

		$actions = array(
			'expired'     => 'allowlist_expired',
			'deactivated' => 'allowlist_deactivated',
		);
		WFAM_Store::audit(
			isset( $actions[ $reason ] ) ? $actions[ $reason ] : 'allowlist_remove',
			$ip,
			$removed ? $reason : $reason . '; entry was already gone from Wordfence'
		);

		return array(
			'removed' => $removed,
			'synced'  => $synced,
		);
	}

	/**
	 * Removes every helper allowlist entry whose expiry has passed. Called by
	 * the due-time cron event, the hourly sweep, maybe_purge_due() and the
	 * admin list endpoint.
	 *
	 * @return int Number of entries removed.
	 */
	public static function purge_expired() {
		if ( ! WFAM_Wordfence::is_available() || get_transient( self::PURGE_LOCK ) ) {
			return 0; // Wordfence missing: keep the registry and retry later.
		}
		set_transient( self::PURGE_LOCK, 1, MINUTE_IN_SECONDS );

		$count = 0;
		foreach ( WFAM_Store::registry() as $ip => $entry ) {
			if ( (int) $entry['expires_at'] > 0 && (int) $entry['expires_at'] <= time() ) {
				if ( ! is_wp_error( self::remove_allowlisted_ip( $ip, 'expired' ) ) ) {
					$count++;
				}
			}
		}

		delete_transient( self::PURGE_LOCK );
		return $count;
	}

	/**
	 * (Re)schedules the single cron event for the earliest pending expiry.
	 * Past-due entries are not scheduled: maybe_purge_due() removes them on
	 * the very next request.
	 *
	 * @return void
	 */
	private static function schedule_due_event() {
		wp_clear_scheduled_hook( self::DUE_HOOK );
		$next = WFAM_Store::next_expiry();
		if ( $next > time() ) {
			wp_schedule_single_event( $next, self::DUE_HOOK );
		}
	}
}
