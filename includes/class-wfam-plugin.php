<?php
/**
 * Bootstrap, WP-Cron expiry and the three shared operations (unblock,
 * allowlist, remove) used by both the admin AJAX handlers and cron.
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

class WFAM_Plugin {

	const CRON_HOOK = 'wfam_purge_expired';

	/**
	 * Registers hooks. Wordfence availability is only checked inside hooks,
	 * because Wordfence loads after this plugin (alphabetical order).
	 *
	 * @return void
	 */
	public static function init() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'purge_expired' ) );
		add_action( 'admin_init', array( __CLASS__, 'ensure_cron' ) );
		add_action( 'admin_notices', array( __CLASS__, 'unavailable_notice' ) );

		if ( is_admin() ) {
			WFAM_Admin::init();
		}
	}

	/**
	 * Activation: schedule the hourly expiry check.
	 *
	 * @return void
	 */
	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK );
		}
	}

	/**
	 * Deactivation: stop the expiry check. Helper-added IPs stay in the
	 * Wordfence allowlist (nothing is removed silently); their expiry resumes
	 * if the plugin is re-activated.
	 *
	 * @return void
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	/**
	 * Re-schedules the cron event if it went missing (e.g. cron option reset).
	 *
	 * @return void
	 */
	public static function ensure_cron() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			self::activate();
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

		$missing = WFAM_Wordfence::missing_requirements();
		printf(
			'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s</p><p><code>%3$s</code></p></div>',
			esc_html__( 'Wordfence Access Manager is inactive.', 'wordfence-access-manager' ),
			esc_html__( 'Wordfence is not active, or this Wordfence version does not provide the functions the helper needs. No actions are available until this is resolved.', 'wordfence-access-manager' ),
			esc_html( implode( ', ', $missing ) )
		);
	}

	/**
	 * Unblocks one IP (all block/lockout rows + failed-login counters) and
	 * syncs the firewall.
	 *
	 * @param string $ip Canonical public IP.
	 * @return array{synced:bool}
	 */
	public static function unblock_ip( $ip ) {
		WFAM_Wordfence::unblock( $ip );
		$synced = WFAM_Wordfence::sync_firewall();

		WFAM_Store::audit( 'unblock', $ip, $synced ? '' : 'firewall sync deferred to next request' );

		return array( 'synced' => $synced );
	}

	/**
	 * Adds one IP to the Wordfence allowlist (optionally unblocking it first),
	 * records it as helper-owned, and syncs the firewall once.
	 *
	 * If an existing Wordfence entry already covers the IP, nothing is added
	 * and the IP is NOT recorded as helper-owned, so "Remove" can never delete
	 * an entry the helper did not create.
	 *
	 * @param string $ip         Canonical public IP.
	 * @param string $note       Sanitized note.
	 * @param string $expiry_key One of WFAM_Store::expiry_choices() keys.
	 * @param bool   $unblock    Also unblock the IP.
	 * @return array{status:string, synced:bool}|WP_Error status is 'added' or 'exists'.
	 */
	public static function allowlist_ip( $ip, $note, $expiry_key, $unblock ) {
		$choices = WFAM_Store::expiry_choices();
		if ( ! isset( $choices[ $expiry_key ] ) ) {
			return new WP_Error( 'wfam_bad_expiry', __( 'Choose a valid expiry.', 'wordfence-access-manager' ) );
		}

		if ( $unblock ) {
			WFAM_Wordfence::unblock( $ip );
		}

		$status = WFAM_Wordfence::add_to_allowlist( $ip );
		if ( is_wp_error( $status ) ) {
			if ( $unblock ) {
				WFAM_Wordfence::sync_firewall();
				WFAM_Store::audit( 'unblock', $ip, 'allowlist step failed: ' . $status->get_error_message() );
			}
			return $status;
		}

		if ( 'added' === $status ) {
			$expires_at = $choices[ $expiry_key ] ? time() + $choices[ $expiry_key ] : 0;
			WFAM_Store::add_entry( $ip, $note, $expires_at );
		}

		$synced = WFAM_Wordfence::sync_firewall();

		$details = ( 'added' === $status )
			? sprintf( 'expiry: %s; note: %s', $expiry_key, $note )
			: 'already covered by an existing Wordfence allowlist entry; not added';
		if ( ! $synced ) {
			$details .= '; firewall sync deferred to next request';
		}
		WFAM_Store::audit( $unblock ? 'unblock_allowlist' : 'allowlist_add', $ip, $details );

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
	 * @param string $reason 'manual' or 'expired' (for the audit log).
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
		$synced = WFAM_Wordfence::sync_firewall();

		$details = $removed ? $reason : $reason . '; entry was already gone from Wordfence';
		WFAM_Store::audit( 'expired' === $reason ? 'allowlist_expired' : 'allowlist_remove', $ip, $details );

		return array(
			'removed' => $removed,
			'synced'  => $synced,
		);
	}

	/**
	 * WP-Cron callback (hourly): removes helper-added entries whose expiry has
	 * passed. Also run when the admin screen loads its data, so expiry still
	 * happens even if cron is delayed.
	 *
	 * @return int Number of entries removed.
	 */
	public static function purge_expired() {
		if ( ! WFAM_Wordfence::is_available() ) {
			return 0; // Keep the registry; retry once Wordfence is back.
		}

		$count = 0;
		foreach ( WFAM_Store::registry() as $ip => $entry ) {
			if ( ! empty( $entry['expires_at'] ) && (int) $entry['expires_at'] <= time() ) {
				if ( ! is_wp_error( self::remove_allowlisted_ip( $ip, 'expired' ) ) ) {
					$count++;
				}
			}
		}

		return $count;
	}
}
