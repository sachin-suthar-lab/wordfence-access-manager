<?php
/**
 * Admin screen (Wordfence → Access Manager) and its AJAX endpoints.
 *
 * Scope: IPs currently locked out by Wordfence's failed-login protection
 * (wfBlock TYPE_LOCKOUT). Other firewall blocks are not managed here.
 *
 * Every endpoint: nonce + manage_options + Wordfence availability check,
 * strict IP validation, sanitized input. Output is JSON rendered with
 * textContent in admin.js (attempted usernames are attacker-controlled, so
 * they are never inserted as HTML).
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

class WFAM_Admin {

	const PAGE_SLUG = 'wordfence-access-manager';
	const NONCE     = 'wfam_ajax';
	const PER_PAGE  = 20;

	/**
	 * Distinct usernames from one IP at/above which the UI warns that the IP
	 * may be shared (proxy, office NAT) or a bot.
	 */
	const MANY_USERNAMES = 5;

	/**
	 * Hook suffix returned by add_submenu_page(); '' until registered.
	 *
	 * @var string
	 */
	public static $hook_suffix = '';

	/**
	 * Registers admin hooks.
	 *
	 * @return void
	 */
	public static function init() {
		// After Wordfence's own admin_menu callbacks (priorities 10-60).
		add_action( 'admin_menu', array( __CLASS__, 'register_menu' ), 99 );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue' ) );

		$actions = array(
			'list'              => 'ajax_list',
			'registry'          => 'ajax_registry',
			'unblock'           => 'ajax_unblock',
			'unblock_allowlist' => 'ajax_unblock_allowlist',
			'remove_allowlist'  => 'ajax_remove_allowlist',
		);
		foreach ( $actions as $action => $method ) {
			add_action( 'wp_ajax_wfam_' . $action, array( __CLASS__, $method ) );
		}
	}

	/**
	 * Adds Wordfence → Access Manager. Skipped when the Wordfence menu does
	 * not exist (Wordfence inactive); the admin notice explains why.
	 *
	 * @return void
	 */
	public static function register_menu() {
		if ( ! class_exists( 'wordfence' ) ) {
			return;
		}

		self::$hook_suffix = (string) add_submenu_page(
			'Wordfence',
			__( 'Access Manager', 'wordfence-access-manager' ),
			__( 'Access Manager', 'wordfence-access-manager' ),
			'manage_options',
			self::PAGE_SLUG,
			array( __CLASS__, 'render_page' )
		);
	}

	/**
	 * Loads the admin CSS/JS on this screen only (no frontend assets).
	 *
	 * @param string $hook Current admin page hook.
	 * @return void
	 */
	public static function enqueue( $hook ) {
		if ( '' === self::$hook_suffix || $hook !== self::$hook_suffix || ! WFAM_Wordfence::is_available() ) {
			return;
		}

		$css = 'assets/admin.css';
		$js  = 'assets/admin.js';
		wp_enqueue_style( 'wordfence-access-manager', WFAM_URL . $css, array(), (string) filemtime( WFAM_DIR . $css ) );
		wp_enqueue_script( 'wordfence-access-manager', WFAM_URL . $js, array(), (string) filemtime( WFAM_DIR . $js ), true );

		wp_localize_script(
			'wordfence-access-manager',
			'wfamHelper',
			array(
				'ajaxUrl'    => admin_url( 'admin-ajax.php' ),
				'nonce'      => wp_create_nonce( self::NONCE ),
				'maxSeconds' => WFAM_Store::max_seconds(),
				'minSeconds' => WFAM_Store::MIN_SECONDS,
				'i18n'       => array(
					'none'             => __( 'No IPs are currently locked out by Wordfence for failed logins.', 'wordfence-access-manager' ),
					'noneFiltered'     => __( 'No locked-out IPs match these filters.', 'wordfence-access-manager' ),
					'noHelperEntries'  => __( 'No temporary allowlist entries are active.', 'wordfence-access-manager' ),
					'noAudit'          => __( 'No activity recorded yet.', 'wordfence-access-manager' ),
					'noMatch'          => __( 'No matching account', 'wordfence-access-manager' ),
					'unblock'          => __( 'Unblock', 'wordfence-access-manager' ),
					'unblockAllowlist' => __( 'Unblock + Temporary Allowlist', 'wordfence-access-manager' ),
					'remove'           => __( 'Remove now', 'wordfence-access-manager' ),
					'notAllowlisted'   => __( 'Not allowlisted', 'wordfence-access-manager' ),
					'helperUntil'      => __( 'Temporary, expires %s', 'wordfence-access-manager' ),
					'wordfenceEntry'   => __( 'Allowlisted in Wordfence settings', 'wordfence-access-manager' ),
					'firewallBlock'    => __( 'Also has a firewall IP block (manage in Wordfence → Firewall → Blocking).', 'wordfence-access-manager' ),
					'others'           => __( '+%d other usernames', 'wordfence-access-manager' ),
					'attemptsTotal'    => __( '%d total in Wordfence log', 'wordfence-access-manager' ),
					'pageOf'           => __( 'Page %1$d of %2$d · %3$d locked-out IPs', 'wordfence-access-manager' ),
					'expired'          => __( 'Expired', 'wordfence-access-manager' ),
					'noExpiry'         => __( 'No expiry', 'wordfence-access-manager' ),
					'left'             => __( '%s left', 'wordfence-access-manager' ),
					'requestFailed'    => __( 'The request failed. Check your connection and try again.', 'wordfence-access-manager' ),
					'customInvalid'    => __( 'Choose a custom expiry date and time.', 'wordfence-access-manager' ),
					'confirmUnblockT'  => __( 'Unblock this IP?', 'wordfence-access-manager' ),
					'confirmUnblock'   => __( 'The Wordfence login lockout for %s will be removed and its failed-login counter reset. The IP is NOT allowlisted: if more logins fail, Wordfence will lock it out again under its normal settings.', 'wordfence-access-manager' ),
					'confirmAllowT'    => __( 'Unblock and temporarily allowlist this IP?', 'wordfence-access-manager' ),
					'confirmAllow'     => __( 'The lockout for %s will be removed and the IP added to the Wordfence allowlist until the time you choose. Until then it bypasses Wordfence firewall rules and login lockouts (a correct password is still required). When it expires, the entry is removed and normal Wordfence protection applies again.', 'wordfence-access-manager' ),
					'confirmRemoveT'   => __( 'Remove temporary allowlist now?', 'wordfence-access-manager' ),
					'confirmRemove'    => __( '%s will be removed from the Wordfence allowlist now. Wordfence will count and lock it out like any other IP again.', 'wordfence-access-manager' ),
					'manyWarning'      => __( 'Warning: this IP tried %d different usernames. It may be shared by many people (office network, proxy) or be a bot.', 'wordfence-access-manager' ),
					'dynamicWarning'   => __( 'Home and mobile IPs change. If this IP is reassigned during the allowlist period, whoever gets it inherits the bypass, so keep the period short.', 'wordfence-access-manager' ),
				),
			)
		);
	}

	/**
	 * Renders the screen shell; table data is loaded over AJAX.
	 *
	 * @return void
	 */
	public static function render_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to access this page.', 'wordfence-access-manager' ) );
		}

		if ( ! WFAM_Wordfence::is_available() ) {
			echo '<div class="wrap"><h1>' . esc_html__( 'Access Manager', 'wordfence-access-manager' ) . '</h1></div>';
			return; // The admin notice lists what is missing.
		}

		$settings      = WFAM_Wordfence::lockout_settings();
		$cause_labels  = self::cause_labels();
		$current_ip    = WFAM_Wordfence::current_ip();
		$ip_is_public  = (bool) filter_var( $current_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		$expiry_labels = self::expiry_labels();
		$human_minutes = static function ( $seconds ) {
			return human_time_diff( 0, max( 60, (int) $seconds ) );
		};

		include WFAM_DIR . 'views/admin-page.php';
	}

	/* ---------------------------------------------------------------------
	 * AJAX: read
	 * ------------------------------------------------------------------- */

	/**
	 * Returns one filtered page of locked-out IPs.
	 *
	 * POST: page, ip, user, cause, allowlisted ('all'|'yes'|'no'), member ('all'|'likely').
	 *
	 * @return void
	 */
	public static function ajax_list() {
		self::guard();

		// Expire anything due first, so the allowlist column is never stale.
		WFAM_Plugin::purge_expired();

		$filters = array(
			'ip'          => strtolower( self::post_string( 'ip', 64 ) ),
			'user'        => strtolower( self::post_string( 'user', 100 ) ),
			'cause'       => self::post_string( 'cause', 20 ),
			'allowlisted' => self::post_string( 'allowlisted', 10 ),
			'member'      => self::post_string( 'member', 10 ),
		);
		if ( ! isset( self::cause_labels()[ $filters['cause'] ] ) ) {
			$filters['cause'] = 'all';
		}

		$all  = self::dataset();
		$rows = array_filter(
			$all,
			static function ( $row ) use ( $filters ) {
				if ( '' !== $filters['ip'] && false === strpos( strtolower( $row['ip'] ), $filters['ip'] ) ) {
					return false;
				}
				if ( '' !== $filters['user'] && false === strpos( $row['search_names'], $filters['user'] ) ) {
					return false;
				}
				if ( 'all' !== $filters['cause'] && $row['cause'] !== $filters['cause'] ) {
					return false;
				}
				if ( 'yes' === $filters['allowlisted'] && ! $row['allowlisted'] ) {
					return false;
				}
				if ( 'no' === $filters['allowlisted'] && $row['allowlisted'] ) {
					return false;
				}
				if ( 'likely' === $filters['member'] && null === $row['member'] ) {
					return false;
				}
				return true;
			}
		);

		usort(
			$rows,
			static function ( $a, $b ) {
				return $b['blocked_time'] - $a['blocked_time'];
			}
		);

		$total = count( $rows );
		$pages = max( 1, (int) ceil( $total / self::PER_PAGE ) );
		$page  = min( $pages, max( 1, absint( isset( $_POST['page'] ) ? wp_unslash( $_POST['page'] ) : 1 ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().

		wp_send_json_success(
			array(
				'rows'       => array_map( array( __CLASS__, 'format_row' ), array_slice( $rows, ( $page - 1 ) * self::PER_PAGE, self::PER_PAGE ) ),
				'total'      => $total,
				'totalAll'   => count( $all ),
				'page'       => $page,
				'pages'      => $pages,
				'serverTime' => time(),
			)
		);
	}

	/**
	 * Returns active temporary allowlist entries and recent audit entries.
	 *
	 * @return void
	 */
	public static function ajax_registry() {
		self::guard();
		WFAM_Plugin::purge_expired();

		$entries = array();
		foreach ( WFAM_Store::registry() as $entry ) {
			$entries[] = array(
				'ip'        => $entry['ip'],
				'note'      => $entry['note'],
				'addedBy'   => '' !== $entry['added_by_name'] ? $entry['added_by_name'] : '#' . (int) $entry['added_by'],
				'added'     => self::format_time( $entry['added_at'] ),
				'addedAt'   => (int) $entry['added_at'],
				'expiresAt' => (int) $entry['expires_at'],
				'expires'   => $entry['expires_at'] ? self::format_date( $entry['expires_at'] ) : __( 'No expiry', 'wordfence-access-manager' ),
			);
		}
		usort(
			$entries,
			static function ( $a, $b ) {
				return $a['expiresAt'] - $b['expiresAt'];
			}
		);

		$audit = array();
		foreach ( WFAM_Store::recent_audit( 20 ) as $item ) {
			$audit[] = array(
				'time'    => self::format_time( $item['time'] ),
				'user'    => $item['user_login'],
				'action'  => self::action_label( $item['action'] ),
				'ip'      => $item['ip'],
				'details' => $item['details'],
			);
		}

		wp_send_json_success(
			array(
				'entries'    => $entries,
				'audit'      => $audit,
				'serverTime' => time(),
			)
		);
	}

	/* ---------------------------------------------------------------------
	 * AJAX: actions
	 * ------------------------------------------------------------------- */

	/**
	 * Unblock only. The IP must currently be locked out.
	 *
	 * @return void
	 */
	public static function ajax_unblock() {
		self::guard();

		$ip = WFAM_Wordfence::normalize_ip( self::post_raw( 'ip' ) );
		self::fail_on_error( $ip );
		self::require_active_lockout( $ip );

		$result = WFAM_Plugin::unblock_ip( $ip );

		/* translators: %s: IP address. */
		self::send_done( sprintf( __( 'The Wordfence login lockout for %s was removed.', 'wordfence-access-manager' ), $ip ), $result['synced'] );
	}

	/**
	 * Unblock + temporary allowlist (public IPs only, IP must be locked out).
	 *
	 * POST: ip, note, expiry ('1h'|'4h'|'24h'|'7d'|'custom'), custom_ts (unix, for custom).
	 *
	 * @return void
	 */
	public static function ajax_unblock_allowlist() {
		self::guard();

		$ip = WFAM_Wordfence::normalize_public_ip( self::post_raw( 'ip' ) );
		self::fail_on_error( $ip );
		self::require_active_lockout( $ip );

		$expires_at = WFAM_Store::resolve_expiry( self::post_string( 'expiry', 10 ), absint( self::post_string( 'custom_ts', 12 ) ) );
		self::fail_on_error( $expires_at );

		$result = WFAM_Plugin::unblock_and_allowlist( $ip, self::post_string( 'note', 200 ), $expires_at );
		self::fail_on_error( $result );

		if ( 'exists' === $result['status'] ) {
			/* translators: %s: IP address. */
			$message = sprintf( __( 'The lockout for %s was removed. The IP is already covered by an allowlist entry in the Wordfence settings, so no temporary entry was added.', 'wordfence-access-manager' ), $ip );
		} else {
			/* translators: 1: IP address, 2: date/time. */
			$message = sprintf( __( 'The lockout for %1$s was removed and the IP is allowlisted until %2$s.', 'wordfence-access-manager' ), $ip, self::format_date( $expires_at ) );
		}

		self::send_done( $message, $result['synced'] );
	}

	/**
	 * Removes a helper-added temporary allowlist entry early.
	 *
	 * @return void
	 */
	public static function ajax_remove_allowlist() {
		self::guard();

		$ip = WFAM_Wordfence::normalize_ip( self::post_raw( 'ip' ) );
		self::fail_on_error( $ip );

		$result = WFAM_Plugin::remove_allowlisted_ip( $ip );
		self::fail_on_error( $result );

		/* translators: %s: IP address. */
		self::send_done( sprintf( __( '%s was removed from the Wordfence allowlist.', 'wordfence-access-manager' ), $ip ), $result['synced'] );
	}

	/* ---------------------------------------------------------------------
	 * Internals
	 * ------------------------------------------------------------------- */

	/**
	 * Builds one row per locked-out IP from Wordfence's lockouts + login log.
	 *
	 * @return array[]
	 */
	private static function dataset() {
		$settings = WFAM_Wordfence::lockout_settings();
		$by_ip    = array();

		// Wordfence keeps one active lockout per IP (createLockout() updates it); keep the newest just in case.
		foreach ( WFAM_Wordfence::get_lockouts() as $lockout ) {
			if ( ! isset( $by_ip[ $lockout['ip'] ] ) || $lockout['blocked_time'] > $by_ip[ $lockout['ip'] ]['blocked_time'] ) {
				$by_ip[ $lockout['ip'] ] = $lockout;
			}
		}
		if ( ! $by_ip ) {
			return array();
		}

		$logins   = WFAM_Wordfence::get_login_failures( array_keys( $by_ip ) );
		$firewall = WFAM_Wordfence::ips_with_firewall_blocks();
		$ids      = array();
		$names    = array();
		$per_ip   = array();

		foreach ( $by_ip as $ip => $lockout ) {
			$list = ! empty( $logins[ $ip ]['names'] ) ? $logins[ $ip ]['names'] : array();

			// Lockout reasons quote the username tried; used if the login log was pruned.
			if ( ! $list && preg_match( "/'([^']+)'/", $lockout['reason'], $m ) ) {
				$list[ strtolower( $m[1] ) ] = array(
					'name'    => $m[1],
					'user_id' => 0,
				);
			}

			$per_ip[ $ip ] = $list;
			foreach ( $list as $key => $item ) {
				$names[ $key ] = $item['name'];
				if ( $item['user_id'] > 0 ) {
					$ids[ $item['user_id'] ] = $item['user_id'];
				}
			}
		}

		$users    = self::lookup_users( array_values( $ids ), array_values( $names ) );
		$matcher  = WFAM_Wordfence::allowlist_matcher();
		$registry = WFAM_Store::registry();
		$rows     = array();

		foreach ( $by_ip as $ip => $lockout ) {
			$member    = null;
			$usernames = array();
			$search    = array();

			// Newest attempt first: the first name that maps to a real account is shown.
			foreach ( $per_ip[ $ip ] as $key => $item ) {
				$usernames[] = $item['name'];
				$search[]    = $key;
				if ( null === $member ) {
					if ( $item['user_id'] > 0 && isset( $users['id'][ $item['user_id'] ] ) ) {
						$member = $users['id'][ $item['user_id'] ];
					} elseif ( isset( $users['key'][ $key ] ) ) {
						$member = $users['key'][ $key ];
					}
				}
			}
			if ( $member ) {
				$search[] = strtolower( $member->display_name . ' ' . $member->user_login . ' ' . $member->user_email );
			}

			// Failures inside Wordfence's counting window that led to this lockout.
			$times     = isset( $logins[ $ip ] ) ? $logins[ $ip ]['times'] : array();
			$from      = $lockout['blocked_time'] - $settings['count_window'];
			$to        = $lockout['blocked_time'] + MINUTE_IN_SECONDS;
			$in_window = count(
				array_filter(
					$times,
					static function ( $t ) use ( $from, $to ) {
						return $t >= $from && $t <= $to;
					}
				)
			);

			$allowlisted = $matcher( $ip );
			$rows[]      = array(
				'ip'             => $ip,
				'reason'         => $lockout['reason'],
				'cause'          => self::cause_from_reason( $lockout['reason'] ),
				'blocked_time'   => $lockout['blocked_time'],
				'expiration'     => $lockout['expiration'],
				'attempts'       => $in_window,
				'attempts_total' => count( $times ),
				'usernames'      => $usernames,
				'search_names'   => implode( ' ', $search ),
				'member'         => $member,
				'allowlisted'    => $allowlisted,
				'helper_expires' => ( $allowlisted && isset( $registry[ $ip ] ) ) ? (int) $registry[ $ip ]['expires_at'] : null,
				'firewall_block' => isset( $firewall[ $ip ] ),
			);
		}

		return $rows;
	}

	/**
	 * Batch lookup of WordPress users by ID and by login/email.
	 *
	 * @param int[]    $ids   User IDs recorded by Wordfence.
	 * @param string[] $names Attempted usernames/emails.
	 * @return array{id: array<int, object>, key: array<string, object>}
	 */
	private static function lookup_users( array $ids, array $names ) {
		global $wpdb;

		$found = array();
		foreach ( array_chunk( $ids, 200 ) as $chunk ) {
			$in = implode( ',', array_fill( 0, count( $chunk ), '%d' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- placeholders built above.
			$found = array_merge( $found, (array) $wpdb->get_results( $wpdb->prepare( "SELECT ID, user_login, user_email, display_name FROM {$wpdb->users} WHERE ID IN ($in)", $chunk ) ) );
		}
		foreach ( array_chunk( $names, 100 ) as $chunk ) {
			$in = implode( ',', array_fill( 0, count( $chunk ), '%s' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- placeholders built above.
			$found = array_merge( $found, (array) $wpdb->get_results( $wpdb->prepare( "SELECT ID, user_login, user_email, display_name FROM {$wpdb->users} WHERE user_login IN ($in) OR user_email IN ($in)", array_merge( $chunk, $chunk ) ) ) );
		}

		$by_id  = array();
		$by_key = array();
		foreach ( $found as $user ) {
			$by_id[ (int) $user->ID ]                  = $user;
			$by_key[ strtolower( $user->user_login ) ] = $user;
			$by_key[ strtolower( $user->user_email ) ] = $user;
		}

		return array(
			'id'  => $by_id,
			'key' => $by_key,
		);
	}

	/**
	 * Converts a dataset row to the JSON shape admin.js renders.
	 *
	 * @param array $row Dataset row.
	 * @return array
	 */
	private static function format_row( array $row ) {
		$member = null;
		if ( $row['member'] ) {
			$member = array(
				'name' => '' !== $row['member']->display_name ? $row['member']->display_name : $row['member']->user_login,
				'url'  => esc_url_raw( get_edit_user_link( (int) $row['member']->ID ) ),
			);
		}

		$causes = self::cause_labels();

		return array(
			'ip'                 => $row['ip'],
			'member'             => $member,
			'username'           => isset( $row['usernames'][0] ) ? $row['usernames'][0] : '',
			'otherUsernames'     => max( 0, count( $row['usernames'] ) - 1 ),
			'manyUsernames'      => count( $row['usernames'] ) >= self::MANY_USERNAMES ? count( $row['usernames'] ) : 0,
			'attempts'           => $row['attempts'],
			'attemptsTotal'      => $row['attempts_total'],
			'cause'              => $causes[ $row['cause'] ],
			'reason'             => $row['reason'],
			'blockedAt'          => self::format_time( $row['blocked_time'] ),
			'expiresAt'          => $row['expiration'],
			'expires'            => $row['expiration'] ? self::format_date( $row['expiration'] ) : '',
			'allowlisted'        => $row['allowlisted'],
			'helperExpiresAt'    => $row['helper_expires'],
			'helperExpires'      => $row['helper_expires'] ? self::format_date( $row['helper_expires'] ) : '',
			'firewallBlock'      => $row['firewall_block'],
			'canAllowlist'       => ! is_wp_error( WFAM_Wordfence::normalize_public_ip( $row['ip'] ) ),
		);
	}

	/**
	 * Lockout cause from Wordfence's (English) reason templates in
	 * wfWAFBlockI18n. Anything else, including translated text, is "other".
	 *
	 * @param string $reason Stored reason.
	 * @return string Key of cause_labels().
	 */
	private static function cause_from_reason( $reason ) {
		if ( 0 === strpos( $reason, 'Exceeded the maximum number of login failures' ) ) {
			return 'failures';
		}
		if ( 0 === strpos( $reason, 'Used an invalid username' ) ) {
			return 'invalid_username';
		}
		if ( 0 === strpos( $reason, 'Exceeded the maximum number of tries to recover their password' ) ) {
			return 'forgot_password';
		}
		return 'other';
	}

	/**
	 * Lockout cause labels (also the filter options).
	 *
	 * @return array<string, string>
	 */
	private static function cause_labels() {
		return array(
			'all'              => __( 'All causes', 'wordfence-access-manager' ),
			'failures'         => __( 'Too many failed logins', 'wordfence-access-manager' ),
			'invalid_username' => __( 'Unknown username/email', 'wordfence-access-manager' ),
			'forgot_password'  => __( 'Too many password resets', 'wordfence-access-manager' ),
			'other'            => __( 'Other', 'wordfence-access-manager' ),
		);
	}

	/**
	 * The IP must have an active Wordfence login lockout; exits otherwise.
	 *
	 * @param string $ip Canonical IP.
	 * @return void
	 */
	private static function require_active_lockout( $ip ) {
		if ( ! WFAM_Wordfence::has_active_lockout( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'This IP is no longer locked out: the Wordfence lockout has expired or was already removed. No action was taken.', 'wordfence-access-manager' ) ), 409 );
		}
	}

	/**
	 * Nonce + capability + Wordfence availability. Exits with JSON on failure.
	 *
	 * @return void
	 */
	private static function guard() {
		if ( ! check_ajax_referer( self::NONCE, 'nonce', false ) ) {
			wp_send_json_error( array( 'message' => __( 'Your session has expired. Reload the page and try again.', 'wordfence-access-manager' ) ), 403 );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'wordfence-access-manager' ) ), 403 );
		}
		if ( ! WFAM_Wordfence::is_available() ) {
			wp_send_json_error( array( 'message' => __( 'Wordfence is not available, so no action was taken.', 'wordfence-access-manager' ) ), 503 );
		}
	}

	/**
	 * Sends a WP_Error as a JSON error and exits; otherwise does nothing.
	 *
	 * @param mixed $value Value to check.
	 * @return void
	 */
	private static function fail_on_error( $value ) {
		if ( is_wp_error( $value ) ) {
			wp_send_json_error( array( 'message' => $value->get_error_message() ), 400 );
		}
	}

	/**
	 * Success response, noting when the firewall sync was deferred.
	 *
	 * @param string $message Message.
	 * @param bool   $synced  Whether the firewall config was synced now.
	 * @return void
	 */
	private static function send_done( $message, $synced ) {
		if ( ! $synced ) {
			$message .= ' ' . __( 'Wordfence will apply it to its firewall on the next page request.', 'wordfence-access-manager' );
		}
		wp_send_json_success( array( 'message' => $message ) );
	}

	/**
	 * Sanitized single-line POST string, length-limited.
	 *
	 * @param string $key POST key.
	 * @param int    $max Max characters.
	 * @return string
	 */
	private static function post_string( $key, $max ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
		if ( ! isset( $_POST[ $key ] ) || ! is_string( $_POST[ $key ] ) ) {
			return '';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
		$value = sanitize_text_field( wp_unslash( $_POST[ $key ] ) );
		return function_exists( 'mb_substr' ) ? mb_substr( $value, 0, $max ) : substr( $value, 0, $max );
	}

	/**
	 * Unslashed raw POST string for IP fields; strictly validated afterwards
	 * by WFAM_Wordfence::normalize_ip()/normalize_public_ip().
	 *
	 * @param string $key POST key.
	 * @return string
	 */
	private static function post_raw( $key ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- verified in guard(); validated by normalize_*_ip().
		return isset( $_POST[ $key ] ) && is_string( $_POST[ $key ] ) ? trim( wp_unslash( $_POST[ $key ] ) ) : '';
	}

	/**
	 * Date/time in the site's format and timezone.
	 *
	 * @param int $ts Unix timestamp.
	 * @return string
	 */
	private static function format_date( $ts ) {
		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $ts );
	}

	/**
	 * "date time (3 hours ago)" for past events.
	 *
	 * @param int $ts Unix timestamp.
	 * @return string
	 */
	private static function format_time( $ts ) {
		$ts = (int) $ts;
		if ( $ts <= 0 ) {
			return '—';
		}
		/* translators: %s: human time difference. */
		return self::format_date( $ts ) . ' (' . sprintf( __( '%s ago', 'wordfence-access-manager' ), human_time_diff( $ts, time() ) ) . ')';
	}

	/**
	 * Expiry choice labels (keys match WFAM_Store::expiry_presets() + 'custom').
	 *
	 * @return array<string, string>
	 */
	private static function expiry_labels() {
		return array(
			'1h'     => __( '1 hour', 'wordfence-access-manager' ),
			'4h'     => __( '4 hours', 'wordfence-access-manager' ),
			'24h'    => __( '24 hours', 'wordfence-access-manager' ),
			'7d'     => __( '7 days', 'wordfence-access-manager' ),
			'custom' => __( 'Custom…', 'wordfence-access-manager' ),
		);
	}

	/**
	 * Human label for an audit action.
	 *
	 * @param string $action Machine name.
	 * @return string
	 */
	private static function action_label( $action ) {
		$labels = array(
			'unblock'               => __( 'Unblocked', 'wordfence-access-manager' ),
			'unblock_allowlist'     => __( 'Unblocked + temporary allowlist', 'wordfence-access-manager' ),
			'allowlist_extended'    => __( 'Unblocked + allowlist period replaced', 'wordfence-access-manager' ),
			'allowlist_remove'      => __( 'Allowlist removed early', 'wordfence-access-manager' ),
			'allowlist_expired'     => __( 'Allowlist expired (auto-removed)', 'wordfence-access-manager' ),
			'allowlist_deactivated' => __( 'Allowlist removed (plugin deactivated)', 'wordfence-access-manager' ),
			'allowlist_add'         => __( 'Allowlisted', 'wordfence-access-manager' ),
		);
		return isset( $labels[ $action ] ) ? $labels[ $action ] : $action;
	}
}
