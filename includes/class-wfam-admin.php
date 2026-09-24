<?php
/**
 * Admin screen (Wordfence → Access Manager) and its AJAX endpoints.
 *
 * Every endpoint: nonce + manage_options + Wordfence availability check,
 * strict IP validation, sanitized input. Output is returned as JSON data and
 * rendered with textContent in admin.js (attempted usernames are attacker-
 * controlled, so they are never inserted as HTML).
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
			'add_allowlist'     => 'ajax_add_allowlist',
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
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( self::NONCE ),
				'i18n'    => array(
					'loading'          => __( 'Loading…', 'wordfence-access-manager' ),
					'none'             => __( 'No blocked IPs match these filters.', 'wordfence-access-manager' ),
					'noHelperEntries'  => __( 'No IPs have been added through this helper.', 'wordfence-access-manager' ),
					'noAudit'          => __( 'No activity recorded yet.', 'wordfence-access-manager' ),
					'noMatch'          => __( 'No matching account', 'wordfence-access-manager' ),
					'unblock'          => __( 'Unblock', 'wordfence-access-manager' ),
					'unblockAllowlist' => __( 'Unblock + Allowlist', 'wordfence-access-manager' ),
					'remove'           => __( 'Remove', 'wordfence-access-manager' ),
					'yes'              => __( 'Yes', 'wordfence-access-manager' ),
					'no'               => __( 'No', 'wordfence-access-manager' ),
					'helperAdded'      => __( 'added by helper', 'wordfence-access-manager' ),
					'others'           => __( '+%d other usernames', 'wordfence-access-manager' ),
					'blockedHits'      => __( '%d blocked requests', 'wordfence-access-manager' ),
					'pageOf'           => __( 'Page %1$d of %2$d · %3$d IPs', 'wordfence-access-manager' ),
					'requestFailed'    => __( 'The request failed. Check your connection and try again.', 'wordfence-access-manager' ),
					'confirmUnblockT'  => __( 'Unblock this IP?', 'wordfence-access-manager' ),
					'confirmUnblock'   => __( 'All Wordfence blocks and login lockouts for %s will be removed and its failed-login counter reset. It is NOT added to the allowlist, so it can be blocked again.', 'wordfence-access-manager' ),
					'confirmAllowT'    => __( 'Unblock and allowlist this IP?', 'wordfence-access-manager' ),
					'confirmAllow'     => __( '%s will be unblocked and added to the Wordfence allowlist. It will bypass Wordfence firewall rules, blocks and login lockouts until removed. A correct password is still required to log in.', 'wordfence-access-manager' ),
					'confirmAddT'      => __( 'Add this IP to the allowlist?', 'wordfence-access-manager' ),
					'confirmAdd'       => __( '%s will be added to the Wordfence allowlist and will bypass Wordfence firewall rules, blocks and login lockouts until removed.', 'wordfence-access-manager' ),
					'confirmRemoveT'   => __( 'Remove from allowlist?', 'wordfence-access-manager' ),
					'confirmRemove'    => __( '%s will be removed from the Wordfence allowlist. Wordfence will count and block it like any other IP again.', 'wordfence-access-manager' ),
					'manyWarning'      => __( 'Warning: this IP tried %d different usernames. It may be shared by many people (office network, proxy) or be a bot. Only allowlist it if you are sure it is a trusted, fixed address.', 'wordfence-access-manager' ),
					'dynamicWarning'   => __( 'Only allowlist fixed addresses (office, VPN exit). Home and mobile IPs change; if this one is reassigned, a stranger inherits the bypass. For those, use Unblock only.', 'wordfence-access-manager' ),
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

		$type_labels   = WFAM_Wordfence::type_labels();
		$current_ip    = WFAM_Wordfence::current_ip();
		$ip_is_public  = (bool) filter_var( $current_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		$ip_allowed    = '' !== $current_ip && WFAM_Wordfence::is_allowlisted( $current_ip );
		$expiry_labels = self::expiry_labels();

		include WFAM_DIR . 'views/admin-page.php';
	}

	/* ---------------------------------------------------------------------
	 * AJAX: read
	 * ------------------------------------------------------------------- */

	/**
	 * Returns one filtered page of blocked IPs.
	 *
	 * POST: page, ip, user, type ('all' | wfBlock type id), allowlisted
	 * ('all'|'yes'|'no'), member ('all'|'likely').
	 *
	 * @return void
	 */
	public static function ajax_list() {
		self::guard();

		// Opportunistic expiry so a delayed WP-Cron never leaves an expired entry active while admins are looking.
		WFAM_Plugin::purge_expired();

		$labels  = WFAM_Wordfence::type_labels();
		$filters = array(
			'ip'          => strtolower( self::post_string( 'ip', 64 ) ),
			'user'        => strtolower( self::post_string( 'user', 100 ) ),
			'type'        => self::post_string( 'type', 10 ),
			'allowlisted' => self::post_string( 'allowlisted', 10 ),
			'member'      => self::post_string( 'member', 10 ),
		);
		$type_id = ctype_digit( $filters['type'] ) && isset( $labels[ (int) $filters['type'] ] ) ? (int) $filters['type'] : null;

		$rows = array_filter(
			self::dataset(),
			static function ( $row ) use ( $filters, $type_id ) {
				if ( '' !== $filters['ip'] && false === strpos( strtolower( $row['ip'] ), $filters['ip'] ) ) {
					return false;
				}
				if ( '' !== $filters['user'] && false === strpos( $row['search_names'], $filters['user'] ) ) {
					return false;
				}
				if ( null !== $type_id && ! in_array( $type_id, $row['type_ids'], true ) ) {
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
				return $b['last_attempt'] - $a['last_attempt'];
			}
		);

		$total = count( $rows );
		$pages = max( 1, (int) ceil( $total / self::PER_PAGE ) );
		$page  = min( $pages, max( 1, absint( isset( $_POST['page'] ) ? wp_unslash( $_POST['page'] ) : 1 ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().

		$slice = array_slice( $rows, ( $page - 1 ) * self::PER_PAGE, self::PER_PAGE );

		wp_send_json_success(
			array(
				'rows'  => array_map( array( __CLASS__, 'format_row' ), $slice ),
				'total' => $total,
				'page'  => $page,
				'pages' => $pages,
			)
		);
	}

	/**
	 * Returns the helper-added allowlist and recent audit entries.
	 *
	 * @return void
	 */
	public static function ajax_registry() {
		self::guard();
		self::send_registry();
	}

	/* ---------------------------------------------------------------------
	 * AJAX: actions
	 * ------------------------------------------------------------------- */

	/**
	 * Unblock only. The IP must currently have an active single-IP block.
	 *
	 * @return void
	 */
	public static function ajax_unblock() {
		self::guard();

		$ip = WFAM_Wordfence::normalize_ip( self::post_raw( 'ip' ) );
		self::fail_on_error( $ip );

		if ( ! self::has_active_block( $ip ) ) {
			wp_send_json_error( array( 'message' => __( 'No active Wordfence block was found for this IP. It may already have expired or been removed.', 'wordfence-access-manager' ) ), 404 );
		}

		$result = WFAM_Plugin::unblock_ip( $ip );

		/* translators: %s: IP address. */
		self::send_done( sprintf( __( '%s was unblocked.', 'wordfence-access-manager' ), $ip ), $result['synced'] );
	}

	/**
	 * Unblock + add to the Wordfence allowlist (public IPs only).
	 *
	 * @return void
	 */
	public static function ajax_unblock_allowlist() {
		self::guard();
		self::allowlist_from_request( true );
	}

	/**
	 * Manual "Add IP to Allowlist" form (public IPs only). Optional unblock.
	 *
	 * @return void
	 */
	public static function ajax_add_allowlist() {
		self::guard();
		self::allowlist_from_request( '1' === self::post_string( 'unblock', 1 ) );
	}

	/**
	 * Removes a helper-added IP from the Wordfence allowlist.
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
	 * Shared handler for both allowlist actions.
	 *
	 * @param bool $unblock Also unblock the IP.
	 * @return void Sends JSON.
	 */
	private static function allowlist_from_request( $unblock ) {
		$ip = WFAM_Wordfence::normalize_public_ip( self::post_raw( 'ip' ) );
		self::fail_on_error( $ip );

		$result = WFAM_Plugin::allowlist_ip( $ip, self::post_string( 'note', 200 ), self::post_string( 'expiry', 10 ), $unblock );
		self::fail_on_error( $result );

		if ( 'added' === $result['status'] ) {
			$message = $unblock
				/* translators: %s: IP address. */
				? sprintf( __( '%s was unblocked and added to the Wordfence allowlist.', 'wordfence-access-manager' ), $ip )
				/* translators: %s: IP address. */
				: sprintf( __( '%s was added to the Wordfence allowlist.', 'wordfence-access-manager' ), $ip );
		} else {
			$message = $unblock
				/* translators: %s: IP address. */
				? sprintf( __( '%s was unblocked. It is already covered by an existing Wordfence allowlist entry, so nothing new was added.', 'wordfence-access-manager' ), $ip )
				/* translators: %s: IP address. */
				: sprintf( __( '%s is already covered by an existing Wordfence allowlist entry. Nothing was added.', 'wordfence-access-manager' ), $ip );
		}

		self::send_done( $message, $result['synced'] );
	}

	/**
	 * Builds one row per blocked IP from Wordfence's blocks + login log.
	 *
	 * @return array[]
	 */
	private static function dataset() {
		$by_ip = array();

		foreach ( WFAM_Wordfence::get_ip_blocks() as $block ) {
			$ip = $block['ip'];
			if ( ! isset( $by_ip[ $ip ] ) ) {
				$by_ip[ $ip ] = array(
					'type_ids'     => array(),
					'reason'       => '',
					'reason_time'  => -1,
					'expiration'   => null,
					'hits'         => 0,
					'last_block'   => 0,
					'reason_names' => array(),
				);
			}
			$row = &$by_ip[ $ip ];

			$row['type_ids'][ $block['type'] ] = $block['type'];
			$row['hits']                     += $block['hits'];
			$row['last_block']                = max( $row['last_block'], $block['blocked_time'], $block['last_attempt'] );

			if ( $block['blocked_time'] > $row['reason_time'] ) {
				$row['reason']      = $block['reason'];
				$row['reason_time'] = $block['blocked_time'];
			}

			// 0 = permanent and always wins; otherwise keep the latest expiry.
			if ( null === $row['expiration'] || ( 0 !== $row['expiration'] && ( 0 === $block['expiration'] || $block['expiration'] > $row['expiration'] ) ) ) {
				$row['expiration'] = $block['expiration'];
			}

			// Lockout reasons quote the username tried; used if the login log was pruned.
			if ( wfBlock::TYPE_LOCKOUT === $block['type'] && preg_match( "/'([^']+)'/", $block['reason'], $m ) ) {
				$row['reason_names'][ strtolower( $m[1] ) ] = array(
					'name'    => $m[1],
					'user_id' => 0,
				);
			}
		}
		unset( $row );

		$logins  = WFAM_Wordfence::get_login_failures( array_keys( $by_ip ) );
		$ids     = array();
		$names   = array();
		$per_ip  = array();

		foreach ( $by_ip as $ip => $row ) {
			$list          = ! empty( $logins[ $ip ]['names'] ) ? $logins[ $ip ]['names'] : $row['reason_names'];
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

		foreach ( $by_ip as $ip => $row ) {
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

			$rows[] = array(
				'ip'           => $ip,
				'type_ids'     => array_values( $row['type_ids'] ),
				'reason'       => $row['reason'],
				'expiration'   => (int) $row['expiration'],
				'hits'         => $row['hits'],
				'attempts'     => isset( $logins[ $ip ] ) ? $logins[ $ip ]['attempts'] : 0,
				'last_attempt' => max( $row['last_block'], isset( $logins[ $ip ] ) ? $logins[ $ip ]['last'] : 0 ),
				'usernames'    => $usernames,
				'search_names' => implode( ' ', $search ),
				'member'       => $member,
				'allowlisted'  => $matcher( $ip ),
				'helper_owned' => isset( $registry[ $ip ] ),
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
			$in    = implode( ',', array_fill( 0, count( $chunk ), '%d' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- placeholders built above.
			$found = array_merge( $found, (array) $wpdb->get_results( $wpdb->prepare( "SELECT ID, user_login, user_email, display_name FROM {$wpdb->users} WHERE ID IN ($in)", $chunk ) ) );
		}
		foreach ( array_chunk( $names, 100 ) as $chunk ) {
			$in    = implode( ',', array_fill( 0, count( $chunk ), '%s' ) );
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
		$labels = WFAM_Wordfence::type_labels();
		$types  = array();
		foreach ( $row['type_ids'] as $id ) {
			$types[] = isset( $labels[ $id ] ) ? $labels[ $id ] : (string) $id;
		}

		$member = null;
		if ( $row['member'] ) {
			$member = array(
				'name' => '' !== $row['member']->display_name ? $row['member']->display_name : $row['member']->user_login,
				'url'  => esc_url_raw( get_edit_user_link( (int) $row['member']->ID ) ),
			);
		}

		return array(
			'ip'             => $row['ip'],
			'member'         => $member,
			'username'       => isset( $row['usernames'][0] ) ? $row['usernames'][0] : '',
			'otherUsernames' => max( 0, count( $row['usernames'] ) - 1 ),
			'manyUsernames'  => count( $row['usernames'] ) >= self::MANY_USERNAMES ? count( $row['usernames'] ) : 0,
			'attempts'       => $row['attempts'],
			'blockedHits'    => $row['hits'],
			'lastAttempt'    => self::format_time( $row['last_attempt'] ),
			'types'          => $types,
			'reason'         => $row['reason'],
			'expiration'     => 0 === $row['expiration'] ? __( 'Never (permanent)', 'wordfence-access-manager' ) : self::format_time( $row['expiration'] ),
			'allowlisted'    => $row['allowlisted'],
			'helperOwned'    => $row['helper_owned'],
		);
	}

	/**
	 * Sends the helper registry + recent audit log.
	 *
	 * @return void
	 */
	private static function send_registry() {
		$entries = array();
		foreach ( WFAM_Store::registry() as $entry ) {
			if ( empty( $entry['expires_at'] ) ) {
				$expiry = __( 'Never', 'wordfence-access-manager' );
			} elseif ( $entry['expires_at'] <= time() ) {
				$expiry = __( 'Expired – removal pending', 'wordfence-access-manager' );
			} else {
				$expiry = self::format_time( $entry['expires_at'] );
			}

			$entries[] = array(
				'ip'      => $entry['ip'],
				'note'    => $entry['note'],
				'addedBy' => '' !== $entry['added_by_name'] ? $entry['added_by_name'] : '#' . (int) $entry['added_by'],
				'added'   => self::format_time( $entry['added_at'] ),
				'addedAt' => (int) $entry['added_at'],
				'expiry'  => $expiry,
			);
		}
		usort(
			$entries,
			static function ( $a, $b ) {
				return $b['addedAt'] - $a['addedAt'];
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
				'entries' => $entries,
				'audit'   => $audit,
			)
		);
	}

	/**
	 * Whether the IP currently has an active single-IP block or lockout.
	 *
	 * @param string $ip Canonical IP.
	 * @return bool
	 */
	private static function has_active_block( $ip ) {
		foreach ( WFAM_Wordfence::get_ip_blocks() as $block ) {
			if ( $block['ip'] === $ip ) {
				return true;
			}
		}
		return false;
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
	 * "Y-m-d H:i (3 hours ago / in 2 days)" in the site's formats/timezone.
	 *
	 * @param int $ts Unix timestamp.
	 * @return string
	 */
	private static function format_time( $ts ) {
		$ts = (int) $ts;
		if ( $ts <= 0 ) {
			return '—';
		}

		$date     = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ts );
		$relative = $ts > time()
			/* translators: %s: human time difference. */
			? sprintf( __( 'in %s', 'wordfence-access-manager' ), human_time_diff( time(), $ts ) )
			/* translators: %s: human time difference. */
			: sprintf( __( '%s ago', 'wordfence-access-manager' ), human_time_diff( $ts, time() ) );

		return $date . ' (' . $relative . ')';
	}

	/**
	 * Expiry dropdown labels (keys match WFAM_Store::expiry_choices()).
	 *
	 * @return array<string, string>
	 */
	private static function expiry_labels() {
		return array(
			'7'     => __( '7 days', 'wordfence-access-manager' ),
			'30'    => __( '30 days', 'wordfence-access-manager' ),
			'never' => __( 'Never', 'wordfence-access-manager' ),
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
			'unblock'           => __( 'Unblocked', 'wordfence-access-manager' ),
			'unblock_allowlist' => __( 'Unblocked + allowlisted', 'wordfence-access-manager' ),
			'allowlist_add'     => __( 'Allowlisted', 'wordfence-access-manager' ),
			'allowlist_remove'  => __( 'Removed from allowlist', 'wordfence-access-manager' ),
			'allowlist_expired' => __( 'Allowlist expired (auto-removed)', 'wordfence-access-manager' ),
		);
		return isset( $labels[ $action ] ) ? $labels[ $action ] : $action;
	}
}
