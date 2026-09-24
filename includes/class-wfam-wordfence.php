<?php
/**
 * Thin adapter around the Wordfence classes this plugin relies on.
 *
 * Every Wordfence call in the plugin goes through this class so that:
 *  - availability is checked in one place (the plugin fails safely when
 *    Wordfence is inactive or an expected class/method has changed), and
 *  - a future Wordfence API change only needs fixing in one file.
 *
 * Verified against Wordfence 8.2.2. The only Wordfence data this class ever
 * changes is (a) block rows for one explicitly chosen IP, via Wordfence's own
 * wfBlock::unblockIP(), and (b) single-IP entries in the "Allowlisted IP
 * addresses that bypass all rules" setting. It never touches login limits,
 * firewall on/off, lockout durations or any other setting.
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

class WFAM_Wordfence {

	/**
	 * Wordfence classes/methods this plugin calls. Checked before any use.
	 *
	 * @var array<string, string[]>
	 */
	private static $required = array(
		'wordfence'     => array( 'whitelistIP', 'clearLockoutCounters' ),
		'wfBlock'       => array( 'allBlocks', 'unblockIP' ),
		'wfConfig'      => array( 'get', 'set' ),
		'wfUtils'       => array( 'inet_pton', 'inet_ntop', 'getIP', 'subnetContainsIP', 'isPrivateAddress' ),
		'wfDB'          => array( 'networkTable', 'binaryValueToSQLHex' ),
		'wfUserIPRange' => array( 'isIPInRange' ),
	);

	/**
	 * wfBlock type constants this plugin lists (single-IP block types only;
	 * country and pattern blocks have no single IP and are never touched).
	 *
	 * @var string[]
	 */
	private static $type_constants = array(
		'TYPE_LOCKOUT',
		'TYPE_IP_AUTOMATIC_TEMPORARY',
		'TYPE_IP_AUTOMATIC_PERMANENT',
		'TYPE_IP_MANUAL',
		'TYPE_WFSN_TEMPORARY',
		'TYPE_RATE_BLOCK',
		'TYPE_RATE_THROTTLE',
	);

	/**
	 * Ranges rejected on top of PHP's private/reserved filter. Includes the
	 * documentation nets (Wordfence stores its country/pattern block rows
	 * under 192.0.2.1 / 192.0.2.2, so these must never reach unblockIP()) and
	 * carrier-grade NAT, which is shared by many unrelated users.
	 *
	 * @var string[]
	 */
	private static $extra_rejected_ranges = array(
		'100.64.0.0/10',
		'192.0.0.0/24',
		'192.0.2.0/24',
		'198.18.0.0/15',
		'198.51.100.0/24',
		'203.0.113.0/24',
		'2001:db8::/32',
		'fc00::/7',
		'fe80::/10',
	);

	/**
	 * Returns the list of missing Wordfence classes/methods/constants.
	 * An empty array means everything this plugin needs is present.
	 *
	 * Must only be called after `plugins_loaded` (Wordfence loads after this
	 * plugin alphabetically).
	 *
	 * @return string[]
	 */
	public static function missing_requirements() {
		static $missing = null;
		if ( null !== $missing ) {
			return $missing;
		}

		$missing = array();
		foreach ( self::$required as $class => $methods ) {
			if ( ! class_exists( $class ) ) {
				$missing[] = $class;
				continue;
			}
			foreach ( $methods as $method ) {
				if ( ! method_exists( $class, $method ) ) {
					$missing[] = $class . '::' . $method . '()';
				}
			}
		}
		if ( class_exists( 'wfBlock' ) ) {
			foreach ( self::$type_constants as $const ) {
				if ( ! defined( 'wfBlock::' . $const ) ) {
					$missing[] = 'wfBlock::' . $const;
				}
			}
		}

		return $missing;
	}

	/**
	 * True when Wordfence is active and exposes everything this plugin uses.
	 *
	 * @return bool
	 */
	public static function is_available() {
		return array() === self::missing_requirements();
	}

	/**
	 * Map of wfBlock type ID => label shown in the admin screen.
	 *
	 * Our own labels are used because wfBlock::nameForType() groups most
	 * types as a generic "IP Block".
	 *
	 * @return array<int, string>
	 */
	public static function type_labels() {
		return array(
			wfBlock::TYPE_LOCKOUT                => __( 'Login lockout', 'wordfence-access-manager' ),
			wfBlock::TYPE_IP_AUTOMATIC_TEMPORARY => __( 'Automatic block (temporary)', 'wordfence-access-manager' ),
			wfBlock::TYPE_IP_AUTOMATIC_PERMANENT => __( 'Automatic block (made permanent)', 'wordfence-access-manager' ),
			wfBlock::TYPE_IP_MANUAL              => __( 'Manual block', 'wordfence-access-manager' ),
			wfBlock::TYPE_WFSN_TEMPORARY         => __( 'Wordfence Security Network', 'wordfence-access-manager' ),
			wfBlock::TYPE_RATE_BLOCK             => __( 'Rate limit block', 'wordfence-access-manager' ),
			wfBlock::TYPE_RATE_THROTTLE          => __( 'Rate limit throttle', 'wordfence-access-manager' ),
		);
	}

	/**
	 * All active single-IP blocks, read through Wordfence's wfBlock::allBlocks()
	 * (which already excludes expired rows).
	 *
	 * @return array[] List of plain arrays (id, type, ip, reason, blocked_time, last_attempt, hits, expiration).
	 */
	public static function get_ip_blocks() {
		$blocks = wfBlock::allBlocks( true, array_keys( self::type_labels() ) );
		$out    = array();

		foreach ( $blocks as $block ) {
			$ip = (string) $block->ip;
			if ( '' === $ip ) {
				continue;
			}
			$out[] = array(
				'id'           => (int) $block->id,
				'type'         => (int) $block->type,
				'ip'           => $ip,
				'reason'       => (string) $block->reason,
				'blocked_time' => (int) $block->blockedTime,
				'last_attempt' => (int) $block->lastAttempt,
				'hits'         => (int) $block->blockedHits,
				'expiration'   => (int) $block->expiration,
			);
		}

		return $out;
	}

	/**
	 * Failed-login history for the given IPs, read (read-only) from
	 * Wordfence's own login log table (wfLogins).
	 *
	 * Wordfence has no public reader for this table, so it is queried with the
	 * same table-name and binary-IP helpers Wordfence itself uses.
	 *
	 * @param string[] $ips Printable IPs.
	 * @return array<string, array> Keyed by printable IP: attempts, last, names (lowercased username => [name, user_id]) newest first.
	 */
	public static function get_login_failures( array $ips ) {
		global $wpdb;

		$table  = wfDB::networkTable( 'wfLogins' );
		$result = array();

		foreach ( array_chunk( array_values( array_unique( $ips ) ), 200 ) as $chunk ) {
			$hex = array();
			foreach ( $chunk as $ip ) {
				$hex[] = wfDB::binaryValueToSQLHex( wfUtils::inet_pton( $ip ) );
			}

			// Values are hex literals built by wfDB::binaryValueToSQLHex(), not user input.
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( "SELECT `IP`, `username`, `userID`, `ctime` FROM `{$table}` WHERE `fail` = 1 AND `IP` IN (" . implode( ',', $hex ) . ') ORDER BY `ctime` DESC', ARRAY_A );

			foreach ( (array) $rows as $row ) {
				$ip = wfUtils::inet_ntop( $row['IP'] );
				if ( ! isset( $result[ $ip ] ) ) {
					$result[ $ip ] = array(
						'attempts' => 0,
						'last'     => 0,
						'names'    => array(),
					);
				}

				$result[ $ip ]['attempts']++;
				$result[ $ip ]['last'] = max( $result[ $ip ]['last'], (int) floor( (float) $row['ctime'] ) );

				$name = (string) $row['username'];
				$key  = strtolower( $name );
				if ( '' !== $name && ! isset( $result[ $ip ]['names'][ $key ] ) ) {
					$result[ $ip ]['names'][ $key ] = array(
						'name'    => $name,
						'user_id' => (int) $row['userID'],
					);
				}
			}
		}

		return $result;
	}

	/**
	 * Current entries of Wordfence's "Allowlisted IP addresses that bypass all
	 * rules" setting (stored comma-separated in wfConfig 'whitelisted').
	 *
	 * @return string[]
	 */
	public static function allowlist_entries() {
		return array_values( array_filter( array_map( 'trim', explode( ',', (string) wfConfig::get( 'whitelisted', '' ) ) ) ) );
	}

	/**
	 * Builds a matcher for the current allowlist using Wordfence's own
	 * wfUserIPRange, so single IPs, CIDR, bracket and dash ranges all match
	 * exactly the way Wordfence matches them.
	 *
	 * Read fresh from wfConfig on purpose: wfUtils::getIPWhitelist() caches for
	 * the whole request and would not reflect a change made moments earlier.
	 *
	 * @return callable (string $ip): bool
	 */
	public static function allowlist_matcher() {
		$ranges = array();
		foreach ( self::allowlist_entries() as $entry ) {
			$ranges[] = new wfUserIPRange( $entry );
		}

		return static function ( $ip ) use ( $ranges ) {
			foreach ( $ranges as $range ) {
				if ( $range->isIPInRange( $ip ) ) {
					return true;
				}
			}
			return false;
		};
	}

	/**
	 * Whether an IP is already covered by the Wordfence allowlist setting.
	 *
	 * @param string $ip Printable IP.
	 * @return bool
	 */
	public static function is_allowlisted( $ip ) {
		$matcher = self::allowlist_matcher();
		return $matcher( $ip );
	}

	/**
	 * Adds one IP to the Wordfence allowlist via wordfence::whitelistIP().
	 * Does not sync the firewall; callers run sync_firewall() once afterwards.
	 *
	 * @param string $ip Canonical public IP (see normalize_public_ip()).
	 * @return string|WP_Error 'added', or 'exists' when an existing entry already covers it.
	 */
	public static function add_to_allowlist( $ip ) {
		if ( self::is_allowlisted( $ip ) ) {
			return 'exists';
		}

		try {
			$added = wordfence::whitelistIP( $ip );
		} catch ( Exception $e ) {
			return new WP_Error( 'wfam_allowlist_failed', $e->getMessage() );
		}

		return $added ? 'added' : 'exists';
	}

	/**
	 * Removes one exact single-IP entry from the Wordfence allowlist, leaving
	 * every other entry (ranges, other IPs) exactly as it was.
	 *
	 * Wordfence has no "remove one allowlist IP" function, so this uses its
	 * config API (wfConfig::set), which is what the Wordfence options page uses
	 * and which fires Wordfence's `wordfence_updated_allowed_ips` hook.
	 *
	 * @param string $ip Canonical IP.
	 * @return bool True when an entry was removed.
	 */
	public static function remove_from_allowlist( $ip ) {
		$entries = self::allowlist_entries();
		$kept    = array();

		foreach ( $entries as $entry ) {
			if ( filter_var( $entry, FILTER_VALIDATE_IP ) && self::canonical_ip( $entry ) === $ip ) {
				continue;
			}
			$kept[] = $entry;
		}

		if ( count( $kept ) === count( $entries ) ) {
			return false;
		}

		wfConfig::set( 'whitelisted', implode( ',', $kept ) );
		return true;
	}

	/**
	 * Removes every Wordfence block/lockout row for one IP and resets its
	 * failed-login counters. This is exactly what Wordfence's own
	 * "Unblock" button does (wordfence::ajax_unblockIP_callback()).
	 * Does not sync the firewall; callers run sync_firewall() once afterwards.
	 *
	 * @param string $ip Canonical public IP.
	 * @return void
	 */
	public static function unblock( $ip ) {
		wfBlock::unblockIP( $ip );
		wordfence::clearLockoutCounters( $ip );
	}

	/**
	 * Pushes the current block list and allowlist into the Wordfence firewall's
	 * synced config (wflogs/config-synced.php) immediately, instead of waiting
	 * for Wordfence to do it on the next request.
	 *
	 *  - wfWAFIPBlocksController::synchronizeConfigSettings() is the function
	 *    Wordfence itself runs after creating blocks; it copies blocks/lockouts.
	 *  - The allowlist copy mirrors wordfence::veryFirstAction(), which writes
	 *    `whitelistedIPs` from wfConfig on every request.
	 *
	 * Only data is copied; no setting is changed.
	 *
	 * @return bool False when the firewall could not be synced now (Wordfence will still sync on its next request).
	 */
	public static function sync_firewall() {
		if ( defined( 'WFWAF_SUBDIRECTORY_INSTALL' ) && WFWAF_SUBDIRECTORY_INSTALL ) {
			return false;
		}

		try {
			if ( class_exists( 'wfWAFIPBlocksController' ) && method_exists( 'wfWAFIPBlocksController', 'synchronizeConfigSettings' ) ) {
				wfWAFIPBlocksController::synchronizeConfigSettings();
			} elseif ( class_exists( 'wfWAFIPBlocksController' ) && method_exists( 'wfWAFIPBlocksController', 'setNeedsSynchronizeConfigSettings' ) ) {
				wfWAFIPBlocksController::setNeedsSynchronizeConfigSettings();
			} else {
				return false;
			}

			if ( class_exists( 'wfWAF' ) && wfWAF::getInstance() ) {
				wfWAF::getInstance()->getStorageEngine()->setConfig( 'whitelistedIPs', (string) wfConfig::get( 'whitelisted' ), 'synced' );
			}
		} catch ( Throwable $e ) {
			return false;
		}

		return true;
	}

	/**
	 * The visitor IP exactly as Wordfence resolves it (honours the
	 * "How does Wordfence get IPs" setting).
	 *
	 * @return string
	 */
	public static function current_ip() {
		return (string) wfUtils::getIP();
	}

	/**
	 * Canonical printable form Wordfence uses (IPv4-mapped IPv6 -> IPv4,
	 * IPv6 compressed/lowercased).
	 *
	 * @param string $ip Valid IP.
	 * @return string
	 */
	public static function canonical_ip( $ip ) {
		return (string) wfUtils::inet_ntop( wfUtils::inet_pton( $ip ) );
	}

	/**
	 * Validates input as ONE IP address (any scope) and returns Wordfence's
	 * canonical form. Used for Unblock, where the IP must also match an
	 * existing block row.
	 *
	 * Always rejects 192.0.2.0/24: Wordfence stores its country and pattern
	 * block rows under 192.0.2.1 / 192.0.2.2, and wfBlock::unblockIP() deletes
	 * every row for an IP, so those must never be passed to it.
	 *
	 * @param mixed $raw Unslashed input.
	 * @return string|WP_Error Canonical IP or error.
	 */
	public static function normalize_ip( $raw ) {
		$raw = is_string( $raw ) ? trim( $raw ) : '';

		if ( '' === $raw ) {
			return new WP_Error( 'wfam_ip_empty', __( 'Enter an IP address.', 'wordfence-access-manager' ) );
		}

		// Only hex digits, dots and colons: rules out "/", "[", "-", "*", ",", spaces.
		if ( strlen( $raw ) > 45 || preg_match( '/[^0-9a-f:.]/i', $raw ) || ! filter_var( $raw, FILTER_VALIDATE_IP ) ) {
			return new WP_Error( 'wfam_ip_invalid', __( 'Enter a single valid IP address. Ranges, CIDR blocks and wildcards are not allowed.', 'wordfence-access-manager' ) );
		}

		$ip = self::canonical_ip( $raw );

		if ( wfUtils::subnetContainsIP( '192.0.2.0/24', $ip ) ) {
			return new WP_Error( 'wfam_ip_reserved', __( 'This address is reserved and cannot be used.', 'wordfence-access-manager' ) );
		}

		return $ip;
	}

	/**
	 * Strictly validates input as ONE public IP address. Used for anything
	 * that adds to the allowlist.
	 *
	 * Rejects: ranges, CIDR, wildcards, lists, private, reserved, loopback,
	 * link-local, documentation, benchmarking and carrier-grade NAT addresses.
	 *
	 * @param mixed $raw Unslashed input.
	 * @return string|WP_Error Canonical IP or error.
	 */
	public static function normalize_public_ip( $raw ) {
		$ip = self::normalize_ip( $raw );
		if ( is_wp_error( $ip ) ) {
			return $ip;
		}

		$is_public = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		if ( ! $is_public || wfUtils::isPrivateAddress( $ip ) ) {
			return new WP_Error( 'wfam_ip_not_public', __( 'Private, reserved and loopback addresses cannot be used. Enter the public IP address.', 'wordfence-access-manager' ) );
		}

		foreach ( self::$extra_rejected_ranges as $range ) {
			if ( wfUtils::subnetContainsIP( $range, $ip ) ) {
				return new WP_Error( 'wfam_ip_not_public', __( 'This address is in a reserved or shared range (for example carrier-grade NAT) and cannot be used.', 'wordfence-access-manager' ) );
			}
		}

		return $ip;
	}
}
