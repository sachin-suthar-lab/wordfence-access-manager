<?php
/**
 * Plugin Name: Wordfence Access Manager
 * Description: Adds Wordfence → Access Manager: see who is temporarily locked out by Wordfence's failed-login protection, unblock them, or unblock + allowlist their IP for a limited time. Uses Wordfence's own lockouts, settings and functions.
 * Version: 1.1.0
 * Author: Sachin Suthar
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Requires Plugins: wordfence
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wordfence-access-manager
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

define( 'WFAM_VERSION', '1.1.0' );
define( 'WFAM_FILE', __FILE__ );
define( 'WFAM_DIR', plugin_dir_path( __FILE__ ) );
define( 'WFAM_URL', plugin_dir_url( __FILE__ ) );

require_once WFAM_DIR . 'includes/class-wfam-wordfence.php';
require_once WFAM_DIR . 'includes/class-wfam-store.php';
require_once WFAM_DIR . 'includes/class-wfam-plugin.php';
require_once WFAM_DIR . 'includes/class-wfam-admin.php';

register_activation_hook( __FILE__, array( 'WFAM_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WFAM_Plugin', 'deactivate' ) );

WFAM_Plugin::init();
