<?php
/**
 * Plugin Name:       SquidShield
 * Plugin URI:        https://squidsec.com/shield
 * Description:       Install and activate to secure your WordPress site automatically. Firewall, login protection, malware scanning, file integrity, hardening, and more. By SquidSec.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            SquidSec
 * Author URI:        https://squidsec.com
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       squidsec-shield
 * Domain Path:       /languages
 *
 * @package    SquidSec_Shield
 * @author     SquidSec
 * @copyright  2026 SquidSec
 * @license    GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'SQUIDSEC_SHIELD_VERSION', '1.0.0' );
define( 'SQUIDSEC_SHIELD_NAME', 'SquidShield by SquidSec' );
define( 'SQUIDSEC_SHIELD_FILE', __FILE__ );
define( 'SQUIDSEC_SHIELD_DIR', plugin_dir_path( __FILE__ ) );
define( 'SQUIDSEC_SHIELD_URL', plugin_dir_url( __FILE__ ) );
define( 'SQUIDSEC_SHIELD_BASENAME', plugin_basename( __FILE__ ) );
define( 'SQUIDSEC_SHIELD_DB_VERSION', '1.0.0' );

require_once SQUIDSEC_SHIELD_DIR . 'includes/class-autoloader.php';
SquidSec_Shield_Autoloader::register();

register_activation_hook( __FILE__, array( 'SquidSec_Shield_Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'SquidSec_Shield_Deactivator', 'deactivate' ) );

/**
 * Boot the plugin.
 *
 * @return SquidSec_Shield_Plugin
 */
function squidsec_shield() {
	return SquidSec_Shield_Plugin::instance();
}

add_action( 'plugins_loaded', array( 'SquidSec_Shield_Plugin', 'instance' ), 1 );

// Run WAF as early as possible after plugins load (mu-plugin drop-in runs even earlier).
add_action( 'plugins_loaded', array( 'SquidSec_Shield_WAF', 'maybe_run' ), 0 );
