<?php
/**
 * PHPUnit bootstrap for SquidShield WP.
 *
 * Loads the local WordPress install (Docker path or relative path).
 *
 * @package SquidSec_Shield
 */

// phpcs:disable WordPress.Security.EscapeOutput

define( 'SQUIDSHIELD_TESTING', true );

$wp_load_candidates = array(
	getenv( 'WP_LOAD' ) ?: '',
	'/var/www/html/wp-load.php',
	dirname( __DIR__, 4 ) . '/wp-load.php', // .../wordpress/wp-load.php from plugins/squidsec-shield/tests
	dirname( __DIR__, 3 ) . '/../../wp-load.php',
);

// Plugin lives at: wordpress/wp-content/plugins/squidsec-shield
// so wp-load is three levels up from plugin root, four from tests/.
$wp_load_candidates[] = dirname( __DIR__, 3 ) . '/wp-load.php';
$wp_load_candidates[] = dirname( __DIR__ ) . '/../../../wp-load.php';

$wp_load = null;
foreach ( $wp_load_candidates as $candidate ) {
	if ( $candidate && file_exists( $candidate ) ) {
		$wp_load = $candidate;
		break;
	}
}

if ( ! $wp_load ) {
	fwrite( STDERR, "Could not find wp-load.php. Set WP_LOAD env var.\n" );
	fwrite( STDERR, "Tried:\n" . implode( "\n", array_filter( $wp_load_candidates ) ) . "\n" );
	exit( 1 );
}

// Avoid theme output / cron noise.
if ( ! defined( 'WP_USE_THEMES' ) ) {
	define( 'WP_USE_THEMES', false );
}
if ( ! defined( 'SHORTINIT' ) ) {
	// Full WP needed for options, DB, plugins.
}

require_once $wp_load;

// Ensure plugin constants + autoloader.
$plugin_root = dirname( __DIR__ );
if ( ! defined( 'SQUIDSEC_SHIELD_VERSION' ) ) {
	// Manually load plugin bootstrap pieces without re-running activation hooks.
	define( 'SQUIDSEC_SHIELD_VERSION', '1.0.0-test' );
	define( 'SQUIDSEC_SHIELD_NAME', 'SquidShield WP - By SquidSec' );
	define( 'SQUIDSEC_SHIELD_FILE', $plugin_root . '/squidsec-shield.php' );
	define( 'SQUIDSEC_SHIELD_DIR', trailingslashit( $plugin_root ) );
	define( 'SQUIDSEC_SHIELD_URL', plugins_url( '/', SQUIDSEC_SHIELD_FILE ) );
	define( 'SQUIDSEC_SHIELD_BASENAME', plugin_basename( SQUIDSEC_SHIELD_FILE ) );
	define( 'SQUIDSEC_SHIELD_DB_VERSION', '1.0.0' );
	require_once SQUIDSEC_SHIELD_DIR . 'includes/class-autoloader.php';
	SquidSec_Shield_Autoloader::register();
}

// Make sure plugin is active for integration expectations.
if ( function_exists( 'activate_plugin' ) ) {
	$basename = 'squidsec-shield/squidsec-shield.php';
	if ( ! is_plugin_active( $basename ) ) {
		// Don't hard-fail; classes still load via autoloader.
	}
}

// Ensure tables exist for log/FIM tests.
if ( class_exists( 'SquidSec_Shield_Database' ) ) {
	SquidSec_Shield_Database::create_tables();
}
if ( class_exists( 'SquidSec_Shield_Options' ) ) {
	SquidSec_Shield_Options::ensure_defaults();
}

require_once __DIR__ . '/Support/TestCase.php';
