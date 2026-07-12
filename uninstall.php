<?php
/**
 * Uninstall SquidSec Shield.
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$tables = array(
	$wpdb->prefix . 'squidsec_shield_logs',
	$wpdb->prefix . 'squidsec_shield_blocks',
	$wpdb->prefix . 'squidsec_shield_scans',
	$wpdb->prefix . 'squidsec_shield_findings',
	$wpdb->prefix . 'squidsec_shield_fim',
	$wpdb->prefix . 'squidsec_shield_rules_custom',
	$wpdb->prefix . 'squidsec_shield_ip_list',
	$wpdb->prefix . 'squidsec_shield_rate',
);

foreach ( $tables as $table ) {
	// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
}

$options = array(
	'squidsec_shield_settings',
	'squidsec_shield_hardening',
	'squidsec_shield_db_version',
	'squidsec_shield_rules_state',
	'squidsec_shield_fim_baseline',
	'squidsec_shield_threat_level',
	'squidsec_shield_last_scan',
	'squidsec_shield_vuln_cache',
	'squidsec_shield_signature_version',
	'squidsec_shield_waf_rules_version',
	'squidsec_shield_activated',
);

foreach ( $options as $opt ) {
	delete_option( $opt );
}

// Remove 2FA user meta.
$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'squidsec_shield_%'" );

// Remove early WAF mu-plugin if we installed it.
$mu = WPMU_PLUGIN_DIR . '/squidsec-shield-early.php';
if ( file_exists( $mu ) ) {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
	@unlink( $mu );
}
