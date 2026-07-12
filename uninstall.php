<?php
/**
 * Uninstall SquidSec Shield.
 *
 * @package SquidSec_Shield
 * @author            SquidSec
 * @copyright         2026 SquidSec
 * @license           GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

$squidsec_shield_tables = array(
	$wpdb->prefix . 'squidsec_shield_logs',
	$wpdb->prefix . 'squidsec_shield_blocks',
	$wpdb->prefix . 'squidsec_shield_scans',
	$wpdb->prefix . 'squidsec_shield_findings',
	$wpdb->prefix . 'squidsec_shield_fim',
	$wpdb->prefix . 'squidsec_shield_rules_custom',
	$wpdb->prefix . 'squidsec_shield_ip_list',
	$wpdb->prefix . 'squidsec_shield_rate',
);

foreach ( $squidsec_shield_tables as $squidsec_shield_table ) {
	// Table names are built from $wpdb->prefix + fixed suffix (no user input).
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $squidsec_shield_table ) . '`' );
}

$squidsec_shield_options = array(
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

foreach ( $squidsec_shield_options as $squidsec_shield_opt ) {
	delete_option( $squidsec_shield_opt );
}

// Remove 2FA and other plugin user meta.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query(
	$wpdb->prepare(
		"DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s",
		$wpdb->esc_like( 'squidsec_shield_' ) . '%'
	)
);

// Remove early WAF mu-plugin if we installed it.
$squidsec_shield_mu = WPMU_PLUGIN_DIR . '/squidsec-shield-early.php';
if ( file_exists( $squidsec_shield_mu ) ) {
	// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
	@unlink( $squidsec_shield_mu );
}
