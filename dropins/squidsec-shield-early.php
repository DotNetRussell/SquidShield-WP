<?php
/**
 * SquidSec Shield early WAF drop-in (must-use).
 *
 * Copied to wp-content/mu-plugins/ on activation. Keep lightweight.
 *
 * Do not declare a WordPress plugin header in this file (no Plugin-Name field).
 * After zip install, plugin_info() scans one subdirectory deep; a nested
 * plugin header makes Activate target this file and fail with
 * "The plugin does not have a valid header."
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
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Early lightweight pattern block (subset). Full engine runs after plugins_loaded.
 */
function squidsec_shield_early_waf() {
	// Skip CLI.
	if ( PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' ) {
		return;
	}
	// Skip if settings say disabled — options may not be loaded; use raw DB only when $wpdb ready.
	// At muplugins_loaded, $wpdb is available.
	if ( ! function_exists( 'get_option' ) ) {
		return;
	}

	$settings = get_option( 'squidsec_shield_settings', array() );
	if ( is_array( $settings ) ) {
		if ( isset( $settings['enabled'] ) && ! $settings['enabled'] ) {
			return;
		}
		if ( isset( $settings['waf_enabled'] ) && ! $settings['waf_enabled'] ) {
			return;
		}
		if ( ! empty( $settings['pentest_mode'] ) ) {
			return; // Full plugin will log.
		}
	}

	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- public request inspection.
	$uri  = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- public request inspection.
	$qs   = isset( $_SERVER['QUERY_STRING'] ) ? sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) : '';
	$blob = strtolower( $uri . ' ' . $qs );

	// Critical high-confidence patterns only (low FP).
	$patterns = array(
		'union select',
		'union%20select',
		'../wp-config',
		'..%2fwp-config',
		'/etc/passwd',
		'wp-config.php.bak',
		'base64_decode(',
		'<?php',
		'eval(base64',
		'file_put_contents(',
		'shell_exec(',
		'passthru(',
		'\x00',
	);

	// Don't block normal admin logged-in traffic with php tags in post body — only URI/query here.
	foreach ( $patterns as $p ) {
		if ( false !== strpos( $blob, $p ) ) {
			if ( ! headers_sent() ) {
				header( 'HTTP/1.1 403 Forbidden' );
				header( 'X-SquidSec-Shield: early-block' );
				header( 'Content-Type: text/plain; charset=utf-8' );
			}
			echo 'Forbidden';
			exit;
		}
	}
}
add_action( 'muplugins_loaded', 'squidsec_shield_early_waf', 0 );
