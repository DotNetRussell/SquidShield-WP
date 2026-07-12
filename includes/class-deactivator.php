<?php
/**
 * Deactivation routines.
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
 * Deactivator.
 */
class SquidSec_Shield_Deactivator {

	/**
	 * Run on deactivation (keeps data; uninstall removes it).
	 */
	public static function deactivate() {
		wp_clear_scheduled_hook( 'squidsec_shield_daily' );
		wp_clear_scheduled_hook( 'squidsec_shield_hourly' );
		wp_clear_scheduled_hook( 'squidsec_shield_scan_batch' );
		wp_clear_scheduled_hook( 'squidsec_shield_fim_check' );

		// Remove early drop-in so requests are not blocked while inactive.
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) {
			$dst = WPMU_PLUGIN_DIR . '/squidsec-shield-early.php';
			if ( file_exists( $dst ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
				@unlink( $dst );
			}
		}

		flush_rewrite_rules();
	}
}
