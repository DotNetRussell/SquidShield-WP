<?php
/**
 * Activation routines.
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
 * Activator.
 */
class SquidSec_Shield_Activator {

	/**
	 * Run on plugin activation — secure by default, zero config.
	 */
	public static function activate() {
		SquidSec_Shield_Database::create_tables();
		self::install_early_dropin();
		SquidSec_Shield_Cron::schedule_events();

		// Apply full protection profile immediately (firewall, login, hardening, etc.).
		SquidSec_Shield_Setup::secure_on_activate();

		update_option( 'squidsec_shield_activated', time() );
		update_option( 'squidsec_shield_db_version', SQUIDSEC_SHIELD_DB_VERSION );

		if ( ! wp_next_scheduled( 'squidsec_shield_daily' ) ) {
			wp_schedule_event( time() + 120, 'daily', 'squidsec_shield_daily' );
		}
		if ( ! wp_next_scheduled( 'squidsec_shield_hourly' ) ) {
			wp_schedule_event( time() + 60, 'hourly', 'squidsec_shield_hourly' );
		}

		flush_rewrite_rules();
	}

	/**
	 * Install early WAF mu-plugin drop-in.
	 */
	public static function install_early_dropin() {
		if ( ! defined( 'WPMU_PLUGIN_DIR' ) ) {
			return;
		}
		if ( ! is_dir( WPMU_PLUGIN_DIR ) ) {
			wp_mkdir_p( WPMU_PLUGIN_DIR );
		}
		$src = SQUIDSEC_SHIELD_DIR . 'dropins/squidsec-shield-early.php';
		$dst = WPMU_PLUGIN_DIR . '/squidsec-shield-early.php';
		if ( file_exists( $src ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_copy
			@copy( $src, $dst );
		}
	}
}
