<?php
/**
 * Scheduled jobs.
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
 * Cron.
 */
class SquidSec_Shield_Cron {

	/**
	 * Hook handlers.
	 */
	public static function init() {
		add_action( 'squidsec_shield_daily', array( __CLASS__, 'run_daily' ) );
		add_action( 'squidsec_shield_hourly', array( __CLASS__, 'run_hourly' ) );
		add_action( 'squidsec_shield_scan_batch', array( 'SquidSec_Shield_Malware_Scanner', 'process_batch' ) );
		add_action( 'squidsec_shield_fim_check', array( 'SquidSec_Shield_FIM', 'check_integrity' ) );
	}

	/**
	 * Ensure schedules exist.
	 */
	public static function schedule_events() {
		if ( ! wp_next_scheduled( 'squidsec_shield_daily' ) ) {
			wp_schedule_event( time() + 300, 'daily', 'squidsec_shield_daily' );
		}
		if ( ! wp_next_scheduled( 'squidsec_shield_hourly' ) ) {
			wp_schedule_event( time() + 120, 'hourly', 'squidsec_shield_hourly' );
		}
	}

	/**
	 * Daily tasks.
	 */
	public static function run_daily() {
		if ( ! SquidSec_Shield_Options::is_enabled() ) {
			return;
		}
		if ( SquidSec_Shield_Options::get( 'malware_scan_enabled' ) ) {
			SquidSec_Shield_Malware_Scanner::start_scan( 'scheduled' );
		}
		if ( SquidSec_Shield_Options::get( 'vuln_scan_enabled' ) ) {
			SquidSec_Shield_Vuln_Scanner::run_scan( true );
		}
		if ( SquidSec_Shield_Options::get( 'misconfig_scan_enabled' ) ) {
			SquidSec_Shield_Misconfig::run_scan( true );
		}
		if ( SquidSec_Shield_Options::get( 'sensitive_file_protect' ) ) {
			SquidSec_Shield_Sensitive_Files::scan( true );
		}
		SquidSec_Shield_Audit_Log::purge_old();
		if ( SquidSec_Shield_Options::get( 'daily_report' ) ) {
			SquidSec_Shield_Alerts::send_daily_summary();
		}
	}

	/**
	 * Hourly tasks.
	 */
	public static function run_hourly() {
		if ( ! SquidSec_Shield_Options::is_enabled() ) {
			return;
		}
		if ( SquidSec_Shield_Options::get( 'fim_enabled' ) ) {
			SquidSec_Shield_FIM::check_integrity();
		}
		SquidSec_Shield_Anomaly::evaluate();
	}
}
