<?php
/**
 * Main plugin orchestrator.
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
 * Plugin singleton.
 */
class SquidSec_Shield_Plugin {

	/**
	 * Instance.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Get singleton.
	 *
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->init_modules();
	}

	/**
	 * Bootstrap modules.
	 */
	private function init_modules() {
		SquidSec_Shield_Database::maybe_upgrade();
		SquidSec_Shield_Options::ensure_defaults();

		// Core runtime.
		SquidSec_Shield_Cron::init();
		SquidSec_Shield_Setup::init();
		SquidSec_Shield_Audit_Log::init();
		SquidSec_Shield_Alerts::init();

		// Security modules (always register hooks; each checks its own settings).
		// Defaults are ON — average site is protected without opening Settings.
		SquidSec_Shield_WAF::init();
		SquidSec_Shield_Virtual_Patch::init();
		SquidSec_Shield_Rate_Limit::init();
		SquidSec_Shield_Login_Protection::init();
		SquidSec_Shield_User_Enumeration::init();
		SquidSec_Shield_Two_Factor::init();
		SquidSec_Shield_Captcha::init();
		SquidSec_Shield_Hardening::init();
		SquidSec_Shield_Sensitive_Files::init();
		SquidSec_Shield_Fingerprint_Cleanup::init();
		SquidSec_Shield_Malware_Scanner::init();
		SquidSec_Shield_FIM::init();
		SquidSec_Shield_Vuln_Scanner::init();
		SquidSec_Shield_Plugin_Risk::init();
		SquidSec_Shield_Misconfig::init();
		SquidSec_Shield_Anomaly::init();
		SquidSec_Shield_REST_API::init();
		SquidSec_Shield_Webhooks::init();

		if ( is_admin() ) {
			SquidSec_Shield_Admin::init();
		}

		// Deferred first-run FIM baseline (also handled by Setup first-run).
		if ( get_option( 'squidsec_shield_fim_needs_baseline' ) ) {
			add_action( 'init', array( 'SquidSec_Shield_FIM', 'create_baseline' ), 99 );
		}
	}
}
