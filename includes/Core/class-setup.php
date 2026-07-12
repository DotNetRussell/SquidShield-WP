<?php
/**
 * Zero-config secure-by-default setup.
 *
 * Goal: activate the plugin → site is protected. Power users can tweak later.
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Setup / first-run automation.
 */
class SquidSec_Shield_Setup {

	const FLAG_FIRST_SCAN = 'squidsec_shield_needs_first_scan';
	const FLAG_AUTO_CLEAN = 'squidsec_shield_needs_auto_clean';
	const FLAG_SETUP_DONE = 'squidsec_shield_setup_complete';

	/**
	 * Run on plugin activation (and can be re-run safely).
	 */
	public static function secure_on_activate() {
		SquidSec_Shield_Options::ensure_defaults();

		// Force the full protection profile on. Users can turn pieces off later in Settings.
		$profile = SquidSec_Shield_Hardening::is_woocommerce() ? 'woocommerce' : 'default';
		SquidSec_Shield_Hardening::apply_wizard( $profile );

		// Ensure every core protection switch is ON (wizard covers most; this is belt-and-suspenders).
		SquidSec_Shield_Options::update(
			array(
				'enabled'               => true,
				'pentest_mode'          => false,
				'waf_enabled'           => true,
				'waf_block_sqli'        => true,
				'waf_block_xss'         => true,
				'waf_block_rce'         => true,
				'waf_block_lfi'         => true,
				'waf_block_upload'      => true,
				'virtual_patch_enabled' => true,
				'rate_limit_enabled'    => true,
				'login_protection'      => true,
				'hide_login_errors'     => true,
				'user_enum_prevention'  => true,
				'disable_author_archives' => true,
				'disable_xmlrpc'        => true,
				'disable_xmlrpc_pingback' => true,
				'totp_enabled'          => true,
				'malware_scan_enabled'  => true,
				'fim_enabled'           => true,
				'vuln_scan_enabled'     => true,
				'misconfig_scan_enabled'=> true,
				'sensitive_file_protect'=> true,
				'anomaly_detection'     => true,
				'hardening_file_editor' => true,
				'hardening_hide_version'=> true,
				'hardening_headers'     => true,
				'hardening_remove_wp_gen' => true,
				'hardening_disable_app_pass_nonadmin' => true,
				'remove_readme_license' => true,
				'daily_report'          => true,
				'async_scans'           => true,
			)
		);

		// Best-effort uploads hardening (no-op if not writable).
		SquidSec_Shield_Sensitive_Files::apply_uploads_htaccess();

		// Strip version-leaking readme/license files immediately when possible.
		SquidSec_Shield_Fingerprint_Cleanup::cleanup_all( true );

		// Defer heavy work until WordPress is fully up (and not blocking activation).
		update_option( self::FLAG_FIRST_SCAN, 1, false );
		update_option( self::FLAG_AUTO_CLEAN, 1, false );
		update_option( 'squidsec_shield_fim_needs_baseline', 1, false );
		update_option( self::FLAG_SETUP_DONE, time(), false );

		if ( ! wp_next_scheduled( 'squidsec_shield_first_run' ) ) {
			wp_schedule_single_event( time() + 15, 'squidsec_shield_first_run' );
		}

		SquidSec_Shield_Audit_Log::write(
			'setup_secure_default',
			'info',
			'SquidShield WP activated with automatic protection (profile: ' . $profile . ').'
		);
	}

	/**
	 * Register deferred first-run handler.
	 */
	public static function init() {
		add_action( 'squidsec_shield_first_run', array( __CLASS__, 'run_first_tasks' ) );
		// Also pick up flags if cron is delayed (admin visit).
		add_action( 'admin_init', array( __CLASS__, 'maybe_run_first_tasks' ), 5 );
		// Existing installs that pre-date secure-by-default: apply once.
		add_action( 'admin_init', array( __CLASS__, 'maybe_migrate_legacy_install' ), 3 );
	}

	/**
	 * One-time migration for sites that activated before auto-setup existed.
	 */
	public static function maybe_migrate_legacy_install() {
		if ( get_option( self::FLAG_SETUP_DONE ) ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		// Only if plugin is already active in DB history.
		if ( ! get_option( 'squidsec_shield_activated' ) && ! get_option( 'squidsec_shield_db_version' ) ) {
			return;
		}
		self::secure_on_activate();
	}

	/**
	 * Admin fallback for first-run tasks.
	 */
	public static function maybe_run_first_tasks() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( ! get_option( self::FLAG_FIRST_SCAN ) && ! get_option( self::FLAG_AUTO_CLEAN ) && ! get_option( 'squidsec_shield_fim_needs_baseline' ) ) {
			return;
		}
		// Avoid running mid-POST save.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_POST['sss_action'] ) ) {
			return;
		}
		self::run_first_tasks();
	}

	/**
	 * First scans + safe auto-clean of junk sensitive files.
	 */
	public static function run_first_tasks() {
		static $ran = false;
		if ( $ran ) {
			return;
		}
		$ran = true;

		if ( get_option( 'squidsec_shield_fim_needs_baseline' ) ) {
			SquidSec_Shield_FIM::create_baseline();
		}

		if ( get_option( self::FLAG_AUTO_CLEAN ) ) {
			// Quarantine (not delete) known junk: config backups, dumps, etc.
			$result = SquidSec_Shield_Remediation::remediate_all_sensitive( 'quarantine' );
			// Delete public readme/license fingerprint files site-wide.
			$fps = SquidSec_Shield_Fingerprint_Cleanup::cleanup_all( true );
			delete_option( self::FLAG_AUTO_CLEAN );
			if ( ! empty( $result['ok'] ) ) {
				SquidSec_Shield_Audit_Log::write(
					'setup_auto_clean',
					'info',
					'Automatically quarantined ' . count( $result['ok'] ) . ' sensitive file(s) on setup.',
					array( 'files' => $result['ok'] )
				);
			}
			if ( $fps ) {
				SquidSec_Shield_Audit_Log::write(
					'setup_fingerprint_cleanup',
					'info',
					'Removed ' . count( $fps ) . ' readme/license file(s) on setup.',
					array( 'files' => array_slice( $fps, 0, 40 ) )
				);
			}
		}

		if ( get_option( self::FLAG_FIRST_SCAN ) ) {
			// Silent background baseline scans.
			if ( SquidSec_Shield_Options::get( 'malware_scan_enabled' ) ) {
				SquidSec_Shield_Malware_Scanner::start_scan( 'setup' );
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
			delete_option( self::FLAG_FIRST_SCAN );
			SquidSec_Shield_Audit_Log::write( 'setup_first_scan', 'info', 'Initial security scans started after activation.' );
		}
	}

	/**
	 * Protection layers for simple status UI (plain language).
	 *
	 * @return array[]
	 */
	public static function protection_layers() {
		$opts = SquidSec_Shield_Options::all();
		$on   = ! empty( $opts['enabled'] ) && empty( $opts['pentest_mode'] );

		return array(
			array(
				'id'      => 'master',
				'label'   => 'Automatic protection',
				'detail'  => $on ? 'Shield is on and blocking attacks for you.' : ( ! empty( $opts['pentest_mode'] ) ? 'Pentest mode is on — attacks are logged but not blocked.' : 'Protection is turned off in Settings.' ),
				'ok'      => $on,
				'critical'=> empty( $opts['enabled'] ),
			),
			array(
				'id'     => 'firewall',
				'label'  => 'Website firewall',
				'detail' => 'Blocks common hacks (SQL injection, script attacks, malicious uploads) before they hit WordPress.',
				'ok'     => ! empty( $opts['enabled'] ) && ! empty( $opts['waf_enabled'] ),
			),
			array(
				'id'     => 'login',
				'label'  => 'Login protection',
				'detail' => 'Stops password guessing and hides whether a username exists.',
				'ok'     => ! empty( $opts['enabled'] ) && ! empty( $opts['login_protection'] ) && ! empty( $opts['hide_login_errors'] ),
			),
			array(
				'id'     => 'privacy',
				'label'  => 'Hide usernames from the public',
				'detail' => 'Blocks common ways attackers list your authors and account names.',
				'ok'     => ! empty( $opts['enabled'] ) && ! empty( $opts['user_enum_prevention'] ),
			),
			array(
				'id'     => 'xmlrpc',
				'label'  => 'Close unused remote login (XML-RPC)',
				'detail' => 'Turns off an old WordPress feature often abused for brute-force attacks.',
				'ok'     => ! empty( $opts['enabled'] ) && ! empty( $opts['disable_xmlrpc'] ),
			),
			array(
				'id'     => 'hardening',
				'label'  => 'Admin hardening',
				'detail' => 'Disables the theme/plugin code editor and adds basic security headers.',
				'ok'     => ! empty( $opts['enabled'] ) && ! empty( $opts['hardening_file_editor'] ) && ! empty( $opts['hardening_headers'] ),
			),
			array(
				'id'     => 'fingerprints',
				'label'  => 'Hide version leak files',
				'detail' => 'Deletes public readme and license files (core, plugins, themes) that advertise software versions. Runs on install and after updates.',
				'ok'     => ! empty( $opts['enabled'] ) && ! empty( $opts['remove_readme_license'] ),
			),
			array(
				'id'     => 'scans',
				'label'  => 'Automatic security scans',
				'detail' => 'Checks for malware, risky plugins, and configuration mistakes on a schedule.',
				'ok'     => ! empty( $opts['enabled'] ) && ! empty( $opts['malware_scan_enabled'] ) && ! empty( $opts['vuln_scan_enabled'] ),
			),
			array(
				'id'     => 'fim',
				'label'  => 'File change monitoring',
				'detail' => 'Watches important files and alerts if something unexpected changes.',
				'ok'     => ! empty( $opts['enabled'] ) && ! empty( $opts['fim_enabled'] ),
			),
		);
	}

	/**
	 * Overall site status for the simple dashboard.
	 *
	 * @return array{level:string,title:string,message:string,action_needed:bool}
	 */
	public static function overall_status() {
		$opts   = SquidSec_Shield_Options::all();
		$counts = SquidSec_Shield_Audit_Log::recent_counts( 24 );
		$threat = SquidSec_Shield_Alerts::threat_level( $counts );
		$sens   = get_option( 'squidsec_shield_sensitive_cache', array() );
		$misc   = get_option( 'squidsec_shield_misconfig_cache', array() );
		$sens_n = count( $sens['files'] ?? array() );
		$misc_n = 0;
		foreach ( $misc['findings'] ?? array() as $f ) {
			if ( ! empty( $f['remediable'] ) && in_array( $f['severity'] ?? '', array( 'critical', 'high', 'medium' ), true ) ) {
				$misc_n++;
			}
		}

		if ( empty( $opts['enabled'] ) ) {
			return array(
				'level'         => 'off',
				'title'         => 'Protection is off',
				'message'       => 'Turn protection back on in Settings. Until then, Shield is not securing the site.',
				'action_needed' => true,
			);
		}
		if ( ! empty( $opts['pentest_mode'] ) ) {
			return array(
				'level'         => 'monitor',
				'title'         => 'Monitoring only (not blocking)',
				'message'       => 'Pentest mode is on. Attacks are logged but not stopped. Turn it off when you are done testing.',
				'action_needed' => true,
			);
		}
		if ( 'critical' === $threat || $sens_n > 0 ) {
			return array(
				'level'         => 'attention',
				'title'         => 'Protected — action recommended',
				'message'       => $sens_n
					? sprintf( 'Shield is blocking attacks, but %d sensitive file(s) should be cleaned up.', $sens_n )
					: 'Shield is blocking attacks. Review recent critical events in Activity.',
				'action_needed' => true,
			);
		}
		if ( 'high' === $threat || 'elevated' === $threat || $misc_n > 0 ) {
			return array(
				'level'         => 'attention',
				'title'         => 'Protected — a few items to review',
				'message'       => 'Your site is secured. Open Issues if you want to clear recommended fixes.',
				'action_needed' => $misc_n > 0,
			);
		}

		return array(
			'level'         => 'ok',
			'title'         => 'Your site is protected',
			'message'       => 'Shield is running with recommended settings. You do not need to configure anything unless you want to customize.',
			'action_needed' => false,
		);
	}
}
