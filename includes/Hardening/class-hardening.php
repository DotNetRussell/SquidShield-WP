<?php
/**
 * Hardening wizard & runtime hardening.
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
 * Hardening.
 */
class SquidSec_Shield_Hardening {

	/**
	 * Init runtime hardening.
	 */
	public static function init() {
		if ( ! SquidSec_Shield_Options::is_enabled() ) {
			return;
		}
		if ( SquidSec_Shield_Options::get( 'hardening_file_editor' ) ) {
			if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
				define( 'DISALLOW_FILE_EDIT', true );
			}
		}
		if ( SquidSec_Shield_Options::get( 'hardening_hide_version' ) || SquidSec_Shield_Options::get( 'hardening_remove_wp_gen' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}
		if ( SquidSec_Shield_Options::get( 'hardening_headers' ) ) {
			add_action( 'send_headers', array( __CLASS__, 'security_headers' ) );
		}
		if ( SquidSec_Shield_Options::get( 'hardening_disable_reg' ) ) {
			add_filter( 'pre_option_users_can_register', static function () {
				return '0';
			} );
		}
		if ( SquidSec_Shield_Options::get( 'hardening_disable_app_pass_nonadmin' ) ) {
			add_filter( 'wp_is_application_passwords_available_for_user', array( __CLASS__, 'app_passwords' ), 10, 2 );
		}
		// Disable XML-RPC pingbacks fully when WAF option set.
		if ( SquidSec_Shield_Options::get( 'disable_xmlrpc_pingback' ) ) {
			add_filter( 'xmlrpc_methods', static function ( $methods ) {
				unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
				return $methods;
			} );
			add_filter( 'wp_headers', static function ( $headers ) {
				unset( $headers['X-Pingback'] );
				return $headers;
			} );
		}
	}

	/**
	 * Security headers.
	 */
	public static function security_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
		// Do not force CSP here — site may have custom CSP; X-* headers only.
		if ( is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
		}
	}

	/**
	 * Application passwords for admins only.
	 *
	 * @param bool    $available Available.
	 * @param WP_User $user      User.
	 * @return bool
	 */
	public static function app_passwords( $available, $user ) {
		if ( ! $user instanceof WP_User ) {
			return false;
		}
		return user_can( $user, 'manage_options' );
	}

	/**
	 * Apply one-click hardening profile.
	 *
	 * @param string $profile default|woocommerce|strict.
	 * @return array Applied keys.
	 */
	public static function apply_wizard( $profile = 'default' ) {
		$patch = array(
			'hardening_file_editor'              => true,
			'hardening_hide_version'             => true,
			'hardening_headers'                  => true,
			'hardening_remove_wp_gen'            => true,
			'hardening_disable_app_pass_nonadmin'=> true,
			'disable_xmlrpc'                     => true,
			'disable_xmlrpc_pingback'            => true,
			'user_enum_prevention'               => true,
			'disable_author_archives'            => true,
			'hide_login_errors'                  => true,
			'login_protection'                   => true,
			'waf_enabled'                        => true,
			'virtual_patch_enabled'              => true,
			'sensitive_file_protect'             => true,
			'remove_readme_license'              => true,
		);
		// Drop public readme/license files that advertise versions.
		if ( class_exists( 'SquidSec_Shield_Fingerprint_Cleanup' ) ) {
			SquidSec_Shield_Fingerprint_Cleanup::cleanup_all( true );
		}
		if ( 'woocommerce' === $profile || self::is_woocommerce() ) {
			// Keep registration if WC needs customers — don't force disable_reg.
			$patch['hardening_disable_reg'] = false;
			$patch['rate_limit_ajax']       = 200; // WC uses ajax heavily.
		}
		if ( 'strict' === $profile ) {
			$patch['hardening_disable_reg'] = true;
			$patch['login_max_attempts']    = 3;
			$patch['rate_limit_login']      = 5;
		}
		SquidSec_Shield_Options::update( $patch );
		self::fix_file_permissions();
		SquidSec_Shield_Audit_Log::write( 'hardening_wizard', 'info', 'Hardening wizard applied: ' . $profile, $patch );
		return array_keys( $patch );
	}

	/**
	 * Detect WooCommerce.
	 *
	 * @return bool
	 */
	public static function is_woocommerce() {
		return class_exists( 'WooCommerce' ) || in_array( 'woocommerce/woocommerce.php', (array) get_option( 'active_plugins', array() ), true );
	}

	/**
	 * Attempt to set safer file permissions (best effort).
	 *
	 * @return array Results.
	 */
	public static function fix_file_permissions() {
		$results = array();
		$targets = array(
			ABSPATH . 'wp-config.php' => 0640,
			ABSPATH . '.htaccess'     => 0644,
		);
		foreach ( $targets as $path => $mode ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- permission hardening requires direct FS probe.
			if ( file_exists( $path ) && is_writable( $path ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
				$ok = @chmod( $path, $mode );
				$results[ $path ] = $ok ? 'ok' : 'failed';
			}
		}
		// Directories 755, files 644 for wp-content uploads root.
		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['basedir'] ) && is_dir( $uploads['basedir'] ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod
			@chmod( $uploads['basedir'], 0755 );
			$results[ $uploads['basedir'] ] = 'checked';
		}
		return $results;
	}

	/**
	 * Recommendations for UI.
	 *
	 * @return array
	 */
	public static function recommendations() {
		$recs = array();
		if ( get_option( 'users_can_register' ) ) {
			$recs[] = array(
				'id'    => 'registration',
				'title' => 'User registration is open',
				'fix'  => 'Disable if you do not need public signups.',
				'level' => 'medium',
			);
		}
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			$recs[] = array(
				'id'    => 'debug_log',
				'title' => 'Debug logging enabled',
				'fix'  => 'Disable WP_DEBUG_LOG on production or protect debug.log.',
				'level' => 'high',
			);
		}
		if ( ! SquidSec_Shield_Options::get( 'disable_xmlrpc' ) ) {
			$recs[] = array(
				'id'    => 'xmlrpc',
				'title' => 'XML-RPC enabled',
				'fix'  => 'Disable XML-RPC if not required (mobile apps, Jetpack).',
				'level' => 'medium',
			);
		}
		if ( self::is_woocommerce() ) {
			$recs[] = array(
				'id'    => 'woo',
				'title' => 'WooCommerce detected',
				'fix'  => 'Keep registration as needed for checkout; ensure payment pages use HTTPS; review REST permissions.',
				'level' => 'info',
			);
		}
		return $recs;
	}
}
