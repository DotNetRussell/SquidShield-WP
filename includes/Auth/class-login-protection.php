<?php
/**
 * Brute force & login protection.
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Login protection.
 */
class SquidSec_Shield_Login_Protection {

	/**
	 * Init.
	 */
	public static function init() {
		if ( ! SquidSec_Shield_Options::get( 'login_protection' ) ) {
			// Still allow custom login slug hooks if set.
		}
		add_action( 'wp_login_failed', array( __CLASS__, 'on_fail' ) );
		add_filter( 'authenticate', array( __CLASS__, 'check_lockout' ), 20, 3 );
		add_action( 'wp_login', array( __CLASS__, 'on_success' ), 10, 2 );
		add_filter( 'login_errors', array( __CLASS__, 'generic_errors' ) );
		add_filter( 'xmlrpc_methods', array( __CLASS__, 'filter_xmlrpc_methods' ) );
		add_action( 'init', array( __CLASS__, 'custom_login_slug' ), 1 );
		add_action( 'login_init', array( __CLASS__, 'maybe_block_default_login' ) );
	}

	/**
	 * On failed login.
	 *
	 * @param string $username Username.
	 */
	public static function on_fail( $username ) {
		if ( ! SquidSec_Shield_Options::is_enabled() || ! SquidSec_Shield_Options::get( 'login_protection' ) ) {
			return;
		}
		$ip  = SquidSec_Shield_IP::client();
		$max = max( 3, (int) SquidSec_Shield_Options::get( 'login_max_attempts', 5 ) );
		$mins = max( 1, (int) SquidSec_Shield_Options::get( 'login_lockout_minutes', 15 ) );

		$ip_key = 'sss_login_ip_' . md5( $ip );
		$fails  = (int) get_transient( $ip_key ) + 1;
		set_transient( $ip_key, $fails, $mins * MINUTE_IN_SECONDS );

		if ( SquidSec_Shield_Options::get( 'login_lock_username' ) && $username ) {
			$u_key = 'sss_login_user_' . md5( strtolower( $username ) );
			$uf    = (int) get_transient( $u_key ) + 1;
			set_transient( $u_key, $uf, $mins * MINUTE_IN_SECONDS );
		}

		if ( $fails >= $max ) {
			SquidSec_Shield_IP::block( $ip, 'Login brute force', $mins, 'login_bruteforce' );
			SquidSec_Shield_Audit_Log::write( 'login_lockout', 'high', 'IP locked after failed logins: ' . $ip, array( 'fails' => $fails, 'username' => $username ) );
		}
	}

	/**
	 * Check lockout during authenticate.
	 *
	 * @param mixed  $user     User.
	 * @param string $username Username.
	 * @param string $password Password.
	 * @return mixed
	 */
	public static function check_lockout( $user, $username, $password ) {
		if ( ! SquidSec_Shield_Options::is_enabled() || ! SquidSec_Shield_Options::get( 'login_protection' ) ) {
			return $user;
		}
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}
		$ip = SquidSec_Shield_IP::client();
		if ( SquidSec_Shield_IP::is_blocked( $ip ) ) {
			return new WP_Error( 'sss_locked', __( 'Too many failed login attempts. Please try again later.', 'squidsec-shield' ) );
		}
		$max  = max( 3, (int) SquidSec_Shield_Options::get( 'login_max_attempts', 5 ) );
		$fails = (int) get_transient( 'sss_login_ip_' . md5( $ip ) );
		if ( $fails >= $max ) {
			return new WP_Error( 'sss_locked', __( 'Too many failed login attempts. Please try again later.', 'squidsec-shield' ) );
		}
		if ( SquidSec_Shield_Options::get( 'login_lock_username' ) && $username ) {
			$uf = (int) get_transient( 'sss_login_user_' . md5( strtolower( $username ) ) );
			if ( $uf >= $max ) {
				return new WP_Error( 'sss_locked', __( 'Too many failed login attempts for this account.', 'squidsec-shield' ) );
			}
		}
		return $user;
	}

	/**
	 * Clear counters on success.
	 *
	 * @param string  $user_login Login.
	 * @param WP_User $user      User.
	 */
	public static function on_success( $user_login, $user ) {
		$ip = SquidSec_Shield_IP::client();
		delete_transient( 'sss_login_ip_' . md5( $ip ) );
		delete_transient( 'sss_login_user_' . md5( strtolower( $user_login ) ) );
	}

	/**
	 * Generic login errors.
	 *
	 * @param string $error Error.
	 * @return string
	 */
	public static function generic_errors( $error ) {
		if ( SquidSec_Shield_Options::get( 'hide_login_errors' ) ) {
			return __( 'Invalid credentials.', 'squidsec-shield' );
		}
		return $error;
	}

	/**
	 * Harden XML-RPC methods.
	 *
	 * @param array $methods Methods.
	 * @return array
	 */
	public static function filter_xmlrpc_methods( $methods ) {
		if ( SquidSec_Shield_Options::get( 'disable_xmlrpc' ) ) {
			return array();
		}
		if ( SquidSec_Shield_Options::get( 'disable_xmlrpc_pingback' ) ) {
			unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		}
		return $methods;
	}

	/**
	 * Register custom login slug rewrite.
	 */
	public static function custom_login_slug() {
		$slug = trim( (string) SquidSec_Shield_Options::get( 'custom_login_slug', '' ), '/' );
		if ( $slug === '' ) {
			return;
		}
		add_rewrite_rule( '^' . preg_quote( $slug, '/' ) . '/?$', 'wp-login.php', 'top' );
	}

	/**
	 * Block direct wp-login.php when custom slug is set (except logout/post).
	 */
	public static function maybe_block_default_login() {
		$slug = trim( (string) SquidSec_Shield_Options::get( 'custom_login_slug', '' ), '/' );
		if ( $slug === '' || SquidSec_Shield_Options::is_pentest() ) {
			return;
		}
		// Allow POST (form submit) and logout/action.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_REQUEST['action'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['action'] ) ) : '';
		if ( in_array( $action, array( 'logout', 'postpass', 'rp', 'resetpass', 'confirmaction' ), true ) ) {
			return;
		}
		$uri = SquidSec_Shield_Helpers::request_uri();
		if ( false !== strpos( $uri, 'wp-login.php' ) && false === strpos( $uri, $slug ) ) {
			// Only block GET to reduce lockout risk for form posts.
			if ( 'GET' === SquidSec_Shield_Helpers::request_method() ) {
				status_header( 404 );
				nocache_headers();
				echo 'Not Found';
				exit;
			}
		}
	}
}
