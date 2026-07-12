<?php
/**
 * Shared helpers.
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Helpers.
 */
class SquidSec_Shield_Helpers {

	/**
	 * Current request URI path + query.
	 *
	 * @return string
	 */
	public static function request_uri() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		return (string) $uri;
	}

	/**
	 * Request method.
	 *
	 * @return string
	 */
	public static function request_method() {
		return isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( (string) wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET';
	}

	/**
	 * Flatten request payload for inspection (GET/POST/JSON body).
	 *
	 * @return string
	 */
	public static function request_payload() {
		$parts = array();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! empty( $_GET ) && is_array( $_GET ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$parts[] = wp_json_encode( self::sanitize_array( wp_unslash( $_GET ) ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST ) && is_array( $_POST ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$parts[] = wp_json_encode( self::sanitize_array( wp_unslash( $_POST ) ) );
		}
		$raw = file_get_contents( 'php://input' );
		if ( is_string( $raw ) && $raw !== '' && strlen( $raw ) < 100000 ) {
			$parts[] = $raw;
		}
		return implode( "\n", $parts );
	}

	/**
	 * Recursively sanitize array values to strings.
	 *
	 * @param mixed $data Data.
	 * @return mixed
	 */
	public static function sanitize_array( $data ) {
		if ( ! is_array( $data ) ) {
			return is_scalar( $data ) ? (string) $data : '';
		}
		$out = array();
		foreach ( $data as $k => $v ) {
			$out[ sanitize_text_field( (string) $k ) ] = is_array( $v ) ? self::sanitize_array( $v ) : ( is_scalar( $v ) ? (string) $v : '' );
		}
		return $out;
	}

	/**
	 * Detect WordPress request context.
	 *
	 * @return string login|admin|ajax|rest|xmlrpc|cron|front
	 */
	public static function request_context() {
		$uri = self::request_uri();
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return 'xmlrpc';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		if ( false !== strpos( $uri, 'wp-login.php' ) || false !== strpos( $uri, 'wp-signup.php' ) ) {
			return 'login';
		}
		if ( false !== strpos( $uri, 'admin-ajax.php' ) ) {
			return 'ajax';
		}
		if ( false !== strpos( $uri, 'wp-cron.php' ) ) {
			return 'cron';
		}
		if ( false !== strpos( $uri, '/wp-json' ) || false !== strpos( $uri, 'rest_route=' ) ) {
			return 'rest';
		}
		if ( false !== strpos( $uri, '/wp-admin' ) || false !== strpos( $uri, 'wp-admin/' ) ) {
			return 'admin';
		}
		if ( false !== strpos( $uri, 'xmlrpc.php' ) ) {
			return 'xmlrpc';
		}
		return 'front';
	}

	/**
	 * Safe regex match (guard against catastrophic backtracking with time limit if available).
	 *
	 * @param string $pattern Pattern with delimiters.
	 * @param string $subject Subject.
	 * @return bool
	 */
	public static function safe_match( $pattern, $subject ) {
		if ( $pattern === '' || $subject === '' ) {
			return false;
		}
		// Suppress errors from invalid user patterns.
		set_error_handler( static function () {
			return true;
		} );
		$result = @preg_match( $pattern, $subject );
		restore_error_handler();
		return 1 === $result;
	}

	/**
	 * Active plugin versions map slug => version.
	 *
	 * @return array
	 */
	public static function active_plugin_versions() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all    = get_plugins();
		$active = get_option( 'active_plugins', array() );
		$out    = array();
		foreach ( $active as $file ) {
			if ( ! isset( $all[ $file ] ) ) {
				continue;
			}
			$slug         = dirname( $file );
			if ( '.' === $slug ) {
				$slug = basename( $file, '.php' );
			}
			$out[ $slug ] = $all[ $file ]['Version'] ?? '';
		}
		return $out;
	}

	/**
	 * Compare version against constraint like "<=1.2.3" or "<2.0.0" or "*".
	 *
	 * @param string $version    Installed.
	 * @param string $constraint Constraint.
	 * @return bool
	 */
	public static function version_matches( $version, $constraint ) {
		$constraint = trim( (string) $constraint );
		if ( $constraint === '' || $constraint === '*' ) {
			return true;
		}
		if ( preg_match( '/^(<=|>=|<|>|==|=)\s*(.+)$/', $constraint, $m ) ) {
			$op = $m[1];
			if ( $op === '=' ) {
				$op = '==';
			}
			return version_compare( $version, trim( $m[2] ), $op );
		}
		return version_compare( $version, $constraint, '==' );
	}

	/**
	 * Severity rank for sorting.
	 *
	 * @param string $sev Severity.
	 * @return int
	 */
	public static function severity_rank( $sev ) {
		$map = array(
			'critical' => 5,
			'high'     => 4,
			'medium'   => 3,
			'low'      => 2,
			'info'     => 1,
		);
		return $map[ strtolower( $sev ) ] ?? 0;
	}
}
