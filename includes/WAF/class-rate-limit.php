<?php
/**
 * Endpoint-aware rate limiting.
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
 * Rate limit.
 */
class SquidSec_Shield_Rate_Limit {

	/**
	 * Init.
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'check' ), 1 );
	}

	/**
	 * Check rate limits.
	 */
	public static function check() {
		if ( ! SquidSec_Shield_Options::is_enabled() || ! SquidSec_Shield_Options::get( 'rate_limit_enabled' ) ) {
			return;
		}
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return;
		}

		$ip      = SquidSec_Shield_IP::client();
		$allow   = SquidSec_Shield_Options::get( 'ip_allowlist', array() );
		if ( is_array( $allow ) && SquidSec_Shield_IP::in_list( $ip, $allow ) ) {
			return;
		}

		$context = SquidSec_Shield_Helpers::request_context();
		$limit   = self::limit_for( $context );
		if ( $limit <= 0 ) {
			return;
		}

		$window = max( 10, (int) SquidSec_Shield_Options::get( 'rate_limit_window', 60 ) );
		$key    = 'sss_rl_' . md5( $ip . '|' . $context );
		$count  = (int) get_transient( $key );
		if ( $count >= $limit ) {
			SquidSec_Shield_Audit_Log::write(
				'rate_limit',
				'medium',
				sprintf( 'Rate limit exceeded for %s from %s', $context, $ip ),
				array( 'context' => $context, 'limit' => $limit )
			);
			if ( ! SquidSec_Shield_Options::is_pentest() ) {
				if ( ! headers_sent() ) {
					status_header( 429 );
					header( 'Retry-After: ' . $window );
					header( 'Content-Type: text/plain; charset=utf-8' );
				}
				echo 'Too many requests. Please slow down.';
				exit;
			}
			return;
		}
		set_transient( $key, $count + 1, $window );
	}

	/**
	 * Limit for context.
	 *
	 * @param string $context Context.
	 * @return int
	 */
	public static function limit_for( $context ) {
		switch ( $context ) {
			case 'ajax':
				return (int) SquidSec_Shield_Options::get( 'rate_limit_ajax', 120 );
			case 'rest':
				return (int) SquidSec_Shield_Options::get( 'rate_limit_rest', 90 );
			case 'login':
				return (int) SquidSec_Shield_Options::get( 'rate_limit_login', 10 );
			case 'xmlrpc':
				return (int) SquidSec_Shield_Options::get( 'rate_limit_xmlrpc', 20 );
			case 'admin':
				return (int) SquidSec_Shield_Options::get( 'rate_limit_admin', 60 );
			default:
				// New: optional general front-end rate limit (0 = disabled by default)
				return (int) SquidSec_Shield_Options::get( 'rate_limit_general', 0 );
		}
	}

	/**
	 * Penalize IP (lower remaining budget).
	 *
	 * @param string $ip      IP.
	 * @param string $context Context.
	 */
	public static function penalize( $ip, $context ) {
		$key   = 'sss_rl_' . md5( $ip . '|' . $context );
		$limit = self::limit_for( $context );
		set_transient( $key, max( $limit, 1 ), (int) SquidSec_Shield_Options::get( 'rate_limit_window', 60 ) );
	}
}
