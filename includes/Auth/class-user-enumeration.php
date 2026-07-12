<?php
/**
 * User enumeration prevention.
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
 * User enumeration.
 */
class SquidSec_Shield_User_Enumeration {

	/**
	 * Init.
	 */
	public static function init() {
		add_filter( 'rest_endpoints', array( __CLASS__, 'filter_rest' ) );
		add_filter( 'rest_user_query', array( __CLASS__, 'filter_rest_query' ), 10, 2 );
		add_filter( 'rest_prepare_user', array( __CLASS__, 'filter_rest_prepare' ), 10, 3 );
		add_action( 'template_redirect', array( __CLASS__, 'block_author_archives' ) );
		add_filter( 'redirect_canonical', array( __CLASS__, 'block_author_query' ), 10, 2 );
		add_filter( 'oembed_response_data', array( __CLASS__, 'filter_oembed' ), 10, 1 );
		add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'filter_sitemap_users' ), 10, 2 );
	}

	/**
	 * Is enum prevention on?
	 *
	 * @return bool
	 */
	private static function enabled() {
		return SquidSec_Shield_Options::is_enabled() && SquidSec_Shield_Options::get( 'user_enum_prevention' );
	}

	/**
	 * Remove REST user routes for anonymous users.
	 *
	 * @param array $endpoints Endpoints.
	 * @return array
	 */
	public static function filter_rest( $endpoints ) {
		if ( ! self::enabled() || is_user_logged_in() ) {
			return $endpoints;
		}
		unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\\d]+)'] );
		return $endpoints;
	}

	/**
	 * Restrict REST user queries.
	 *
	 * @param array           $args    Args.
	 * @param WP_REST_Request $request Request.
	 * @return array
	 */
	public static function filter_rest_query( $args, $request ) {
		if ( ! self::enabled() ) {
			return $args;
		}
		if ( ! is_user_logged_in() ) {
			$args['include'] = array( 0 );
			return $args;
		}
		if ( ! current_user_can( 'list_users' ) && ! current_user_can( 'edit_posts' ) ) {
			$args['include'] = array( get_current_user_id() );
		}
		return $args;
	}

	/**
	 * Filter prepared user.
	 *
	 * @param WP_REST_Response $response Response.
	 * @param WP_User          $user     User.
	 * @param WP_REST_Request  $request  Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function filter_rest_prepare( $response, $user, $request ) {
		if ( ! self::enabled() ) {
			return $response;
		}
		if ( ! is_user_logged_in() ) {
			self::log_attempt( 'rest_user' );
			return new WP_Error( 'rest_user_cannot_view', 'Sorry, you are not allowed to list users.', array( 'status' => 401 ) );
		}
		$uid = (int) ( $user instanceof WP_User ? $user->ID : 0 );
		if ( current_user_can( 'list_users' ) || $uid === get_current_user_id() || current_user_can( 'edit_posts' ) ) {
			return $response;
		}
		return new WP_Error( 'rest_user_cannot_view', 'Sorry, you are not allowed to list users.', array( 'status' => 401 ) );
	}

	/**
	 * Block author archives.
	 */
	public static function block_author_archives() {
		if ( ! self::enabled() || ! SquidSec_Shield_Options::get( 'disable_author_archives' ) ) {
			return;
		}
		if ( is_author() ) {
			self::log_attempt( 'author_archive' );
			global $wp_query;
			$wp_query->set_404();
			status_header( 404 );
			nocache_headers();
		}
	}

	/**
	 * Block ?author=1 style enumeration.
	 *
	 * @param string $redirect Redirect.
	 * @param string $request  Request.
	 * @return string|false
	 */
	public static function block_author_query( $redirect, $request ) {
		if ( ! self::enabled() ) {
			return $redirect;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- public front-end probe block.
		if ( isset( $_GET['author'] ) && ! is_user_logged_in() ) {
			// Presence alone is enough; value is not used.
			self::log_attempt( 'author_query' );
			return false;
		}
		return $redirect;
	}

	/**
	 * Remove author from oEmbed.
	 *
	 * @param array $data Data.
	 * @return array
	 */
	public static function filter_oembed( $data ) {
		if ( self::enabled() ) {
			unset( $data['author_name'], $data['author_url'] );
		}
		return $data;
	}

	/**
	 * Remove users from sitemaps.
	 *
	 * @param WP_Sitemaps_Provider $provider Provider.
	 * @param string               $name     Name.
	 * @return WP_Sitemaps_Provider|false
	 */
	public static function filter_sitemap_users( $provider, $name ) {
		if ( self::enabled() && 'users' === $name ) {
			return false;
		}
		return $provider;
	}

	/**
	 * Log enumeration attempt.
	 *
	 * @param string $vector Vector.
	 */
	private static function log_attempt( $vector ) {
		$key = 'sss_enum_' . md5( SquidSec_Shield_IP::client() );
		$n   = (int) get_transient( $key );
		set_transient( $key, $n + 1, HOUR_IN_SECONDS );
		if ( 0 === $n || 0 === ( $n % 10 ) ) {
			SquidSec_Shield_Audit_Log::write( 'user_enum_attempt', 'medium', 'User enumeration attempt via ' . $vector, array( 'vector' => $vector ) );
		}
	}
}
