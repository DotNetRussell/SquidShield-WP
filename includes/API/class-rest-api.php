<?php
/**
 * REST API for automation / agents / SIEM.
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
 * REST API.
 */
class SquidSec_Shield_REST_API {

	const NS = 'squidsec-shield/v1';

	/**
	 * Init.
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
	}

	/**
	 * Permission: manage_options or application password with cap.
	 *
	 * @return bool
	 */
	public static function can_manage() {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Register routes.
	 */
	public static function register_routes() {
		register_rest_route(
			self::NS,
			'/status',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'status' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/logs',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'logs' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/scan/malware',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'scan_malware' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/scan/vuln',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'scan_vuln' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/scan/misconfig',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'scan_misconfig' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/rules',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'rules' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/rules/(?P<id>[a-zA-Z0-9_\-\.]+)',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'toggle_rule' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/settings',
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( __CLASS__, 'get_settings' ),
					'permission_callback' => array( __CLASS__, 'can_manage' ),
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( __CLASS__, 'update_settings' ),
					'permission_callback' => array( __CLASS__, 'can_manage' ),
				),
			)
		);
		register_rest_route(
			self::NS,
			'/findings',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'findings' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/virtual-patches',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'virtual_patches' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
		register_rest_route(
			self::NS,
			'/hardening',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'hardening' ),
				'permission_callback' => array( __CLASS__, 'can_manage' ),
			)
		);
	}

	/**
	 * Status endpoint.
	 *
	 * @return WP_REST_Response
	 */
	public static function status() {
		$counts = SquidSec_Shield_Audit_Log::recent_counts( 24 );
		return rest_ensure_response(
			array(
				'version'      => SQUIDSEC_SHIELD_VERSION,
				'enabled'      => SquidSec_Shield_Options::is_enabled(),
				'pentest_mode' => SquidSec_Shield_Options::is_pentest(),
				'threat_level' => SquidSec_Shield_Alerts::threat_level( $counts ),
				'events_24h'   => $counts,
				'last_scan'    => (int) get_option( 'squidsec_shield_last_scan', 0 ),
				'waf_rules_ver'=> get_option( 'squidsec_shield_waf_rules_version', '' ),
				'sig_ver'      => get_option( 'squidsec_shield_signature_version', '' ),
			)
		);
	}

	/**
	 * Logs.
	 *
	 * @param WP_REST_Request $req Request.
	 * @return WP_REST_Response
	 */
	public static function logs( $req ) {
		return rest_ensure_response(
			SquidSec_Shield_Audit_Log::query(
				array(
					'limit'      => (int) $req->get_param( 'limit' ) ?: 50,
					'event_type' => $req->get_param( 'event_type' ),
					'severity'   => $req->get_param( 'severity' ),
					'search'     => $req->get_param( 'search' ),
					'ip'         => $req->get_param( 'ip' ),
				)
			)
		);
	}

	/** @return WP_REST_Response */
	public static function scan_malware() {
		$id = SquidSec_Shield_Malware_Scanner::start_scan( 'api' );
		return rest_ensure_response( array( 'scan_id' => $id ) );
	}

	/** @return WP_REST_Response */
	public static function scan_vuln() {
		return rest_ensure_response( SquidSec_Shield_Vuln_Scanner::run_scan() );
	}

	/** @return WP_REST_Response */
	public static function scan_misconfig() {
		return rest_ensure_response( SquidSec_Shield_Misconfig::run_scan() );
	}

	/** @return WP_REST_Response */
	public static function rules() {
		return rest_ensure_response( SquidSec_Shield_Rules_Engine::get_rules() );
	}

	/**
	 * Toggle rule.
	 *
	 * @param WP_REST_Request $req Request.
	 * @return WP_REST_Response
	 */
	public static function toggle_rule( $req ) {
		$id      = $req['id'];
		$enabled = ! empty( $req->get_param( 'enabled' ) );
		SquidSec_Shield_Rules_Engine::set_rule_enabled( $id, $enabled );
		return rest_ensure_response( array( 'id' => $id, 'enabled' => $enabled ) );
	}

	/** @return WP_REST_Response */
	public static function get_settings() {
		return rest_ensure_response( SquidSec_Shield_Options::all() );
	}

	/**
	 * Update settings.
	 *
	 * @param WP_REST_Request $req Request.
	 * @return WP_REST_Response
	 */
	public static function update_settings( $req ) {
		$params = $req->get_json_params();
		if ( ! is_array( $params ) ) {
			$params = $req->get_params();
		}
		return rest_ensure_response( SquidSec_Shield_Options::update( $params ) );
	}

	/** @return WP_REST_Response */
	public static function findings() {
		return rest_ensure_response( SquidSec_Shield_Malware_Scanner::get_findings( 200 ) );
	}

	/** @return WP_REST_Response */
	public static function virtual_patches() {
		return rest_ensure_response( SquidSec_Shield_Virtual_Patch::list_patches() );
	}

	/**
	 * Hardening wizard.
	 *
	 * @param WP_REST_Request $req Request.
	 * @return WP_REST_Response
	 */
	public static function hardening( $req ) {
		$profile = $req->get_param( 'profile' ) ?: 'default';
		return rest_ensure_response(
			array(
				'applied' => SquidSec_Shield_Hardening::apply_wizard( $profile ),
			)
		);
	}
}
