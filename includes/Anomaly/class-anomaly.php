<?php
/**
 * Rule-based behavioral anomaly detection (transparent, extensible).
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
 * Anomaly detection.
 */
class SquidSec_Shield_Anomaly {

	/**
	 * Init.
	 */
	public static function init() {
		if ( ! SquidSec_Shield_Options::get( 'anomaly_detection' ) ) {
			return;
		}
		add_action( 'init', array( __CLASS__, 'track_request' ), 2 );
	}

	/**
	 * Track request counters for anomaly baselines.
	 */
	public static function track_request() {
		$context = SquidSec_Shield_Helpers::request_context();
		if ( ! in_array( $context, array( 'ajax', 'rest', 'login', 'admin' ), true ) ) {
			return;
		}
		$key   = 'sss_anom_' . $context . '_' . gmdate( 'YmdH' );
		$count = (int) get_transient( $key );
		set_transient( $key, $count + 1, 2 * HOUR_IN_SECONDS );

		// Uploads PHP creation is checked in FIM.
	}

	/**
	 * Evaluate anomalies hourly.
	 */
	public static function evaluate() {
		if ( ! SquidSec_Shield_Options::get( 'anomaly_detection' ) ) {
			return;
		}
		$contexts = array( 'ajax', 'rest', 'login', 'admin' );
		$alerts   = array();
		foreach ( $contexts as $ctx ) {
			$cur_key = 'sss_anom_' . $ctx . '_' . gmdate( 'YmdH' );
			$prev_h  = gmdate( 'YmdH', time() - HOUR_IN_SECONDS );
			$prev_key = 'sss_anom_' . $ctx . '_' . $prev_h;
			$cur  = (int) get_transient( $cur_key );
			$prev = (int) get_transient( $prev_key );
			// Spike: >5x previous hour and absolute threshold.
			$threshold = ( 'login' === $ctx ) ? 20 : 200;
			if ( $prev > 0 && $cur > $threshold && $cur > ( $prev * 5 ) ) {
				$alerts[] = array(
					'context' => $ctx,
					'current' => $cur,
					'previous'=> $prev,
					'rule'    => 'traffic_spike',
				);
			}
		}

		// Impossible travel: different country headers for same user within short window — CF only.
		// Track last login geo in user meta when CF header present — lightweight.
		if ( is_user_logged_in() && ! empty( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) {
			$uid = get_current_user_id();
			$cc  = strtoupper( sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_IPCOUNTRY'] ) ) );
			$last = get_user_meta( $uid, 'squidsec_shield_last_country', true );
			$last_t = (int) get_user_meta( $uid, 'squidsec_shield_last_country_time', true );
			if ( $last && $last !== $cc && $last_t && ( time() - $last_t ) < 3600 ) {
				$alerts[] = array(
					'context' => 'geo',
					'rule'    => 'impossible_travel',
					'from'    => $last,
					'to'      => $cc,
					'user_id' => $uid,
				);
			}
			update_user_meta( $uid, 'squidsec_shield_last_country', $cc );
			update_user_meta( $uid, 'squidsec_shield_last_country_time', time() );
		}

		foreach ( $alerts as $a ) {
			SquidSec_Shield_Audit_Log::write(
				'anomaly',
				'high',
				'Anomaly detected: ' . ( $a['rule'] ?? 'unknown' ),
				$a
			);
		}

		// Community-extensible.
		$extra = apply_filters( 'squidsec_shield_anomaly_rules', array(), $alerts );
		if ( is_array( $extra ) ) {
			foreach ( $extra as $e ) {
				if ( ! empty( $e['message'] ) ) {
					SquidSec_Shield_Audit_Log::write( 'anomaly', $e['severity'] ?? 'medium', $e['message'], $e['context'] ?? array() );
				}
			}
		}
	}
}
