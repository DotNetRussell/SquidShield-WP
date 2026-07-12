<?php
/**
 * Alerts & notifications.
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
 * Alerts.
 */
class SquidSec_Shield_Alerts {

	/**
	 * Init.
	 */
	public static function init() {
		add_action( 'squidsec_shield_security_event', array( __CLASS__, 'on_event' ), 10, 4 );
	}

	/**
	 * Handle high-severity events.
	 *
	 * @param string $type     Type.
	 * @param string $severity Severity.
	 * @param string $message  Message.
	 * @param array  $context  Context.
	 */
	public static function on_event( $type, $severity, $message, $context ) {
		// Throttle identical alerts.
		$key = 'sss_alert_' . md5( $type . '|' . $message );
		if ( get_transient( $key ) ) {
			return;
		}
		set_transient( $key, 1, 10 * MINUTE_IN_SECONDS );

		$subject = sprintf( '[SquidShield] %s: %s', strtoupper( $severity ), $type );
		$body    = $message . "\n\n" . wp_json_encode( $context, JSON_PRETTY_PRINT );
		$body   .= "\n\nSite: " . home_url() . "\nIP: " . SquidSec_Shield_IP::client();

		$email = SquidSec_Shield_Options::get( 'notify_email' );
		if ( ! $email ) {
			$email = get_option( 'admin_email' );
		}
		if ( $email && is_email( $email ) ) {
			wp_mail( $email, $subject, $body );
		}

		$slack = SquidSec_Shield_Options::get( 'slack_webhook' );
		if ( $slack ) {
			wp_remote_post(
				$slack,
				array(
					'timeout' => 8,
					'headers' => array( 'Content-Type' => 'application/json' ),
					'body'    => wp_json_encode( array( 'text' => $subject . "\n" . $message ) ),
				)
			);
		}

		$hook = SquidSec_Shield_Options::get( 'webhook_url' );
		if ( $hook ) {
			wp_remote_post(
				$hook,
				array(
					'timeout' => 8,
					'headers' => array( 'Content-Type' => 'application/json' ),
					'body'    => wp_json_encode(
						array(
							'event'     => $type,
							'severity'  => $severity,
							'message'   => $message,
							'context'   => $context,
							'site'      => home_url(),
							'timestamp' => gmdate( 'c' ),
						)
					),
				)
			);
		}

		SquidSec_Shield_Webhooks::dispatch( $type, $severity, $message, $context );
	}

	/**
	 * Daily summary email.
	 */
	public static function send_daily_summary() {
		$counts = SquidSec_Shield_Audit_Log::recent_counts( 24 );
		$threat = self::threat_level( $counts );
		update_option( 'squidsec_shield_threat_level', $threat, false );

		$email = SquidSec_Shield_Options::get( 'notify_email' );
		if ( ! $email ) {
			$email = get_option( 'admin_email' );
		}
		if ( ! $email || ! is_email( $email ) ) {
			return;
		}
		$subject = sprintf( '[SquidShield] Daily report — threat level: %s', $threat );
		$body    = "24h event counts:\n";
		foreach ( $counts as $sev => $c ) {
			$body .= sprintf( "  %s: %d\n", $sev, $c );
		}
		$body .= "\nDashboard: " . admin_url( 'admin.php?page=squidsec-shield' );
		wp_mail( $email, $subject, $body );
	}

	/**
	 * Compute threat level string.
	 *
	 * @param array $counts Counts.
	 * @return string
	 */
	public static function threat_level( array $counts ) {
		if ( ( $counts['critical'] ?? 0 ) > 0 ) {
			return 'critical';
		}
		if ( ( $counts['high'] ?? 0 ) >= 5 ) {
			return 'high';
		}
		if ( ( $counts['high'] ?? 0 ) > 0 || ( $counts['medium'] ?? 0 ) >= 20 ) {
			return 'elevated';
		}
		if ( ( $counts['medium'] ?? 0 ) > 0 ) {
			return 'low';
		}
		return 'normal';
	}
}
