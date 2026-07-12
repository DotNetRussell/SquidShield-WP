<?php
/**
 * Outbound webhooks for SIEM / agents.
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Webhooks.
 */
class SquidSec_Shield_Webhooks {

	/**
	 * Init.
	 */
	public static function init() {
		// Dispatch is called from Alerts.
	}

	/**
	 * Dispatch event to configured webhook.
	 *
	 * @param string $type     Type.
	 * @param string $severity Severity.
	 * @param string $message  Message.
	 * @param array  $context  Context.
	 */
	public static function dispatch( $type, $severity, $message, array $context = array() ) {
		$url = SquidSec_Shield_Options::get( 'webhook_url' );
		if ( ! $url ) {
			return;
		}
		// Avoid double-post if Alerts already posted to same URL — Alerts handles primary.
		// This method is for extension / action consumers.
		do_action(
			'squidsec_shield_webhook_payload',
			array(
				'event'     => $type,
				'severity'  => $severity,
				'message'   => $message,
				'context'   => $context,
				'site'      => home_url(),
				'timestamp' => gmdate( 'c' ),
				'source'    => 'squidsec-shield',
				'version'   => SQUIDSEC_SHIELD_VERSION,
			)
		);
	}
}
