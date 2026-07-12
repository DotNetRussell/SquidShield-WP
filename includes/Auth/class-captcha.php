<?php
/**
 * CAPTCHA / Turnstile integration (optional free providers).
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
 * Captcha.
 */
class SquidSec_Shield_Captcha {

	/**
	 * Init.
	 */
	public static function init() {
		$provider = SquidSec_Shield_Options::get( 'captcha_provider', 'none' );
		if ( 'none' === $provider || ! SquidSec_Shield_Options::get( 'captcha_on_login' ) ) {
			return;
		}
		// Print provider tags on login only (not wp_enqueue_script with remote URLs —
		// WordPress.org disallows offloaded enqueues).
		add_action( 'login_footer', array( __CLASS__, 'print_provider_scripts' ), 5 );
		add_action( 'login_form', array( __CLASS__, 'render' ) );
		add_filter( 'wp_authenticate_user', array( __CLASS__, 'verify' ), 25, 2 );
	}

	/**
	 * Print CAPTCHA provider scripts on the login screen when enabled.
	 */
	public static function print_provider_scripts() {
		$provider = SquidSec_Shield_Options::get( 'captcha_provider' );
		$site     = SquidSec_Shield_Options::get( 'captcha_site_key' );
		if ( ! $site || ! $provider || 'none' === $provider ) {
			return;
		}
		if ( 'recaptcha' === $provider ) {
			// Required by Google reCAPTCHA v2 when that option is enabled.
			echo '<script src="' . esc_url( 'https://www.google.com/recaptcha/api.js' ) . '" async defer></script>'; // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
		} elseif ( 'turnstile' === $provider ) {
			echo '<script src="' . esc_url( 'https://challenges.cloudflare.com/turnstile/v0/api.js' ) . '" async defer></script>'; // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript
		}
	}

	/**
	 * Render widget.
	 */
	public static function render() {
		$site = SquidSec_Shield_Options::get( 'captcha_site_key' );
		if ( ! $site ) {
			return;
		}
		$provider = SquidSec_Shield_Options::get( 'captcha_provider' );
		if ( 'recaptcha' === $provider ) {
			echo '<div class="g-recaptcha" data-sitekey="' . esc_attr( $site ) . '"></div>';
		} elseif ( 'turnstile' === $provider ) {
			echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( $site ) . '"></div>';
		}
	}

	/**
	 * Verify on login.
	 *
	 * @param WP_User|WP_Error $user User.
	 * @param string           $password Password.
	 * @return WP_User|WP_Error
	 */
	public static function verify( $user, $password ) {
		if ( is_wp_error( $user ) ) {
			return $user;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( empty( $_POST['log'] ) && empty( $_POST['pwd'] ) ) {
			return $user;
		}
		$secret = SquidSec_Shield_Options::get( 'captcha_secret_key' );
		if ( ! $secret ) {
			return $user;
		}
		$provider = SquidSec_Shield_Options::get( 'captcha_provider' );
		$token    = '';
		if ( 'recaptcha' === $provider ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$token = isset( $_POST['g-recaptcha-response'] ) ? sanitize_text_field( wp_unslash( $_POST['g-recaptcha-response'] ) ) : '';
			$url   = 'https://www.google.com/recaptcha/api/siteverify';
		} else {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$token = isset( $_POST['cf-turnstile-response'] ) ? sanitize_text_field( wp_unslash( $_POST['cf-turnstile-response'] ) ) : '';
			$url   = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
		}
		if ( $token === '' ) {
			return new WP_Error( 'sss_captcha', __( 'Please complete the captcha.', 'squidsec-shield' ) );
		}
		$resp = wp_remote_post(
			$url,
			array(
				'timeout' => 12,
				'body'    => array(
					'secret'   => $secret,
					'response' => $token,
					'remoteip' => SquidSec_Shield_IP::client(),
				),
			)
		);
		if ( is_wp_error( $resp ) ) {
			return new WP_Error( 'sss_captcha', __( 'Captcha verification failed.', 'squidsec-shield' ) );
		}
		$data = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( empty( $data['success'] ) ) {
			return new WP_Error( 'sss_captcha', __( 'Captcha check failed.', 'squidsec-shield' ) );
		}
		return $user;
	}
}
