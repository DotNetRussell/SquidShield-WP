<?php
/**
 * CAPTCHA / Turnstile integration (optional free providers).
 *
 * @package SquidSec_Shield
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
		add_action( 'login_enqueue_scripts', array( __CLASS__, 'enqueue' ) );
		add_action( 'login_form', array( __CLASS__, 'render' ) );
		add_filter( 'wp_authenticate_user', array( __CLASS__, 'verify' ), 25, 2 );
	}

	/**
	 * Enqueue provider scripts.
	 */
	public static function enqueue() {
		$provider = SquidSec_Shield_Options::get( 'captcha_provider' );
		if ( 'recaptcha' === $provider ) {
			wp_enqueue_script( 'sss-recaptcha', 'https://www.google.com/recaptcha/api.js', array(), null, true );
		} elseif ( 'turnstile' === $provider ) {
			wp_enqueue_script( 'sss-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), null, true );
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
