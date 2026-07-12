<?php
/**
 * Early WAF drop-in tests.
 *
 * @package SquidSec_Shield
 */

/**
 * Early drop-in presence / pattern list.
 */
class EarlyDropinTest extends SquidShield_TestCase {

	public function test_dropin_source_exists() {
		$src = SQUIDSEC_SHIELD_DIR . 'dropins/squidsec-shield-early.php';
		$this->assertFileExists( $src );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$code = (string) file_get_contents( $src );
		$this->assertStringContainsString( 'squidsec_shield_early_waf', $code );
		$this->assertStringContainsString( 'union select', $code );
		$this->assertStringContainsString( 'muplugins_loaded', $code );
	}

	public function test_plugin_main_file_headers() {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$main = (string) file_get_contents( SQUIDSEC_SHIELD_DIR . 'squidsec-shield.php' );
		$this->assertStringContainsString( 'Plugin Name:', $main );
		$this->assertStringContainsString( 'SquidShield WP', $main );
	}
}
