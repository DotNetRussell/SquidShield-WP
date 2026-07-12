<?php
/**
 * TOTP / 2FA pure logic tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Two_Factor
 */
class TwoFactorTest extends SquidShield_TestCase {

	public function test_generate_secret_is_base32ish() {
		$secret = SquidSec_Shield_Two_Factor::generate_secret( 16 );
		$this->assertSame( 16, strlen( $secret ) );
		$this->assertMatchesRegularExpression( '/^[A-Z2-7]+$/', $secret );
	}

	public function test_totp_is_six_digits_and_stable_for_window() {
		$secret = 'JBSWY3DPEHPK3PXP'; // classic test secret "Hello!"
		$code   = SquidSec_Shield_Two_Factor::totp( $secret, 1234567890 );
		$this->assertMatchesRegularExpression( '/^\d{6}$/', $code );
		// Same counter window.
		$same = SquidSec_Shield_Two_Factor::totp( $secret, 1234567890 + 10 );
		$this->assertSame( $code, $same );
	}

	public function test_verify_accepts_current_totp() {
		$user_id = self::factory_user();
		$secret  = SquidSec_Shield_Two_Factor::generate_secret();
		update_user_meta( $user_id, SquidSec_Shield_Two_Factor::META_SECRET, $secret );
		$code = SquidSec_Shield_Two_Factor::totp( $secret );
		$this->assertTrue( SquidSec_Shield_Two_Factor::verify( $user_id, $code ) );
		$this->assertFalse( SquidSec_Shield_Two_Factor::verify( $user_id, '000000' ) );
		wp_delete_user( $user_id );
	}

	public function test_backup_codes_are_single_use() {
		$user_id = self::factory_user();
		$codes   = SquidSec_Shield_Two_Factor::generate_backup_codes();
		$this->assertCount( 8, $codes );
		update_user_meta( $user_id, SquidSec_Shield_Two_Factor::META_BACKUP, $codes );
		$code = array_key_first( $codes );
		$this->assertTrue( SquidSec_Shield_Two_Factor::verify( $user_id, $code ) );
		// Second use fails.
		$this->assertFalse( SquidSec_Shield_Two_Factor::verify( $user_id, $code ) );
		wp_delete_user( $user_id );
	}

	/**
	 * Create a disposable user.
	 *
	 * @return int
	 */
	private static function factory_user() {
		$login = 'sss_test_' . wp_generate_password( 8, false );
		$id    = wp_create_user( $login, wp_generate_password( 16 ), $login . '@example.com' );
		if ( is_wp_error( $id ) ) {
			self::fail( $id->get_error_message() );
		}
		return (int) $id;
	}
}
