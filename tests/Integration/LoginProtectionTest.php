<?php
/**
 * Login protection integration tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Login_Protection
 */
class LoginProtectionTest extends SquidShield_TestCase {

	protected function setUp(): void {
		parent::setUp();
		$this->set_settings(
			array(
				'enabled'               => true,
				'login_protection'      => true,
				'login_max_attempts'    => 3,
				'login_lockout_minutes' => 15,
				'hide_login_errors'     => true,
				'disable_xmlrpc'        => true,
			)
		);
		// Clear fail counters for this IP.
		$ip = SquidSec_Shield_IP::client();
		delete_transient( 'sss_login_ip_' . md5( $ip ) );
	}

	public function test_generic_login_errors() {
		$msg = SquidSec_Shield_Login_Protection::generic_errors( 'Invalid username.' );
		$this->assertStringContainsStringIgnoringCase( 'invalid', $msg );
	}

	public function test_lockout_after_max_failures() {
		$ip = SquidSec_Shield_IP::client();
		// Simulate failures.
		for ( $i = 0; $i < 3; $i++ ) {
			SquidSec_Shield_Login_Protection::on_fail( 'no_such_user_sss' );
		}
		$result = SquidSec_Shield_Login_Protection::check_lockout( null, 'admin', 'wrong' );
		$this->assertInstanceOf( WP_Error::class, $result );

		delete_transient( 'sss_login_ip_' . md5( $ip ) );
		// Clear any IP blocks created.
		global $wpdb;
		$table = SquidSec_Shield_Database::table( 'blocks' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE ip = %s", $ip ) );
	}

	public function test_xmlrpc_fully_disabled() {
		$methods = array(
			'pingback.ping' => 'cb',
			'wp.getUsersBlogs' => 'cb',
		);
		// When disable_xmlrpc is true, filter returns empty via Login_Protection filter_xmlrpc_methods
		// but only removes pingbacks when full disable is handled by WAF filter_xmlrpc.
		// Login protection filter_xmlrpc_methods with disable_xmlrpc true returns [].
		$out = SquidSec_Shield_Login_Protection::filter_xmlrpc_methods( $methods );
		$this->assertSame( array(), $out );
	}

	public function test_success_clears_counters() {
		$ip = SquidSec_Shield_IP::client();
		set_transient( 'sss_login_ip_' . md5( $ip ), 2, HOUR_IN_SECONDS );
		SquidSec_Shield_Login_Protection::on_success( 'admin', new WP_User( 1 ) );
		$this->assertFalse( get_transient( 'sss_login_ip_' . md5( $ip ) ) );
	}
}
