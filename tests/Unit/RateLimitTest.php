<?php
/**
 * Rate limit tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Rate_Limit
 */
class RateLimitTest extends SquidShield_TestCase {

	public function test_limit_for_contexts() {
		$this->set_settings(
			array(
				'rate_limit_ajax'   => 120,
				'rate_limit_rest'   => 90,
				'rate_limit_login'  => 10,
				'rate_limit_xmlrpc' => 20,
			)
		);
		$this->assertSame( 120, SquidSec_Shield_Rate_Limit::limit_for( 'ajax' ) );
		$this->assertSame( 90, SquidSec_Shield_Rate_Limit::limit_for( 'rest' ) );
		$this->assertSame( 10, SquidSec_Shield_Rate_Limit::limit_for( 'login' ) );
		$this->assertSame( 20, SquidSec_Shield_Rate_Limit::limit_for( 'xmlrpc' ) );
		$this->assertSame( 0, SquidSec_Shield_Rate_Limit::limit_for( 'front' ) );
	}

	public function test_penalize_sets_transient() {
		$ip = '198.51.100.10';
		SquidSec_Shield_Rate_Limit::penalize( $ip, 'login' );
		$key = 'sss_rl_' . md5( $ip . '|login' );
		$this->assertNotFalse( get_transient( $key ) );
		delete_transient( $key );
	}
}
