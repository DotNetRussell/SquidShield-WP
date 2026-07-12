<?php
/**
 * Helpers tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Helpers
 */
class HelpersTest extends SquidShield_TestCase {

	public function test_version_matches_operators() {
		$this->assertTrue( SquidSec_Shield_Helpers::version_matches( '1.2.3', '*' ) );
		$this->assertTrue( SquidSec_Shield_Helpers::version_matches( '1.2.3', '<=1.2.3' ) );
		$this->assertTrue( SquidSec_Shield_Helpers::version_matches( '1.2.3', '<2.0.0' ) );
		$this->assertFalse( SquidSec_Shield_Helpers::version_matches( '2.0.0', '<2.0.0' ) );
		$this->assertTrue( SquidSec_Shield_Helpers::version_matches( '2.0.0', '>=2.0.0' ) );
		$this->assertTrue( SquidSec_Shield_Helpers::version_matches( '1.0.0', '==1.0.0' ) );
		$this->assertTrue( SquidSec_Shield_Helpers::version_matches( '1.0.0', '=1.0.0' ) );
	}

	public function test_severity_rank_order() {
		$this->assertGreaterThan(
			SquidSec_Shield_Helpers::severity_rank( 'high' ),
			SquidSec_Shield_Helpers::severity_rank( 'critical' )
		);
		$this->assertGreaterThan(
			SquidSec_Shield_Helpers::severity_rank( 'medium' ),
			SquidSec_Shield_Helpers::severity_rank( 'high' )
		);
		$this->assertSame( 0, SquidSec_Shield_Helpers::severity_rank( 'unknown' ) );
	}

	public function test_safe_match() {
		$this->assertTrue( SquidSec_Shield_Helpers::safe_match( '/union\s+select/i', '1 UNION SELECT 1' ) );
		$this->assertFalse( SquidSec_Shield_Helpers::safe_match( '/nope/', 'hello' ) );
		$this->assertFalse( SquidSec_Shield_Helpers::safe_match( '', 'x' ) );
	}

	public function test_sanitize_array() {
		$in  = array( 'a' => ' <b>x</b> ', 'n' => array( 'k' => 1 ) );
		$out = SquidSec_Shield_Helpers::sanitize_array( $in );
		$this->assertIsArray( $out );
		$this->assertArrayHasKey( 'a', $out );
		$this->assertSame( '1', $out['n']['k'] );
	}

	public function test_request_method_and_uri_available() {
		$method = SquidSec_Shield_Helpers::request_method();
		$this->assertNotEmpty( $method );
		$uri = SquidSec_Shield_Helpers::request_uri();
		$this->assertIsString( $uri );
	}
}
