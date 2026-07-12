<?php
/**
 * REST API route registration tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_REST_API
 */
class RestApiTest extends SquidShield_TestCase {

	public function test_routes_registered() {
		// Ensure routes registered.
		do_action( 'rest_api_init' );
		$routes = rest_get_server()->get_routes();
		$found  = 0;
		foreach ( array_keys( $routes ) as $route ) {
			if ( false !== strpos( $route, 'squidsec-shield' ) ) {
				$found++;
			}
		}
		$this->assertGreaterThanOrEqual( 8, $found );
	}

	public function test_status_requires_manage_options() {
		wp_set_current_user( 0 );
		$this->assertFalse( SquidSec_Shield_REST_API::can_manage() );
	}

	public function test_status_payload_as_admin() {
		// Find an administrator.
		$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
		if ( empty( $admins ) ) {
			$this->markTestSkipped( 'No administrator user' );
		}
		wp_set_current_user( $admins[0]->ID );
		$this->assertTrue( SquidSec_Shield_REST_API::can_manage() );

		$response = SquidSec_Shield_REST_API::status();
		$data     = $response->get_data();
		$this->assertArrayHasKey( 'version', $data );
		$this->assertArrayHasKey( 'enabled', $data );
		$this->assertArrayHasKey( 'events_24h', $data );
		wp_set_current_user( 0 );
	}

	public function test_get_settings_returns_defaults_keys() {
		$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
		if ( empty( $admins ) ) {
			$this->markTestSkipped( 'No administrator user' );
		}
		wp_set_current_user( $admins[0]->ID );
		$response = SquidSec_Shield_REST_API::get_settings();
		$data     = $response->get_data();
		$this->assertArrayHasKey( 'waf_enabled', $data );
		$this->assertArrayHasKey( 'login_protection', $data );
		wp_set_current_user( 0 );
	}
}
