<?php
/**
 * Setup / protection layers tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Setup
 */
class SetupTest extends SquidShield_TestCase {

	public function test_protection_layers_structure() {
		$layers = SquidSec_Shield_Setup::protection_layers();
		$this->assertNotEmpty( $layers );
		foreach ( $layers as $layer ) {
			$this->assertArrayHasKey( 'id', $layer );
			$this->assertArrayHasKey( 'label', $layer );
			$this->assertArrayHasKey( 'detail', $layer );
			$this->assertArrayHasKey( 'ok', $layer );
		}
		$ids = array_column( $layers, 'id' );
		$this->assertContains( 'firewall', $ids );
		$this->assertContains( 'login', $ids );
		$this->assertContains( 'fingerprints', $ids );
	}

	public function test_overall_status_off_when_disabled() {
		$this->set_settings( array( 'enabled' => false ) );
		$status = SquidSec_Shield_Setup::overall_status();
		$this->assertSame( 'off', $status['level'] );
		$this->assertTrue( $status['action_needed'] );
	}

	public function test_overall_status_monitor_in_pentest() {
		$this->set_settings( array( 'enabled' => true, 'pentest_mode' => true ) );
		$status = SquidSec_Shield_Setup::overall_status();
		$this->assertSame( 'monitor', $status['level'] );
	}

	public function test_layers_reflect_settings() {
		$this->set_settings(
			array(
				'enabled'     => true,
				'pentest_mode'=> false,
				'waf_enabled' => true,
				'login_protection' => true,
				'hide_login_errors' => true,
			)
		);
		$layers = SquidSec_Shield_Setup::protection_layers();
		$map    = array();
		foreach ( $layers as $l ) {
			$map[ $l['id'] ] = $l['ok'];
		}
		$this->assertTrue( $map['master'] );
		$this->assertTrue( $map['firewall'] );
		$this->assertTrue( $map['login'] );
	}
}
