<?php
/**
 * Focused tests for admin IP protection and block mode behaviour.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_WAF
 */
class AdminIpAndBlockModeTest extends SquidShield_TestCase {

	public function test_admin_ip_allowlist_setting_roundtrips() {
		$this->set_settings(
			array(
				'admin_ip_protection' => true,
				'admin_ip_allowlist'  => array( '203.0.113.5', '198.51.100.0/24' ),
			)
		);

		$all = SquidSec_Shield_Options::all();
		$this->assertTrue( $all['admin_ip_protection'] );
		$this->assertContains( '203.0.113.5', $all['admin_ip_allowlist'] );
	}

	public function test_block_mode_defaults_to_soft_and_can_be_set_to_hard() {
		$all = SquidSec_Shield_Options::all();
		$this->assertSame( 'soft', $all['block_mode'] ?? 'soft' );

		$this->set_settings( array( 'block_mode' => 'hard' ) );
		$all = SquidSec_Shield_Options::all();
		$this->assertSame( 'hard', $all['block_mode'] );
	}
}
