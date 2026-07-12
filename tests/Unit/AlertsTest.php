<?php
/**
 * Alerts / threat level tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Alerts
 */
class AlertsTest extends SquidShield_TestCase {

	public function test_threat_level_critical_when_critical_events() {
		$this->assertSame( 'critical', SquidSec_Shield_Alerts::threat_level( array( 'critical' => 1, 'high' => 0, 'medium' => 0 ) ) );
	}

	public function test_threat_level_high_threshold() {
		$this->assertSame( 'high', SquidSec_Shield_Alerts::threat_level( array( 'critical' => 0, 'high' => 5, 'medium' => 0 ) ) );
	}

	public function test_threat_level_normal() {
		$this->assertSame( 'normal', SquidSec_Shield_Alerts::threat_level( array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0 ) ) );
	}

	public function test_threat_level_elevated_from_medium_spike() {
		$this->assertSame( 'elevated', SquidSec_Shield_Alerts::threat_level( array( 'critical' => 0, 'high' => 0, 'medium' => 20 ) ) );
	}
}
