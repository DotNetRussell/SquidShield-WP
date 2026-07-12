<?php
/**
 * Misconfig scanner + hardening tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Misconfig
 * @covers SquidSec_Shield_Hardening
 */
class MisconfigAndHardeningTest extends SquidShield_TestCase {

	public function test_misconfig_scan_returns_findings_array() {
		$findings = SquidSec_Shield_Misconfig::run_scan( true );
		$this->assertIsArray( $findings );
		if ( $findings ) {
			$f = $findings[0];
			$this->assertArrayHasKey( 'id', $f );
			$this->assertArrayHasKey( 'severity', $f );
			$this->assertArrayHasKey( 'title', $f );
			$this->assertArrayHasKey( 'remediable', $f );
		}
	}

	public function test_hardening_wizard_enables_protections() {
		$this->set_settings(
			array(
				'waf_enabled'      => false,
				'login_protection' => false,
			)
		);
		$keys = SquidSec_Shield_Hardening::apply_wizard( 'default' );
		$this->assertContains( 'waf_enabled', $keys );
		$this->assertTrue( (bool) SquidSec_Shield_Options::get( 'waf_enabled' ) );
		$this->assertTrue( (bool) SquidSec_Shield_Options::get( 'login_protection' ) );
		$this->assertTrue( (bool) SquidSec_Shield_Options::get( 'user_enum_prevention' ) );
	}

	public function test_recommendations_is_array() {
		$recs = SquidSec_Shield_Hardening::recommendations();
		$this->assertIsArray( $recs );
	}

	public function test_fix_misconfig_uploads_index() {
		$uploads = wp_upload_dir();
		$idx     = trailingslashit( $uploads['basedir'] ) . 'index.php';
		// Don't delete real index if present — only test API success path.
		$r = SquidSec_Shield_Remediation::fix_misconfig( 'uploads_index' );
		$this->assertTrue( $r );
		$this->assertFileExists( $idx );
	}
}
