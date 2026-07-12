<?php
/**
 * Vulnerability + plugin risk tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Vuln_Scanner
 * @covers SquidSec_Shield_Plugin_Risk
 */
class VulnAndRiskTest extends SquidShield_TestCase {

	public function test_load_vuln_db() {
		$db = SquidSec_Shield_Vuln_Scanner::load_db();
		$this->assertArrayHasKey( 'vulnerabilities', $db );
		$this->assertIsArray( $db['vulnerabilities'] );
	}

	public function test_risk_score_bounds() {
		$low = SquidSec_Shield_Vuln_Scanner::risk_score(
			array(
				'severity'       => 'low',
				'exploitability'  => 'low',
				'fixed_in'        => '1.0',
			)
		);
		$crit = SquidSec_Shield_Vuln_Scanner::risk_score(
			array(
				'severity'       => 'critical',
				'exploitability'  => 'high',
				'fixed_in'        => '',
			)
		);
		$this->assertGreaterThanOrEqual( 0, $low );
		$this->assertLessThanOrEqual( 100, $crit );
		$this->assertGreaterThan( $low, $crit );
	}

	public function test_run_scan_returns_array() {
		$results = SquidSec_Shield_Vuln_Scanner::run_scan( true );
		$this->assertIsArray( $results );
		$cached = SquidSec_Shield_Vuln_Scanner::cached();
		$this->assertArrayHasKey( 'results', $cached );
	}

	public function test_plugin_risk_scores_installed_plugins() {
		$scores = SquidSec_Shield_Plugin_Risk::score_all();
		$this->assertIsArray( $scores );
		$this->assertNotEmpty( $scores );
		$first = $scores[0];
		$this->assertArrayHasKey( 'slug', $first );
		$this->assertArrayHasKey( 'score', $first );
		$this->assertArrayHasKey( 'signals', $first );
		$this->assertGreaterThanOrEqual( 0, $first['score'] );
		$this->assertLessThanOrEqual( 100, $first['score'] );
	}

	public function test_first_party_squidsec_scored_lower() {
		$score = SquidSec_Shield_Plugin_Risk::score_plugin(
			'squidsec-example',
			array(
				'Name'    => 'SquidSec Example',
				'Version' => '1.0.0',
				'Author'  => 'SquidSec',
			),
			true
		);
		$other = SquidSec_Shield_Plugin_Risk::score_plugin(
			'unknown-plugin',
			array(
				'Name'    => 'Unknown',
				'Version' => '1.0.0',
				'Author'  => '',
			),
			false
		);
		$this->assertLessThan( $other['score'], $score['score'] );
	}
}
