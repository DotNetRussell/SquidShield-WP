<?php
/**
 * Audit log integration tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Audit_Log
 */
class AuditLogTest extends SquidShield_TestCase {

	public function test_write_and_query() {
		$id = SquidSec_Shield_Audit_Log::write(
			'unit_test_event',
			'info',
			'SquidShield unit test log row',
			array( 'test' => true ),
			'rule_test',
			'CVE-TEST-1'
		);
		$this->assertGreaterThan( 0, $id );

		$rows = SquidSec_Shield_Audit_Log::query(
			array(
				'event_type' => 'unit_test_event',
				'limit'      => 5,
				'search'     => 'unit test log',
			)
		);
		$this->assertNotEmpty( $rows );
		$this->assertSame( 'unit_test_event', $rows[0]['event_type'] );
	}

	public function test_export_json_and_csv() {
		SquidSec_Shield_Audit_Log::write( 'unit_export', 'low', 'export me' );
		$json = SquidSec_Shield_Audit_Log::export( 'json', 10 );
		$this->assertJson( $json );
		$csv = SquidSec_Shield_Audit_Log::export( 'csv', 10 );
		$this->assertIsString( $csv );
	}

	public function test_recent_counts_structure() {
		$counts = SquidSec_Shield_Audit_Log::recent_counts( 24 );
		foreach ( array( 'critical', 'high', 'medium', 'low', 'info' ) as $sev ) {
			$this->assertArrayHasKey( $sev, $counts );
			$this->assertIsInt( $counts[ $sev ] );
		}
	}
}
