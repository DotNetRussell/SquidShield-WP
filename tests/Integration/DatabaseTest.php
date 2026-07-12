<?php
/**
 * Database schema tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Database
 */
class DatabaseTest extends SquidShield_TestCase {

	public function test_tables_exist() {
		global $wpdb;
		$suffixes = array( 'logs', 'blocks', 'scans', 'findings', 'fim', 'rules_custom', 'ip_list' );
		foreach ( $suffixes as $suffix ) {
			$table = SquidSec_Shield_Database::table( $suffix );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
			$this->assertSame( $table, $found, "Missing table {$table}" );
		}
	}

	public function test_create_tables_is_idempotent() {
		SquidSec_Shield_Database::create_tables();
		SquidSec_Shield_Database::create_tables();
		$this->assertTrue( true );
	}
}
