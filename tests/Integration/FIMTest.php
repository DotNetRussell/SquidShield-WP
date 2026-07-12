<?php
/**
 * File integrity monitoring tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_FIM
 */
class FIMTest extends SquidShield_TestCase {

	public function test_hash_file_stable() {
		$path = $this->create_temp_file( 'wp-content/sss-fim-hash.txt', "abc\n" );
		$h1   = SquidSec_Shield_FIM::hash_file( $path );
		$h2   = SquidSec_Shield_FIM::hash_file( $path );
		$this->assertNotEmpty( $h1 );
		$this->assertSame( $h1, $h2 );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $path, "changed\n" );
		$h3 = SquidSec_Shield_FIM::hash_file( $path );
		$this->assertNotSame( $h1, $h3 );
	}

	public function test_monitored_files_includes_core_login() {
		$files = SquidSec_Shield_FIM::monitored_files();
		$this->assertIsArray( $files );
		$basenames = array_map( 'basename', $files );
		$this->assertContains( 'wp-login.php', $basenames );
	}

	public function test_baseline_and_check() {
		$this->set_settings( array( 'fim_enabled' => true ) );
		SquidSec_Shield_FIM::create_baseline();
		global $wpdb;
		$table = SquidSec_Shield_Database::table( 'fim' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
		$this->assertGreaterThan( 0, $count );

		$changes = SquidSec_Shield_FIM::check_integrity();
		$this->assertIsArray( $changes );
	}
}
