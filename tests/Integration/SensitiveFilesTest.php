<?php
/**
 * Sensitive file scan tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Sensitive_Files
 */
class SensitiveFilesTest extends SquidShield_TestCase {

	public function test_scan_finds_planted_backup() {
		$rel  = 'wp-config.php.bak.sss-test';
		$full = ABSPATH . $rel;
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $full, "<?php // fake backup\n" );
		$this->temp_paths[] = $full;

		$found = SquidSec_Shield_Sensitive_Files::scan( true );
		$paths = array_column( $found, 'path' );
		$this->assertContains( $rel, $paths );

		// Cleanup via remediation.
		SquidSec_Shield_Remediation::delete_file( $rel, true );
	}

	public function test_risk_for_config_backup_is_critical() {
		$this->assertSame( 'critical', SquidSec_Shield_Sensitive_Files::risk_for( 'wp-config.php.bak' ) );
		$this->assertSame( 'low', SquidSec_Shield_Sensitive_Files::risk_for( 'readme.html' ) );
	}

	public function test_suggested_server_rules_present() {
		$rules = SquidSec_Shield_Sensitive_Files::suggested_server_rules();
		$this->assertArrayHasKey( 'apache', $rules );
		$this->assertArrayHasKey( 'nginx', $rules );
		$this->assertStringContainsString( 'wp-config', $rules['apache'] );
		$this->assertStringContainsString( 'deny', strtolower( $rules['nginx'] ) );
	}
}
