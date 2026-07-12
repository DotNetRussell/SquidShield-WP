<?php
/**
 * Remediation safety + sensitive file helpers.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Remediation
 */
class RemediationTest extends SquidShield_TestCase {

	public function test_live_wp_config_is_protected() {
		$this->assertTrue( SquidSec_Shield_Remediation::is_protected_path( 'wp-config.php' ) );
		$r = SquidSec_Shield_Remediation::delete_file( 'wp-config.php', true );
		$this->assertInstanceOf( WP_Error::class, $r );
	}

	public function test_core_paths_protected() {
		$this->assertTrue( SquidSec_Shield_Remediation::is_protected_path( 'wp-load.php' ) );
		$this->assertTrue( SquidSec_Shield_Remediation::is_protected_path( 'wp-admin/index.php' ) );
	}

	public function test_config_backup_is_remediable() {
		$this->assertTrue( SquidSec_Shield_Remediation::is_remediable_sensitive_file( 'wp-config.php.bak' ) );
		$this->assertTrue( SquidSec_Shield_Remediation::is_remediable_sensitive_file( 'wp-config.prod.php.bak' ) );
		$this->assertTrue( SquidSec_Shield_Remediation::is_remediable_sensitive_file( 'readme.html' ) );
		$this->assertTrue( SquidSec_Shield_Remediation::is_remediable_sensitive_file( 'debug.log' ) );
		$this->assertFalse( SquidSec_Shield_Remediation::is_remediable_sensitive_file( 'wp-config.php' ) );
	}

	public function test_normalize_blocks_traversal() {
		$r = SquidSec_Shield_Remediation::normalize_rel_path( '../etc/passwd' );
		$this->assertInstanceOf( WP_Error::class, $r );
	}

	public function test_delete_sensitive_temp_file() {
		$rel  = 'sss-test-delete-' . wp_generate_password( 6, false ) . '.sql';
		$full = $this->create_temp_file( $rel, "DROP TABLE x;\n" );
		$this->assertFileExists( $full );
		$this->assertTrue( SquidSec_Shield_Remediation::is_remediable_sensitive_file( $rel ) );
		$r = SquidSec_Shield_Remediation::delete_file( $rel, true );
		$this->assertTrue( $r );
		$this->assertFileDoesNotExist( $full );
	}

	public function test_quarantine_moves_file() {
		$rel  = 'sss-test-q-' . wp_generate_password( 6, false ) . '.sql';
		$full = $this->create_temp_file( $rel, "-- dump\n" );
		$r    = SquidSec_Shield_Remediation::quarantine( $rel, true );
		$this->assertTrue( $r );
		$this->assertFileDoesNotExist( $full );
		$upload = wp_upload_dir();
		$qdir   = trailingslashit( $upload['basedir'] ) . 'squidsec-shield-quarantine';
		$this->assertDirectoryExists( $qdir );
	}
}
