<?php
/**
 * Virtual patches + WAF helpers.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Virtual_Patch
 * @covers SquidSec_Shield_WAF
 */
class VirtualPatchAndWAFTest extends SquidShield_TestCase {

	public function test_list_patches() {
		$this->set_settings( array( 'virtual_patch_enabled' => true ) );
		$patches = SquidSec_Shield_Virtual_Patch::list_patches();
		$this->assertIsArray( $patches );
		$this->assertNotEmpty( $patches );
		$p = $patches[0];
		$this->assertArrayHasKey( 'id', $p );
		$this->assertArrayHasKey( 'enabled', $p );
		$this->assertArrayHasKey( 'applies', $p );
		$this->assertArrayHasKey( 'reason', $p );
	}

	public function test_xmlrpc_filter_respects_setting() {
		$this->set_settings( array( 'disable_xmlrpc' => true ) );
		$this->assertFalse( SquidSec_Shield_WAF::filter_xmlrpc( true ) );
		$this->set_settings( array( 'disable_xmlrpc' => false ) );
		$this->assertTrue( SquidSec_Shield_WAF::filter_xmlrpc( true ) );
	}

	public function test_data_files_exist_and_valid_json() {
		foreach ( array( 'waf-rules.json', 'virtual-patches.json', 'malware-signatures.json', 'vuln-db.json' ) as $file ) {
			$path = SQUIDSEC_SHIELD_DIR . 'data/' . $file;
			$this->assertFileExists( $path );
			$data = json_decode( (string) file_get_contents( $path ), true );
			$this->assertIsArray( $data, $file );
		}
	}
}
