<?php
/**
 * WAF rules engine tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Rules_Engine
 */
class RulesEngineTest extends SquidShield_TestCase {

	protected function setUp(): void {
		parent::setUp();
		$this->set_settings(
			array(
				'enabled'             => true,
				'waf_enabled'         => true,
				'waf_block_sqli'      => true,
				'waf_block_xss'       => true,
				'waf_block_rce'       => true,
				'waf_block_lfi'       => true,
				'waf_block_upload'    => true,
				'virtual_patch_enabled' => true,
			)
		);
		SquidSec_Shield_Rules_Engine::flush_cache();
	}

	public function test_loads_builtin_rules() {
		$rules = SquidSec_Shield_Rules_Engine::get_rules();
		$this->assertIsArray( $rules );
		$this->assertNotEmpty( $rules );
		$ids = array_column( $rules, 'id' );
		$this->assertContains( 'waf-sqli-union', $ids );
	}

	public function test_detects_sqli_union_select() {
		$match = SquidSec_Shield_Rules_Engine::evaluate( '/?id=1', '1 union select user,pass from wp_users', 'front' );
		$this->assertIsArray( $match );
		$this->assertNotEmpty( $match['id'] );
	}

	public function test_detects_xss_script_tag() {
		$match = SquidSec_Shield_Rules_Engine::evaluate( '/', '<script>alert(1)</script>', 'front' );
		$this->assertIsArray( $match );
	}

	public function test_detects_path_traversal() {
		// Explicit traversal + classic LFI target (both covered by LFI rules).
		$match = SquidSec_Shield_Rules_Engine::evaluate( '/download', 'file=../../../etc/passwd', 'front' );
		$this->assertIsArray( $match, 'Expected LFI/path-traversal rule to match' );
		$match2 = SquidSec_Shield_Rules_Engine::evaluate( '/?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd', '', 'front' );
		$this->assertIsArray( $match2 );
	}

	public function test_detects_rce_shell_exec() {
		$match = SquidSec_Shield_Rules_Engine::evaluate( '/', 'shell_exec("id")', 'front' );
		$this->assertIsArray( $match );
	}

	public function test_benign_request_does_not_match() {
		$match = SquidSec_Shield_Rules_Engine::evaluate( '/hello-world/', 's=security tips', 'front' );
		// May still match log-only rules; ensure no block action for plain search.
		if ( is_array( $match ) ) {
			$this->assertNotSame( 'block', $match['action'] ?? 'block' );
		} else {
			$this->assertNull( $match );
		}
	}

	public function test_category_toggle_disables_sqli() {
		$this->set_settings( array( 'waf_block_sqli' => false ) );
		SquidSec_Shield_Rules_Engine::flush_cache();
		$match = SquidSec_Shield_Rules_Engine::evaluate( '/', 'union select 1,2,3', 'front' );
		// SQLi rules skipped; other categories might still hit — ensure not sqli category.
		if ( is_array( $match ) ) {
			$this->assertNotSame( 'sqli', $match['category'] ?? '' );
		} else {
			$this->assertNull( $match );
		}
	}

	public function test_set_rule_enabled_disables_rule() {
		SquidSec_Shield_Rules_Engine::set_rule_enabled( 'waf-sqli-union', false );
		$rules = SquidSec_Shield_Rules_Engine::get_rules();
		foreach ( $rules as $r ) {
			if ( ( $r['id'] ?? '' ) === 'waf-sqli-union' ) {
				$this->assertFalse( (bool) $r['enabled'] );
			}
		}
		// Re-enable.
		SquidSec_Shield_Rules_Engine::set_rule_enabled( 'waf-sqli-union', true );
	}

	public function test_sandbox_rejects_unsafe_and_accepts_valid() {
		$ok = SquidSec_Shield_Rules_Engine::sandbox_validate_pattern( 'badbot' );
		$this->assertTrue( $ok );

		$bad = SquidSec_Shield_Rules_Engine::sandbox_validate_pattern( '(?R)evil' );
		$this->assertInstanceOf( WP_Error::class, $bad );

		$long = SquidSec_Shield_Rules_Engine::sandbox_validate_pattern( str_repeat( 'a', 600 ) );
		$this->assertInstanceOf( WP_Error::class, $long );
	}
}
