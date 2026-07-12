<?php
/**
 * Malware signature tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Signatures
 */
class SignaturesTest extends SquidShield_TestCase {

	public function test_loads_signature_database() {
		$sigs = SquidSec_Shield_Signatures::all();
		$this->assertIsArray( $sigs );
		$this->assertNotEmpty( $sigs );
	}

	public function test_detects_eval_base64() {
		$code = '<?php eval(base64_decode("YXNzZXJ0"));';
		$hits = SquidSec_Shield_Signatures::match( $code, 'evil.php' );
		$this->assertNotEmpty( $hits );
		$ids  = array_column( $hits, 'signature_id' );
		$this->assertContains( 'mw-eval-base64', $ids );
	}

	public function test_detects_filesman_marker() {
		$hits = SquidSec_Shield_Signatures::match( '<!-- FilesMan shell -->', 'x.php' );
		$this->assertNotEmpty( $hits );
	}

	public function test_clean_php_has_no_hits() {
		$code = "<?php\necho 'Hello World';\n";
		$hits = SquidSec_Shield_Signatures::match( $code, 'hello.php' );
		$this->assertSame( array(), $hits );
	}

	public function test_line_numbers_reported() {
		$code = "line1\nline2\neval(base64_decode('x'));\n";
		$hits = SquidSec_Shield_Signatures::match( $code, 't.php' );
		$this->assertNotEmpty( $hits );
		$this->assertGreaterThan( 0, (int) $hits[0]['line_no'] );
	}
}
