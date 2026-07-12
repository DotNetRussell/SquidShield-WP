<?php
/**
 * Early WAF drop-in tests.
 *
 * @package SquidSec_Shield
 */

/**
 * Early drop-in presence / pattern list.
 */
class EarlyDropinTest extends SquidShield_TestCase {

	public function test_dropin_source_exists() {
		$src = SQUIDSEC_SHIELD_DIR . 'dropins/squidsec-shield-early.php';
		$this->assertFileExists( $src );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$code = (string) file_get_contents( $src );
		$this->assertStringContainsString( 'squidsec_shield_early_waf', $code );
		$this->assertStringContainsString( 'union select', $code );
		$this->assertStringContainsString( 'muplugins_loaded', $code );
		// Nested Plugin Name headers break WP Activate after zip install.
		$this->assertStringNotContainsString( 'Plugin Name:', $code );
	}

	public function test_plugin_main_file_headers() {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		$main = (string) file_get_contents( SQUIDSEC_SHIELD_DIR . 'squidsec-shield.php' );
		$this->assertStringContainsString( 'Plugin Name:', $main );
		// WordPress.org forbids "WP" in the plugin name — brand is "SquidShield".
		$this->assertMatchesRegularExpression( '/Plugin Name:\s*SquidShield\b/', $main );
		$this->assertStringNotContainsString( 'Plugin Name:       SquidShield WP', $main );
		$this->assertStringNotContainsString( 'Plugin Name: SquidShield WP', $main );
	}

	/**
	 * Only the plugin root may declare Plugin Name — mirrors WP plugin_info().
	 */
	public function test_no_nested_plugin_name_headers() {
		$root  = rtrim( SQUIDSEC_SHIELD_DIR, '/\\' );
		$found = array();
		$iter  = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS )
		);
		foreach ( $iter as $file ) {
			if ( ! $file->isFile() || 'php' !== $file->getExtension() ) {
				continue;
			}
			$rel = substr( $file->getPathname(), strlen( $root ) + 1 );
			// Top-level only is allowed.
			if ( false === strpos( $rel, '/' ) && false === strpos( $rel, '\\' ) ) {
				continue;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
			$code = (string) file_get_contents( $file->getPathname() );
			if ( preg_match( '/^\s*\*\s*Plugin Name:/m', $code ) ) {
				$found[] = $rel;
			}
		}
		$this->assertSame( array(), $found, 'Nested Plugin Name headers break Activate: ' . implode( ', ', $found ) );
	}
}
