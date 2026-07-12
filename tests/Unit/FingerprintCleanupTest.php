<?php
/**
 * Readme/license fingerprint cleanup tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Fingerprint_Cleanup
 */
class FingerprintCleanupTest extends SquidShield_TestCase {

	protected function setUp(): void {
		parent::setUp();
		$this->set_settings(
			array(
				'enabled'               => true,
				'remove_readme_license' => true,
			)
		);
	}

	public function test_target_basenames_include_readme_and_license() {
		$t = SquidSec_Shield_Fingerprint_Cleanup::target_basenames();
		$this->assertContains( 'readme.txt', $t );
		$this->assertContains( 'readme.html', $t );
		$this->assertContains( 'license.txt', $t );
	}

	public function test_cleanup_directory_removes_readme() {
		$dir = WP_CONTENT_DIR . '/sss-fp-test-' . wp_generate_password( 5, false );
		wp_mkdir_p( $dir );
		$this->temp_paths[] = $dir;
		$readme             = $dir . '/readme.txt';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $readme, "Stable tag: 1.2.3\n" );
		$keep = $dir . '/plugin.php';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $keep, "<?php\n// keep\n" );
		$this->temp_paths[] = $keep;

		$removed = SquidSec_Shield_Fingerprint_Cleanup::cleanup_directory( $dir, false );
		$this->assertNotEmpty( $removed );
		$this->assertFileDoesNotExist( $readme );
		$this->assertFileExists( $keep );
	}

	public function test_cleanup_does_not_delete_php() {
		$dir = WP_CONTENT_DIR . '/sss-fp-php-' . wp_generate_password( 5, false );
		wp_mkdir_p( $dir );
		$this->temp_paths[] = $dir;
		// Even if named oddly — only exact basenames without php.
		$php = $dir . '/index.php';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $php, "<?php\n" );
		$this->temp_paths[] = $php;
		SquidSec_Shield_Fingerprint_Cleanup::cleanup_directory( $dir, false );
		$this->assertFileExists( $php );
	}

	public function test_disabled_option_skips_cleanup_all() {
		$this->set_settings( array( 'remove_readme_license' => false ) );
		$dir = WP_CONTENT_DIR . '/sss-fp-off-' . wp_generate_password( 5, false );
		wp_mkdir_p( $dir );
		$this->temp_paths[] = $dir;
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $dir . '/readme.txt', 'x' );
		$removed = SquidSec_Shield_Fingerprint_Cleanup::cleanup_all( false );
		// File may still exist because cleanup_all returns early.
		$this->assertSame( array(), $removed );
		$this->assertFileExists( $dir . '/readme.txt' );
	}

	public function test_on_plugin_event_cleans_plugin_dir() {
		// Plant inside an existing plugin folder if possible.
		$plugin_dir = WP_PLUGIN_DIR . '/squidsec-traffic';
		if ( ! is_dir( $plugin_dir ) ) {
			$this->markTestSkipped( 'squidsec-traffic not installed' );
		}
		$path = $plugin_dir . '/readme.txt';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $path, "Stable tag: 0.0.1\n" );
		$this->temp_paths[] = $path;
		SquidSec_Shield_Fingerprint_Cleanup::on_plugin_event( 'squidsec-traffic/squidsec-traffic.php' );
		$this->assertFileDoesNotExist( $path );
	}
}
