<?php
/**
 * Base test case for SquidShield WP.
 *
 * @package SquidSec_Shield
 */

use PHPUnit\Framework\TestCase as PHPUnit_TestCase;

/**
 * Shared helpers.
 */
abstract class SquidShield_TestCase extends PHPUnit_TestCase {

	/**
	 * Paths created during a test for cleanup.
	 *
	 * @var string[]
	 */
	protected $temp_paths = array();

	/**
	 * Option keys to restore after test.
	 *
	 * @var array<string,mixed>
	 */
	protected $option_backup = array();

	/**
	 * Tear down temp files / options.
	 */
	protected function tearDown(): void {
		foreach ( $this->temp_paths as $path ) {
			if ( is_file( $path ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
				@unlink( $path );
			} elseif ( is_dir( $path ) ) {
				$this->rrmdir( $path );
			}
		}
		$this->temp_paths = array();

		foreach ( $this->option_backup as $key => $value ) {
			if ( null === $value ) {
				delete_option( $key );
			} else {
				update_option( $key, $value, false );
			}
		}
		$this->option_backup = array();

		// Clear WAF rule cache between tests.
		if ( class_exists( 'SquidSec_Shield_Rules_Engine' ) ) {
			SquidSec_Shield_Rules_Engine::flush_cache();
		}

		parent::tearDown();
	}

	/**
	 * Snapshot an option for restore.
	 *
	 * @param string $key Option key.
	 */
	protected function backup_option( $key ) {
		if ( ! array_key_exists( $key, $this->option_backup ) ) {
			$this->option_backup[ $key ] = get_option( $key, null );
		}
	}

	/**
	 * Set plugin settings patch for a test.
	 *
	 * @param array $patch Settings.
	 */
	protected function set_settings( array $patch ) {
		$this->backup_option( SquidSec_Shield_Options::OPTION_KEY );
		SquidSec_Shield_Options::update( $patch );
	}

	/**
	 * Create a temp file under ABSPATH and track for cleanup.
	 *
	 * @param string $rel_path Relative path.
	 * @param string $contents Contents.
	 * @return string Absolute path.
	 */
	protected function create_temp_file( $rel_path, $contents = "test\n" ) {
		$rel  = ltrim( str_replace( array( '..', "\0" ), '', $rel_path ), '/' );
		$full = ABSPATH . $rel;
		$dir  = dirname( $full );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		file_put_contents( $full, $contents );
		$this->temp_paths[] = $full;
		return $full;
	}

	/**
	 * Recursive remove dir.
	 *
	 * @param string $dir Directory.
	 */
	protected function rrmdir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$items = scandir( $dir );
		if ( ! $items ) {
			return;
		}
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}
			$path = $dir . '/' . $item;
			if ( is_dir( $path ) ) {
				$this->rrmdir( $path );
			} else {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
				@unlink( $path );
			}
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
		@rmdir( $dir );
	}

	/**
	 * Assert path is under ABSPATH.
	 *
	 * @param string $path Path.
	 */
	protected function assertUnderAbspath( $path ) {
		$root = realpath( ABSPATH );
		$real = realpath( $path );
		$this->assertNotFalse( $root );
		if ( $real ) {
			$this->assertStringStartsWith( $root, $real );
		}
	}
}
