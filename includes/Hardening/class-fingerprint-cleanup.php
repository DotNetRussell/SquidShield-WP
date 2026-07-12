<?php
/**
 * Remove version-leaking readme / license files.
 *
 * Runs on SquidShield install/setup and after plugin, theme, or core updates.
 *
 * @package SquidSec_Shield
 * @author            SquidSec
 * @copyright         2026 SquidSec
 * @license           GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Fingerprint cleanup.
 */
class SquidSec_Shield_Fingerprint_Cleanup {

	/**
	 * Basenames (lowercase) that are safe to remove from web-accessible trees.
	 *
	 * @return string[]
	 */
	public static function target_basenames() {
		return array(
			'readme.html',
			'readme.htm',
			'readme.txt',
			'readme.md',
			'readme',
			'license.txt',
			'license.md',
			'license',
			'licence.txt',
			'licence.md',
			'licence',
			'copying',
			'copying.txt',
			// Also common version banners; harmless if missing.
			'changelog.txt',
			'changelog.md',
			'changes.txt',
		);
	}

	/**
	 * Init hooks.
	 */
	public static function init() {
		if ( ! SquidSec_Shield_Options::get( 'remove_readme_license', true ) ) {
			return;
		}
		// After any upgrade (plugin / theme / core / translation).
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrade' ), 20, 2 );
		// New plugin drops files on install/activate.
		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin_event' ), 20, 1 );
		// Theme switch can pull a theme with readmes.
		add_action( 'after_switch_theme', array( __CLASS__, 'cleanup_all' ), 20 );
	}

	/**
	 * Feature enabled?
	 *
	 * @return bool
	 */
	public static function is_enabled() {
		return (bool) SquidSec_Shield_Options::get( 'enabled', true )
			&& (bool) SquidSec_Shield_Options::get( 'remove_readme_license', true );
	}

	/**
	 * After WP upgrader finishes.
	 *
	 * @param WP_Upgrader $upgrader Upgrader.
	 * @param array       $options  Options.
	 */
	public static function on_upgrade( $upgrader, $options ) {
		if ( ! self::is_enabled() ) {
			return;
		}
		$type = $options['type'] ?? '';
		if ( 'plugin' === $type ) {
			$plugins = array();
			if ( ! empty( $options['plugins'] ) && is_array( $options['plugins'] ) ) {
				$plugins = $options['plugins'];
			} elseif ( ! empty( $options['plugin'] ) ) {
				$plugins = array( $options['plugin'] );
			}
			foreach ( $plugins as $plugin_file ) {
				$dir = WP_PLUGIN_DIR . '/' . dirname( $plugin_file );
				if ( '.' === dirname( $plugin_file ) ) {
					// Single-file plugin — clean next to it.
					self::cleanup_directory( WP_PLUGIN_DIR, false );
				} else {
					self::cleanup_directory( $dir, false );
				}
			}
			// Always scrub root leak files too.
			self::cleanup_wordpress_root();
			return;
		}
		if ( 'theme' === $type ) {
			$themes = array();
			if ( ! empty( $options['themes'] ) && is_array( $options['themes'] ) ) {
				$themes = $options['themes'];
			} elseif ( ! empty( $options['theme'] ) ) {
				$themes = array( $options['theme'] );
			}
			foreach ( $themes as $slug ) {
				$theme = wp_get_theme( $slug );
				if ( $theme->exists() ) {
					self::cleanup_directory( $theme->get_stylesheet_directory(), false );
				}
			}
			self::cleanup_wordpress_root();
			return;
		}
		if ( 'core' === $type ) {
			self::cleanup_all();
			return;
		}
		// Unknown / bulk — full sweep is fine and cheap (top-level only).
		self::cleanup_all();
	}

	/**
	 * After a plugin is activated (covers installs).
	 *
	 * @param string $plugin Plugin basename.
	 */
	public static function on_plugin_event( $plugin ) {
		if ( ! self::is_enabled() || ! is_string( $plugin ) || $plugin === '' ) {
			return;
		}
		$dir = WP_PLUGIN_DIR . '/' . dirname( $plugin );
		if ( '.' === dirname( $plugin ) ) {
			self::cleanup_directory( WP_PLUGIN_DIR, false );
		} else {
			self::cleanup_directory( $dir, false );
		}
		self::cleanup_wordpress_root();
	}

	/**
	 * Full site cleanup (root + all plugins + all themes + mu-plugins).
	 *
	 * @param bool $log Whether to write an audit log when something is removed.
	 * @return array Removed relative paths.
	 */
	public static function cleanup_all( $log = true ) {
		if ( ! SquidSec_Shield_Options::get( 'remove_readme_license', true ) ) {
			return array();
		}
		// Master kill-switch (still allow during setup when protection is on by default).
		if ( ! SquidSec_Shield_Options::get( 'enabled', true ) ) {
			return array();
		}

		$removed = array();
		$removed = array_merge( $removed, self::cleanup_wordpress_root() );

		if ( defined( 'WP_PLUGIN_DIR' ) && is_dir( WP_PLUGIN_DIR ) ) {
			// Each plugin folder.
			foreach ( glob( WP_PLUGIN_DIR . '/*', GLOB_ONLYDIR ) ?: array() as $dir ) {
				$removed = array_merge( $removed, self::cleanup_directory( $dir, false ) );
			}
			// Single-file plugins living in plugins root.
			$removed = array_merge( $removed, self::cleanup_directory( WP_PLUGIN_DIR, false ) );
		}

		if ( defined( 'WPMU_PLUGIN_DIR' ) && is_dir( WPMU_PLUGIN_DIR ) ) {
			$removed = array_merge( $removed, self::cleanup_directory( WPMU_PLUGIN_DIR, false ) );
		}

		$themes_root = get_theme_root();
		if ( $themes_root && is_dir( $themes_root ) ) {
			foreach ( glob( $themes_root . '/*', GLOB_ONLYDIR ) ?: array() as $dir ) {
				$removed = array_merge( $removed, self::cleanup_directory( $dir, false ) );
			}
		}

		$removed = array_values( array_unique( $removed ) );

		if ( $log && $removed ) {
			SquidSec_Shield_Audit_Log::write(
				'fingerprint_cleanup',
				'info',
				sprintf( 'Removed %d readme/license file(s) that leak version info.', count( $removed ) ),
				array( 'files' => array_slice( $removed, 0, 50 ) )
			);
		}

		return $removed;
	}

	/**
	 * WordPress core root leak files.
	 *
	 * @return array
	 */
	public static function cleanup_wordpress_root() {
		return self::cleanup_directory( untrailingslashit( ABSPATH ), false );
	}

	/**
	 * Remove target files in a single directory (non-recursive).
	 *
	 * @param string $dir   Directory.
	 * @param bool   $log   Log each (usually false; batch logs).
	 * @return array Relative paths removed.
	 */
	public static function cleanup_directory( $dir, $log = false ) {
		$removed = array();
		$dir     = rtrim( str_replace( '\\', '/', (string) $dir ), '/' );
		if ( $dir === '' || ! is_dir( $dir ) ) {
			return $removed;
		}

		// Never operate outside the WordPress root.
		$root = rtrim( str_replace( '\\', '/', untrailingslashit( ABSPATH ) ), '/' );
		if ( 0 !== strpos( $dir . '/', $root . '/' ) && $dir !== $root ) {
			return $removed;
		}

		// Never touch uploads.
		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['basedir'] ) ) {
			$up = rtrim( str_replace( '\\', '/', $uploads['basedir'] ), '/' );
			if ( 0 === strpos( $dir . '/', $up . '/' ) || $dir === $up ) {
				return $removed;
			}
		}

		$targets = self::target_basenames();
		$entries = @scandir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( ! is_array( $entries ) ) {
			return $removed;
		}

		foreach ( $entries as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$base_l = strtolower( $name );
			if ( ! in_array( $base_l, $targets, true ) ) {
				continue;
			}
			$path = $dir . '/' . $name;
			if ( ! is_file( $path ) || is_link( $path ) ) {
				continue;
			}
			// Absolute safety: never delete PHP or config.
			if ( preg_match( '/\.(php|phtml|ini)$/i', $name ) ) {
				continue;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
			if ( @unlink( $path ) ) {
				$rel       = ltrim( str_replace( $root . '/', '', $path ), '/' );
				$removed[] = $rel;
				if ( $log ) {
					SquidSec_Shield_Audit_Log::write( 'fingerprint_cleanup', 'info', 'Removed leak file: ' . $rel );
				}
			}
		}

		return $removed;
	}
}
