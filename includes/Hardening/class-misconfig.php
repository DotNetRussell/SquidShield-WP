<?php
/**
 * Misconfiguration / interesting findings scanner.
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
 * Misconfig scanner.
 */
class SquidSec_Shield_Misconfig {

	/**
	 * Init.
	 */
	public static function init() {}

	/**
	 * Run scan.
	 *
	 * @param bool $silent Silent.
	 * @return array
	 */
	public static function run_scan( $silent = false ) {
		$findings = array();
		$uploads  = wp_upload_dir();

		// Debug log exposure.
		$debug_log = WP_CONTENT_DIR . '/debug.log';
		if ( file_exists( $debug_log ) ) {
			$findings[] = self::item(
				'debug_log',
				'high',
				'debug.log exists',
				'Delete wp-content/debug.log or disable WP_DEBUG_LOG on production.',
				'wp-content/debug.log',
				true,
				'delete_file'
			);
		}

		// readme.html.
		if ( file_exists( ABSPATH . 'readme.html' ) ) {
			$findings[] = self::item(
				'readme_html',
				'low',
				'readme.html present',
				'Delete readme.html to reduce version fingerprinting.',
				'readme.html',
				true,
				'delete_file'
			);
		}

		// license.txt.
		if ( file_exists( ABSPATH . 'license.txt' ) ) {
			$findings[] = self::item(
				'license_txt',
				'info',
				'license.txt present',
				'Optional: remove for minor fingerprint reduction.',
				'license.txt',
				true,
				'delete_file'
			);
		}

		// User registration.
		if ( get_option( 'users_can_register' ) ) {
			$findings[] = self::item(
				'registration',
				'medium',
				'Open registration',
				'Disable public membership if you do not need signups (WooCommerce stores may need this on).',
				'',
				true,
				'disable_registration'
			);
		}

		// File editor.
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			// If Shield hardening option is already on, runtime define may apply next load.
			if ( ! SquidSec_Shield_Options::get( 'hardening_file_editor' ) ) {
				$findings[] = self::item(
					'file_editor',
					'medium',
					'Theme/plugin file editor enabled',
					'Turn on Shield’s “disable file editor” hardening so themes/plugins cannot be edited from wp-admin.',
					'',
					true,
					'enable_file_editor_block'
				);
			}
		}

		// WP Cron.
		if ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) {
			$findings[] = self::item(
				'wp_cron',
				'info',
				'DISABLE_WP_CRON is true',
				'Ensure a real system cron hits wp-cron.php. Cannot be changed from this UI (server/wp-config).',
				'',
				false,
				''
			);
		}

		// Directory listing check (uploads index).
		if ( ! empty( $uploads['basedir'] ) ) {
			$idx = $uploads['basedir'] . '/index.php';
			if ( ! file_exists( $idx ) && ! file_exists( $uploads['basedir'] . '/index.html' ) ) {
				$findings[] = self::item(
					'uploads_index',
					'medium',
					'Uploads directory may allow listing',
					'Create index.php in uploads and block PHP execution.',
					'',
					true,
					'create_uploads_index'
				);
			}
		}

		// Timthumb legacy.
		$timthumb_hits = self::find_named( 'timthumb.php' );
		foreach ( $timthumb_hits as $hit ) {
			$findings[] = self::item(
				'timthumb',
				'critical',
				'Legacy TimThumb found',
				'Delete this unsafe legacy script immediately.',
				$hit,
				true,
				'delete_file'
			);
		}

		// Exposed sql dumps.
		foreach ( array( ABSPATH, WP_CONTENT_DIR, $uploads['basedir'] ?? '' ) as $dir ) {
			if ( ! $dir || ! is_dir( $dir ) ) {
				continue;
			}
			$candidates = array_merge(
				glob( $dir . '/*.sql' ) ?: array(),
				glob( $dir . '/*.sql.gz' ) ?: array()
			);
			foreach ( $candidates as $dump ) {
				$rel = ltrim( str_replace( ABSPATH, '', $dump ), '/' );
				$findings[] = self::item(
					'db_dump',
					'critical',
					'Possible database dump on disk',
					'Delete publicly accessible dump from the web root.',
					$rel,
					true,
					'delete_file'
				);
			}
		}

		// Full path disclosure via wp-config sample.
		if ( file_exists( ABSPATH . 'wp-config-sample.php' ) ) {
			$findings[] = self::item(
				'config_sample',
				'low',
				'wp-config-sample.php present',
				'Safe to delete on production.',
				'wp-config-sample.php',
				true,
				'delete_file'
			);
		}

		// Admin user named admin.
		$admin = get_user_by( 'login', 'admin' );
		if ( $admin ) {
			$findings[] = self::item(
				'admin_username',
				'medium',
				'User "admin" exists',
				'Rename this user from Users → All Users (not automated to avoid lockouts).',
				'',
				false,
				''
			);
		}

		update_option( 'squidsec_shield_misconfig_cache', array( 'time' => time(), 'findings' => $findings ), false );
		if ( ! $silent ) {
			SquidSec_Shield_Audit_Log::write( 'misconfig_scan', 'info', 'Misconfiguration scan: ' . count( $findings ) . ' finding(s)' );
		}
		return $findings;
	}

	/**
	 * Item helper.
	 *
	 * @param string $id         ID.
	 * @param string $sev        Severity.
	 * @param string $title      Title.
	 * @param string $fix        Fix description.
	 * @param string $path       Optional path.
	 * @param bool   $remediable Can fix from UI.
	 * @param string $action     Action key.
	 * @return array
	 */
	private static function item( $id, $sev, $title, $fix, $path = '', $remediable = false, $action = '' ) {
		return array(
			'id'         => $id,
			'severity'   => $sev,
			'title'      => $title,
			'fix'        => $fix,
			'path'       => $path,
			'remediable' => (bool) $remediable,
			'action'     => $action,
		);
	}

	/**
	 * Find files by name under wp-content.
	 *
	 * @param string $name Filename.
	 * @return array
	 */
	private static function find_named( $name ) {
		$hits = array();
		$root = WP_CONTENT_DIR;
		if ( ! is_dir( $root ) ) {
			return $hits;
		}
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			$n = 0;
			foreach ( $it as $file ) {
				if ( ++$n > 8000 ) {
					break;
				}
				if ( $file->isFile() && strtolower( $file->getFilename() ) === strtolower( $name ) ) {
					$hits[] = ltrim( str_replace( ABSPATH, '', $file->getPathname() ), '/' );
				}
			}
		} catch ( Exception $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch
			// ignore.
		}
		return $hits;
	}
}
