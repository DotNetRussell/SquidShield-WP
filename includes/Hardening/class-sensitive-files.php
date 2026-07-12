<?php
/**
 * Sensitive file exposure detection & protection.
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
 * Sensitive files.
 */
class SquidSec_Shield_Sensitive_Files {

	/**
	 * Patterns of sensitive files relative to ABSPATH.
	 *
	 * @return array
	 */
	public static function patterns() {
		return array(
			'wp-config.php.bak',
			'wp-config.php.old',
			'wp-config.php.save',
			'wp-config.php~',
			'wp-config.txt',
			'wp-config.php.bak.harden',
			'wp-config.php.bak.harden2',
			'wp-config.prod.php.bak',
			'.env',
			'debug.log',
			'wp-content/debug.log',
			'readme.html',
			'error_log',
			'wp-content/error_log',
			'wp-content/uploads/dump.sql',
			'backup.sql',
			'database.sql',
			'wp-config-sample.php',
			'license.txt',
		);
	}

	/**
	 * Init — block known sensitive paths via WP when requested.
	 */
	public static function init() {
		if ( ! SquidSec_Shield_Options::get( 'sensitive_file_protect' ) ) {
			return;
		}
		add_action( 'init', array( __CLASS__, 'block_request' ), 0 );
	}

	/**
	 * Block direct requests to sensitive files when served through WP.
	 */
	public static function block_request() {
		$uri  = SquidSec_Shield_Helpers::request_uri();
		$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
		$base = basename( $path );
		$deny = array(
			'wp-config.php',
			'wp-config.php.bak',
			'debug.log',
			'.env',
			'error_log',
			'phpinfo.php',
		);
		foreach ( $deny as $d ) {
			if ( strcasecmp( $base, $d ) === 0 || false !== stripos( $path, '/' . $d ) ) {
				if ( false !== stripos( $path, 'wp-config' ) || false !== stripos( $path, 'debug.log' ) || false !== stripos( $path, '.env' ) ) {
					SquidSec_Shield_Audit_Log::write( 'sensitive_access', 'high', 'Blocked sensitive path: ' . $path );
					if ( ! SquidSec_Shield_Options::is_pentest() ) {
						status_header( 403 );
						exit( 'Forbidden' );
					}
				}
			}
		}
	}

	/**
	 * Risk level for a path.
	 *
	 * @param string $rel Relative path.
	 * @return string
	 */
	public static function risk_for( $rel ) {
		$base = basename( $rel );
		if ( preg_match( '/wp-config/i', $base ) && 'wp-config.php' !== $base ) {
			return 'critical';
		}
		if ( in_array( $base, array( '.env', 'debug.log', 'error_log' ), true ) || preg_match( '/\.(sql|sql\.gz)$/i', $base ) ) {
			return 'critical';
		}
		if ( in_array( $base, array( 'readme.html', 'license.txt', 'wp-config-sample.php' ), true ) ) {
			return 'low';
		}
		return 'high';
	}

	/**
	 * Advice text.
	 *
	 * @param string $risk Risk.
	 * @return string
	 */
	public static function advice_for( $risk ) {
		if ( 'critical' === $risk ) {
			return 'Delete from the web root immediately (or quarantine). Live wp-config.php is never removed.';
		}
		if ( 'low' === $risk ) {
			return 'Safe to delete to reduce fingerprinting.';
		}
		return 'Remove from the web root or restrict with server rules.';
	}

	/**
	 * Scan for exposures (deduplicated).
	 *
	 * @param bool $silent Silent.
	 * @return array
	 */
	public static function scan( $silent = false ) {
		$found = array();
		$seen  = array();

		$add = static function ( $full ) use ( &$found, &$seen ) {
			if ( ! is_string( $full ) || ! file_exists( $full ) || ! is_file( $full ) ) {
				return;
			}
			$rel = ltrim( str_replace( '\\', '/', str_replace( ABSPATH, '', $full ) ), '/' );
			if ( isset( $seen[ $rel ] ) ) {
				return;
			}
			// Never list live wp-config.php as a "delete me" finding.
			if ( 'wp-config.php' === $rel ) {
				return;
			}
			$seen[ $rel ] = true;
			$risk         = self::risk_for( $rel );
			$found[]      = array(
				'path'       => $rel,
				'risk'       => $risk,
				'advice'     => self::advice_for( $risk ),
				'remediable' => SquidSec_Shield_Remediation::is_remediable_sensitive_file( $rel ),
				'size'       => (int) filesize( $full ),
			);
		};

		foreach ( self::patterns() as $rel ) {
			$add( ABSPATH . $rel );
			$add( WP_CONTENT_DIR . '/' . basename( $rel ) );
		}

		foreach ( glob( ABSPATH . 'wp-config*' ) ?: array() as $f ) {
			$base = basename( $f );
			if ( 'wp-config.php' === $base ) {
				continue;
			}
			$add( $f );
		}

		// Common dumps.
		foreach ( array( ABSPATH, WP_CONTENT_DIR ) as $dir ) {
			foreach ( array_merge( glob( $dir . '/*.sql' ) ?: array(), glob( $dir . '/*.sql.gz' ) ?: array() ) as $f ) {
				$add( $f );
			}
		}

		// Sort critical first.
		usort(
			$found,
			static function ( $a, $b ) {
				$rank = array( 'critical' => 3, 'high' => 2, 'medium' => 1, 'low' => 0, 'info' => 0 );
				return ( $rank[ $b['risk'] ] ?? 0 ) <=> ( $rank[ $a['risk'] ] ?? 0 );
			}
		);

		update_option( 'squidsec_shield_sensitive_cache', array( 'time' => time(), 'files' => $found ), false );
		update_option( 'squidsec_shield_server_rules_suggest', self::suggested_server_rules(), false );

		if ( ! $silent && $found ) {
			SquidSec_Shield_Audit_Log::write( 'sensitive_scan', 'high', 'Sensitive files detected: ' . count( $found ), array( 'count' => count( $found ) ) );
		}
		return $found;
	}

	/**
	 * Suggested Apache/Nginx rules.
	 *
	 * @return array
	 */
	public static function suggested_server_rules() {
		$apache = <<<'HTACCESS'
# SquidSec Shield — deny sensitive files
<FilesMatch "(^\.env|wp-config\.php|\.sql$|debug\.log|error_log)$">
  Require all denied
</FilesMatch>
# Deny backup variants
<FilesMatch "wp-config.*\.(bak|old|save|swp|txt)$">
  Require all denied
</FilesMatch>
Options -Indexes
HTACCESS;
		$nginx = <<<'NGINX'
# SquidSec Shield — deny sensitive files
location ~* /(wp-config\.php|\.env|debug\.log|error_log)$ { deny all; }
location ~* /wp-config.*\.(bak|old|save|txt)$ { deny all; }
location ~* \.(sql|sql\.gz)$ { deny all; }
autoindex off;
NGINX;
		return array(
			'apache' => $apache,
			'nginx'  => $nginx,
		);
	}

	/**
	 * Best-effort write deny rules to uploads .htaccess.
	 *
	 * @return true|WP_Error
	 */
	public static function apply_uploads_htaccess() {
		$uploads = wp_upload_dir();
		if ( empty( $uploads['basedir'] ) ) {
			return new WP_Error( 'no_uploads', 'Uploads dir missing' );
		}
		$path  = $uploads['basedir'] . '/.htaccess';
		$rules = "# SquidSec Shield\n<FilesMatch \"\\.(php|phtml|php5|phar)$\">\n  Require all denied\n</FilesMatch>\nOptions -Indexes\n";
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
		if ( false === file_put_contents( $path, $rules ) ) {
			return new WP_Error( 'write_failed', 'Could not write .htaccess' );
		}
		$idx = $uploads['basedir'] . '/index.php';
		if ( ! file_exists( $idx ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents
			file_put_contents( $idx, "<?php\n// Silence is golden.\n" );
		}
		SquidSec_Shield_Audit_Log::write( 'sensitive_protect_apply', 'info', 'Applied uploads .htaccess protection' );
		return true;
	}
}
