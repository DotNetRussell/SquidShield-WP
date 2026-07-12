<?php
/**
 * Database schema.
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Database.
 */
class SquidSec_Shield_Database {

	/**
	 * Create or upgrade tables.
	 */
	public static function create_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();

		$logs = $wpdb->prefix . 'squidsec_shield_logs';
		$sql_logs = "CREATE TABLE {$logs} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			event_type VARCHAR(64) NOT NULL,
			severity VARCHAR(16) NOT NULL DEFAULT 'info',
			ip VARCHAR(45) NOT NULL DEFAULT '',
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			username VARCHAR(191) NOT NULL DEFAULT '',
			uri TEXT NULL,
			method VARCHAR(16) NOT NULL DEFAULT '',
			rule_id VARCHAR(64) NOT NULL DEFAULT '',
			cve VARCHAR(32) NOT NULL DEFAULT '',
			message TEXT NULL,
			context LONGTEXT NULL,
			PRIMARY KEY  (id),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY created_at (created_at),
			KEY ip (ip)
		) {$charset};";

		$blocks = $wpdb->prefix . 'squidsec_shield_blocks';
		$sql_blocks = "CREATE TABLE {$blocks} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			ip VARCHAR(45) NOT NULL,
			reason VARCHAR(191) NOT NULL DEFAULT '',
			rule_id VARCHAR(64) NOT NULL DEFAULT '',
			cve VARCHAR(32) NOT NULL DEFAULT '',
			expires_at DATETIME NULL,
			permanent TINYINT(1) NOT NULL DEFAULT 0,
			PRIMARY KEY  (id),
			KEY ip (ip),
			KEY expires_at (expires_at)
		) {$charset};";

		$scans = $wpdb->prefix . 'squidsec_shield_scans';
		$sql_scans = "CREATE TABLE {$scans} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			started_at DATETIME NOT NULL,
			finished_at DATETIME NULL,
			scan_type VARCHAR(32) NOT NULL,
			status VARCHAR(32) NOT NULL DEFAULT 'running',
			files_scanned INT UNSIGNED NOT NULL DEFAULT 0,
			findings_count INT UNSIGNED NOT NULL DEFAULT 0,
			meta LONGTEXT NULL,
			PRIMARY KEY  (id),
			KEY scan_type (scan_type),
			KEY status (status)
		) {$charset};";

		$findings = $wpdb->prefix . 'squidsec_shield_findings';
		$sql_findings = "CREATE TABLE {$findings} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			scan_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			finding_type VARCHAR(64) NOT NULL,
			severity VARCHAR(16) NOT NULL DEFAULT 'medium',
			path TEXT NULL,
			line_no INT UNSIGNED NOT NULL DEFAULT 0,
			signature_id VARCHAR(64) NOT NULL DEFAULT '',
			title VARCHAR(255) NOT NULL DEFAULT '',
			detail LONGTEXT NULL,
			status VARCHAR(32) NOT NULL DEFAULT 'open',
			PRIMARY KEY  (id),
			KEY scan_id (scan_id),
			KEY finding_type (finding_type),
			KEY status (status)
		) {$charset};";

		$fim = $wpdb->prefix . 'squidsec_shield_fim';
		$sql_fim = "CREATE TABLE {$fim} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			path VARCHAR(512) NOT NULL,
			file_hash VARCHAR(64) NOT NULL DEFAULT '',
			file_size BIGINT UNSIGNED NOT NULL DEFAULT 0,
			perms VARCHAR(12) NOT NULL DEFAULT '',
			mtime INT UNSIGNED NOT NULL DEFAULT 0,
			baseline_at DATETIME NOT NULL,
			last_checked DATETIME NULL,
			status VARCHAR(32) NOT NULL DEFAULT 'ok',
			PRIMARY KEY  (id),
			UNIQUE KEY path (path(191)),
			KEY status (status)
		) {$charset};";

		$rules = $wpdb->prefix . 'squidsec_shield_rules_custom';
		$sql_rules = "CREATE TABLE {$rules} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			rule_id VARCHAR(64) NOT NULL,
			name VARCHAR(191) NOT NULL,
			enabled TINYINT(1) NOT NULL DEFAULT 1,
			rule_type VARCHAR(32) NOT NULL DEFAULT 'pattern',
			pattern TEXT NOT NULL,
			targets TEXT NULL,
			action VARCHAR(32) NOT NULL DEFAULT 'block',
			severity VARCHAR(16) NOT NULL DEFAULT 'high',
			cve VARCHAR(32) NOT NULL DEFAULT '',
			sandbox_ok TINYINT(1) NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY rule_id (rule_id)
		) {$charset};";

		$ip_list = $wpdb->prefix . 'squidsec_shield_ip_list';
		$sql_ip = "CREATE TABLE {$ip_list} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			ip VARCHAR(45) NOT NULL,
			list_type VARCHAR(16) NOT NULL DEFAULT 'block',
			reason VARCHAR(255) NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL,
			expires_at DATETIME NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY ip_type (ip, list_type)
		) {$charset};";

		dbDelta( $sql_logs );
		dbDelta( $sql_blocks );
		dbDelta( $sql_scans );
		dbDelta( $sql_findings );
		dbDelta( $sql_fim );
		dbDelta( $sql_rules );
		dbDelta( $sql_ip );
	}

	/**
	 * Upgrade if needed.
	 */
	public static function maybe_upgrade() {
		$ver = get_option( 'squidsec_shield_db_version', '' );
		if ( $ver !== SQUIDSEC_SHIELD_DB_VERSION ) {
			self::create_tables();
			update_option( 'squidsec_shield_db_version', SQUIDSEC_SHIELD_DB_VERSION );
		}
	}

	/**
	 * Table name helper.
	 *
	 * @param string $suffix Suffix without prefix.
	 * @return string
	 */
	public static function table( $suffix ) {
		global $wpdb;
		return $wpdb->prefix . 'squidsec_shield_' . $suffix;
	}
}
