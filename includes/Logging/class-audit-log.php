<?php
/**
 * Audit logging.
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Audit log.
 */
class SquidSec_Shield_Audit_Log {

	/**
	 * Init hooks for WP events.
	 */
	public static function init() {
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_login_failed' ) );
		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin_toggle' ), 10, 1 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_toggle' ), 10, 1 );
		add_action( 'switch_theme', array( __CLASS__, 'on_theme_switch' ), 10, 1 );
		add_action( 'user_register', array( __CLASS__, 'on_user_register' ) );
		add_action( 'delete_user', array( __CLASS__, 'on_user_delete' ) );
		add_action( 'updated_option', array( __CLASS__, 'on_option_update' ), 10, 1 );
	}

	/**
	 * Write a log row.
	 *
	 * @param string $event_type Type.
	 * @param string $severity   Severity.
	 * @param string $message    Message.
	 * @param array  $context    Context.
	 * @param string $rule_id    Rule.
	 * @param string $cve        CVE.
	 * @return int Insert ID.
	 */
	public static function write( $event_type, $severity, $message, array $context = array(), $rule_id = '', $cve = '' ) {
		global $wpdb;
		$table = SquidSec_Shield_Database::table( 'logs' );
		$uid   = function_exists( 'get_current_user_id' ) ? (int) get_current_user_id() : 0;
		$user  = '';
		if ( $uid && function_exists( 'wp_get_current_user' ) ) {
			$u = wp_get_current_user();
			$user = $u->user_login ?? '';
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$table,
			array(
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
				'event_type' => substr( (string) $event_type, 0, 64 ),
				'severity'   => substr( (string) $severity, 0, 16 ),
				'ip'         => SquidSec_Shield_IP::client(),
				'user_id'    => $uid,
				'username'   => substr( $user, 0, 191 ),
				'uri'        => substr( SquidSec_Shield_Helpers::request_uri(), 0, 2000 ),
				'method'     => SquidSec_Shield_Helpers::request_method(),
				'rule_id'    => substr( (string) $rule_id, 0, 64 ),
				'cve'        => substr( (string) $cve, 0, 32 ),
				'message'    => $message,
				'context'    => wp_json_encode( $context ),
			),
			array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
		$id = (int) $wpdb->insert_id;

		// Fire alerts for high severity.
		if ( in_array( strtolower( $severity ), array( 'critical', 'high' ), true ) ) {
			do_action( 'squidsec_shield_security_event', $event_type, $severity, $message, $context );
		}
		return $id;
	}

	/**
	 * Query logs.
	 *
	 * @param array $args Args.
	 * @return array
	 */
	public static function query( array $args = array() ) {
		global $wpdb;
		$table  = SquidSec_Shield_Database::table( 'logs' );
		$limit  = isset( $args['limit'] ) ? max( 1, min( 500, (int) $args['limit'] ) ) : 50;
		$offset = isset( $args['offset'] ) ? max( 0, (int) $args['offset'] ) : 0;
		$where  = array( '1=1' );
		$params = array();

		if ( ! empty( $args['event_type'] ) ) {
			$where[]  = 'event_type = %s';
			$params[] = $args['event_type'];
		}
		if ( ! empty( $args['severity'] ) ) {
			$where[]  = 'severity = %s';
			$params[] = $args['severity'];
		}
		if ( ! empty( $args['ip'] ) ) {
			$where[]  = 'ip = %s';
			$params[] = $args['ip'];
		}
		if ( ! empty( $args['search'] ) ) {
			$where[]  = '(message LIKE %s OR uri LIKE %s OR rule_id LIKE %s OR cve LIKE %s)';
			$like     = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
			$params[] = $like;
		}

		$sql = "SELECT * FROM {$table} WHERE " . implode( ' AND ', $where ) . ' ORDER BY id DESC LIMIT %d OFFSET %d';
		$params[] = $limit;
		$params[] = $offset;
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		return $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );
	}

	/**
	 * Export logs.
	 *
	 * @param string $format csv|json.
	 * @param int    $limit  Limit.
	 * @return string
	 */
	public static function export( $format = 'json', $limit = 1000 ) {
		$rows = self::query( array( 'limit' => $limit ) );
		if ( 'csv' === $format ) {
			$out = fopen( 'php://temp', 'r+' );
			if ( $rows ) {
				fputcsv( $out, array_keys( $rows[0] ) );
				foreach ( $rows as $row ) {
					fputcsv( $out, $row );
				}
			}
			rewind( $out );
			$csv = stream_get_contents( $out );
			fclose( $out );
			return (string) $csv;
		}
		return wp_json_encode( $rows );
	}

	/**
	 * Purge old logs.
	 */
	public static function purge_old() {
		global $wpdb;
		$days  = max( 7, (int) SquidSec_Shield_Options::get( 'log_retention_days', 90 ) );
		$table = SquidSec_Shield_Database::table( 'logs' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
				$days
			)
		);
	}

	/**
	 * Recent counts by severity.
	 *
	 * @param int $hours Hours.
	 * @return array
	 */
	public static function recent_counts( $hours = 24 ) {
		global $wpdb;
		$table = SquidSec_Shield_Database::table( 'logs' );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) AS c FROM {$table} WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d HOUR) GROUP BY severity",
				$hours
			),
			ARRAY_A
		);
		$out = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 );
		if ( $rows ) {
			foreach ( $rows as $r ) {
				$s = strtolower( $r['severity'] );
				if ( isset( $out[ $s ] ) ) {
					$out[ $s ] = (int) $r['c'];
				}
			}
		}
		return $out;
	}

	/** @param string $user_login Login. @param WP_User $user User. */
	public static function on_login( $user_login, $user ) {
		self::write( 'login_success', 'info', 'Successful login: ' . $user_login, array( 'user_id' => $user->ID ?? 0 ) );
	}

	/** @param string $username Username. */
	public static function on_login_failed( $username ) {
		self::write( 'login_failed', 'medium', 'Failed login for: ' . sanitize_user( (string) $username ), array( 'username' => $username ) );
	}

	/** @param string $plugin Plugin. */
	public static function on_plugin_toggle( $plugin ) {
		self::write( 'plugin_change', 'info', 'Plugin activated/deactivated: ' . $plugin, array( 'plugin' => $plugin ) );
	}

	/** @param string $theme Theme. */
	public static function on_theme_switch( $theme ) {
		self::write( 'theme_switch', 'info', 'Theme switched: ' . $theme, array( 'theme' => $theme ) );
	}

	/** @param int $user_id ID. */
	public static function on_user_register( $user_id ) {
		self::write( 'user_register', 'info', 'User registered: ' . (int) $user_id );
	}

	/** @param int $user_id ID. */
	public static function on_user_delete( $user_id ) {
		self::write( 'user_delete', 'medium', 'User deleted: ' . (int) $user_id );
	}

	/** @param string $option Option. */
	public static function on_option_update( $option ) {
		$watch = array( 'users_can_register', 'default_role', 'siteurl', 'home', 'admin_email', 'active_plugins', 'template', 'stylesheet' );
		if ( in_array( $option, $watch, true ) ) {
			self::write( 'option_update', 'low', 'Watched option updated: ' . $option, array( 'option' => $option ) );
		}
	}
}
