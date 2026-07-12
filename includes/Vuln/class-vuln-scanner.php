<?php
/**
 * Vulnerability scanner against community/local DB + WordPress.org signals.
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
 * Vulnerability scanner.
 */
class SquidSec_Shield_Vuln_Scanner {

	/**
	 * Init.
	 */
	public static function init() {
		// Cron via Cron class.
	}

	/**
	 * Load vulnerability database.
	 *
	 * @return array
	 */
	public static function load_db() {
		$file = SQUIDSEC_SHIELD_DIR . 'data/vuln-db.json';
		if ( ! file_exists( $file ) ) {
			return array( 'vulnerabilities' => array() );
		}
		$data = json_decode( (string) file_get_contents( $file ), true );
		return is_array( $data ) ? $data : array( 'vulnerabilities' => array() );
	}

	/**
	 * Run scan.
	 *
	 * @param bool $silent Silent.
	 * @return array Results.
	 */
	public static function run_scan( $silent = false ) {
		$db     = self::load_db();
		$vulns  = $db['vulnerabilities'] ?? array();
		$hits   = array();
		$core   = get_bloginfo( 'version' );

		foreach ( $vulns as $v ) {
			$comp = $v['component'] ?? '';
			$type = $v['type'] ?? 'plugin'; // plugin|theme|core
			$affected = $v['affected'] ?? '*';
			$installed = null;
			$slug = $v['slug'] ?? '';

			if ( 'core' === $type ) {
				$installed = $core;
			} elseif ( 'plugin' === $type ) {
				$versions = SquidSec_Shield_Helpers::active_plugin_versions();
				// Also check inactive installed.
				if ( ! function_exists( 'get_plugins' ) ) {
					require_once ABSPATH . 'wp-admin/includes/plugin.php';
				}
				$all = get_plugins();
				foreach ( $all as $file => $data ) {
					$s = dirname( $file );
					if ( '.' === $s ) {
						$s = basename( $file, '.php' );
					}
					if ( $s === $slug ) {
						$installed = $data['Version'] ?? '';
						break;
					}
				}
			} elseif ( 'theme' === $type ) {
				$theme = wp_get_theme( $slug );
				if ( $theme->exists() ) {
					$installed = $theme->get( 'Version' );
				}
			}

			if ( null === $installed || $installed === '' ) {
				continue;
			}
			if ( SquidSec_Shield_Helpers::version_matches( $installed, $affected ) ) {
				$score = self::risk_score( $v );
				$hits[] = array(
					'id'          => $v['id'] ?? '',
					'cve'         => $v['cve'] ?? '',
					'title'       => $v['title'] ?? $comp,
					'slug'        => $slug,
					'type'        => $type,
					'installed'   => $installed,
					'affected'    => $affected,
					'severity'    => $v['severity'] ?? 'medium',
					'score'       => $score,
					'fixed_in'    => $v['fixed_in'] ?? '',
					'description' => $v['description'] ?? '',
					'exploitability' => $v['exploitability'] ?? 'unknown',
					'recommendation' => $v['recommendation'] ?? 'Update to a patched version when available. Virtual patches may already mitigate exploitation.',
				);
			}
		}

		// Supply-chain / abandoned signals for plugins.
		$risks = SquidSec_Shield_Plugin_Risk::score_all();
		foreach ( $risks as $r ) {
			if ( ( $r['score'] ?? 0 ) >= 70 ) {
				$hits[] = array(
					'id'       => 'risk-' . $r['slug'],
					'cve'      => '',
					'title'    => 'High plugin risk: ' . $r['name'],
					'slug'     => $r['slug'],
					'type'     => 'plugin',
					'installed'=> $r['version'],
					'affected' => '*',
					'severity' => 'medium',
					'score'    => $r['score'],
					'fixed_in' => '',
					'description' => implode( '; ', $r['signals'] ),
					'exploitability' => 'n/a',
					'recommendation' => $r['recommendation'],
				);
			}
		}

		usort(
			$hits,
			static function ( $a, $b ) {
				return ( $b['score'] ?? 0 ) <=> ( $a['score'] ?? 0 );
			}
		);

		update_option( 'squidsec_shield_vuln_cache', array( 'time' => time(), 'results' => $hits ), false );

		if ( ! $silent ) {
			SquidSec_Shield_Audit_Log::write( 'vuln_scan', count( $hits ) ? 'medium' : 'info', 'Vulnerability scan found ' . count( $hits ) . ' issue(s)' );
		}
		return $hits;
	}

	/**
	 * Risk score 0-100.
	 *
	 * @param array $v Vuln entry.
	 * @return int
	 */
	public static function risk_score( array $v ) {
		$base = array(
			'critical' => 95,
			'high'     => 80,
			'medium'   => 55,
			'low'      => 30,
			'info'     => 10,
		);
		$score = $base[ strtolower( $v['severity'] ?? 'medium' ) ] ?? 50;
		if ( ( $v['exploitability'] ?? '' ) === 'high' ) {
			$score = min( 100, $score + 10 );
		}
		if ( empty( $v['fixed_in'] ) ) {
			$score = min( 100, $score + 5 );
		}
		return $score;
	}

	/**
	 * Cached results.
	 *
	 * @return array
	 */
	public static function cached() {
		$c = get_option( 'squidsec_shield_vuln_cache', array() );
		return is_array( $c ) ? $c : array();
	}
}
