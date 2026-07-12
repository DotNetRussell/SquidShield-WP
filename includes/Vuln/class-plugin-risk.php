<?php
/**
 * Plugin risk intelligence (maintenance, abandonment, supply chain signals).
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin risk.
 */
class SquidSec_Shield_Plugin_Risk {

	/**
	 * Init.
	 */
	public static function init() {
		// On-demand / scheduled via vuln scanner.
	}

	/**
	 * Score all installed plugins.
	 *
	 * @return array
	 */
	public static function score_all() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all    = get_plugins();
		$active = get_option( 'active_plugins', array() );
		$out    = array();
		foreach ( $all as $file => $data ) {
			$slug = dirname( $file );
			if ( '.' === $slug ) {
				$slug = basename( $file, '.php' );
			}
			$out[] = self::score_plugin( $slug, $data, in_array( $file, $active, true ) );
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return ( $b['score'] ?? 0 ) <=> ( $a['score'] ?? 0 );
			}
		);
		return $out;
	}

	/**
	 * Score one plugin.
	 *
	 * @param string $slug   Slug.
	 * @param array  $data   Header data.
	 * @param bool   $active Active.
	 * @return array
	 */
	public static function score_plugin( $slug, array $data, $active ) {
		$score   = 10;
		$signals = array();
		$name    = $data['Name'] ?? $slug;
		$version = $data['Version'] ?? '';
		$uri     = $data['PluginURI'] ?? '';
		$author  = $data['Author'] ?? '';

		// No update URI / not on wp.org often higher risk if abandoned.
		$update_plugins = get_site_transient( 'update_plugins' );
		if ( is_object( $update_plugins ) && ! empty( $update_plugins->response ) ) {
			foreach ( $update_plugins->response as $file => $obj ) {
				if ( isset( $obj->slug ) && $obj->slug === $slug ) {
					$score    += 15;
					$signals[] = 'Update available (may include security fixes)';
				}
			}
		}

		// Heuristic: very old PHP-style versions or missing author.
		if ( $author === '' ) {
			$score    += 20;
			$signals[] = 'Missing author metadata';
		}
		if ( $uri === '' && 0 !== strpos( $slug, 'squidsec' ) ) {
			$score    += 10;
			$signals[] = 'No plugin URI';
		}

		// Custom SquidSec plugins are first-party.
		if ( 0 === strpos( $slug, 'squidsec' ) ) {
			$score     = max( 5, $score - 30 );
			$signals[] = 'First-party SquidSec component';
		}

		// Premium SEO bundles etc. — flag commercial closed source for awareness (not block).
		if ( false !== stripos( $name, 'premium' ) || false !== stripos( $slug, 'premium' ) ) {
			$score    += 5;
			$signals[] = 'Premium/closed-source component — ensure license & updates';
		}

		// Inactive plugins still attack surface.
		if ( ! $active ) {
			$score    += 10;
			$signals[] = 'Installed but inactive (still readable on disk)';
		}

		$score = max( 0, min( 100, $score ) );
		$rec   = 'Monitor for updates.';
		if ( $score >= 70 ) {
			$rec = 'Consider replacing or removing; review update history and maintainer reputation.';
		} elseif ( $score >= 40 ) {
			$rec = 'Keep updated; review changelog for security fixes.';
		}

		return array(
			'slug'           => $slug,
			'name'           => $name,
			'version'        => $version,
			'active'         => $active,
			'score'          => $score,
			'signals'        => $signals,
			'recommendation' => $rec,
		);
	}
}
