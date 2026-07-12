<?php
/**
 * WAF / virtual patch rules engine.
 *
 * @package SquidSec_Shield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Rules engine.
 */
class SquidSec_Shield_Rules_Engine {

	/**
	 * Cached rules.
	 *
	 * @var array|null
	 */
	private static $rules = null;

	/**
	 * Load all rules (built-in + virtual patches + custom).
	 *
	 * @return array
	 */
	public static function get_rules() {
		if ( null !== self::$rules ) {
			return self::$rules;
		}
		$cache_key = 'squidsec_shield_rules_compiled_v1';
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			self::$rules = $cached;
			return self::$rules;
		}

		$rules = array();

		$waf_file = SQUIDSEC_SHIELD_DIR . 'data/waf-rules.json';
		if ( file_exists( $waf_file ) ) {
			$data = json_decode( (string) file_get_contents( $waf_file ), true );
			if ( ! empty( $data['rules'] ) && is_array( $data['rules'] ) ) {
				$rules = array_merge( $rules, $data['rules'] );
				update_option( 'squidsec_shield_waf_rules_version', $data['version'] ?? '1.0.0', false );
			}
		}

		$vp_file = SQUIDSEC_SHIELD_DIR . 'data/virtual-patches.json';
		if ( file_exists( $vp_file ) && SquidSec_Shield_Options::get( 'virtual_patch_enabled' ) ) {
			$data = json_decode( (string) file_get_contents( $vp_file ), true );
			if ( ! empty( $data['rules'] ) && is_array( $data['rules'] ) ) {
				$rules = array_merge( $rules, $data['rules'] );
			}
		}

		// Custom user rules (sandbox-validated only).
		if ( SquidSec_Shield_Options::get( 'custom_rules_enabled' ) ) {
			global $wpdb;
			$table = SquidSec_Shield_Database::table( 'rules_custom' );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( "SELECT * FROM {$table} WHERE enabled = 1 AND sandbox_ok = 1", ARRAY_A );
			if ( $rows ) {
				foreach ( $rows as $row ) {
					$rules[] = array(
						'id'       => $row['rule_id'],
						'name'     => $row['name'],
						'type'     => $row['rule_type'],
						'pattern'  => $row['pattern'],
						'targets'  => $row['targets'] ? json_decode( $row['targets'], true ) : array( 'all' ),
						'action'   => $row['action'],
						'severity' => $row['severity'],
						'cve'      => $row['cve'],
						'enabled'  => true,
						'source'   => 'custom',
					);
				}
			}
		}

		// Per-rule enable/disable state.
		$state = get_option( 'squidsec_shield_rules_state', array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		$out = array();
		foreach ( $rules as $rule ) {
			$id = $rule['id'] ?? '';
			if ( $id === '' ) {
				continue;
			}
			if ( isset( $state[ $id ] ) && empty( $state[ $id ] ) ) {
				$rule['enabled'] = false;
			} else {
				$rule['enabled'] = array_key_exists( 'enabled', $rule ) ? (bool) $rule['enabled'] : true;
			}
			$out[] = $rule;
		}

		self::$rules = $out;
		set_transient( $cache_key, $out, 5 * MINUTE_IN_SECONDS );
		return self::$rules;
	}

	/**
	 * Flush compiled cache.
	 */
	public static function flush_cache() {
		self::$rules = null;
		delete_transient( 'squidsec_shield_rules_compiled_v1' );
	}

	/**
	 * Evaluate request against rules.
	 *
	 * @param string $uri     URI.
	 * @param string $payload Combined payload.
	 * @param string $context Request context.
	 * @return array|null Match info or null.
	 */
	public static function evaluate( $uri, $payload, $context = 'front' ) {
		$haystack = $uri . "\n" . $payload;
		$plugins  = null;

		foreach ( self::get_rules() as $rule ) {
			if ( empty( $rule['enabled'] ) ) {
				continue;
			}

			// Context targets.
			$targets = $rule['targets'] ?? array( 'all' );
			if ( ! is_array( $targets ) ) {
				$targets = array( 'all' );
			}
			if ( ! in_array( 'all', $targets, true ) && ! in_array( $context, $targets, true ) ) {
				continue;
			}

			// Category toggles.
			$cat = $rule['category'] ?? '';
			if ( $cat === 'sqli' && ! SquidSec_Shield_Options::get( 'waf_block_sqli' ) ) {
				continue;
			}
			if ( $cat === 'xss' && ! SquidSec_Shield_Options::get( 'waf_block_xss' ) ) {
				continue;
			}
			if ( $cat === 'rce' && ! SquidSec_Shield_Options::get( 'waf_block_rce' ) ) {
				continue;
			}
			if ( $cat === 'lfi' && ! SquidSec_Shield_Options::get( 'waf_block_lfi' ) ) {
				continue;
			}
			if ( $cat === 'upload' && ! SquidSec_Shield_Options::get( 'waf_block_upload' ) ) {
				continue;
			}

			// Version-aware virtual patches.
			if ( ! empty( $rule['requires_plugin'] ) ) {
				if ( null === $plugins ) {
					$plugins = SquidSec_Shield_Helpers::active_plugin_versions();
				}
				$slug = $rule['requires_plugin'];
				if ( ! isset( $plugins[ $slug ] ) ) {
					continue; // Plugin not installed — skip to reduce FPs.
				}
				if ( ! empty( $rule['vulnerable_versions'] ) ) {
					if ( ! SquidSec_Shield_Helpers::version_matches( $plugins[ $slug ], $rule['vulnerable_versions'] ) ) {
						continue;
					}
				}
			}
			if ( ! empty( $rule['requires_core'] ) ) {
				if ( ! SquidSec_Shield_Helpers::version_matches( get_bloginfo( 'version' ), $rule['requires_core'] ) ) {
					continue;
				}
			}

			$pattern = $rule['pattern'] ?? '';
			$type    = $rule['type'] ?? 'regex';
			$matched = false;

			if ( $type === 'regex' || $type === 'pattern' ) {
				$pattern = self::compile_regex( $pattern );
				$matched = $pattern ? SquidSec_Shield_Helpers::safe_match( $pattern, $haystack ) : false;
			} elseif ( $type === 'contains' ) {
				$matched = ( false !== stripos( $haystack, $pattern ) );
			} elseif ( $type === 'uri_regex' ) {
				$pattern = self::compile_regex( $pattern );
				$matched = $pattern ? SquidSec_Shield_Helpers::safe_match( $pattern, $uri ) : false;
			}

			if ( $matched ) {
				return $rule;
			}
		}
		return null;
	}

	/**
	 * Compile a user/builtin pattern to a delimited regex.
	 *
	 * Uses # delimiters so patterns may contain / without broken escaping.
	 *
	 * @param string $pattern Pattern.
	 * @return string Empty string if invalid.
	 */
	public static function compile_regex( $pattern ) {
		$pattern = (string) $pattern;
		if ( $pattern === '' ) {
			return '';
		}
		// Already delimited.
		if ( strlen( $pattern ) > 2 && in_array( $pattern[0], array( '/', '#', '~', '%' ), true ) ) {
			return $pattern;
		}
		return '#' . str_replace( '#', '\#', $pattern ) . '#i';
	}

	/**
	 * Set rule enabled state.
	 *
	 * @param string $rule_id Rule ID.
	 * @param bool   $enabled Enabled.
	 */
	public static function set_rule_enabled( $rule_id, $enabled ) {
		$state = get_option( 'squidsec_shield_rules_state', array() );
		if ( ! is_array( $state ) ) {
			$state = array();
		}
		$state[ $rule_id ] = (bool) $enabled;
		update_option( 'squidsec_shield_rules_state', $state, false );
		self::flush_cache();
	}

	/**
	 * Sandbox-validate a custom regex pattern.
	 *
	 * @param string $pattern Pattern.
	 * @return true|WP_Error
	 */
	public static function sandbox_validate_pattern( $pattern ) {
		if ( strlen( $pattern ) > 500 ) {
			return new WP_Error( 'pattern_long', 'Pattern too long (max 500).' );
		}
		// Disallow dangerous constructs.
		$banned = array( '(?R', '(?0', '(*', '.*.*', '.+.+', '{1000', '{999' );
		foreach ( $banned as $b ) {
			if ( false !== strpos( $pattern, $b ) ) {
				return new WP_Error( 'pattern_unsafe', 'Pattern contains disallowed constructs.' );
			}
		}
		$test = self::compile_regex( $pattern );
		set_error_handler( static function () {
			return true;
		} );
		$ok = @preg_match( $test, 'test-string-sandbox' );
		restore_error_handler();
		if ( false === $ok ) {
			return new WP_Error( 'pattern_invalid', 'Invalid regular expression.' );
		}
		return true;
	}
}
