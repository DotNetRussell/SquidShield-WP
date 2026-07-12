<?php
/**
 * Virtual patching coordination.
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
 * Virtual patch module.
 */
class SquidSec_Shield_Virtual_Patch {

	/**
	 * Init.
	 */
	public static function init() {
		// Virtual patches are applied via Rules_Engine + WAF.
		// This class exposes coordination helpers for admin/API.
	}

	/**
	 * List active virtual patches with status.
	 *
	 * @return array
	 */
	public static function list_patches() {
		$file = SQUIDSEC_SHIELD_DIR . 'data/virtual-patches.json';
		if ( ! file_exists( $file ) ) {
			return array();
		}
		$data  = json_decode( (string) file_get_contents( $file ), true );
		$rules = $data['rules'] ?? array();
		$state = get_option( 'squidsec_shield_rules_state', array() );
		$plugins = SquidSec_Shield_Helpers::active_plugin_versions();
		$out = array();
		foreach ( $rules as $rule ) {
			$id = $rule['id'] ?? '';
			$enabled = ! isset( $state[ $id ] ) || ! empty( $state[ $id ] );
			$applies = true;
			$reason  = 'Active virtual patch';
			if ( ! empty( $rule['requires_plugin'] ) ) {
				$slug = $rule['requires_plugin'];
				if ( ! isset( $plugins[ $slug ] ) ) {
					$applies = false;
					$reason  = 'Plugin not installed — rule idle (low FP mode)';
				} elseif ( ! empty( $rule['vulnerable_versions'] ) && ! SquidSec_Shield_Helpers::version_matches( $plugins[ $slug ], $rule['vulnerable_versions'] ) ) {
					$applies = false;
					$reason  = 'Installed version not in vulnerable range';
				} else {
					$reason = 'Protecting ' . $slug . ' ' . $plugins[ $slug ];
				}
			}
			$out[] = array(
				'id'          => $id,
				'name'        => $rule['name'] ?? $id,
				'cve'         => $rule['cve'] ?? '',
				'severity'    => $rule['severity'] ?? 'high',
				'enabled'     => $enabled,
				'applies'     => $applies,
				'reason'      => $reason,
				'fix_hint'    => $rule['fix_hint'] ?? 'Update the affected component when a safe official release is available.',
			);
		}
		return $out;
	}
}
