<?php
/**
 * Admin / dashboard widget smoke tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_Admin
 */
class AdminWidgetTest extends SquidShield_TestCase {

	public function test_dashboard_widget_renders_without_fatal() {
		$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
		if ( empty( $admins ) ) {
			$this->markTestSkipped( 'No administrator user' );
		}
		wp_set_current_user( $admins[0]->ID );
		ob_start();
		SquidSec_Shield_Admin::render_dashboard_widget();
		$html = ob_get_clean();
		$this->assertStringContainsString( 'sss-wp-dash', $html );
		$this->assertStringContainsString( 'Protections on', $html );
		$this->assertStringContainsString( 'Open SquidShield', $html );
		wp_set_current_user( 0 );
	}

	public function test_action_links_include_open_shield() {
		$links = SquidSec_Shield_Admin::action_links( array( 'deactivate' => 'x' ) );
		$joined = implode( ' ', $links );
		$this->assertStringContainsString( 'Open Shield', $joined );
	}
}
