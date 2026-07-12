<?php
/**
 * User enumeration prevention tests.
 *
 * @package SquidSec_Shield
 */

/**
 * @covers SquidSec_Shield_User_Enumeration
 */
class UserEnumerationTest extends SquidShield_TestCase {

	protected function setUp(): void {
		parent::setUp();
		$this->set_settings(
			array(
				'enabled'              => true,
				'user_enum_prevention' => true,
				'disable_author_archives' => true,
			)
		);
		wp_set_current_user( 0 );
	}

	public function test_rest_endpoints_removed_for_anonymous() {
		$endpoints = array(
			'/wp/v2/users' => array(),
			'/wp/v2/users/(?P<id>[\\d]+)' => array(),
			'/wp/v2/posts' => array(),
		);
		$out = SquidSec_Shield_User_Enumeration::filter_rest( $endpoints );
		$this->assertArrayNotHasKey( '/wp/v2/users', $out );
		$this->assertArrayHasKey( '/wp/v2/posts', $out );
	}

	public function test_oembed_strips_author() {
		$data = array(
			'author_name' => 'admin',
			'author_url'  => 'http://example.com/author/admin',
			'title'       => 'Post',
		);
		$out = SquidSec_Shield_User_Enumeration::filter_oembed( $data );
		$this->assertArrayNotHasKey( 'author_name', $out );
		$this->assertArrayNotHasKey( 'author_url', $out );
		$this->assertSame( 'Post', $out['title'] );
	}

	public function test_sitemap_users_provider_removed() {
		$provider = new stdClass();
		$out      = SquidSec_Shield_User_Enumeration::filter_sitemap_users( $provider, 'users' );
		$this->assertFalse( $out );
		$this->assertSame( $provider, SquidSec_Shield_User_Enumeration::filter_sitemap_users( $provider, 'posts' ) );
	}
}
