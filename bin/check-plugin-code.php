#!/usr/bin/php
<?php

namespace WordPressdotorg\Plugin_Directory;

use WordPressdotorg\Plugin_Directory\Tools\PHPCS;

// This script should only be called in a CLI environment.
if ( 'cli' != php_sapi_name() ) {
	die();
}

$opts = getopt( '', array( 'slug:', 'report:' ) );
if ( empty( $opts['slug'] ) ) {
	$opts['slug'] = 'plugin-directory';
}
if ( empty( $opts['report'] ) ) {
	$opts['report'] = 'summary';
}

// Bootstrap WordPress
$url = 'https://wordpress.org/plugins/';
$_SERVER['HTTP_HOST']   = parse_url( $url, PHP_URL_HOST );
$_SERVER['REQUEST_URI'] = parse_url( $url, PHP_URL_PATH );

$abspath = substr( __DIR__, 0, strpos( __DIR__, 'wp-content' ) );
require rtrim( $abspath, '/' ) . '/wp-load.php';

if ( ! class_exists( '\WordPressdotorg\Plugin_Directory\Plugin_Directory' ) ) {
	fwrite( STDERR, "Error! This site doesn't have the Plugin Directory plugin enabled.\n" );
	if ( defined( 'WPORG_PLUGIN_DIRECTORY_BLOGID' ) ) {
		fwrite( STDERR, "Run the following command instead:\n" );
		fwrite( STDERR, "\tphp " . implode( ' ', $argv ) . ' --url ' . get_site_url( WPORG_PLUGIN_DIRECTORY_BLOGID, '/' ) . "\n" );
	}
	die();
}

$phpcs = new PHPCS();
$phpcs->set_standard( dirname( __DIR__ ) . '/rulesets/reviewer-flags.xml' );

$path = dirname( dirname( __DIR__ ) ) . '/' . $opts['slug'];
$args = array(
	'extensions' => 'php',
	's' => true,
);

echo $path;

switch ( $opts['report'] ) {
	case 'full':
		echo $phpcs->run_full_report( $path, $args );
		break;
	case 'summary':
	default:
		echo $phpcs->run_summary_report( $path, $args );
		break;
}

