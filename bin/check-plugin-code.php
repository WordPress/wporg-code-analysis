#!/usr/bin/env php
<?php
/**
 * A quick and dirty script for testing the PHPCS class against plugins installed on wporg.
 */

namespace WordPressDotOrg\Code_Analysis;

use WordPressDotOrg\Code_Analysis\PHPCS;

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

// Load phpcs class
require dirname( __DIR__ ) . '/includes/class-phpcs.php';

$phpcs = new PHPCS();
$phpcs->set_standard( dirname( __DIR__ ) . '/MinimalPluginStandard' );

$path = dirname( dirname( __DIR__ ) ) . '/' . $opts['slug'];
$args = array(
	'extensions' => 'php', // Only check php files.
	's' => true, // Show the name of the sniff triggering a violation.
);

echo "Checking $path...\n";

switch ( $opts['report'] ) {
	case 'full':
		echo $phpcs->run_full_report( $path, $args );
		break;
	case 'json':
		$result = $phpcs->run_json_report( $path, $args, 'array' );
		if ( is_array( $result ) ) {
			print_r( $result );
		} else {
			echo $result;
		}
		break;
	case 'summary':
	default:
		echo $phpcs->run_summary_report( $path, $args );
		break;
}

