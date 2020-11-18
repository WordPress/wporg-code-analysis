#!/usr/bin/php
<?php
/**
 * A quick and dirty script for testing the PHPCS class against any plugin in the directory.
 * This script does not use or require WordPress.
 *
 * Usage:
 * php check-plugin-by-slug.php --slug akismet
 * Or:
 * php check-plugin-by-slug.php
 */

use WordPressDotOrg\Code_Analysis\PHPCS;

// This script should only be called in a CLI environment.
if ( 'cli' != php_sapi_name() ) {
	die();
}

$opts = getopt( '', array( 'slug:', 'report:' ) );
if ( empty( $opts['report'] ) ) {
	$opts['report'] = 'summary';
}

// Fetch the slugs of the top plugins in the directory
function get_top_slugs( $plugins_to_retrieve ) {
	$payload = array(
		'action' => 'query_plugins',
		'request' => serialize( (object) array( 'browse' => 'popular', 'per_page' => $plugins_to_retrieve ) ) );

	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL,"https://api.wordpress.org/plugins/info/1.0/");
	curl_setopt($ch, CURLOPT_POST, true);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $payload );

	$response = curl_exec( $ch );

	$data = unserialize( $response );

	curl_close( $ch );

	$out = [];

	foreach ( $data->plugins as $plugin ) {
		$out[] = $plugin->slug;
	}

	return $out;
}

// Export a plugin to ./plugins/SLUG and return the full path to that directory
function export_plugin( $slug ) {

	$tmpnam = tempnam( '/tmp', 'plugin-' . $slug );
	if ( $tmpnam ) {
		$tmpnam = realpath( $tmpnam );
		unlink( $tmpnam );
		mkdir( $tmpnam ) || die( "Failed creating temp directory $tmpnam" );
		$cmd = "svn export --force https://plugins.svn.wordpress.org/" . $slug . "/trunk " . $tmpnam;
		shell_exec( $cmd );

		return $tmpnam;
	}
}

// Fake WP_Error class so the PHPCS class works
class WP_Error {
	var $code;
	var $message;
	var $data;

	function __construct( $code = '', $message = '', $data = '' ) {
		$this->code = $code;
		$this->message = $message;
		$this->data = $data;
	}

	public function __toString() {
		return var_export( $this, true );
	}
}

// Again so PHPCS class works
define( 'WPINC', 'yeahnah' );

// Load phpcs class
require dirname( __DIR__ ) . '/includes/class-phpcs.php';

if ( empty( $opts['slug'] ) ) {
	$slugs = get_top_slugs( 25 );
} else {
	$slugs = [ $opts['slug'] ];
}

foreach ( $slugs as $slug ) {

	// Do we need a fresh object each time?
	$phpcs = new PHPCS();
	$phpcs->set_standard( dirname( __DIR__ ) . '/rulesets/reviewer-flags.xml' );

	$path = export_plugin( $slug );
	$args = array(
		'extensions' => 'php', // Only check php files.
		's' => true, // Show the name of the sniff triggering a violation.
	);

	echo "Checking $slug in $path...\n";

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
}