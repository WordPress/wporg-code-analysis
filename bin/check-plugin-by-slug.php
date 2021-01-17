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

$opts = getopt( '', array( 'slug:', 'report:', 'page:', 'number:', 'errors' ) );
if ( empty( $opts['report'] ) ) {
	$opts['report'] = 'summary';
}
if ( intval( $opts['page'] ) <= 1 ) {
	$opts['page'] = 1;
}
if ( intval( $opts['number'] ) <= 1 ) {
	$opts['number'] = 25;
}

// Fetch the slugs of the top plugins in the directory
function get_top_slugs( $plugins_to_retrieve, $starting_page = 1 ) {
	$payload = array(
		'action' => 'query_plugins',
		'request' => serialize( (object) array( 'browse' => 'popular', 'per_page' => $plugins_to_retrieve, 'page' => $starting_page, 'fields' => [ 'active_installs' => true ] ) ) );

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
		$out[ $plugin->slug ] = [ 
			'slug' => $plugin->slug,
			'installs' => $plugin->active_installs,
			'updated' => $plugin->last_updated,
		];
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
	$plugins = get_top_slugs( intval( $opts['number'] ), intval( $opts['page'] ) );
	$slugs = array_map( 'reset', $plugins ); // ugh
} else {
	$slugs = [ $opts['slug'] ];
}

$phpcs = new PHPCS();
$phpcs->set_standard( dirname( __DIR__ ) . '/MinimalPluginStandard' );

foreach ( $slugs as $slug ) {

	$path = export_plugin( $slug );
	$args = array(
		'extensions' => 'php', // Only check php files.
		's' => true, // Show the name of the sniff triggering a violation.
	);

	if ( isset( $opts['errors'] ) ) {
		$args[ 'n' ] = true;
	}

	echo str_repeat( '=', 80 ) . "\n";
	echo "Checking $slug in $path...\n";
	if ( isset( $plugins[$slug] ) ) {
		echo number_format( $plugins[$slug]['installs'] ) . " active installs\n";
		echo "last updated " . $plugins[$slug]['updated'] . "\n";
		echo 'https://plugins.trac.wordpress.org/browser/' . $slug . "/trunk/\n";
	}
	echo str_repeat( '=', 80 ) . "\n";

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