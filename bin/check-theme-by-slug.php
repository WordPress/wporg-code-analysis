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

$opts = getopt( '', array( 'slug:', 'tag:', 'report:', 'page:', 'number:', 'errors', 'browse:' ) );
if ( empty( $opts['report'] ) ) {
	$opts['report'] = 'summary';
}
if ( intval( @$opts['page'] ) <= 1 ) {
	$opts['page'] = 1;
}
if ( intval( @$opts['number'] ) <= 1 ) {
	$opts['number'] = 25;
}
if ( empty( $opts['tag'] ) || empty( $opts['slug'] ) ) {
	$opts['tag'] = null;
}

// Fetch the slugs of the top plugins in the directory
function get_top_slugs( $plugins_to_retrieve, $starting_page = 1, $browse = 'popular' ) {
	$payload = array(
		'action' => 'query_themes',
		'request' => serialize( (object) array( 'browse' => $browse, 'per_page' => $plugins_to_retrieve, 'page' => $starting_page, 'fields' => [ 'downloadlink' => true, 'active_installs' => true, 'last_updated' => true ] ) ) );

	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL,"https://api.wordpress.org/themes/info/1.0/");
	curl_setopt($ch, CURLOPT_POST, true);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $payload );

	$response = curl_exec( $ch );

	$data = unserialize( $response );

	curl_close( $ch );

	$out = [];

	foreach ( $data->themes as $theme ) {
		$out[ $theme->slug ] = [
			'slug' => $theme->slug,
			'installs' => $theme->active_installs,
			'updated' => $theme->last_updated,
			'url' => $theme->download_link,
		];
	}

	return $out;
}
/*
function get_dir_for_tag( $tag ) {
	if ( !empty( $tag ) ) {
		$dir = '/tags/' . basename( $tag );
	} else {
		$dir = '/trunk';
	}

	return $dir;
}

// Export a plugin to ./plugins/SLUG and return the full path to that directory
function export_plugin( $slug, $tag = null ) {

	$tmpnam = tempnam( '/tmp', 'plugin-' . $slug );

	$dir = get_dir_for_tag( $tag );

	if ( $tmpnam ) {
		$tmpnam = realpath( $tmpnam );
		unlink( $tmpnam );
		mkdir( $tmpnam ) || die( "Failed creating temp directory $tmpnam" );
		$cmd = "svn export --force https://plugins.svn.wordpress.org/" . $slug . $dir . ' ' . $tmpnam;
		shell_exec( $cmd );

		return $tmpnam;
	}
}
*/

// Export a theme to ./themes/SLUG and return the full path to that directory
function export_theme( $slug, $url ) {

	$zipfile = tempnam( '/tmp', $slug . '.zip' );
	copy( $url, $zipfile );

	$tmpnam = tempnam( '/tmp', 'theme-' . $slug );

	if ( $tmpnam ) {
		$tmpnam = realpath( $tmpnam );
		unlink( $tmpnam );
		mkdir( $tmpnam ) || die( "Failed creating temp directory $tmpnam" );

		$zip = new ZipArchive();
		if ( $zip->open( $zipfile ) ) {
			$zip->extractTo( $tmpnam . '/' );
			$zip->close();
			unlink( $zipfile );
			return $tmpnam;
		}
	}

	return false;
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
	$themes = get_top_slugs( intval( $opts['number'] ), intval( $opts['page'] ), $opts['browse'] ?? 'popular' );
	$slugs = array_map( 'reset', $themes ); // ugh
} else {
	$slugs = [ $opts['slug'] ];
}

$phpcs = new PHPCS();
$phpcs->set_standard( dirname( __DIR__ ) . '/MinimalThemeStandard' );

foreach ( $slugs as $slug ) {

	#$path = export_plugin( $slug, $opts['tag'] );
	$path = export_theme( $slug, $themes[ $slug ]['url'] );

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
		#echo 'https://plugins.trac.wordpress.org/browser/' . $slug . get_dir_for_tag( $opts['tag'] ) . "/\n";
	}
	echo str_repeat( '=', 80 ) . "\n";

	switch ( $opts['report'] ) {
		case 'full':
			echo $phpcs->run_full_report( $path, $args );
			break;
		case 'json':
			$result = $phpcs->run_json_report( $path, $args, 'array' );
			if ( is_array( $result ) ) {
				var_dump( $result );
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