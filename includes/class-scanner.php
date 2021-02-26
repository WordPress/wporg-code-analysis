<?php
namespace WordPressDotOrg\Code_Analysis;
use WordPressdotorg\Plugin_Directory\Tools\Filesystem;
use WordPressdotorg\Plugin_Directory\Template;
use WP_Error;

defined( 'WPINC' ) || die();

class Scanner {
	public static function get_scan_results_for_zip( $zip_file_path ) {

		$out = wp_cache_get( $zip_file_path, 'wporg-code-analysis-scan' );

		// Note that unzip() automatically removes the temp directory on shutdown
		$unzip_dir = Filesystem::unzip( $zip_file_path );

		if ( !$unzip_dir || !is_readable( $unzip_dir ) ) {
			return false;
		}

		// FIXME: autoload?
		require_once dirname( __DIR__ ) . '/includes/class-phpcs.php';

		$now = microtime( true );

		$phpcs = new PHPCS();
		$phpcs->set_standard( dirname( __DIR__ ) . '/MinimalPluginStandard' );

		$args = array(
			'extensions' => 'php', // Only check php files.
			's' => true, // Show the name of the sniff triggering a violation.
		);

		$result = $phpcs->run_json_report( $unzip_dir, $args, 'array' );

		// Count the time running PHPCS.
		$result['time_taken'] = microtime( true ) - $now;

		// Add context to the results
		foreach ( $result['files'] as $filename => $data ) {
			foreach ( $data['messages'] as $i => $message ) {
				$result['files'][ $filename ]['messages'][ $i ]['context'] = array();

				if ( $source = file( $unzip_dir . '/' . $filename ) ) {
					$context = array_slice( $source, $message['line'] - 3, 5, true );
					foreach ( $context as $line => $data ) {
						// Lines are indexed from 0 in file(), but from 1 in PHPCS.
						$result['files'][ $filename ]['messages'][ $i ]['context'][ $line + 1 ] = rtrim( $data, "\r\n" );
					}
				}
			}
		}

		//TODO: cache this?

		return $result;
	}

	public static function get_latest_zip_path( $post = null ) {
		//TODO: make it so it's possible to specify a tag via a dropdown
		$post = get_post( $post );

		// Scan the published ZIP file.
		if ( in_array( $post->post_status, [ 'publish', 'disabled', 'closed' ] ) ) {
			// Need to fetch the zip remotely from the downloads server.
			$zip_url = Template::download_link( $post );

			$tmp_dir = Filesystem::temp_directory( $post->post_name );
			$zip_file = $tmp_dir . '/' . basename( $zip_url );

			$request = wp_safe_remote_get(
				$zip_url,
				array(
					'stream'   => true,
					'filename' => $zip_file,
				)
			);

			if ( ! is_wp_error( $request ) ) {
				return $zip_file;
			}

			// If not successful, we'll use the ZIP attached to the post, if possible.
		}

		$zip_files = array();
		foreach ( get_attached_media( 'application/zip', $post ) as $zip_file ) {
			$zip_files[ $zip_file->post_date ] = array( get_attached_file( $zip_file->ID ), $zip_file );
		}
		uksort( $zip_files, function ( $a, $b ) {
			return strtotime( $a ) < strtotime( $b );
		} );

		if ( count( $zip_files ) ) {
			return end( $zip_files )[0];
		}

		return false;
	}
}