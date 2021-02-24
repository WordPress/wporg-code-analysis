<?php
/**
 * The Scan tool metabox. For use with the plugin-directory admin tools.
 */

namespace WordPressdotorg\Code_Analysis\Admin;

use WordPressDotOrg\Code_Analysis\PHPCS;

use WordPressdotorg\Plugin_Directory\Tools\Filesystem;
use WordPressdotorg\Plugin_Directory\Template;

/**
 * The Scan metabox.
 *
 * @package WordPressdotorg\Code_Analysis\Admin
 */
class Scan_Metabox {
	public static function display( $post = null ) {
		$post = get_post( $post );

		$zip_file = self::get_latest_zip_path( $post );
		if ( !$zip_file || !is_readable( $zip_file ) ) {
			printf( '<p>Unable to scan %s</p>', $zip_file );
			return false;
		}

		$now = microtime( true );
		list( $results, $zip_dir ) = self::get_scan_results_for_zip( $zip_file );
		$delta = microtime( true ) - $now;

		if ( isset( $results[ 'totals' ] ) ) {
			printf( '<p>Found %d errors and %d warnings in %d files (%0.2fs).</p>', $results[ 'totals' ][ 'errors' ], $results[ 'totals' ][ 'warnings' ], count( $results[ 'files' ] ), $delta );
		}

		echo '<pre style="white-space: pre-wrap;">';
		foreach ( $results[ 'files' ] as $pathname => $file ) {
			list( $slug, $filename ) = explode( '/', $pathname, 2 );
			foreach ( $file[ 'messages' ] as $message ) {
				// Skip warnings for now
				if ( 'WARNING' === $message[ 'type' ] ) {
					continue;
				}
				printf( "%s %s in <a href='https://plugins.trac.wordpress.org/browser/%s/trunk/%s#L%d'>%s line %d</a>\n", esc_html( $message[ 'type' ] ), esc_html( $message[ 'source' ] ), esc_attr( $slug ), esc_attr( $filename ), $message[ 'line' ], esc_html( $filename ), $message[ 'line' ] );
				echo esc_html( $message[ 'message' ] ) . "\n";
				if ( $source = file( $zip_dir . '/' . $pathname ) ) {
					$context = array_slice( $source, $message['line'] - 3, 5, true );
					foreach ( $context as $line_no => $context_line ) {
						$line_no += 1; // Ironic that source code lines are conventionally 1-indexed
						$line = $line_no . '&emsp;' . esc_html( rtrim( $context_line ) ). "\n";
						if ( $line_no == $message['line'] ) {
							echo '<b>' . $line . '</b>';
						} else {
							echo $line;
						}
					}
					echo "\n";
				}
			}
		}
		echo '</pre>';
	}

	public static function display_ajax() {
		echo '<div id="scan_plugin_output">Loading...</div>';
		wp_nonce_field( 'scan-plugin', 'scan_plugin_nonce', false );

	}

	/**
	 * Ajax handler that runs a scan and returns the output to display
	 */
	public static function get_ajax_response( $action = 'scan-plugin' ) {
		global $post_id;

		if ( empty( $post_id ) && !empty( $_REQUEST[ 'p' ] ) ) {
			$id = absint( $_REQUEST[ 'p' ] );
			if ( !empty( $id ) ) {
				$post_id = $id;
			}
		}

		if ( empty( $post_id ) ) {
			wp_die( -1 );
		}

		$out = new \WP_Ajax_Response();

		$out->add( [ 
			'what' => 'scan-results',
			'data' => self::get_scan_output_cached( $post_id ),
		 ] );
		$out->send();

	}

	/**
	 * Return the output of a scan as a string, with caching.
	 */
	public static function get_scan_output_cached( $post_id ) {
		$post_id = intval( $post_id );
		if ( $post_id < 1 ) {
			return false;
		}

		if ( $cached = get_transient( "code_scan_$post_id" ) ) {
			return $cached;
		}

		// Set a temporary cached value for 2 minutes, to prevent a stampede of multiple scans running at once.
		set_transient( "code_scan_$post_id", '...', 2 * MINUTE_IN_SECONDS );

		ob_start();
		self::display( $post_id );
		$out = ob_get_clean();

		// Cache the results and return it.
		set_transient( "code_scan_$post_id", $out, 15 * MINUTE_IN_SECONDS );
		return $out;
	}

	public static function get_scan_results_for_zip( $zip_file_path ) {

		$out = wp_cache_get( $zip_file_path, 'wporg-code-analysis-scan' );

		// Note that unzip() automatically removes the temp directory on shutdown
		$unzip_dir = Filesystem::unzip( $zip_file_path );

		if ( !$unzip_dir || !is_readable( $unzip_dir ) ) {
			return false;
		}

		// FIXME: autoload?
		require_once dirname( __DIR__ ) . '/includes/class-phpcs.php';

		$phpcs = new PHPCS();
		$phpcs->set_standard( dirname( __DIR__ ) . '/MinimalPluginStandard' );

		$args = array(
			'extensions' => 'php', // Only check php files.
			's' => true, // Show the name of the sniff triggering a violation.
		);

		//TODO: cache this?
		$result = $phpcs->run_json_report( $unzip_dir, $args, 'array' );
		return [ $result, $unzip_dir ];
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

