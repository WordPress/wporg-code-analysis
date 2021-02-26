<?php
/**
 * The Scan tool metabox. For use with the plugin-directory admin tools.
 */

namespace WordPressdotorg\Code_Analysis\Admin;

use WordPressDotOrg\Code_Analysis\PHPCS;

/**
 * The Scan metabox.
 *
 * @package WordPressdotorg\Code_Analysis\Admin
 */
class Scan_Metabox {
	public static function display( $post = null ) {
		$post = get_post( $post );

		$zip_file = Scanner::get_latest_zip_path( $post );
		if ( !$zip_file || !is_readable( $zip_file ) ) {
			printf( '<p>Unable to scan %s</p>', $zip_file );
			return false;
		}

		$results = Scanner::get_scan_results_for_zip( $zip_file );

		if ( isset( $results[ 'totals' ] ) ) {
			printf(
				'<p>Found %d errors and %d warnings in %d files (%0.2fs).</p>',
				$results[ 'totals' ][ 'errors' ],
				$results[ 'totals' ][ 'warnings' ],
				count( $results[ 'files' ] ),
				$results[ 'time_taken' ]
			);
		}

ini_set( 'xdebug.var_display_max_depth', -1 );
ini_set( 'xdebug.var_display_max_children', -1 );
ini_set( 'xdebug.var_display_max_data', -1 );
var_dump( $results );

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
				if ( $message['context'] ) {
					foreach ( $message['context'] as $line_no => $context_line ) {
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
	//		return $cached;
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

	
}

