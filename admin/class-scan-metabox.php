<?php
/**
 * The Scan tool metabox. For use with the plugin-directory admin tools.
 */

namespace WordPressdotorg\Code_Analysis\Admin;

use WordPressDotOrg\Code_Analysis\PHPCS;
use WordPressDotOrg\Code_Analysis\Scanner;

/**
 * The Scan metabox.
 *
 * @package WordPressdotorg\Code_Analysis\Admin
 */
class Scan_Metabox {
	/**
	 * Maximum number of code snippet blocks to highlight; a lazy workaround for Prism performance issues.
	 */
	const MAX_HIGHLIGHT_SNIPPETS = 15;

	public static function display( $post = null, $version = '' ) {
		$post = get_post( $post );

		$include_warnings = false;
		// Include warnings for non-published plugins.
		if ( 'publish' !== $post->post_status ) {
			$include_warnings = true;
		}

		$results = Scanner::get_scan_results_for_plugin( $post, $version );
		if ( ! $results ) {
			printf( '<p>Unable to scan.</p>' );
			return false;
		}

		printf(
			'<p>Found %d errors and %d warnings in %d files (%0.2fs).</p>',
			$results[ 'totals' ][ 'errors' ],
			$results[ 'totals' ][ 'warnings' ],
			count( $results[ 'files' ] ),
			$results[ 'time_taken' ]
		);

		if ( empty( $results[ 'files' ] ) ) {
			return;
		}

		$tag_dir          = ( 'trunk' === $post->stable_tag || '' == $post->stable_tag ? 'trunk' : 'tags/' . $post->stable_tag );
		$upload_dir       = wp_get_upload_dir();
		$is_uploaded_file = str_starts_with( $results['file'], $upload_dir['basedir'] );
		$snippet_count	  = 0;

		echo '<pre style="white-space: pre-wrap;">';
		foreach ( $results[ 'files' ] as $pathname => $file ) {
			// Trim off the slug. Present in published plugins, not necesarily present in uploaded ZIPs
			$filename = $pathname;
			if ( str_starts_with( $filename, "{$post->post_name}/" ) ) {
				list( , $filename ) = explode( '/', $filename, 2 );
			}

			foreach ( $file[ 'messages' ] as $message ) {
				// Skip warnings for now
				if ( 'WARNING' === $message[ 'type' ] && ! $include_warnings ) {
					continue;
				}

				$marks = [];
				if ( preg_match_all( '/ at line (\d+):/', $message[ 'message' ], $matches, PREG_PATTERN_ORDER ) ) {
					$marks = array_map( 'intval', $matches[1] );
				}
				$marks[] = $message[ 'line' ];
				$marks = array_unique( $marks );
				echo '<div class="phpcs phpcs-severity-' . intval( $message[ 'severity' ] ) . '">';
				if ( $is_uploaded_file ) {
					printf(
						"%s %s in <em>%s line %d</em>\n",
						esc_html( $message[ 'type' ] ),
						esc_html( $message[ 'source' ] ),
						esc_html( $filename ),
						$message[ 'line' ]
					);
				} else {
					// Must have been a plugin zip from svn.
					printf(
						"%s %s in <a href='https://plugins.trac.wordpress.org/browser/%s/%s/%s%s#L%d'>%s line %d</a>\n",
						esc_html( $message[ 'type' ] ),
						esc_html( $message[ 'source' ] ),
						esc_attr( $post->post_name ),
						esc_attr( $tag_dir ),
						esc_attr( $filename ),
						($marks ? '?marks=' . join( ',', $marks ) : '' ),
						$message[ 'line' ],
						esc_html( $filename ),
						$message[ 'line' ]
					);
				}

				echo esc_html( $message[ 'message' ] ) . "\n";
				if ( $message['context'] ) {
					// Only highlight a limited number of snippets, to avoid Prism performance issues.
					if ( ++ $snippet_count <= self::MAX_HIGHLIGHT_SNIPPETS ) {
						$code_class = 'language-php';
					} else {
						$code_class = '';
					}
					$first_line = array_key_first( $message['context'] );
					echo '<pre class="line-numbers" data-start="' . intval($first_line) . '" data-line-offset="' . intval($first_line) . '" data-line="' . intval($message['line']) .'"><code language="php" class="' . $code_class . '">&lt;?php ';
					foreach ( $message['context'] as $line_no => $context_line ) {
						$line = esc_html( $context_line ). "\n";
						if ( $line_no == $message['line'] ) {
							echo '<b>' . $line . '</b>';
						} else {
							echo $line;
						}
					}
					echo "</code></pre>\n";
				}
				echo "</div>\n";
			}
		}
		echo '</pre>';
	}

	/**
	 * Display the metabox, if cached output directly, else ajax load.
	 */
	public static function maybe_display_ajax() {
		global $post;

		wp_nonce_field( 'scan-plugin', 'scan_plugin_nonce', false );

		$output = self::get_scan_output_cached( $post->ID, '', true );

		$attachments     = get_attached_media( 'application/zip', $post );
		$tagged_versions = get_post_meta( $post->ID, 'tagged_versions', true ) ?: [];

		echo '<select id="scan_plugin_version">';
		echo '<option value="" disabled>Select a version</option>';
		echo '<option value="latest">Latest</option>';
		if ( $tagged_versions ) {
			echo '<optgroup label="Tagged versions">';
			foreach ( $tagged_versions as $version ) {
				printf( '<option value="%s">%s</option>', esc_attr( $version ), esc_html( $version ) );
			}
			echo '</optgroup>';
		}
		if ( $attachments ) {
			echo '<optgroup label="ZIPs">';
			foreach ( $attachments as $zip_file ) {
				$file = basename( get_attached_file( $zip_file->ID ) );
				printf( '<option value="%s">%s</option>', esc_attr( $file ), esc_html( $file ) );
			}
			echo '</optgroup>';
		}
		echo '</select>';

		echo '<div id="scan_plugin_output">' . ( $output ?: '<p class="placeholder">Loading...</p>' ) . '</div>';
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

		$version = wp_unslash( $_REQUEST[ 'version' ] ?? '' );

		wp_send_json_success( self::get_scan_output_cached( $post_id, $version ) );

	}

	/**
	 * Return the output of a scan as a string, with caching.
	 */
	public static function get_scan_output_cached( $post_id, $version = '', $bail_if_not_cached = false ) {
		$post_id = intval( $post_id );
		if ( $post_id < 1 ) {
			return false;
		}

		$transient = "code_scan_{$post_id}_{$version}";
		$cached    = get_transient( $transient );

		if ( $cached ) {
			return $cached;
		} elseif ( $bail_if_not_cached ) {
			return false;
		}

		// Set a temporary cached value for 2 minutes, to prevent a stampede of multiple scans running at once.
		set_transient( $transient, '...', 2 * MINUTE_IN_SECONDS );

		ob_start();
		self::display( $post_id, $version );
		$out = ob_get_clean();

		// Cache the results and return it.
		set_transient( $transient, $out, 15 * MINUTE_IN_SECONDS );
		return $out;
	}

}

