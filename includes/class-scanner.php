<?php
namespace WordPressDotOrg\Code_Analysis;
use WordPressdotorg\Plugin_Directory\Tools\Filesystem;
use WordPressdotorg\Plugin_Directory\Email\Generic_To_Committers;
use WordPressdotorg\Plugin_Directory\Template;
use WordPressdotorg\Plugin_Directory\Tools;
use WP_Error;

defined( 'WPINC' ) || die();

class Scanner {

	public static function get_scan_results_for_plugin( $post, $version = 'latest' ) {
		$zip_file = self::get_zip_path( $post, $version );
		if ( ! $zip_file || ! is_readable( $zip_file ) ) {
			return false;
		}

		return self::get_scan_results_for_zip( $zip_file );
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

					// Determine how many whitespace characters are prefixed on the lines.
					$strip_chars = (int)array_reduce(
						$context,
						function( $carry, $item ) {
							if ( ! trim( $item ) || ! preg_match( '!^(\s+)\S!', $item, $m ) ) {
								return $carry;
							}
							$prefixed_whitespace = strlen( $m[1] ?? '' );

							return is_null( $carry ) ? $prefixed_whitespace : min( $carry, $prefixed_whitespace );
						}
					);

					foreach ( $context as $line => $data ) {
						// Lines are indexed from 0 in file(), but from 1 in PHPCS.
						$result['files'][ $filename ]['messages'][ $i ]['context'][ $line + 1 ] = rtrim( substr( $data, $strip_chars ), "\r\n" );
					}
				}
			}
		}

		$result['hash'] = self::get_result_hash( $result );

		//TODO: cache this?

		return $result;
	}

	public static function get_zip_path( $post = null, $version = 'latest' ) {
		//TODO: make it so it's possible to scan a specific ZIP based on $version
		$post = get_post( $post );

		// Scan the published ZIP file.
		if ( in_array( $post->post_status, [ 'publish', 'disabled', 'closed' ] ) ) {
			// Need to fetch the zip remotely from the downloads server.
			$zip_url = Template::download_link( $post, $version );

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

	protected static function get_result_hash( $results ) {
		$hash = '';

		// Generate a hash of the warning/error the violated rule and the code responsible.
		// This results in a consistent hash even if the line numbers change.
		foreach ( $results['files'] as $file => $details ) {
			foreach ( $details['messages'] as $message ) {
				$hash .= sha1( $message['type'] . $message['source'] . implode( ' ', $message['context'] ), true );
			}
		}

		return $hash ? sha1( $hash ) : 'all-clear';
	}

	public static function scan_imported_plugin( $plugin, $stable_tag, $old_stable_tag, $changed_svn_tags, $svn_revision ) {
		$to_scan = array_unique( array_merge(
			array( $stable_tag ), // always scan the current stable release
			$changed_svn_tags
		) );

		$already_notified     = get_post_meta( $plugin->ID, '_scan_notified', true ) ?: [];
		$hashes_seen_this_run = [];

		// Clean out any old scan notifications.
		// Re-send the scan results after a month if a change is made.
		foreach ( $already_notified as $key => $time ) {
			if ( $time < time() - MONTH_IN_SECONDS ) {
				unset( $already_notified[ $key ] );
			}
		}

		foreach ( $to_scan as $tag ) {
			$result = self::get_scan_results_for_plugin( $plugin, $tag );
			$hash   = $result['hash'];
			$key    = $tag . ':' . $hash; // Unique hash to identify whether this result has been seen before.

			// Check to see if the plugin authors have been notified about this result yet.
			if ( isset( $already_notified[ $key ] ) ) {
				continue;
			}

			// Record it as the author being notified.
			$already_notified[ $key ] = time();

			// Don't notify for two different tags with the same result.
			if ( isset( $hashes_seen_this_run[ $hash ] ) ) {
				continue;
			}
			$hashes_seen_this_run[ $hash ] = true;

			// Only notify when there's errors.
			if ( $result['totals']['errors'] > 0 ) {
				self::notify_plugin_authors( $plugin, $result, $tag );
			}
		}

		update_post_meta( $plugin->ID, '_scan_notified', $already_notified );
	}

	public static function notify_plugin_authors( $plugin, $results, $tag ) {
		ob_start();

		printf(
			"Found %d errors in %d files.\n\n",
			$results[ 'totals' ][ 'errors' ],
			count( $results[ 'files' ] )
		);

		$last_file = false;
		foreach ( $results[ 'files' ] as $pathname => $file ) {
			list( $slug, $filename ) = explode( '/', $pathname, 2 );
			foreach ( $file[ 'messages' ] as $message ) {
				// Skip warnings for now
				if ( 'WARNING' === $message['type'] ) {
					continue;
				}

				if ( $last_file !== $filename ) {
					printf(
						"File: %s (https://plugins.trac.wordpress.org/browser/%s/%s/%s)\n",
						$filename,
						$plugin->post_name,
						( 'trunk' === $tag ? 'trunk' : 'tags/' . $tag ),
						$filename
					);
					$last_file = $filename;
				}

				// The error/warning
				printf(
					"Line %d - %s %s\n%s\n",
					$message['line'],
					$message['type'],
					$message['source'],
					$message['message']
				);

				if ( $message['context'] ) {
					foreach ( $message['context'] as $line_no => $context_line ) {
						echo $line_no . "\t" . $context_line . "\n";
					}
					echo "\n";
				}
			}
		}

		$body = ob_get_clean();

		$email = new Generic_To_Committers(
			$plugin,
			array(
				'subject' => 'Automated scanning has detected errors in ###PLUGIN###',
				'body'    => $body,
			)
		);

		$email->send();
	}
}