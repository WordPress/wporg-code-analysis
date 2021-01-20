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
    public static function display() {
        $zip_file = self::get_latest_zip_path();
        #var_dump( is_readable( $zip_file ) );
        if ( !$zip_file || !is_readable( $zip_file ) ) {
            printf( '<p>Unable to scan %s</p>', $zip_file );
            return false;
        }

        $results = self::get_scan_results_for_zip( $zip_file );

        if ( isset( $results[ 'totals' ] ) ) {
            printf( '<p>Found %d errors and %d warnings in %d files.</p>', $results[ 'totals' ][ 'errors' ], $results[ 'totals' ][ 'warnings' ], count( $results[ 'files' ] ) );
        }

        echo '<pre style="white-space: pre-wrap;">';
        foreach ( $results[ 'files' ] as $filename => $file ) {
            list( $slug, $filename ) = explode( '/', $filename, 2 );
            foreach ( $file[ 'messages' ] as $message ) {
                printf( "%s %s in <a href='https://plugins.trac.wordpress.org/browser/%s/trunk/%s#L%d'>%s line %d</a>\n", $message[ 'type' ], $message[ 'source' ], $slug, $filename, $message[ 'line' ], $filename, $message[ 'line' ] );
                echo $message[ 'message' ] . "\n\n";
            }
        }
        echo '</pre>';

    }

    public static function get_scan_results_for_zip( $zip_file_path ) {

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
        return $result;
    }

    public static function get_latest_zip_path( $post = null ) {
        //TODO: make it so it's possible to specify a tag via a dropdown
        $post = get_post( $post );

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

        // Need to fetch the zip remotely
        $zip_url = Template::download_link( $post );

        $tmp_dir = Filesystem::temp_directory( $post->post_name );
        $zip_file = $tmp_dir . '/' . basename( $zip_url );
        if ( copy( $zip_url, $zip_file ) ) {
            return $zip_file;
        }

    }
}

