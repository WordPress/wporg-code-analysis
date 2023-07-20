<?php
namespace WordPressdotorg\Code_Analysis\Admin;

use WordPressDotOrg\Code_Analysis\PHPCS;
use WordPressDotOrg\Code_Analysis\Scanner;

class Scan_Detail {
	/**
	 * Fetch the instance of the Scan_Detail class.
	 */
	public static function instance() {
		static $instance = null;

		return ! is_null( $instance ) ? $instance : $instance = new self();
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		add_action( 'admin_menu', array( $this, 'add_to_menu' ) );
		#add_action( 'admin_page_access_denied', array( $this, 'admin_page_access_denied' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Add the Scan Detail tool to the Tools menu.
	 */
	public function add_to_menu() {
		$hook = add_submenu_page(
			'plugin-tools',
			__( 'Scan Detail', 'wporg-plugins' ),
			__( 'Scan Detail', 'wporg-plugins' ),
			'plugin_review',
			'scan-detail',
			array( $this, 'show_scan' )
		);
	}

	public function enqueue_assets( $page ) {
		if ( 'plugin-tools_page_scan-detail' !== $page ) {
			return;
		}
		wp_enqueue_script( 'code-scan-prism-js', plugins_url( 'prism.js', __FILE__ ), array(), 3 );
		wp_enqueue_script( 'code-scan-detail-js', plugins_url( 'detail.js', __FILE__ ), array( 'jquery' ), 3 );
		wp_enqueue_style( 'code-scan-prism-css', plugins_url( 'prism.css', __FILE__ ), array(), 1 );
		wp_enqueue_style( 'code-scan-detail-css', plugins_url( 'detail.css', __FILE__ ), array(), 1 );
	}

	public function show_scan() {
		$post_id = $_REQUEST['post_id'] ?? null;
		$version = $_REQUEST['version'] ?? '';
		$file = $_REQUEST['file'] ?? null;

		if ( ! $post_id || ! $file ) {
			echo '<p>Missing post ID or file.</p>';
			return;
		}

		$post = get_post( $post_id );

		$include_warnings = true;

		// TODO: cache this?
		$results = Scanner::get_scan_results_for_plugin( $post, $version, $file );

		#echo '<pre style="white-space: pre-wrap;">';
		#var_dump( $version, $file, $results );
		#echo '</pre>';

		if ( isset( $results[ 'realfile' ] ) ) {
			$first_line = 0;
			$line_number = 0;
			$code_class = 'language-php';

			$messages_by_line = array();

			foreach ( $results[ 'files' ][ $file ][ 'messages' ] as $message ) {
				$messages_by_line[ $message[ 'line' ] ][] = $message;
			}

			$highlight_lines = array_map( 'intval', array_keys( $messages_by_line ) );

			echo '<pre class="line-numbers" data-start="' . intval($first_line) . '" data-line-offset="' . intval($first_line) . '" data-line="' . join(',', $highlight_lines) . '"><code language="php" class="' . $code_class . '">';
			$fp = fopen( $results['realfile'], 'r');
			while ( $fp && !feof( $fp ) ) {
				$line = fgets( $fp ); // length limit?
				++ $line_number;

				if ( isset( $messages_by_line[$line_number] ) ) {
					$type = $messages_by_line[$line_number][0]['type'];
					echo '<mark id="line-' . intval( $line_number ) . '" class="' . esc_attr($type) . '"><b>' . rtrim( esc_html( $line ) ) . '</b></mark>';
				} else {
					echo rtrim( esc_html( $line ) );
				}

				echo "\n";
			}
			echo '</code></pre>';

			foreach ( $messages_by_line as $line => $message ) {
				echo '<div class="message-detail" id="message-' . intval( $line ) . '" data-line="' . intval( $line ) . '">';
				foreach ( $message as $msg ) {
					echo '<div class="message-' . esc_attr( $msg[ 'type' ] ) . '">';
					echo '<p>' . esc_html( $msg[ 'message' ] ) . '</p>';
					echo '</div>';
				}
				echo '</div>';
			}
		}

		if ( ! $results || empty( $results[ 'files' ] ) ) {
			printf( '<p>Nothing to scan.</p>' );
			return false;
		}

		if ( empty( $results[ 'files' ][ $file ] ) ) {
			printf( '<p>File not found.</p>' );
			return false;
		}

	}
}