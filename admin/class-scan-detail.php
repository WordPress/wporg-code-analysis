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

	protected function find_array_key_after( $array, $key ) {
		$keys = array_keys( $array );
		$pos = array_search( $key, $keys );
		if ( false === $pos ) {
			return false;
		}
		return $keys[ $pos + 1 ] ?? false;
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

		printf(
			'<h1>Scan Detail for %s</h1>',
			esc_html( $post->post_title )
		);
		printf(
			'<p>Version: %s<br/>File: %s</p>',
			esc_html( $version ),
			esc_html( $file )
		);
		printf(
			'<p>Found %d errors and %d warnings in %d (%0.2fs).</p>',
			$results[ 'totals' ][ 'errors' ],
			$results[ 'totals' ][ 'warnings' ],
			$file,
			$results[ 'time_taken' ]
		);

		#echo '<pre style="white-space: pre-wrap;">';
		echo '<form method="GET">';
		echo '<select name="file">';
		echo '<option value="" disabled>Select a file</option>';
		if ( $results['unzipdir'] ) {
			$dir = new \RecursiveDirectoryIterator($results['unzipdir']);
			$files = new \RecursiveIteratorIterator($dir);

			foreach($files as $_file){
				if ( $_file->isDir() ) {
					continue;
				}
				$filepath = $_file->getPath(). '/' . $_file->getFileName();
				if ( substr( $filepath, 0, strlen( $results['unzipdir'] ) ) === $results['unzipdir'] ) {
					$filepath = substr( $filepath, strlen( $results['unzipdir'] ) );
				}
				$filepath = ltrim( $filepath, '/' );
				$value = $filepath;

				if ( substr( $filepath, 0, strlen( $post->post_name ) ) === $post->post_name ) {
					$filepath = substr( $filepath, strlen( $post->post_name ) );
				}
				echo '<option value="' . esc_attr( $value ) . '" ' . selected( $value, $filepath, false ) . '>' . esc_html( $filepath ) . '</option>';
			}
		}
		echo '</select>';
		echo '<input type="hidden" name="post_id" value="' . esc_attr( $post_id ) . '">';
		echo '<input type="hidden" name="version" value="' . esc_attr( $version ) . '">';
		echo '<input type="submit" value="Go">';
		echo '</form>';
		#echo '</pre>';

		if ( isset( $results[ 'realfile' ] ) ) {
			$first_line = 1;
			$line_number = 0;
			$code_class = 'language-php';

			$messages_by_line = array();
			$highlight_lines = array();

			foreach ( $results[ 'files' ][ $file ][ 'messages' ] as $message ) {
				$messages_by_line[ intval($message[ 'line' ]) ][] = $message;
				$highlight_lines[] = intval($message[ 'line' ]);
				if ( preg_match_all( '/ at line (\d+):/', $message[ 'message' ], $matches, PREG_PATTERN_ORDER ) ) {
					$highlight_lines = array_merge( $highlight_lines, array_map( 'intval', $matches[1] ) );
				}
			}

			sort( $highlight_lines );
			$highlight_lines = array_unique( $highlight_lines );

			$next_message_line = array_key_first( $messages_by_line );

			echo '<a href="#line-' . intval( $next_message_line ) . '" class="button-secondary left">Next</a>';
			echo '<pre class="line-numbers" data-start="' . intval($first_line) . '" data-line-offset="' . intval($first_line) . '" data-line="' . join(',', $highlight_lines) . '"><code language="php" class="' . $code_class . '">';

			$fp = fopen( $results['realfile'], 'r');
			while ( $fp && !feof( $fp ) ) {
				$line = fgets( $fp ); // length limit?
				$line = str_replace( array("\r\n", "\r", "\n"), "\n", $line ); // normalize EOLs
				++ $line_number;

				if ( isset( $messages_by_line[$line_number] ) ) {
					$type = strtolower($messages_by_line[$line_number][0]['type']);
					echo '<mark id="line-' . intval( $line_number ) . '" class="message-' . esc_attr($type) . '"><b>' . esc_html( $line ) . '</b></mark>';
					echo '</code></pre>';
					foreach ( $messages_by_line[$line_number] as $msg ) {
						echo '<div class="message-detail message-' . esc_attr( strtolower( $msg[ 'type' ] ) ) . '">';
						echo '<p>' . esc_html( $msg[ 'type' ] ) . esc_html( $msg[ 'source' ] ) . ' on line ' . esc_html( $line_number ) . '</p>';
						echo '<pre>' . esc_html( $msg[ 'message' ] ) . '</pre>';
						#var_dump( $msg );
						echo '</div>';
					}

					$highlight_lines = array_filter( $highlight_lines,
						fn( $line ) => $line > $line_number );

					if ( $next_message_line = $this->find_array_key_after( $messages_by_line, $line_number ) ) {
						echo '<a href="#line-' . intval( $next_message_line ) . '" class="button-secondary left">Next</a>';
					}

					echo '<pre class="line-numbers" data-start="' . intval($line_number + 1) . '" data-line-offset="' . intval($line_number) . '" data-line="' . join(',', $highlight_lines) . '"><code language="php" class="' . $code_class . '">';

				} else {
					echo esc_html( $line );
				}
			}
			echo '</code></pre>';

			/*
			foreach ( $messages_by_line as $line => $message ) {
				echo '<div class="message-detail" id="message-' . intval( $line ) . '" data-line="' . intval( $line ) . '">';
				foreach ( $message as $msg ) {
					echo '<div class="message-' . esc_attr( $msg[ 'type' ] ) . '">';
					echo '<p>' . esc_html( $msg[ 'message' ] ) . '</p>';
					echo '</div>';
				}
				echo '</div>';
			}*/
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