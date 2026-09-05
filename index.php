<?php
/**
 * Plugin name: WordPress.org Code Analysis
 * Description: Tools for analyzing plugin and theme code.
 * Version:     0.1
 * Author:      WordPress.org
 * Author URI:  http://wordpress.org/
 * License:     GPLv2 or later
 */

namespace WordPressDotOrg\Code_Analysis;

defined( 'WPINC' ) || die();

define( __NAMESPACE__ . '\PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( __NAMESPACE__ . '\PLUGIN_URL', plugins_url( '/', __FILE__ ) );

/**
 * Actions and filters.
 */
add_action( 'plugins_loaded', __NAMESPACE__ . '\load_files' );

/**
 * Load the other PHP files for the plugin.
 *
 * @return void
 */
function load_files() {
	require PLUGIN_DIR . 'includes/class-phpcs.php';
	require PLUGIN_DIR . 'includes/class-scanner.php';
	require PLUGIN_DIR . 'admin/class-scan-metabox.php';
	require PLUGIN_DIR . 'admin/class-scan-detail.php';

	// Load this early so we can use the menu hooks.
	if ( defined( 'WP_ADMIN' ) && WP_ADMIN ) {
		Admin\Scan_Detail::instance();
	}
}

function register_admin_metabox( $post_type, $post ) {
	if ( 'plugin' !== $post_type ) {
		return;
	}

	// Only load the metabox if the plugin directory plugin is active
	if ( !class_exists( '\WordPressDotOrg\Plugin_Directory\Plugin_Directory' ) ) {
		return;
	}

	add_meta_box(
		'code-scanner',
		__( 'Code Scanner', 'wporg-plugins' ),
		array( __NAMESPACE__ . '\Admin\Scan_Metabox', 'maybe_display_ajax' ),
		'plugin', 'normal', 'high'
	);

	wp_enqueue_script( 'code-scan-metabox-js', plugins_url( 'admin/metabox.js', __FILE__ ), array( 'wp-util' ), 3 );
	wp_enqueue_style( 'code-scan-metabox-css', plugins_url( 'admin/metabox.css', __FILE__ ), array(), 1 );
	wp_enqueue_script( 'code-scan-prism-js', plugins_url( 'admin/prism.js', __FILE__ ), array(), 3 );
	wp_enqueue_style( 'code-scan-prism-css', plugins_url( 'admin/prism.css', __FILE__ ), array(), 1 );
}

add_action( 'add_meta_boxes', __NAMESPACE__ . '\register_admin_metabox', 10, 2 );
add_filter( 'wp_ajax_scan-plugin', array( __NAMESPACE__ . '\Admin\Scan_Metabox', 'get_ajax_response' ) );

// TODO: Async this?
add_action( 'wporg_plugins_imported', array( __NAMESPACE__ . '\Scanner', 'scan_imported_plugin' ), 10, 5 );