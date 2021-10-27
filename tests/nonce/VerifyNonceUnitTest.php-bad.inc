<?php

// Nonce not checked if it's unset
function insecure_nonce_1() {
	if ( isset( $post_data['nonce'] ) && ! wp_verify_nonce( $post_data['nonce'], 'my_nonce' ) ) { // unsafe!
		wp_send_json_error( new WP_Error( 'invalid_code' ) );
	}
}

function insecure_nonce_2() {
	if ( isset( $_REQUEST['my-nonce'] ) && ! wp_verify_nonce( $_REQUEST['my-nonce'], 'post-nonce' ) ) // unsafe!
		die( 'Security check' );
}

function insecure_nonce_3() {
	if ( isset( $_POST['my_nonce_field'] ) && ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['my_nonce_field'] ) ), 'my_nonce' ) ) { // unsafe!
		return;
	}
}

function insecure_nonce_4() {
	wp_verify_nonce( $_POST['my_nonce_field'], 'my-action' ); // unsafe!
}

function insecure_nonce_5() {
	if ( $something || wp_verify_nonce( $_REQUEST['my-nonce'], 'post-nonce' ) ) {
		do_something();
	} else {
		wp_nonce_ays();
	}
}

function insecure_nonce_6() {
	if ( ! isset( $_REQUEST['nonce'] ) && ! wp_verify_nonce( $_REQUEST['nonce'], 'nonce' ) ) return; // unsafe!
}

function insecure_nonce_7() {
	if (!isset($_GET['my-nonce']) && !wp_verify_nonce($_GET['my-nonce'], 'delete')) {
		if (!current_user_can('editor') || !current_user_can('administrator')) {
			return false;
		}
	}
}

function insecure_nonce_8() {
	if ( $something || wp_verify_nonce( $_REQUEST['my-nonce'], 'post-nonce' ) )
		do_something();
	else
		wp_nonce_ays();
}