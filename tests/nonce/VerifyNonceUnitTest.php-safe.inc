<?php

// Example from docs
function safe_example_1() {
	if ( isset( $_REQUEST['_wpnonce'] ) && wp_verify_nonce( $_REQUEST['_wpnonce'], 'wpdocs-my-nonce' ) ) { // safe!
		//do you action
	} else {
		die( __( 'Security check', 'textdomain' ) );
	}
}

// Another doc example
function safe_example_2() {
	$nonce = $_REQUEST['_wpnonce'];
	if ( ! wp_verify_nonce( $nonce, 'my-nonce' ) ) {
		die( __( 'Security check', 'textdomain' ) );
	} else {
		// Do stuff here.
	}
}

function safe_example_3() {
	if ( wp_verify_nonce( $nonce, 'my-nonce' ) ) { // safe since the action is in the first clause
		$result = do_some_stuff();
	} else {
		$result = 'error';
	}

	return $result;
}

function false_positive_1( $nonce ) {
	// Helper function example
	return wp_verify_nonce( $nonce, $this->get_nonce_action() ); // safe
}

function safe_example_4() {
	if ( ( wp_verify_nonce( $nonce, 'my-nonce' ) ) ) {
		do_something();
	} else {
		die();
	}
}

function safe_example_5() {
	$check = wp_verify_nonce(sanitize_text_field($_POST['security']), 'my-nonce');
	if (!$check)
		return;
}

function safe_example_6() {
	$is_valid = ( isset( $_POST[ 'my_nonce' ] ) && wp_verify_nonce( $_POST[ 'my_nonce' ], 'something' ) ) ? true : false;
	return $is_valid;
}

function safe_example_7() {
	if (  wp_verify_nonce( $_REQUEST['_wpnonce'], 'wpdocs-my-nonce-1' ) || wp_verify_nonce( $_REQUEST['_wpnonce'], 'wpdocs-my-nonce-2' ) ) { // safe!
		//do you action
	} else {
		die( __( 'Security check', 'textdomain' ) );
	}
}

function safe_example_8() {
	if (  !wp_verify_nonce( $_REQUEST['_wpnonce'], 'wpdocs-my-nonce-1' ) && !wp_verify_nonce( $_REQUEST['_wpnonce'], 'wpdocs-my-nonce-2' ) ) { // safe!
		die( __( 'Security check', 'textdomain' ) );
	} else {
		// do secure action
	}
}

function safe_example_9() {
	if ( wp_verify_nonce( $nonce, 'my-nonce' ) && $something_else ) {
		// do secure action
	} else {
		die( __( 'Security check', 'textdomain' ) );
	}
}

function safe_example_10() {
	if ( wp_verify_nonce( $nonce, 'my-nonce' ) )
		do_something();
	else
		die;
}

// This is safe because the `wp_verify_nonce()` call is only short-circuited when the function is returning early.
function safe_example_11() {
	if ( ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) || ! wp_verify_nonce( $nonce, 'csf_taxonomy_nonce' ) ) { // safe!
		return;
	}

	// do secure action
}
