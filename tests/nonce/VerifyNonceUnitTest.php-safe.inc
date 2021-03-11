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