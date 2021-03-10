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