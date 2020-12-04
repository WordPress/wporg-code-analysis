<?php

// This is not a real plugin. Do not try to run this code.
// This merely contains intentionally INSECURE and UNSAFE examples of php code for testing.

// TODO: turn this into unit tests

return false; // Seriously, this should never be run.

function insecure_wpdb_query_1( $foo ) {
	global $wpdb;

	// 1. Unescaped query, string concat
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $foo . "' LIMIT 1" ); // unsafe
}


function insecure_wpdb_query_2( $foo ) {
	global $wpdb;

	// 2. Unescaped query, interpolated string
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$foo' LIMIT 1" ); // unsafe
}


function insecure_wpdb_query_3( $foo ) {
	global $wpdb;

	// 3. Unescaped query, interpolated with {}
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '{$foo}' LIMIT 1" ); // unsafe
}

	
function insecure_wpdb_query_4( $foo ) {
	global $wpdb;

	// 4. Unescaped query, interpolated array
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$foo[1]' LIMIT 1" ); // unsafe
}

function insecure_wpdb_query_5( $foo ) {
	global $wpdb;

	// 5. Unescaped query, superglobal
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $_POST['foo'] . "' LIMIT 1" ); // unsafe
}

function insecure_wpdb_query_6( $foo ) {
	global $wpdb;

	// 6. Unescaped object property, concat
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $foo->bar . "' LIMIT '" ); // unsafe
}

function insecure_wpdb_query_7( $foo ) {
	global $wpdb;

	// 7. Unescaped query, concat unknown function
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . baz( $foo ) . "' LIMIT '" ); // unsafe
}
