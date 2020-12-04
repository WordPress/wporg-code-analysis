<?php

// This is not a real plugin. Do not try to run this code.
// This merely contains intentionally INSECURE and UNSAFE examples of php code for testing.

return false; // Seriously, this should never be run.

function secure_wpdb_query_1( $foo ) {

	global $wpdb;

	// 1. Safe query, esc_sql
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . esc_sql( $foo ) . "' LIMIT 1" ); // safe
}



function secure_wpdb_query_2( $foo ) {

	global $wpdb;

	// 2. Safe query, esc_sql interpolated
	$esc_foo = esc_sql( $foo );
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$esc_foo' LIMIT 1" ); // safe
}


function secure_wpdb_query_3( $foo ) {

	global $wpdb;

	// 3. Safe query, esc_sql interpolated with {}
	$esc_foo = esc_sql( $foo );
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '{$esc_foo}' LIMIT 1" ); // safe
}


function secure_wpdb_query_4( $foo ) {

	global $wpdb;

	// 4. Safe query, interpolated array
	// Note that this might be passing by accident. esc_sql() does handle arrays.
	$esc_foo = esc_sql( $foo );
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$esc_foo[1]' LIMIT 1" ); // safe
}

function secure_wpdb_query_5( $foo ) {

	global $wpdb;

	// 5. Safe query, prepare()
	$wpdb->query( $wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE foo = %s LIMIT 1", $foo ) ); // safe
}

function secure_wpdb_query_6( $foo ) {

	global $wpdb;

	// 6. Safe query, separate prepare()
	$sql = $wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE foo = %s LIMIT 1", $foo );
	$wpdb->query( $sql ); // safe

}

function secure_wpdb_query_7( $foo ) {

	global $wpdb;

	// 7. Safe query, (int)
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . (int) $foo . "' LIMIT 1" ); // safe
}

function secure_wpdb_query_8( $foo ) {

	global $wpdb;

	// 8. Safe query, object property
	$esc->foo = esc_sql( $foo );
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$esc->foo' LIMIT 1" ); // safe
}

function secure_wpdb_query_9( $foo ) {

	global $wpdb;

	// 9. Safe query, complex variable
	$esc[1]->foo = esc_sql( $foo );
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '{$esc[1]->foo}' LIMIT 1" ); // safe
}

