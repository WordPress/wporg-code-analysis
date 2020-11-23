<?php

// This is not a real plugin. Do not try to run this code.
// This merely contains intentionally INSECURE and UNSAFE examples of php code for testing.

// TODO: turn this into unit tests

function insecure_wpdb_queries( $foo ) {

	return false; // Seriously, this should never be run.

	global $wpdb;

	// 1. Unescaped query, string concat
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $foo . "' LIMIT 1" ); // unsafe

	// 2. Unescaped query, interpolated string
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$foo' LIMIT 1" ); // unsafe

	// 3. Unescaped query, interpolated with {}
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '{$foo}' LIMIT 1" ); // unsafe
	
	// 4. Unescaped query, interpolated array
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$foo[1]' LIMIT 1" ); // unsafe

	// 5. Unescaped query, superglobal
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $_POST['foo'] . "' LIMIT 1" ); // unsafe

	// 6. Unescaped object property, concat
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $foo->bar . "' LIMIT '" ); // unsafe

	// 7. Unescaped query, concat unknown function
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . baz( $foo ) . "' LIMIT '" ); // unsafe

}

function secure_wpdb_queries( $foo ) {

	return false; // Even though these are "safe" this is not intended to be run.

	global $wpdb;

	// 8. Safe query, esc_sql
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . esc_sql( $foo ) . "' LIMIT 1" ); // safe

	// 9. Safe query, esc_sql interpolated
	$esc_foo = esc_sql( $foo );
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$esc_foo' LIMIT 1" ); // safe

	// 10. Safe query, esc_sql interpolated with {}
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '{$esc_foo}' LIMIT 1" ); // safe

	// 11. Safe query, interpolated array
	// Note that this might be passing by accident. esc_sql() does handle arrays.
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '$esc_foo[1]' LIMIT 1" ); // safe

	// 12. Safe query, prepare()
	$wpdb->query( $wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE foo = %s LIMIT 1", $foo ) ); // safe

	// 13. Safe query, separate prepare()
	$sql = $wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE foo = %s LIMIT 1", $foo );
	$wpdb->query( $sql ); // safe

}
