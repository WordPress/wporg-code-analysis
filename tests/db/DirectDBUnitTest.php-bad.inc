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

function insecure_wpdb_query_8( $foo ) {
	global $wpdb;

	// 7. Unescaped query, $this->wpdb
	$this->wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $foo . "' LIMIT '" ); // unsafe
}

function insecure_wpdb_query_9( $foo ) {

	global $wpdb;

	// 9. Complex variable that is only partly escaped
	$esc[1]->foo = esc_sql( $foo );
	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '{$esc[2]->foo}' LIMIT 1" ); // unsafe
}

function insecure_wpdb_query_10( $foo ) {
	global $wpdb;

	// 7. Unescaped query, prefixed with a constant
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . SOME_CONSTANT . $foo . "' LIMIT '" ); // unsafe
}

function insecure_wpdb_query_11( $foo ) {
	global $wpdb;

	$table = $wpdb->base_prefix . $foo;
	$wpdb->query( "SELECT * FROM $table WHERE foo=1 LIMIT 1" ); // unsafe because of $foo
}

function insecure_wpdb_query_12() {
	global $wpdb;

	// This looks safe at first glance
	$foo = ( isset( $_GET['foo'] ) ? absint( $_GET['foo'] ) : $_POST['foo'] );
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $foo . "' LIMIT 1" ); // unsafe
}

function false_negative_1() {
	global $wpdb;

	// https://plugins.trac.wordpress.org/browser/automatic-domain-changer/trunk/auto-domain-change.php#L366
	// This wasn't caught for some reason
	$sql = 'UPDATE ' . $t . ' SET ' . implode( ',', $sets ) . ' WHERE `' . $id . '`=' . $row[ $id ] . ' LIMIT 1;';
	$wpdb->get_results($sql); // unsafe
}

function false_negative_2() {
	// https://plugins.trac.wordpress.org/browser/woo-wallet/trunk/includes/admin/class-woo-wallet-transaction-details.php#L100
	// This was caught in earlier revs but recently regressed
	$user_id = filter_input(INPUT_GET, 'user_id' );
	$this->total_count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->base_prefix}woo_wallet_transactions WHERE user_id={$user_id}" );
}

function insecure_wpdb_query_13( $foo ) {
	global $wpdb;

	$foo = not_an_escaping_function( $foo );
	$bar = $wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $foo . "' LIMIT 1" ); // unsafe
}

function insecure_wpdb_query_14() {
	// Cribbed from some real code
	global $wpdb;

	parse_str( $_REQUEST['order'], $data );

	if ( is_array( $data ) ) {
			$id_arr = array( );
			foreach ( $data as $key => $values ) {
					foreach ( $values as $position => $id ) {
							$id_arr[] = $id;
					}
			}


			$menu_order_arr = array( );
			foreach ( $id_arr as $key => $id ) {
					$results = $wpdb->get_results( "SELECT menu_order FROM $wpdb->posts WHERE ID = " . $id ); // unsafe
			}

	}
}

function insecure_wpdb_query_14() {
	global $wpdb;

	$wpdb->get_results( "SELECT * FROM {$this->getPrefix()}_table WHERE 1=1 LIMIT 1" ); // unsafe but a warning rather than an error
}

function insecure_wpdb_query_15( $foo ) {
	global $wpdb;

	$bar = array(
		$foo
	);

	$wpdb->get_results( "SELECT * FROM $wpdb->posts WHERE ID IN ('" . implode( "', '", $bar ) . "') LIMIT 1" ); // unsafe
}

function insecure_wpdb_query_16( $foo ) {
	global $wpdb;

	$bar = $_POST['bad'];

	// $foo is correctly escaped here, but variables in the left hand side of a prepare() are unsafe!
	$wpdb->query( $wpdb->prepare( "SELECT * FROM $wpdb->users WHERE bar='$bar' AND foo=%s", $foo  ) ); // unsafe
}