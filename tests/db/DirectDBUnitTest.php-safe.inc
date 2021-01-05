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

function secure_wpdb_query_10( $foo ) {

	global $wpdb;

	// 5. Safe query, prepare()
	$wpdb->get_results( $wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE foo = %s LIMIT 1", $foo ), ARRAY_A ); // safe
}

function secure_wpdb_query_11( $foo ) {

	global $wpdb;

	// 5. Safe query, $this->wpdb->prepare()
	$this->wpdb->get_results( $this->wpdb->prepare( "SELECT * FROM $wpdb->posts WHERE foo = %s LIMIT 1", $foo ) ); // safe
}

function false_positive_1() {
	// https://plugins.trac.wordpress.org/browser/mailoptin/trunk/vendor/pelago/emogrifier/Classes/Emogrifier.php#L368
	// Not a wpdb->query() call at all

	$nodesMatchingCssSelectors = $xPath->query($this->translateCssToXpath($cssRule['selector']));
}

function false_positive_2( $email ) {
	// https://plugins.trac.wordpress.org/browser/gdpr-framework/trunk/src/Components/WordpressComments/WordpressComments.php#L205
	// Also not a wpdb query (it's WP_Query!)

	$query = new \WP_Comment_Query();

	$comments = $query->query(
			array(
					'author_email'       => $email,
					'include_unapproved' => true,
					'status'             => 'all',
			)
	);
}

function false_positive_3() {
	// https://plugins.trac.wordpress.org/browser/cherry-services-list/trunk/admin/includes/class-cherry-services-meta.php#L109
	$post_id         = absint( $_REQUEST['post'] );

	$post_meta_infos = $wpdb->get_results(
				"SELECT meta_key, meta_value FROM $wpdb->postmeta WHERE post_id = $post_id"
	);
}

function false_positive_4() {
	define( 'MPS_A_CONSTANT', 'foo' );
	global $wpdb;

	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE foo = '" . MPS_A_CONSTANT . "' LIMIT 1" ); // safe-ish, if we assume constants are always literal constants and never derived

}

function false_positive_5() {
	global $wpdb;

	$table = $wpdb->base_prefix . 'foobar';
	$wpdb->query( "SELECT * FROM $table WHERE foo=1 LIMIT 1" ); // safe if we're aware $wpdb->base_prefix is pre-sanitized
}

function false_positive_6() {
	global $wpdb;

	// This is safe but tricky to parse!
	$foo = ( isset( $_GET['foo'] ) ? absint( $_GET['foo'] ) : absint( $_POST['foo'] ) );
	$wpdb->query( "SELECT * FROM $wpdb->users WHERE foo = '" . $foo . "' LIMIT 1" ); // safe
}

function false_positive_7() {
	global $wpdb;

	// A bug in handling $wpdb->prepare() with multiple args?
	$wpdb->query( $wpdb->prepare("UPDATE {$wpdb->posts} SET post_content = REPLACE(post_content, %s, %s)", $from_url, $to_url) ); // safe
}