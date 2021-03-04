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

function false_positive_8() {
	global $wpdb;
	$mysql_vars = array(
			'key_buffer_size'    => true,   // Key cache size limit.
			'max_allowed_packet' => false,  // Individual query size limit.
			'max_connections'    => false,  // Max number of client connections.
			'query_cache_limit'  => true,   // Individual query cache size limit.
			'query_cache_size'   => true,   // Total cache size limit.
			'query_cache_type'   => 'ON',   // Query cache on or off.
	);
	$extra_info = array();
	$variables  = $wpdb->get_results( "SHOW VARIABLES WHERE Variable_name IN ( '" . implode( "', '", array_keys( $mysql_vars ) ) . "' )" ); // db call ok; no-cache ok.

}

function secure_wpdb_query_12( $foo ) {
	global $wpdb;

	$bar = array(
		$foo
	);

	// Just like insecure_wpdb_query_15, except we'll escape $bar to make it safe enough
	$bar = esc_sql( $bar );

	$wpdb->get_results( "SELECT * FROM $wpdb->posts WHERE ID IN ('" . implode( "', '", $bar ) . "') LIMIT 1" ); // safe
}

function false_positive_9() {
	global $wpdb;

	$where_statement = implode( ', ', array_map( 'esc_sql', $default_ids ) );
	$wpdb->query( "DELETE FROM {$wpdb->some_table} WHERE ID IN ({$where_statement})" ); // safe
}

function secure_wpdb_query_13( $foo ) {
	global $wpdb;

	$foo = esc_sql( $foo );

	// Each of the elements in $foo was escaped above. We should treat the `foreach` similar to an assignment operator.
	foreach ( $foo as $foo_i ) {
		$wpdb->query( "SELECT * FROM $wpdb->posts WHERE ID = '$foo_i' LIMIT 1" ); // safe
	}
	// Same deal with an explicit index
	foreach ( $foo as $j => $foo_j ) {
		$wpdb->query( "SELECT * FROM $wpdb->posts WHERE ID = '$foo_j' LIMIT 1" ); // safe
	}
}

function false_positive_10() {
	$sql = "SELECT COUNT(*) FROM `" . $this->wpdb->comments . "` WHERE comment_type = 'trackback';";

	$total = $this->wpdb->get_var($sql);
}

function false_positive_11() {
	global $wpdb;
	$now = $this->datetime();
	$sql = $wpdb->prepare("SELECT COUNT(*) FROM {$this->table} WHERE available_at <= %s", $now);
	return $wpdb->get_var($sql);
}

function secure_wpdb_query_14( $foo ) {

	$foo = something();
	$foo = esc_sql( something () );

	$wpdb->query( "SELECT * FROM $wpdb->posts WHERE ID = '$foo'" ); // safe
}

function secure_wpdb_query_15() {
	// Example from WooCommerce
		/** @var wpdb $wpdb */
		global $wpdb;
		$query = "SELECT a.action_id FROM {$wpdb->actionscheduler_actions} a";
		$args  = [];
		if ( ! empty( $params[ 'group' ] ) ) {
			$query  .= " INNER JOIN {$wpdb->actionscheduler_groups} g ON g.group_id=a.group_id AND g.slug=%s";
			$args[] = $params[ 'group' ];
		}
		$query  .= " WHERE a.hook=%s";
		$args[] = $hook;
		if ( ! is_null( $params[ 'args' ] ) ) {
			$query  .= " AND a.args=%s";
			$args[] = $this->get_args_for_query( $params[ 'args' ] );
		}

		$order = 'ASC';
		if ( ! empty( $params[ 'status' ] ) ) {
			$query  .= " AND a.status=%s";
			$args[] = $params[ 'status' ];

			if ( self::STATUS_PENDING == $params[ 'status' ] ) {
				$order = 'ASC'; // Find the next action that matches.
			} else {
				$order = 'DESC'; // Find the most recent action that matches.
			}
		}

		$query .= " ORDER BY scheduled_date_gmt $order LIMIT 1";

		$query = $wpdb->prepare( $query, $args );

		$id = $wpdb->get_var( $query );
}

function false_positive_12( $tax_rate_id, $output_type = ARRAY_A ) {
	global $wpdb;

	return $wpdb->get_row(
		$wpdb->prepare(
			"
				SELECT *
				FROM {$wpdb->prefix}woocommerce_tax_rates
				WHERE tax_rate_id = %d
			",
			$tax_rate_id
		),
		$output_type
	);
}

function secure_wpdb_query_16() {
	// Test concatenation

	global $wpdb;

	$sql = "SELECT * FROM $wpdb->users WHERE 1=1"; // safe so far..
	$foo = esc_sql( $foo );
	$sql .= " AND display_name = '$foo'"; // also safe here
	$sql .= $wpdb->prepare( ' LIMIT %d, %d', $offset, $limit ); // also safe here

	$result = $wpdb->get_row( $sql ); // safe!
}

function false_positive_13( $comment_ids ) {
	$format_string = implode( ", ", array_fill( 0, count( $comment_ids ), '%s' ) );
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->comments} WHERE comment_id IN ( " . $format_string . " )", $comment_ids ) );
}

function false_positive_14() {
	$wpdb->query( sprintf( "DROP TABLE IF EXISTS %s",
		$wpdb->prefix . 'contact_form_7' ) );
}

function false_positive_15() {
	$media_id_string = join( ',', array_filter( array_map( 'absint', $media_results['media_ids'] ) ) );
	if ( $media_id_string ) {
		// Yes - this is really how wp-admin does it.
		$wpdb->query( $wpdb->prepare(
			"UPDATE $wpdb->posts SET post_parent = %d WHERE post_type = 'attachment' AND ID IN ( $media_id_string )",
			$post_id
		) );
	}
}

function false_positive_16() {
	// array_walk() should be handled similar to array_map().
	array_walk( $exclude, 'esc_sql' );
	$where = sprintf(
			"WHERE comment_type NOT IN ( '%s' )",
			implode( "','", $exclude )
	);

	$count = $wpdb->get_results(
		"SELECT comment_approved, COUNT(*) AS num_comments
				FROM $wpdb->comments
					{$where}
					GROUP BY comment_approved
			"
	);
}

// From readme.md
function secure_but_not_recommended( $ids, $status ) {
	global $wpdb;
	$in = "'" . join( "','", array_map( 'esc_sql', $ids) ) . "'";
	$sql = "SELECT * FROM $wpdb->posts WHERE ID IN ($in)";
	return $wpdb->get_results( $wpdb->prepare( $sql . " AND post_status = %s", $status ) );
}

function false_positive_17() {
	$meta_id = 'meta_id';
	$sql = 'SELECT ' . $meta_id . ' as id, meta_value FROM ' . $table . '
	WHERE meta_value like %s';

	$sql = $wpdb->prepare($sql, '%' . $url . '%');

	$rsmeta = $wpdb->get_results($sql, ARRAY_A);
}