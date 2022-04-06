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
	$sql = 'SELECT ' . $meta_id . ' as id, meta_value FROM mytable
	WHERE meta_value like %s';

	$sql = $wpdb->prepare($sql, '%' . $url . '%');

	$rsmeta = $wpdb->get_results($sql, ARRAY_A);
}

function false_positive_18() {
	global $wpdb;
	$ratings_max = intval(get_option('postratings_max'));
	$ratings_custom = intval(get_option('postratings_customrating'));
	$min_time = strtotime('-'.$time, current_time('timestamp'));
	$output = '';
	if(!empty($mode) && $mode != 'both') {
			$where = $wpdb->prepare( "$wpdb->posts.post_type = %s", $mode );
	} else {
			$where = '1=1';
	}
	if($ratings_custom && $ratings_max == 2) {
			$order_by = 'ratings_score';
	} else {
			$order_by = 'ratings_average';
	}
	$temp = stripslashes(get_option('postratings_template_mostrated'));
	$sql = $wpdb->prepare(
			"SELECT COUNT($wpdb->ratings.rating_postid) AS ratings_users, SUM($wpdb->ratings.rating_rating) AS ratings_score, ROUND(((SUM($wpdb->ratings.rating_rating)/COUNT($wpdb->ratings.rating_postid))), 2) AS ratings_average, $wpdb->posts.ID FROM $wpdb->posts LEFT JOIN $wpdb->ratings ON $wpdb->ratings.rating_postid = $wpdb->posts.ID WHERE rating_timestamp >= $min_time AND $wpdb->posts.post_password = '' AND $wpdb->posts.post_date < NOW() AND $wpdb->posts.post_status = 'publish' AND $where GROUP BY $wpdb->ratings.rating_postid ORDER BY ratings_users DESC, $order_by DESC LIMIT %d",
			$limit
	);
}

function false_positive_19() {
	$now = new \DateTime();
	$day = (int)$now->format('d');
	$month = (int)$now->format('m');
	$year = (int)$now->format('Y');
	$type = $_POST['type'];

	if( $type === 'review' || $type === 'order' ){

		$product_id = (int)$_POST['product_id'];
		$product = wc_get_product( $product_id );

		if( ! $product ){
			response( false );
		}

		$stats = $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}woomotiv_stats
			WHERE product_id={$product_id} AND popup_type IN ('order' , 'review')
			AND the_day=$day
			AND the_month=$month
			AND the_year=$year
		");
	}

}

function secure_wpdb_query_17() {
	$foo = $_POST['option'] ? 'foo' : 'bar';

	$wpdb->query( "SELECT * FROM $wpdb->mytable WHERE name = '$foo'" ); // safe because $foo is always assigned a literal
}

function secure_wpdb_query_18() {
	// Same but with extra parentheses
	$foo = ( ($_POST['option']) ? 'foo' : 'bar' );

	$wpdb->query( "SELECT * FROM $wpdb->mytable WHERE name = '$foo'" ); // safe because $foo is always assigned a literal
}

function false_positive_20($exclude = array()) {
	$exclude = apply_filters('pta_sus_delete_expired_signups_exclusions', $exclude);
		$sql = "DELETE FROM ".$this->tables['signup']['name']." WHERE %s > ADDDATE(date, 1)";
	if(!empty($exclude)) {
			$clean_ids = array_map('absint', $exclude);
			$exclusions = implode(',', $clean_ids);
				$sql .= " AND id NOT IN ($exclusions)";
		}
		$safe_sql = $this->wpdb->prepare($sql, $this->now);
	return $this->wpdb->query($safe_sql);
}

function false_positive_21() {
    $table = $wpdb->prefix . Database::MY_TABLE;
	$sql   = "SELECT id, conditions FROM $table";
	$rows  = $wpdb->get_results($sql);
}

function false_positive_22( $interval_in_days ) {
	global $wpdb;
	$table_name = $this->get_log_table_name();

	$query              = $wpdb->prepare( "DELETE FROM {$table_name} WHERE sent_date < DATE_SUB( CURDATE(), INTERVAL %d DAY )", $interval_in_days );
	$deleted_rows_count = $wpdb->query( $query );
	return $deleted_rows_count;

}

function false_positive_23() {
	global $wpdb;
	$wpdb->query(
			$wpdb->prepare(
					'INSERT INTO ec_address( `user_id`, `first_name`, `last_name`, `company_name`, `address_line_1`, `address_line_2`, `city`, `state`, `zip`, `country`, `phone` ) VALUES( %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s )',
					$user_id,
					( ( -1 != $billing_first_name_index ) ? $rows[ $i ][ $billing_first_name_index ] : '' ),
					( ( -1 != $billing_last_name_index ) ? $rows[ $i ][ $billing_last_name_index ] : '' ),
					( ( -1 != $billing_company_name_index ) ? $rows[ $i ][ $$billing_company_name_index ] : '' ),
					( ( -1 != $billing_address_line_1_index ) ? $rows[ $i ][ $billing_address_line_1_index ] : '' ),
					( ( -1 != $billing_address_line_2_index ) ? $rows[ $i ][ $billing_address_line_2_index ] : '' ),
					( ( -1 != $billing_city_index ) ? $rows[ $i ][ $billing_city_index ] : '' ),
					( ( -1 != $billing_state_index ) ? $rows[ $i ][ $billing_state_index ] : '' ),
					( ( -1 != $billing_zip_index ) ? $rows[ $i ][ $billing_zip_index ] : '' ),
					( ( -1 != $billing_country_index ) ? $rows[ $i ][ $billing_country_index ] : '' ),
					( ( -1 != $billing_phone_index ) ? $rows[ $i ][ $billing_phone_index ] : '' )
			)
	);
}

function false_positive_24() {
	global $wpdb;
	$wpdb->query( "delete from " . WCSC::table_name() );
	$wpdb->query( "delete from " . WCSC_Error_Logs::table_name() );
}

function false_positive_25( $tables ) {
	global $wpdb;
	// Should be ignored because it's a DROP TABLE.
	$wpdb->query( 'DROP TABLE ' . implode( ',', $tables ) );
}

function false_positive_26( $foo_id ) {
		$query = $this->wpdb->prepare(
					"
					SELECT the_id
					FROM $this->the_table
					WHERE foo_id = %d",
					$foo_id
			);

		return (int) $this->wpdb->get_var( $query );
}

function false_positive_27() {
	$wpdb->query( $wpdb->prepare( "SELECT * FROM $wpdb->foo WHERE foo = %s", ( 1 == $bar ? $foo : '' ) ) );
	$wpdb->query( $wpdb->prepare( "SELECT * FROM $wpdb->foo WHERE foo = %s", $foo );
}

function false_positive_28() {

	$r = $wpdb->prepare( "SELECT * FROM foo WHERE bar = %s", $bar );

	$r = $wpdb->get_results( $r );
}
