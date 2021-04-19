<?php

namespace WordPressDotOrg\Code_Analysis\sniffs;

use WordPressDotOrg\Code_Analysis\AbstractEscapingCheckSniff;
use PHP_CodeSniffer\Util\Tokens;
use PHP_CodeSniffer\Util\Variables;
use PHPCSUtils\Utils\PassedParameters;

/**
 * Context-aware checks for output escaping.
 */
class OutputEscapingSniff extends AbstractEscapingCheckSniff {

	protected $rule_name = 'UnescapedOutputParameter';

	/**
	 * Override the parent class escaping functions to only allow HTML-safe escapes
	 */
	protected $escapingFunctions = array(
		'esc_html'                   => true,
		'esc_html__'                 => true,
		'esc_html_x'                 => true,
		'esc_html_e'                 => true,
		'esc_attr'                   => true,
		'esc_attr__'                 => true,
		'esc_attr_x'                 => true,
		'esc_attr_e'                 => true,
		'esc_url'                    => true,
		'esc_textarea'               => true,
		'sanitize_text_field'        => true,
		'intval'                     => true,
		'absint'                     => true,
		'json_encode'                => true,
		'wp_json_encode'             => true,
		'htmlspecialchars'           => true,
		'wp_kses'                    => true,
		'wp_kses_post'               => true,
		'wp_kses_data'               => true,
		'tag_escape'                 => true,
	);

	/**
	 * Functions that are often mistaken for escaping functions.
	 */
	protected $notEscapingFunctions = array(
		'addslashes',
		'addcslashes',
		'filter_input',
		'wp_strip_all_tags',
		'esc_url_raw',
	);

	protected $sanitizingFunctions = array();
	protected $unslashingFunctions = array();

	/**
	 * Functions that are neither safe nor unsafe. Their output is as safe as the data passed as parameters.
	 */
	protected $neutralFunctions = array(
		'implode'             => true,
		'join'                => true,
		'array_keys'          => true,
		'array_values'        => true,
		'array_fill'          => true,
		'sprintf'             => true, // Sometimes used to get around formatting table and column names in queries
		'array_filter'        => true,
		'__'                  => true,
		'_x'                  => true,
		'date'                => true,
		'date_i18n'           => true,
		'get_the_date'        => true, // Could be unsafe if the format parameter is untrusted
		'get_comment_time'    => true,
		'get_comment_date'    => true,
		'comments_number'     => true,
		'get_the_category_list' => true, // separator parameter is unescaped
		'get_header_image_tag' => true, // args are unescaped
		'get_the_tag_list'     => true, // args are unescaped
	);

	/**
	 * Functions with output that can be assumed to be safe. Escaping is always preferred, but alerting on these is unnecessary noise.
	 */
	protected $implicitSafeFunctions = array(
		'gmdate'         => true,
		'current_time'   => true,
		'mktime'         => true,
		'get_post_types' => true,
		'get_charset_collate' => true,
		'get_blog_prefix' => true,
		'get_post_stati' => true,
		'get_avatar'     => true,
		'get_search_query' => true,
		'get_bloginfo'   => true, // depends on params
		'get_the_ID'     => true,
		'count'          => true,
		'strtotime'      => true,
		'uniqid'         => true,
		'md5'            => true,
		'sha1'           => true,
		'rand'           => true,
		'mt_rand'        => true,
		'max'            => true,
		'wp_get_attachment_image' => true,
		'post_class'     => true,
		'wp_trim_words'  => true, // calls wp_strip_all_tags()
		'paginate_links' => true,
		'selected'       => true,
		'checked'        => true,
		'get_the_posts_pagination' => true,
		'get_the_author_posts_link' => true,
		'get_the_password_form' => true,
		'get_the_tag_list' => true,
		'get_the_post_thumbnail' => true,
		'get_custom_logo' => true,
		'plugin_dir_url'  => true, // probably safe?
		'admin_url'       => true, // also probably safe?
		'get_admin_url'   => true, // probably?

	);

	/**
	 * $wpdb methods with escaping built-in
	 *
	 * @var array[]
	 */
	protected $safe_methods = array(
	);

	/**
	 * $wpdb methods that require the first parameter to be escaped.
	 *
	 * @var array[]
	 */
	protected $unsafe_methods = array(
	);

	protected $safe_constants = array(
		'ARRAY_A'     => true,
		'OBJECT'      => true,
	);

	/**
	 * Keep track of sanitized and unsanitized variables
	 */
	protected $sanitized_variables = [];
	protected $unsanitized_variables = [];
	protected $assignments = [];

	/**
	 * Used for providing extra context from some methods.
	 */
	protected $methodPtr = null;
	protected $unsafe_ptr = null;
	protected $unsafe_expression = null;


	protected $warn_only_parameters = [
		'$this', // Typically object properties will be initialised safely. Escaping is better but using a warning here helps the signal:noise ratio.
	];



	// Based on the function from wp-includes/wp-db.php
	protected function get_table_from_query( $query ) {
		// Remove characters that can legally trail the table name.
		$query = rtrim( $query, ';/-#' );

		// Allow (select...) union [...] style queries. Use the first query's table name.
		$query = ltrim( $query, "\r\n\t (" );

		// Strip everything between parentheses except nested selects.
		$query = preg_replace( '/\((?!\s*select)[^(]*?\)/is', '()', $query );

		// Quickly match most common queries.
		if ( preg_match(
			'/^\s*(?:'
				. 'SELECT.*?\s+FROM'
				. '|INSERT(?:\s+LOW_PRIORITY|\s+DELAYED|\s+HIGH_PRIORITY)?(?:\s+IGNORE)?(?:\s+INTO)?'
				. '|REPLACE(?:\s+LOW_PRIORITY|\s+DELAYED)?(?:\s+INTO)?'
				. '|UPDATE(?:\s+LOW_PRIORITY)?(?:\s+IGNORE)?'
				. '|DELETE(?:\s+LOW_PRIORITY|\s+QUICK|\s+IGNORE)*(?:.+?FROM)?'
			. ')\s+((?:[0-9a-zA-Z$_.`-]|[\xC2-\xDF][\x80-\xBF])+)/is',
			$query,
			$maybe
		) ) {
			return str_replace( '`', '', $maybe[1] );
		}

		// SHOW TABLE STATUS and SHOW TABLES WHERE Name = 'wp_posts'
		if ( preg_match( '/^\s*SHOW\s+(?:TABLE\s+STATUS|(?:FULL\s+)?TABLES).+WHERE\s+Name\s*=\s*("|\')((?:[0-9a-zA-Z$_.-]|[\xC2-\xDF][\x80-\xBF])+)\\1/is', $query, $maybe ) ) {
			return $maybe[2];
		}

		/*
		 * SHOW TABLE STATUS LIKE and SHOW TABLES LIKE 'wp\_123\_%'
		 * This quoted LIKE operand seldom holds a full table name.
		 * It is usually a pattern for matching a prefix so we just
		 * strip the trailing % and unescape the _ to get 'wp_123_'
		 * which drop-ins can use for routing these SQL statements.
		 */
		if ( preg_match( '/^\s*SHOW\s+(?:TABLE\s+STATUS|(?:FULL\s+)?TABLES)\s+(?:WHERE\s+Name\s+)?LIKE\s*("|\')((?:[\\\\0-9a-zA-Z$_.-]|[\xC2-\xDF][\x80-\xBF])+)%?\\1/is', $query, $maybe ) ) {
			return str_replace( '\\_', '_', $maybe[2] );
		}

		// Big pattern for the rest of the table-related queries.
		if ( preg_match(
			'/^\s*(?:'
				. '(?:EXPLAIN\s+(?:EXTENDED\s+)?)?SELECT.*?\s+FROM'
				. '|DESCRIBE|DESC|EXPLAIN|HANDLER'
				. '|(?:LOCK|UNLOCK)\s+TABLE(?:S)?'
				. '|(?:RENAME|OPTIMIZE|BACKUP|RESTORE|CHECK|CHECKSUM|ANALYZE|REPAIR).*\s+TABLE'
				. '|TRUNCATE(?:\s+TABLE)?'
				. '|CREATE(?:\s+TEMPORARY)?\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?'
				. '|ALTER(?:\s+IGNORE)?\s+TABLE'
				. '|DROP\s+TABLE(?:\s+IF\s+EXISTS)?'
				. '|CREATE(?:\s+\w+)?\s+INDEX.*\s+ON'
				. '|DROP\s+INDEX.*\s+ON'
				. '|LOAD\s+DATA.*INFILE.*INTO\s+TABLE'
				. '|(?:GRANT|REVOKE).*ON\s+TABLE'
				. '|SHOW\s+(?:.*FROM|.*TABLE)'
			. ')\s+\(*\s*((?:[0-9a-zA-Z$_.`-]|[\xC2-\xDF][\x80-\xBF])+)\s*\)*/is',
			$query,
			$maybe
		) ) {
			return str_replace( '`', '', $maybe[1] );
		}

		return false;
	}





	public function is_warning_parameter( $parameter_name ) {
		foreach ( $this->warn_only_parameters as $warn_param ) {
			if ( preg_match( '/^' . preg_quote( $warn_param ) . '(?:\b|$)/', $parameter_name ) ) {
				return true;
			}
		}
		return false;
	}

	public function is_warning_sql( $sql ) {
		foreach ( $this->warn_only_queries as $warn_query ) {
			if ( 0 === strpos( ltrim( $sql, '\'"' ), $warn_query ) ) {
				return true;
			}
		}

		return false;
	}


	/**
	 * Returns an array of tokens this test wants to listen for.
	 *
	 * @return array
	 */
	public function register() {
		return array(
			\T_ECHO,
			\T_PRINT,
			\T_EXIT,
			\T_STRING,
			\T_OPEN_TAG_WITH_ECHO,
			\T_VARIABLE,
		);
	}



}
