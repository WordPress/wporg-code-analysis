<?php

namespace WordPressDotOrg\Code_Analysis\sniffs;

use WordPressCS\WordPress\Sniff;
use PHP_CodeSniffer\Util\Tokens;
use PHP_CodeSniffer\Util\Variables;
use PHPCSUtils\Utils\PassedParameters;

require_once( dirname( dirname( __DIR__ ) ) . '/vendor/autoload.php' );

/**
 * Flag Database direct queries.
 *
 * @link    https://vip.wordpress.com/documentation/vip-go/code-review-blockers-warnings-notices/#direct-database-queries
 *
 * @package WPCS\WordPressCodingStandards
 *
 * @since   0.3.0
 * @since   0.6.0  Removed the add_unique_message() function as it is no longer needed.
 * @since   0.11.0 This class now extends the WordPressCS native `Sniff` class.
 * @since   0.13.0 Class name changed: this class is now namespaced.
 * @since   1.0.0  This sniff has been moved from the `VIP` category to the `DB` category.
 */
class DirectDBSniff extends Sniff {

	/**
	 * Override the parent class escaping functions to only allow SQL-safe escapes
	 */
	protected $escapingFunctions = array(
		'absint'                     => true,
		'floatval'                   => true,
		'intval'                     => true,
		'json_encode'                => true,
		'like_escape'                => true,
		'wp_json_encode'             => true,
		'isset'                      => true,
		'esc_sql'                    => true,
		'wp_parse_id_list'           => true,
	);

	// None of these are SQL safe
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
		'sanitize_text_field' => true, // Note that this does not escape for SQL.
		'array_fill'          => true,
		'sprintf'             => true, // Sometimes used to get around formatting table and column names in queries
		'array_filter'        => true,
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
		'count'          => true,
		'strtotime'      => true,
	);

	/**
	 * $wpdb methods with escaping built-in
	 *
	 * @var array[]
	 */
	protected $safe_methods = array(
		'delete'  => true,
		'replace' => true,
		'update'  => true,
		'insert'  => true,
		'prepare' => true,
	);

	/**
	 * $wpdb methods that require the first parameter to be escaped.
	 *
	 * @var array[]
	 */
	protected $unsafe_methods = array(
		'query'       => true,
		'get_var'     => true,
		'get_col'     => true,
		'get_row'     => true,
		'get_results' => true,
	);

	protected $safe_constants = array(
		'ARRAY_A'     => true,
		'OBJECT'      => true,
	);

	/**
	 * A list of variable names that, if used unescaped in a SQL query, will only produce a warning rather than an error.
	 * For example, 'SELECT * FROM {$table}' is commonly used and typically a red herring.
	 */
	protected $warn_only_parameters = array(
		'$table',
		'$table_name',
		'$column_name',
		'$this', // typically something like $this->tablename
		'$order_by',
		'$orderby',
	);

	/**
	 * A list of SQL query prefixes that with only produce a warning instead of an error if they contain unsafe paramaters.
	 * For example, 'CREATE TABLE $tablename' is often used because there are no clear ways to escape a table name.
	 */
	protected $warn_only_queries = array(
		'CREATE TABLE',
		'SHOW TABLE',
		'DROP TABLE',
		'TRUNCATE TABLE',
	);

	/**
	 * Tokens that indicate the start of a function call or other non-constant string
	 */
	protected $function_tokens = array(
		\T_OBJECT_OPERATOR     => \T_OBJECT_OPERATOR,
		\T_DOUBLE_COLON        => \T_DOUBLE_COLON,
		\T_OPEN_CURLY_BRACKET  => \T_OPEN_CURLY_BRACKET,
		\T_OPEN_SQUARE_BRACKET => \T_OPEN_SQUARE_BRACKET,
		\T_OPEN_PARENTHESIS    => \T_OPEN_PARENTHESIS,
		\T_OBJECT              => \T_OBJECT,
	);

	/**
	 * Keep track of sanitized and unsanitized variables
	 */
	protected $sanitized_variables = [];
	protected $unsanitized_variables = [];
	protected $assignments = [];

	/**
	 * Used by parent class for providing extra context from some methods.
	 */
	protected $i = null;
	protected $end = null;
	protected $methodPtr = null;

	/**
	 * Get the name of the function containing the code at a given point.
	 */
	public function get_function_name( $stackPtr ) {
		$condition = $this->phpcsFile->getCondition( $stackPtr, \T_FUNCTION );
		if ( false !== $condition ) {
			return $this->phpcsFile->getDeclarationName( $condition );
		}
	}

	/**
	 * Get the scope context of the code at a given point.
	 */
	public function get_context( $stackPtr ) {
		if ( $context = $this->phpcsFile->getCondition( $stackPtr, \T_CLOSURE ) ) {
			return $context;
		} elseif ( $context = $this->phpcsFile->getCondition( $stackPtr, \T_FUNCTION ) ) {
			return $context;
		} else {
			return 'global';
		}
	}

	/**
	 * Mark the variable at $stackPtr as being safely sanitized for use in a SQL context.
	 * $stackPtr must point to a T_VARIABLE. Handles arrays and (maybe) object properties.
	 */
	protected function mark_sanitized_var( $stackPtr, $assignmentPtr = null ) {

		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->get_context( $stackPtr );

		$var = $this->get_variable_as_string( $stackPtr );

		$this->sanitized_variables[ $context ][ $var ] = true;

		// Sanitizing only overrides a previously unsafe assignment if it's at a lower level (ie not withing a conditional)
		if ( isset( $this->unsanitized_variables[ $context ][ $var ] ) ) {
			if ( $this->tokens[ $stackPtr ][ 'level' ] === 1 ||
				$this->tokens[ $stackPtr ][ 'level' ] < $this->unsanitized_variables[ $context ][ $var ] ) {
					unset( $this->unsanitized_variables[ $context ][ $var ] );
				}
		}

		if ( $assignmentPtr ) {
			$end = $this->phpcsFile->findEndOfStatement( $assignmentPtr );
			$this->assignments[ $context ][ $var ][ $assignmentPtr ] = $this->phpcsFile->getTokensAsString( $stackPtr, $end - $stackPtr );
		}
	}

	/**
	 * Mark the variable at $stackPtr as being unsafe. Opposite of mark_sanitized_var().
	 * Use this to reset a variable that might previously have been marked as sanitized.
	 */
	protected function mark_unsanitized_var( $stackPtr, $assignmentPtr = null ) {

		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->get_context( $stackPtr );

		$var = $this->get_variable_as_string( $stackPtr );

		unset( $this->sanitized_variables[ $context ][ $var ] );

		$this->unsanitized_variables[ $context ][ $var ] = $this->tokens[ $stackPtr ][ 'level' ];

		if ( $assignmentPtr ) {
			$end = $this->phpcsFile->findEndOfStatement( $assignmentPtr );
			$this->assignments[ $context ][ $var ][ $assignmentPtr ] = $this->phpcsFile->getTokensAsString( $stackPtr, $end - $stackPtr );
		}

	}

	/**
	 * Check if the variable at $stackPtr has been sanitized for SQL in the current scope.
	 * $stackPtr must point to a T_VARIABLE. Handles arrays and (maybe) object properties.
	 */
	protected function is_sanitized_var( $stackPtr ) {
		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->get_context( $stackPtr );

		$var = $this->get_variable_as_string( $stackPtr );

		return $this->_is_sanitized_var( $var, $context );
	}

	/**
	 * Check if the variable named in $var has been safely sanitized in the given context.
	 */
	protected function _is_sanitized_var( $var, $context ) {

		// If it's $wpdb->tablename then it's implicitly safe
		if ( '$wpdb->' === substr( $var, 0, 7 ) || '$this->table' === substr( $var, 0, 12 ) ) {
			return true;
		}

		// If it's ever been set to something unsanitized in this context then we have to consider it unsafe.
		// See insecure_wpdb_query_17
		if ( isset( $this->unsanitized_variables[ $context ][ $var ] ) ) {
			return false;
		}

		if ( isset( $this->sanitized_variables[ $context ][ $var ] ) ) {
			return true;
		}

		// Is it an array or an object? If so, was the whole array sanitized?
		if ( preg_match( '/^([$]\w+)\W/', $var, $matches ) ) {
			$var_array = $matches[1];
			if ( isset( $this->unsanitized_variables[ $context ][ $var_array ] ) ) {
				return false;
			}
			if ( isset( $this->sanitized_variables[ $context ][ $var_array ] ) ) {
				return true;
			}
		}

		return false;
	}

	protected function find_assignments( $stackPtr ) {
		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->get_context( $stackPtr );

		$var = $this->get_variable_as_string( $stackPtr );

		return $this->assignments[ $context ][ $var ];
	}

	protected function unwind_unsafe_assignments( $stackPtr, $limit = 10 ) {
		$_unsafe_ptr = $this->unsafe_ptr;
		$_unsafe_expression = $this->unsafe_expression;
		$this->unsafe_ptr = null;

		if ( --$limit < 0 ) {
			return [];
		}


		$extra_context = [];
		if ( $assignments = $this->find_assignments( $stackPtr ) ) {
			foreach ( array_reverse( $assignments, true ) as $assignmentPtr => $code ) {
				$unsafe_ptr = $this->check_expression( $assignmentPtr );
				if ( $assignmentPtr < $stackPtr && $unsafe_ptr ) {
					$extra_context = array_merge( $extra_context, $this->unwind_unsafe_assignments( $unsafe_ptr + 1, $limit ) );
				}
				if ( $unsafe_ptr ) {
					$how = 'unsafely';
				} else {
					$how = 'safely';
				}
				$extra_context[] = sprintf( "%s assigned %s at line %d:\n %s", $this->get_variable_as_string( $stackPtr ), $how, $this->tokens[ $assignmentPtr ][ 'line' ], $code );

				if ( $more_vars = $this->find_variables_in_expression( $assignmentPtr ) ) {
					foreach ( $more_vars as $var_name ) {
						$context = $this->get_context( $assignmentPtr );
						if ( isset( $this->assignments[ $context ][ $var_name ] ) ) {
							foreach ( array_reverse( $this->assignments[ $context ][ $var_name ], true ) as $assignmentPtr => $code ) {
								if ( $assignmentPtr < $stackPtr ) {
									$unsafe_ptr = $this->check_expression( $assignmentPtr );
									if ( $unsafe_ptr ) {
										$how = 'unsafely';
									} else {
										$how = 'safely';
									}
									$extra_context[] = sprintf( "%s assigned %s at line %d:\n %s", $var_name, $how, $this->tokens[ $assignmentPtr ][ 'line' ], $code );
									if ( $unsafe_ptr < $stackPtr ) {
										$extra_context = array_merge( $extra_context, $this->unwind_unsafe_assignments( $unsafe_ptr + 1, $limit ) );
									}
									if ( $unsafe_ptr ) {
										break;
									}
								}
							}
						}

					}
				} else {
					// Stop when there's nothing left to unwind.
					break;
				}

				// Stop when we've found 
				if ( $unsafe_ptr ) {
					break;
				}

			}
		}

		$this->unsafe_expression = $_unsafe_expression;
		$this->unsafe_ptr = $_unsafe_ptr;

		return array_unique( $extra_context );
	}

	/**
	 * Helper function to return the next non-empty token starting at $stackPtr inclusive.
	 */
	protected function next_non_empty( $stackPtr, $local_only = true ) {
		return $this->phpcsFile->findNext( Tokens::$emptyTokens, $stackPtr , null, true, null, $local_only );
	}

	/**
	 * Find the token following the end of the current function call pointed to by $stackPtr.
	 */
	protected function end_of_function_call( $stackPtr ) {
		if ( !in_array( $this->tokens[ $stackPtr ][ 'code' ], Tokens::$functionNameTokens ) ) {
			return false;
		}

		$function_params = PassedParameters::getParameters( $this->phpcsFile, $stackPtr );
		if ( $param = end( $function_params ) ) {
			return $this->next_non_empty( $param['end'] + 1 );
		}

		return false;
	}

	protected function get_expression_as_string( $stackPtr ) {
		$end = $this->phpcsFile->findEndOfStatement( $stackPtr );
		return $this->phpcsFile->getTokensAsString( $stackPtr, $end - $stackPtr + 1 );
	}

	protected function get_variable_as_string( $stackPtr ) {

		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		$i = $stackPtr + 1;
		$limit = 200;
		$out = $this->tokens[ $stackPtr ][ 'content' ];

		while ( $limit > 0 ) {
			// Find the next non-empty token
			$nextToken = $this->phpcsFile->findNext( Tokens::$emptyTokens, $i , null, true, null, true );

			// If it's :: or -> then check if the following thing is a string..
			if ( $this->tokens[ $nextToken ][ 'code' ] === \T_OBJECT_OPERATOR
				||  $this->tokens[ $nextToken ][ 'code' ] === \T_DOUBLE_COLON
				||  $this->tokens[ $nextToken ][ 'code' ] === \T_OPEN_SQUARE_BRACKET ) {
				$objectThing = $this->phpcsFile->findNext( Tokens::$emptyTokens, $nextToken + 1 , null, true, null, true );

				// It could be a variable name or function name
				if ( $this->tokens[ $objectThing ][ 'code' ] === \T_STRING ) {
					$lookAhead = $this->phpcsFile->findNext( Tokens::$emptyTokens, $objectThing + 1 , null, true, null, true );
					if ( $this->tokens[ $lookAhead ][ 'code' ] === \T_OPEN_PARENTHESIS ) {
						// It's a function name, so ignore it
						break;
					}
					$out .= '->' . $this->tokens[ $objectThing ][ 'content' ];
					$i = $objectThing + 1;
				} elseif ( $this->tokens[ $objectThing ][ 'code' ] === \T_LNUMBER ) {
					// It's a numeric array index
					$out .= '[' . $this->tokens[ $objectThing ][ 'content' ] . ']';
					$i = $objectThing + 1;

				} else {
					++ $i;
				}
			} elseif ( \T_CLOSE_SQUARE_BRACKET === $this->tokens[ $nextToken ][ 'code' ] ) {
				// It's a ] so see what's next
				++ $i;
			} else {
				// Anything else is not part of a variable so stop here
				break;
			}

			-- $limit;
		}
		
		return $out;
	}

	/**
	 * Find interpolated variable names in a "string" or heredoc.
	 * 
	 * @param $stackPtr Stack pointer to a double quoted string or heredoc.
	 * 
	 * @return array|bool Array of variable names, or false if $stackPtr was not a double quoted string or heredoc.
	 */
	protected function get_interpolated_variables( $stackPtr ) {
		// It must be an interpolated string.
		if ( in_array( $this->tokens[ $stackPtr ][ 'code' ], [ \T_DOUBLE_QUOTED_STRING, \T_HEREDOC ] ) ) {
			$out = array();
			if ( preg_match_all( self::REGEX_COMPLEX_VARS, $this->tokens[ $stackPtr ][ 'content' ], $matches) ) {
				foreach ( $matches[0] as $var ) {
					// Normalize variations like {$foo} and ${foo}
					$out[] = '$' . trim( $var, '${}' );
				}
			}
			return $out;
		}

		return false;
	}
	/**
	 * Is the T_STRING at $stackPtr a constant as set by define()?
	 */
	protected function is_defined_constant( $stackPtr ) {
		// It must be a string
		if ( \T_STRING !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		// It could be a function call or similar. That depends on what comes after it.

		$nextToken = $this->next_non_empty( $stackPtr + 1 );
		if ( in_array( $this->tokens[ $nextToken ][ 'code' ], $this->function_tokens ) ) {
			// It's followed by a paren or similar, so it's not a constant
			return false;
		}

		return true;
	}

	/**
	 * Is the \T_VARIABLE at $stackPtr a property of wpdb like $wpdb->tablename?
	 */
	protected function is_wpdb_property( $stackPtr ) {
		// It must be a variable
		if ( !in_array( $this->tokens[ $stackPtr ][ 'code' ], [ \T_VARIABLE, \T_STRING ] ) ) {
			return false;
		}

		// $wpdb
		if ( !in_array( $this->tokens[ $stackPtr ][ 'content' ], [ '$wpdb', 'wpdb' ] ) ) {
			return false;
		}

		// ->
		$nextToken = $this->next_non_empty( $stackPtr + 1 );
		if ( \T_OBJECT_OPERATOR !== $this->tokens[ $nextToken ][ 'code' ] ) {
			return false;
		}

		// tablename
		$nextToken = $this->next_non_empty( $nextToken + 1 );
		if ( \T_STRING !== $this->tokens[ $nextToken ][ 'code' ] ) {
			return false;
		}

		// not followed by (
		$nextToken = $this->next_non_empty( $nextToken + 1 );
		if ( \T_OPEN_PARENTHESIS === $this->tokens[ $nextToken ][ 'code' ] ) {
			return false;
		}

		return $nextToken;
	}

	/**
	 * Find the end of the current expression, being aware of bracket context etc.
	 * 
	 * @return int A pointer to the last token in the expression.
	 */
	protected function find_end_of_expression( $stackPtr ) {

		if ( isset( $this->tokens[ $stackPtr ][ 'parenthesis_closer' ] ) ) {
			return $this->tokens[ $stackPtr ][ 'parenthesis_closer' ];
		}

		$stops = array (
			\T_SEMICOLON,
			\T_COMMA,
		);
		$prev = $stackPtr;
		$next = $this->next_non_empty( $stackPtr );
		while ( $next ) {
			if ( in_array( $this->tokens[ $next ][ 'code' ], $stops ) ) {
				return $prev;
			}
			// If we found nested parens, jump to the end
			if ( \T_OPEN_PARENTHESIS === $this->tokens[ $next ][ 'code' ] && isset( $this->tokens[ $next ][ 'parenthesis_closer' ] ) ) {
				$prev = $this->tokens[ $next ][ 'parenthesis_closer' ];
				$next = $prev + 1;
				continue;
			}

			$prev = $next;
			$next = $this->next_non_empty( $next + 1 );
		}

		return $next;
	}

	/**
	 * Is $stackPtr within the conditional part of a ternary expression?
	 * 
	 * @return false|int A pointer to the ? operator, or false if it is not a ternary.
	 */
	protected function is_ternary_condition( $stackPtr ) {

		$end_of_expression = $this->find_end_of_expression( $stackPtr );
		$next = $this->next_non_empty( $end_of_expression + 1 );

		$ternaryPtr = $this->phpcsFile->findNext( [ \T_INLINE_THEN => \T_INLINE_THEN ], $stackPtr, $end_of_expression, false, null, true );
		return $ternaryPtr;
	}

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


	/**
	 * Return a string representing the unsafe portion of code pointed to by $stackPtr, as returned by check_expression().
	 * This is necessary because phpcs hobbles the parsing of variables in strings.
	 */
	function get_unsafe_expression_as_string( $stackPtr ) {
		if ( in_array( $this->tokens[ $stackPtr ][ 'code' ], [ \T_DOUBLE_QUOTED_STRING, \T_HEREDOC ] ) ) {
			// It must be a variable within the string that's the unsafe thing
			foreach ( $this->get_interpolated_variables( $stackPtr ) as $var ) {
				// Does it look like a table name, "SELECT * FROM {$my_table}" or similar?
				$var_placeholder = md5( $var );
				$placeholder_query = str_replace( $var, $var_placeholder, $this->tokens[ $stackPtr ][ 'content' ] );
				if( $this->get_table_from_query( trim( $placeholder_query, '"' ) ) === $var_placeholder ) {
					// Add the table variable name to the list of parameters that will only trigger a warning
					$this->warn_only_parameters[] = $var;
				}

				// Where are we?
				$context = $this->get_context( $stackPtr );

				// If we've found an unsanitized var then fail early
				if ( ! $this->_is_sanitized_var( $var, $context ) ) {
					return $var;
				}
			}
		} elseif ( $where = $this->check_expression( $stackPtr ) ) {
			return $this->get_expression_as_string( $where );
		}

		return $this->get_expression_as_string( $stackPtr );
	}

	function find_variables_in_expression( $stackPtr, $endPtr = null ) {
		$tokens_to_find = array(
			\T_VARIABLE => \T_VARIABLE,
			\T_DOUBLE_QUOTED_STRING => \T_DOUBLE_QUOTED_STRING,
			\T_HEREDOC => \T_HEREDOC,
		);

		$out = array();

		$newPtr = $stackPtr;
		while( $this->phpcsFile->findNext( $tokens_to_find, $newPtr, $endPtr, false, null, true ) ) {
			if ( in_array( $this->tokens[ $newPtr ][ 'code' ], [ \T_DOUBLE_QUOTED_STRING, \T_HEREDOC ] ) ) {
				$out = array_merge( $out, $this->get_interpolated_variables( $newPtr ) );
			} elseif ( \T_VARIABLE === $this->tokens[ $newPtr ][ 'code' ] ) {
				$out[] = $this->get_variable_as_string( $newPtr );
			}
			++ $newPtr;
		}

		return $out;
	}

	/**
	 * Decide if an expression (that is used as a parameter to $wpdb->query() or similar) is safely escaped.
	 * We'll consider it safe IFF the first variable in the expression has previously been escaped OR the
	 * first function call in the expression is an escaping function.
	 */
	public function expression_is_safe( $stackPtr, $endPtr = null ) {
		// TODO: could produce warnings or give more context

		$this->unsafe_expression = null;
		$this->unsafe_ptr = null;

		$this->unsafe_ptr = $this->check_expression( $stackPtr, $endPtr );

		if ( $this->unsafe_ptr ) {
			$this->unsafe_expression = $this->get_unsafe_expression_as_string( $this->unsafe_ptr );
		}
		return ! $this->unsafe_ptr;
	}

	/**
	 * Find the first unsafe thing in the given expression, if any.
	 * It's considered safe IFF everything is either escaped or constant.
	 */
	public function check_expression( $stackPtr, $endPtr = null ) {
		$newPtr = $stackPtr;
		$tokens_to_find = array(
			\T_VARIABLE => \T_VARIABLE,
			\T_INT_CAST => \T_INT_CAST,
			\T_BOOL_CAST => \T_BOOL_CAST,
		)
			+ Tokens::$functionNameTokens
			+ Tokens::$textStringTokens;
		while ( $newPtr && $this->phpcsFile->findNext( $tokens_to_find, $newPtr, $endPtr, false, null, true ) ) {
			if ( $ternaryPtr = $this->is_ternary_condition( $newPtr ) ) {
				// We're in the first part of a ternary condition. It doesn't matter if the condition is safe or not.
				$newPtr = $this->next_non_empty( $ternaryPtr + 1 );
				continue;
			} elseif ( in_array( $this->tokens[ $newPtr ][ 'code' ], Tokens::$functionNameTokens ) ) {
				if ( isset( $this->escapingFunctions[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// Function call to an escaping function.
					// Skip over the function's parameters and continue checking the remainder of the expression.
					$function_params = PassedParameters::getParameters( $this->phpcsFile, $newPtr );
					if ( $param = end( $function_params ) ) {
						$newPtr = $this->next_non_empty( $param['end'] + 1 ) ;
						continue;
					}
				} elseif ( isset( $this->implicitSafeFunctions[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// Function call that always returns implicitly safe output.
					// Skip over the function's parameters and continue checking the remainder of the expression.
					$function_params = PassedParameters::getParameters( $this->phpcsFile, $newPtr );
					if ( $param = end( $function_params ) ) {
						$newPtr = $this->next_non_empty( $param['end'] + 1 );
						continue;
					}
				} elseif ( isset( $this->neutralFunctions[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// It's a function like implode(), which is safe if all of the parameters are also safe.
					$function_params = PassedParameters::getParameters( $this->phpcsFile, $newPtr );
					foreach ( $function_params as $param ) {
						$innerPtr = $this->check_expression( $param[ 'start' ], $param[ 'end' ] + 1 );
						if ( $innerPtr ) {
							return $innerPtr;
						}
					};
					// If we got this far, everything in the call is safe, so skip to the next statement.
					$newPtr = $this->next_non_empty( $param['end'] + 1 );
					continue;
				} elseif ( 'array_map' === $this->tokens[ $newPtr ][ 'content' ] ) {
					// Special handling for array_map() calls that map an escaping function
					// See also similar array_walk handler in process_token().
					$function_params = PassedParameters::getParameters( $this->phpcsFile, $newPtr );
					$mapped_function = trim( $function_params[1][ 'clean' ], '"\'' );
					// If this is array_map( 'esc_sql', ... ) or similar, then we can move on to the next statement.
					if ( isset( $this->escapingFunctions[ $mapped_function ] ) ) {
						$param = end( $function_params );
						$newPtr = $this->next_non_empty( $param['end'] + 1 ) ;
						continue;
					}
				} elseif ( 'prepare' === $this->tokens[ $newPtr ][ 'content' ] ) {
					// It's wpdb->prepare(). The first parameter needs to be checked, the remainder are escaped.
					$function_params = PassedParameters::getParameters( $this->phpcsFile, $newPtr );
					$first_param = reset( $function_params );
					if ( $inner = $this->check_expression( $first_param[ 'start' ], $first_param[ 'end' ] + 1 ) ) {
						return $inner;
					}
					// It's safe, so skip past the prepare().
					$param = end( $function_params );
					$newPtr = $this->next_non_empty( $param['end'] + 1 );
					continue;
				} elseif ( $this->is_wpdb_property( $newPtr ) ) {
					// It's $wpdb->tablename
					$newPtr = $this->is_wpdb_property( $newPtr ) + 1;
					continue;
	
				} elseif ( isset( $this->safe_constants[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// It's a constant like ARRAY_A, it's safe.
					$newPtr = $this->next_non_empty( $newPtr + 1 );
					continue;
				} elseif ( $this->is_defined_constant( $newPtr ) ) {
					// It looks like some other constant, assume it's safe and skip over it
					$newPtr = $this->next_non_empty( $newPtr + 1 );
					continue;
				} else {
					// First function call was something else. It should be wrapped in an escape.
					return $newPtr;
				}
			} elseif ( in_array( $this->tokens[ $newPtr ][ 'code' ], [ \T_DOUBLE_QUOTED_STRING, \T_HEREDOC ] ) ) {
				// It's a string that might have variables
				foreach ( $this->get_interpolated_variables( $newPtr ) as $var ) {
					// Does it look like a table name, "SELECT * FROM {$my_table}" or similar?
					$var_placeholder = md5( $var );
					$placeholder_query = preg_replace( '/[${]*' . preg_quote( ltrim( $var, '$' ) ) . '[}]*/', $var_placeholder, $this->tokens[ $newPtr ][ 'content' ] );
					if( $this->get_table_from_query( trim( $placeholder_query, '"' ) ) === $var_placeholder ) {
						// Add the table variable name to the list of parameters that will only trigger a warning
						$this->warn_only_parameters[] = $var;
					}

					// Where are we?
					$context = $this->get_context( $newPtr );

					// If we've found an unsanitized var then fail early
					if ( ! $this->_is_sanitized_var( $var, $context ) ) {
						return $newPtr;
					}
				}

			} elseif ( \T_VARIABLE === $this->tokens[ $newPtr ][ 'code' ] ) {
				// Allow for things like $this->wpdb->prepare()
				if ( '$this' === $this->tokens[ $newPtr ][ 'content' ] ) {
					if ( 'wpdb' === $this->tokens[ $newPtr + 2 ][ 'content' ] && '->' === $this->tokens[ $newPtr + 3 ][ 'content' ] ) {
						// Continue the loop from the wpdb->prepare() part
						$newPtr += 4;
						continue;
					}
				}

				// Also $wpdb->tablename
				if ( $lookahead = $this->is_wpdb_property( $newPtr ) ) {
					$newPtr = $lookahead;
					continue;
				}

				// If the expression contains an unsanitized variable and we haven't already found an escaping function,
				// then we can fail at this point.
				if ( '$wpdb' !== $this->tokens[ $newPtr ][ 'content' ] && !$this->is_sanitized_var( $newPtr ) ) {
					return $newPtr;
				}
			} elseif ( in_array( $this->tokens[ $newPtr ][ 'code' ], Tokens::$castTokens ) ) {
				// We're safely casting to an int or bool
				$newPtr = $this->next_non_empty( $this->phpcsFile->findEndOfStatement( $newPtr ) );
				continue;
			} elseif ( \T_CONSTANT_ENCAPSED_STRING === $this->tokens[ $newPtr ][ 'code' ] ) {
				// A constant string is ok, but we want to check what's after it
			}

			if ( !is_null( $endPtr ) && $newPtr > $endPtr ) {
				// We've run past the end, so exit
				return false;
			}
			++ $newPtr;
		}

		// If we found nothing unsafe, it was probably just a scalar value.
		return false;
	}

	/**
	 * Check if this variable is being assigned a value.
	 * Copied from WordPressCS\WordPress\Sniff with improvements
	 *
	 * E.g., $var = 'foo';
	 *
	 * Also handles array assignments to arbitrary depth:
	 *
	 * $array['key'][ $foo ][ something() ] = $bar;
	 *
	 * @since 0.5.0
	 *
	 * @param int $stackPtr The index of the token in the stack. This must point to
	 *                      either a T_VARIABLE or T_CLOSE_SQUARE_BRACKET token.
	 *
	 * @return bool Whether the token is a variable being assigned a value.
	 */
	protected function is_assignment( $stackPtr ) {

		static $valid = array(
			\T_VARIABLE             => true,
			\T_CLOSE_SQUARE_BRACKET => true,
			\T_STRING               => true,
		);

		// Must be a variable, constant or closing square bracket (see below).
		if ( ! isset( $valid[ $this->tokens[ $stackPtr ]['code'] ] ) ) {
			return false;
		}

		$next_non_empty = $this->phpcsFile->findNext(
			Tokens::$emptyTokens,
			( $stackPtr + 1 ),
			null,
			true,
			null,
			true
		);

		// No token found.
		if ( false === $next_non_empty ) {
			return false;
		}

		// If the next token is an assignment, that's all we need to know.
		if ( isset( Tokens::$assignmentTokens[ $this->tokens[ $next_non_empty ]['code'] ] ) ) {
			return true;
		}

		// Check if this is an array assignment, e.g., `$var['key'] = 'val';` .
		if ( \T_OPEN_SQUARE_BRACKET === $this->tokens[ $next_non_empty ]['code']
			&& isset( $this->tokens[ $next_non_empty ]['bracket_closer'] )
		) {
			return $this->is_assignment( $this->tokens[ $next_non_empty ]['bracket_closer'] );
		} elseif ( \T_OBJECT_OPERATOR === $this->tokens[ $next_non_empty ]['code'] ) {
			return $this->is_assignment( $next_non_empty + 1 );
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

	public function is_suppressed_line( $stackPtr, $sniffs = [ 'WordPress.DB.PreparedSQL.NotPrepared', 'WordPress.DB.PreparedSQL.InterpolatedNotPrepared', 'WordPress.DB.DirectDatabaseQuery.DirectQuery', 'DB call', 'unprepared SQL', 'PreparedSQLPlaceholders replacement count'] ) {
		if ( empty( $this->tokens[ $stackPtr ][ 'line' ] ) ) {
			return false;
		}

		// We'll check all lines related to this function call, because placement can differ depending on exactly where we trigger in a multi-line query
		$end = $this->end_of_function_call( $stackPtr );
		if ( $end < $stackPtr ) {
			$end = $stackPtr;
		}

		for ( $ptr = $stackPtr; $ptr <= $end; $ptr ++ ) {
			foreach ( $sniffs as $sniff_name ) {
				$line_no = $this->tokens[ $ptr ][ 'line' ];
				if ( !empty( $this->phpcsFile->tokenizer->ignoredLines[ $line_no ] ) ) {
					return true;
				}
				if ( $this->has_whitelist_comment( $sniff_name, $ptr ) ) {
					return true;
				}
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
			\T_VARIABLE,
			\T_STRING,
		);
	}

	/**
	 * Processes this test, when one of its tokens is encountered.
	 *
	 * @param int $stackPtr The position of the current token in the stack.
	 *
	 * @return int|void Integer stack pointer to skip forward or void to continue
	 *                  normal file processing.
	 */
	public function process_token( $stackPtr ) {
		static $line_no = null;
		if ( $this->tokens[ $stackPtr ][ 'line' ] !== $line_no ) {
			$line_no = $this->tokens[ $stackPtr ][ 'line' ];
		}

		if ( $this->is_assignment( $stackPtr ) ) {

			// Work out what we're assigning to the variable at $stackPtr    		
			$nextToken = $this->phpcsFile->findNext( Tokens::$assignmentTokens, $stackPtr +1 , null, false, null, true );

			// If the expression being assigned is safe (ie escaped) then mark the variable as sanitized.
			if ( $this->expression_is_safe( $nextToken + 1 ) ) {
				// Don't mark as safe if it's a concat, since that doesn't sanitize the initial part.
				if ( $this->tokens[ $nextToken ][ 'code' ] !== \T_CONCAT_EQUAL ) {
					$this->mark_sanitized_var( $stackPtr, $nextToken + 1 );
				}
			} else {
				$this->mark_unsanitized_var( $stackPtr, $nextToken + 1 );
			}

			return; // ??
		}

		// Handle foreach ( $foo as $bar ), which is similar to assignment
		$nextToken = $this->next_non_empty( $stackPtr + 1 );
		if ( \T_AS === $this->tokens[ $nextToken ][ 'code' ] ) {
			$as_var = $this->next_non_empty( $nextToken + 1 );
			$lookahead = $this->next_non_empty( $as_var + 1 );
			if ( \T_DOUBLE_ARROW === $this->tokens[ $lookahead ][ 'code' ] ) {
				// It's foreach ( $foo as $i => $as_var )
				$as_var = $this->next_non_empty( $lookahead + 1 );
			}
			if ( \T_VARIABLE === $this->tokens[ $as_var ][ 'code' ] ) {
				// $as_var is effectively being assigned to. So if the LHS expression is safe, $as_var is also safe.
				if ( $this->expression_is_safe( $stackPtr, $nextToken ) ) {
					$this->mark_sanitized_var( $as_var );
				} else {
					$this->mark_unsanitized_var( $as_var );
				}
			}
		}

		// Special case for array_walk. Handled here rather than in expression_is_safe() because it's a statement not an expression.
		if ( in_array( $this->tokens[ $stackPtr ][ 'code' ], Tokens::$functionNameTokens )
			&& 'array_walk' === $this->tokens[ $stackPtr ][ 'content' ] ) {
			$function_params = PassedParameters::getParameters( $this->phpcsFile, $stackPtr );
			$mapped_function = trim( $function_params[2][ 'clean' ], '"\'' );
			// If it's an escaping function, then mark the referenced variable in the first parameter as sanitized.
			if ( isset( $this->escapingFunctions[ $mapped_function ] ) ) {
				$escaped_var = $this->next_non_empty( $function_params[ 1 ][ 'start' ] );
				$this->mark_sanitized_var( $escaped_var );
			}
		}

		// We're only interested in wpdb method calls to risky functions
		if ( !$this->is_wpdb_method_call( $stackPtr, $this->unsafe_methods ) ) {
			return;
		}

		$is_object_call = $this->phpcsFile->findNext( \T_OBJECT_OPERATOR, ( $stackPtr + 1 ), null, false, null, true );
		if ( false === $is_object_call ) {
			return; // This is not a call to the wpdb object.
		}

		$methodPtr = $this->phpcsFile->findNext( array( \T_WHITESPACE ), ( $is_object_call + 1 ), null, true, null, true );
		$method    = $this->tokens[ $methodPtr ]['content'];

		// TODO: this might not be a method call, it might be a property $foo->bar

		// If we're in a call to an unsafe db method like $wpdb->query then check all the parameters for safety
		if ( isset( $this->unsafe_methods[ $method ] ) ) {
			// Only the first parameter needs escaping
			$methodParam = reset( PassedParameters::getParameters( $this->phpcsFile, $methodPtr ) );
			// If the expression wasn't escaped safely, then alert.
			if ( $unsafe_ptr = $this->check_expression( $methodParam[ 'start' ], $methodParam[ 'end' ] + 1 ) ) {
				$extra_context = $this->unwind_unsafe_assignments( $unsafe_ptr );
				$unsafe_expression = $this->get_unsafe_expression_as_string( $unsafe_ptr );

				if ( $this->is_warning_parameter( $unsafe_expression ) || $this->is_warning_sql( $methodParam[ 'clean' ] ) || $this->is_suppressed_line( $methodPtr ) ) {
					$this->phpcsFile->addWarning( 'Unescaped parameter %s used in $wpdb->%s(%s)%s',
						$methodPtr,
						'UnescapedDBParameter',
						[ $unsafe_expression, $method, $methodParam[ 'clean' ], rtrim( "\n" . join( "\n", $extra_context ) ) ],
						0,
						false
					);
				} else {
					$this->phpcsFile->addError( 'Unescaped parameter %s used in $wpdb->%s(%s)%s',
						$methodPtr,
						'UnescapedDBParameter',
						[ $unsafe_expression, $method, $methodParam[ 'clean' ], rtrim( "\n" . join( "\n", $extra_context ) ) ],
						0,
						false
					);
				}
				return; // Only need to error on the first occurrence
			}
		}
	}

}
