<?php

namespace WordPressDotOrg\Code_Analysis\sniffs;

use WordPressCS\WordPress\Sniff;
use PHP_CodeSniffer\Util\Tokens;
use PHP_CodeSniffer\Util\Variables;
use PHPCSUtils\Utils\PassedParameters;

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
		'table',
		'table_name',
		'column_name',
		'this', // typically something like $this->tablename
		'order_by',
		'orderby',
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
	protected function mark_sanitized_var( $stackPtr ) {

		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->get_context( $stackPtr );

		$var = $this->get_complex_variable( $stackPtr );

		if ( count( $var[1] ) > 0 ) {
			// array or object?
			$this->sanitized_variables[ $context ][ $var[0] ] = $var[1];
		} else {
			// scalar
			$this->sanitized_variables[ $context ][ $var[0] ] = true;
		}

		// Sanitizing only overrides a previously unsafe assignment if it's at a lower level (ie not withing a conditional)
		if ( isset( $this->unsanitized_variables[ $context ][ $var[0] ] ) ) {
			if ( $this->tokens[ $stackPtr ][ 'level' ] === 1 ||
				$this->tokens[ $stackPtr ][ 'level' ] < $this->unsanitized_variables[ $context ][ $var[0] ] ) {
					unset( $this->unsanitized_variables[ $context ][ $var[0] ] );
				}
		}
	}

	/**
	 * Mark the variable at $stackPtr as being unsafe. Opposite of mark_sanitized_var().
	 * Use this to reset a variable that might previously have been marked as sanitized.
	 */
	protected function mark_unsanitized_var( $stackPtr ) {

		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->get_context( $stackPtr );

		$var = $this->get_complex_variable( $stackPtr );

		unset( $this->sanitized_variables[ $context ][ $var[0] ] );

		$this->unsanitized_variables[ $context ][ $var[0] ] = $this->tokens[ $stackPtr ][ 'level' ];
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

		$var = $this->get_complex_variable( $stackPtr );

		return $this->_is_sanitized_var( $var, $context );
	}

	protected function _is_sanitized_var( $var, $context ) {

		// If it's ever been set to something unsanitized in this context then we have to consider it unsafe.
		// See insecure_wpdb_query_17
		if ( isset( $this->unsanitized_variables[ $context ][ $var[0] ] ) ) {
			return false;
		}

		if ( isset( $this->sanitized_variables[ $context ][ $var[0] ] ) && $var[1] === $this->sanitized_variables[ $context ][ $var[0] ] ) {
			// Check if it's sanitized exactly, with array indexes etc
			return true;
		} elseif ( isset( $this->sanitized_variables[ $context ][ $var[0] ] ) && true === $this->sanitized_variables[ $context ][ $var[0] ] ) {
			// The main $var was sanitized recursively, so consider anything in it safe
			return true;
		}

		return false;
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
	 * Returns an array representing a variable that may be non-scalar.
	 *
	 * The first element of the return value is the variable name.
	 * Subsequent elements are array keys (one element per array dimension) or object properties.
	 *
	 * $stackPtr must point to a T_VARIABLE.
	 */
	public function get_complex_variable( $stackPtr ) {

		// It must be a variable.
		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		$properties = [];
		$i = $stackPtr + 1;
		$limit = 200;
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
					$properties[] = $this->tokens[ $objectThing ][ 'content' ];
					$i = $objectThing + 1;
				} elseif ( $this->tokens[ $objectThing ][ 'code' ] === \T_LNUMBER ) {
					// It's a numeric array index
					$properties[] = $this->tokens[ $objectThing ][ 'content' ];
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

		return [ ltrim( $this->tokens[ $stackPtr ][ 'content' ], '$' ), $properties ];
	}

	/**
	 * Returns an array representing a variable that may be non-scalar.
	 *
	 * Similar usage to get_complex_variable(), but this one takes a string (i.e. a variable from a double quoted string)
	 */

	function get_complex_variable_from_string( $str ) {
		$str = trim( $str, '{}$' );
		$parts = preg_split( '/\W+/', $str, -1, PREG_SPLIT_NO_EMPTY );

		return [ $parts[0], array_slice( $parts, 1 ) ];
	}

	/**
	 * Decide if an expression (that is used as a parameter to $wpdb->query() or similar) is safely escaped.
	 * We'll consider it safe IFF the first variable in the expression has previously been escaped OR the
	 * first function call in the expression is an escaping function.
	 */
	public function expression_is_safe( $stackPtr, $endPtr = null ) {
		// TODO: could produce warnings or give more context

		$this->unsafe_expression = null;

		$newPtr = $stackPtr;
		$tokens_to_find = array(
			\T_VARIABLE => \T_VARIABLE,
			\T_INT_CAST => \T_INT_CAST,
			\T_BOOL_CAST => \T_BOOL_CAST,
		)
			+ Tokens::$functionNameTokens
			+ Tokens::$textStringTokens;
		while ( $this->phpcsFile->findNext( $tokens_to_find, $newPtr, $endPtr, false, null, true ) ) {
			if ( in_array( $this->tokens[ $newPtr ][ 'code' ], Tokens::$functionNameTokens ) ) {
				if ( isset( $this->escapingFunctions[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// Function call to an escaping function.
					// Skip over the function's parameters and continue checking the remainder of the expression.
					$function_params = PassedParameters::getParameters( $this->phpcsFile, $newPtr );
					if ( $param = end( $function_params ) ) {
						$newPtr = $this->next_non_empty( $param['end'] + 1 ) ;
						continue;
					} else {
						// Something went wrong here
						return false;
					}
				} elseif ( isset( $this->implicitSafeFunctions[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// Function call that always returns implicitly safe output.
					// Skip over the function's parameters and continue checking the remainder of the expression.
					$function_params = PassedParameters::getParameters( $this->phpcsFile, $newPtr );
					if ( $param = end( $function_params ) ) {
						$newPtr = $this->next_non_empty( $param['end'] + 1 ) ;
						continue;
					}
				} elseif ( isset( $this->neutralFunctions[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// It's a function like implode(), which is safe if all of the parameters are also safe.
					$function_params = PassedParameters::getParameters( $this->phpcsFile, $newPtr );
					foreach ( $function_params as $param ) {
						if ( !$this->expression_is_safe( $param[ 'start' ], $param[ 'end' ] + 1 ) ) {
							return false;
						}
					};
					// If we got this far, everything in the call is safe, so skip to the next statement.
					$newPtr = $this->next_non_empty( $param['end'] + 1 );
					continue;
				} elseif ( 'array_map' === $this->tokens[ $newPtr ][ 'content' ] ) {
					// Special handling for array_map() calls that map an escaping function
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
					if ( $this->expression_is_safe( $first_param[ 'start' ], $first_param[ 'end' ] + 1 ) ) {
						// It's safe, so skip past the prepare().
						$param = end( $function_params );
						$newPtr = $this->next_non_empty( $param['end'] + 1 ) ;
						continue;
					}
					// It wasn't safe!
					return false;
				} elseif ( $this->is_wpdb_property( $newPtr ) ) {
					// It's $wpdb->tablename
					$newPtr = $this->is_wpdb_property( $newPtr ) + 1;
					continue;
				} elseif ( isset( $this->safe_constants[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// It's a constant like ARRAY_A, it's safe.
					return true;
				} elseif ( $this->is_defined_constant( $newPtr ) ) {
					// It looks like some other constant, assume it's safe and skip over it
					++ $newPtr;
					continue;
				} else {
					// First function call was something else. It should be wrapped in an escape.
					return false;
				}
			} elseif ( in_array( $this->tokens[ $newPtr ][ 'code' ], [ \T_DOUBLE_QUOTED_STRING, \T_HEREDOC ] ) ) {
				// It's a string that might have variables
				if ( preg_match_all( self::REGEX_COMPLEX_VARS, $this->tokens[ $newPtr ][ 'content' ], $matches) ) {
					foreach ( $matches[0] as $var ) {
						// Get the variable in a format understood by _is_sanitized()
						$complex_var = $this->get_complex_variable_from_string( $var );
						// If it's not a $wpdb->table variable, check for sanitizing
						if ( 'wpdb' !== $complex_var[0] && false === strpos( $var, '$this->table' ) ) {
							// Where are we?
							$context = $this->get_context( $newPtr );

							// If we've found an unsanitized var then fail early
							if ( ! $this->_is_sanitized_var( $complex_var, $context ) ) {
								$this->unsafe_expression = $var;
								return false;
							}
						}
					}
				}

			} elseif ( \T_VARIABLE === $this->tokens[ $newPtr ][ 'code' ] ) {
				// Allow for things like $this->wpdb->prepare()
				if ( '$this' === $this->tokens[ $newPtr ][ 'content' ] ) {
					if ( 'wpdb' === $this->tokens[ $newPtr + 2 ][ 'content' ] ) {
						// Continue the loop from the wpdb->prepare() part
						$newPtr += 2;
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
					$this->unsafe_expression = $this->tokens[ $newPtr ][ 'content' ];
					$var = $this->get_complex_variable( $newPtr );
					if ( $var ) {
						$this->unsafe_expression = '$' . $var[0];
						if ( !empty( $var[1] ) ) {
							$this->unsafe_expression .= '[' . implode( '][', $var[1] ) . ']';
						}
					}
					return false;
				}
			} elseif ( in_array( $this->tokens[ $newPtr ][ 'code' ], Tokens::$castTokens ) ) {
				// We're safely casting to an int or bool
				return true;
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
		return true;
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
			if ( preg_match( '/^[${]*' . preg_quote( $warn_param ) . '(?:\b|$)/', $parameter_name ) ) {
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
				$this->mark_sanitized_var( $stackPtr );
			} else {
				$this->mark_unsanitized_var( $stackPtr );
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
			if ( !$this->expression_is_safe( $methodParam[ 'start' ], $methodParam[ 'end' ] + 1 ) ) {
				if ( $this->unsafe_expression ) {
					if ( $this->is_warning_parameter( $this->unsafe_expression ) || $this->is_warning_sql( $methodParam[ 'clean' ] ) || $this->is_suppressed_line( $methodPtr ) ) {
						$this->phpcsFile->addWarning( 'Unescaped parameter %s used in $wpdb->%s(%s)',
							$methodPtr,
							'UnescapedDBParameter',
							[ $this->unsafe_expression, $method, $methodParam[ 'clean' ] ],
							0,
							false
						);
					} else {
						$this->phpcsFile->addError( 'Unescaped parameter %s used in $wpdb->%s(%s)',
						$methodPtr,
						'UnescapedDBParameter',
						[ $this->unsafe_expression, $method, $methodParam[ 'clean' ] ],
						0,
						false
					);

					}
				} else {
					if ( $this->is_warning_parameter( $methodParam[ 'clean' ] ) || $this->is_warning_sql( $methodParam[ 'clean' ] ) || $this->is_suppressed_line( $methodPtr ) ) {
						$this->phpcsFile->addWarning( 'Unescaped parameter %s used in $wpdb->%s',
							$methodPtr,
							'UnescapedDBParameter',
							[ $methodParam[ 'clean' ], $method ],
							0,
							false
						);
					} else {
						$this->phpcsFile->addError( 'Unescaped parameter %s used in $wpdb->%s',
							$methodPtr,
							'UnescapedDBParameter',
							[ $methodParam[ 'clean' ], $method ],
							0,
							false
						);
					}
				}
				return; // Only need to error on the first occurrence
			}
		}
	}

}
