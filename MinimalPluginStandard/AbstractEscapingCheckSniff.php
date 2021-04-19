<?php

namespace WordPressDotOrg\Code_Analysis;

use WordPressDotOrg\Code_Analysis\AbstractSniffHelper;
use PHP_CodeSniffer\Util\Tokens;
use PHP_CodeSniffer\Util\Variables;
use PHPCSUtils\Utils\PassedParameters;

/**
 * Base class for building context-aware escaping checks.
 */
abstract class AbstractEscapingCheckSniff extends AbstractSniffHelper {
	/**
	 * Override these in child classes to list applicable escaping functions etc.
	 */
	protected $escapingFunctions = array(
	);

	/**
	 * Functions that are often mistaken for escaping functions, but are not SQL or HTML safe.
	 */
	protected $notEscapingFunctions = array(
		'addslashes',
		'addcslashes',
		'filter_input',
	);

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
		'count'          => true,
		'strtotime'      => true,
		'uniqid'         => true,
		'md5'            => true,
		'sha1'           => true,
		'rand'           => true,
		'mt_rand'        => true,
		'max'            => true,
	);

	/**
	 * Constants that can be assumed safe.
	 */
	protected $safe_constants = array(
		'ARRAY_A'     => true,
		'OBJECT'      => true,
	);

	/**
	 * Keep track of sanitized and unsanitized variables.
	 */
	protected $sanitized_variables = [];
	protected $unsanitized_variables = [];

	/**
	 * Used by certain methods for providing extra context.
	 */
	protected $methodPtr = null;
	protected $unsafe_ptr = null;
	protected $unsafe_expression = null;

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
		// `$foo[] = $unsafe_val` means we have to assume the whole array is unsafe
		$var = preg_replace( '/\[\]$/', '', $var );

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
		if ( '$wpdb->' === substr( $var, 0, 7 ) || '$this->table' === substr( $var, 0, 12 ) || '$wpdb' === $var ) {
			return true;
		}

		// BuddyPress
		if ( preg_match( '/^[$]bp->\w+->table_name(?:\w+)?$/', $var ) ) {
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

	/**
	 * Unwind the stack to provide an explanation as to why a given variable is considered unsafe.
	 * It might have been previously assigned to an unescaped value; this is to help tell the user exactly where it went wrong.
	 */
	protected function unwind_unsafe_assignments( $stackPtr, $limit = 6 ) {
		$_unsafe_ptr = $this->unsafe_ptr;
		$_unsafe_expression = $this->unsafe_expression;
		$this->unsafe_ptr = null;

		if ( --$limit < 0 ) {
			return [];
		}

		$vars_to_explain = [];
		if ( $var = $this->get_variable_as_string( $stackPtr ) ) {
			$vars_to_explain[ $var ] = true;
		} elseif ( $vars = $this->get_interpolated_variables( $stackPtr ) ) {
			foreach ( $vars as $var ) {
				$vars_to_explain[ $var ] = true;
			}
		}
		$extra_context = [];
		$from = $stackPtr;
		while( $vars_to_explain && --$limit >= 0 ) {
			foreach ( $vars_to_explain as $var => $dummy ) {
				if ( $assignments = $this->find_assignments( $from, $var ) ) {
					foreach ( array_reverse( $assignments, true ) as $assignmentPtr => $code ) {
						// Ignore assignments that happen later in the execution flow.
						if ( $assignmentPtr >= $stackPtr ) {
							continue;
						}

						$unsafe_ptr = $this->check_expression( $assignmentPtr );
						if ( $unsafe_ptr ) {
							$how = 'unsafely';
							$extra_context[] = sprintf( "%s assigned %s at line %d:\n %s", $var, $how, $this->tokens[ $assignmentPtr ][ 'line' ], $code );
							foreach( $this->find_functions_in_expression( $assignmentPtr ) as $func ) {
								if ( in_array( $func, $this->notEscapingFunctions ) ) {
									$extra_context[] = sprintf( "Note: %s() is not a SQL escaping function.", $func );
									break;
								}
							}
							unset( $vars_to_explain[ $var ] );

							if ( $more_vars = $this->find_variables_in_expression( $unsafe_ptr ) ) {
								foreach ( $more_vars as $var_name ) {
									if ( $var_name ) {
										if ( !$this->_is_sanitized_var( $var_name, $this->get_context( $assignmentPtr ) ) ) {
											$vars_to_explain[ $var_name ] = true;
										}
									}
								}
							}
						}

						if ( !isset( $vars_to_explain[ $var ] ) ) {
							break; // out of the assignments loop
						}
					}
				} else {
					if ( !$this->_is_sanitized_var( $var, $from ) && !$this->is_warning_parameter( $var ) ) {
						$extra_context[] = sprintf( "%s used without escaping.", $var );
					}
				}

			}


		}

		$this->unsafe_expression = $_unsafe_expression;
		$this->unsafe_ptr = $_unsafe_ptr;

		return array_unique( $extra_context );
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
			// If the problem is at a variable, and that variable is not sanitized, then return just the variable name.
			if ( \T_VARIABLE === $this->tokens[ $stackPtr ][ 'code' ] && ! $this->is_sanitized_var( $stackPtr ) ) {
				return $this->get_variable_as_string( $stackPtr );
			}
			return $this->get_expression_as_string( $where );
		}

		return $this->get_expression_as_string( $stackPtr );
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
					$param = null;
					foreach ( $function_params as $param ) {
						$innerPtr = $this->check_expression( $param[ 'start' ], $param[ 'end' ] + 1 );
						if ( $innerPtr ) {
							return $innerPtr;
						}
					};
					// If we got this far, everything in the call is safe, so skip to the next statement.
					if ( $param ) {
						$newPtr = $this->next_non_empty( $param['end'] + 1 );
						continue;
					}
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
				if ( '$this' === $this->tokens[ $newPtr ][ 'content' ] || 'this' === $this->tokens[ $newPtr ][ 'content' ] ) {
					if ( 'wpdb' === $this->tokens[ $newPtr + 2 ][ 'content' ] && '->' === $this->tokens[ $newPtr + 3 ][ 'content' ] ) {
						// Continue the loop from the wpdb->prepare() part
						$newPtr += 4;
						continue;
					}
				}

				// If the expression contains an unsanitized variable and we haven't already found an escaping function,
				// then we can fail at this point.
				if ( !$this->is_sanitized_var( $newPtr ) ) {
					return $newPtr;
				}
				// Continue from the end of the variable
				if ( $lookahead = $this->find_end_of_variable( $newPtr ) ) {
					if ( $lookahead > $newPtr ) {
						$newPtr = $lookahead + 1;
						continue;
					}
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

}