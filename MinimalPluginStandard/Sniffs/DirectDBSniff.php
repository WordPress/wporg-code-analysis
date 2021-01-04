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
		'esc_sql'                    => true,
		'floatval'                   => true,
		'intval'                     => true,
		'json_encode'                => true,
		'like_escape'                => true,
		'wp_json_encode'             => true,
		'prepare'                    => true, // $wpdb->prepare
		'wp_parse_id_list'           => true,
	);

	// None of these are SQL safe
	protected $sanitizingFunctions = array();
	protected $unslashingFunctions = array();

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
	 * $wpdb methods that require escaped
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
	 * Get the name of the function containing the code at a given point.
	 */
	public function get_function_name( $stackPtr ) {
		$condition = $this->phpcsFile->getCondition( $stackPtr, \T_FUNCTION );
		if ( false !== $condition ) {
			return $this->phpcsFile->getDeclarationName( $condition );
		}
	}

	/**
	 * Get the name of the variable at $stackPtr.


	/**
	 * Mark the variable at $stackPtr as being safely sanitized for use in a SQL context.
	 * $stackPtr must point to a T_VARIABLE. Handles arrays and (maybe) object properties.
	 */
	protected function mark_sanitized_var( $stackPtr ) {

		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->phpcsFile->getCondition( $stackPtr, \T_CLOSURE )
			|| $this->phpcsFile->getCondition( $stackPtr, \T_FUNCTION )
			|| 'global';

		$var = $this->get_complex_variable( $stackPtr );

		if ( count( $var[1] ) > 0 ) {
			// array or object?
			$this->sanitized_variables[ $context ][ $var[0] ] = $var[1];
		} else {
			// scalar
			$this->sanitized_variables[ $context ][ $var[0] ] = true;
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

		$var = $this->get_complex_variable( $stackPtr );

		return $this->_is_sanitized_var( $var, $context );
	}

	protected function _is_sanitized_var( $var, $context ) {

		if ( isset( $this->sanitized_variables[ $context ][ $var[0] ] ) && $var[1] === $this->sanitized_variables[ $context ][ $var[0] ] ) {
			// Check if it's sanitized exactly, with array indexes etc
			return true;
		} elseif ( isset( $this->sanitized_variables[ $context ][ $var[0] ] ) && true ===  $this->sanitized_variables[ $context ][ $var[0] ] ) {
			// TODO maybe warn on this: it was sanitized as a scalar.
			// That might be ok if the sanitizing function was recursive.
			return true;
		}

		return false;
	}

	protected function get_context( $stackPtr ) {

		// Find the closure or function scope of the variable.
		return $this->phpcsFile->getCondition( $stackPtr, \T_CLOSURE )
			|| $this->phpcsFile->getCondition( $stackPtr, \T_FUNCTION )
			|| 'global';

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
			if ( $nextToken <= $i ) {
				break;
			}

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
			} else {
				++ $i;
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
		$newPtr = $stackPtr;
		while ( $this->phpcsFile->findNext( Tokens::$functionNameTokens + Tokens::$textStringTokens + [ \T_VARIABLE => \T_VARIABLE, \T_INT_CAST => \T_INT_CAST, \T_BOOL_CAST => \T_BOOL_CAST ], $newPtr, $endPtr, false, null, true ) ) {

			if ( in_array( $this->tokens[ $newPtr ][ 'code' ], Tokens::$functionNameTokens ) ) {
				if ( isset( $this->escapingFunctions[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// First function call was to an escaping function. We're good.
					return true;
				} elseif ( isset( $this->safe_constants[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					// It's a constant like ARRAY_A, it's safe.
					return true;
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
						if ( 'wpdb' !== $complex_var[0] ) {
							// Where are we?
							$context = $this->get_context( $newPtr );

							// If we've found an unsanitized var then fail early
							if ( ! $this->_is_sanitized_var( $complex_var, $context ) ) {
								return false;
							}
						}
					}
				}

			} elseif ( \T_VARIABLE === $this->tokens[ $newPtr ][ 'code' ] ) {
				// If the expression contains an unsanitized variable and we haven't already found an escaping function,
				// then we can fail at this point.
				if ( '$wpdb' !== $this->tokens[ $newPtr ][ 'content' ] && !$this->is_sanitized_var( $newPtr ) ) {
					return false;
				}
			} elseif ( in_array( $this->tokens[ $newPtr ][ 'code' ], Tokens::$castTokens ) ) {
				// We're safely casting to an int or bool
				return true;
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

    		// Is it a call to $wpdb->prepare?
    		// TODO: I think this is no longer needed here.
    		if ( $this->is_wpdb_method_call( $nextToken, ['prepare' => true] ) ) {
    			$this->mark_sanitized_var( $stackPtr );
    			return;
    		} else {
    			// If the expression being assigned is safe (ie escaped) then mark the variable as sanitized.
    			if ( $this->expression_is_safe( $nextToken + 1 ) ) {
    				$this->mark_sanitized_var( $stackPtr );
    			}
    		}

    		return; // ??
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
			foreach ( PassedParameters::getParameters( $this->phpcsFile, $methodPtr ) as $methodParam ) {
				// If the expression wasn't escaped safely, then alert.
				if ( !$this->expression_is_safe( $methodParam[ 'start' ], $methodParam[ 'end' ] ) ) {
					$this->phpcsFile->addError( 'Unescaped parameter %s used in $wpdb->%s',
						$methodPtr,
						'UnescapedDBParameter',
						[ $methodParam[ 'clean' ], $method ],
						0,
						false
					);
					return; // Only need to error on the first occurrence
				}

			}
		}

	}

}
