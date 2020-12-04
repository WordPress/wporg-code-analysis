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
			var_dump( "not a variable", $this->tokens[ $stackPtr ] );
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->phpcsFile->getCondition( $stackPtr, \T_CLOSURE )
			|| $this->phpcsFile->getCondition( $stackPtr, \T_FUNCTION )
			|| 'global';

		$var = $this->get_complex_variable( $stackPtr );
		var_dump( "marking as sanitized", $var[0] );

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
			var_dump( "not a variable", $this->tokens[ $stackPtr ] );
			return false;
		}

		// Find the closure or function scope of the variable.
		$context = $this->get_context( $stackPtr );

		$var = $this->get_complex_variable( $stackPtr );
		var_dump( "checking if sanitized", $var );

		return $this->_is_sanitized_var( $var, $context );
	}

	protected function _is_sanitized_var( $var, $context ) {

		if ( isset( $this->sanitized_variables[ $context ][ $var[0] ] ) && $var[1] === $this->sanitized_variables[ $context ][ $var[0] ] ) {
			var_dump( "sanitized exactly" );
			return true;
		} elseif ( isset( $this->sanitized_variables[ $context ][ $var[0] ] ) && true ===  $this->sanitized_variables[ $context ][ $var[0] ] ) {
			var_dump( "sanitized as scalar" );
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

		if ( \T_VARIABLE !== $this->tokens[ $stackPtr ][ 'code' ] ) {
			var_dump( "not a variable", $this->tokens[ $stackPtr ] );
			return false;
		}

		// We already have a handy function for array keys
		if ( $array_keys = $this->get_array_access_keys( $stackPtr ) ) {
			return [ ltrim( $this->tokens[ $stackPtr ][ 'content' ], '$' ), $array_keys ];
		}

		$properties = [];
		$i = $stackPtr + 1;
		while ( true ) {
			// Find the next non-empty token
			$nextToken = $this->phpcsFile->findNext( Tokens::$emptyTokens, $i , null, true, null, true );

			// If it's :: or -> then check if the following thing is a string..
			if ( $this->tokens[ $nextToken ][ 'code' ] === \T_OBJECT_OPERATOR
				||  $this->tokens[ $nextToken ][ 'code' ] === \T_DOUBLE_COLON) {
				$objectThing = $this->phpcsFile->findNext( Tokens::$emptyTokens, ++$i , null, true, null, true );

				// It could be a variable name or function name
				if ( $this->tokens[ $objectThing ][ 'code' ] === \T_STRING ) {
					$lookAhead = $this->phpcsFile->findNext( Tokens::$emptyTokens, $i + 1 , null, true, null, true );
					if ( $this->tokens[ $lookAhead ][ 'code' ] === \T_OPEN_PARENTHESIS ) {
						// It's a function name, so ignore it
						break;
					}
					$properties[] = $this->tokens[ $objectThing ][ 'content' ];

				}

			}

			++ $i;
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
		#var_dump( __FUNCTION__, $stackPtr, $endPtr ); #return;
		#var_dump( array_slice( $this->tokens, $stackPtr, $endPtr - $stackPtr + 1, true ) );
		$newPtr = $stackPtr;
		while ( $this->phpcsFile->findNext( Tokens::$functionNameTokens + Tokens::$textStringTokens + [ \T_VARIABLE => \T_VARIABLE, \T_INT_CAST => \T_INT_CAST, \T_BOOL_CAST => \T_BOOL_CAST ], $newPtr, $endPtr, false, null, true ) ) {
			#echo "qqq\n"; var_dump( $this->tokens[ $newPtr ] ); return;

			if ( in_array( $this->tokens[ $newPtr ][ 'code' ], Tokens::$functionNameTokens ) ) {
				var_dump( __FUNCTION__, "function", $this->tokens[ $newPtr ][ 'content' ] );
				if ( isset( $this->escapingFunctions[ $this->tokens[ $newPtr ][ 'content' ] ] ) ) {
					var_dump( "first function is escape!" );
					return true;
				} else {
					var_dump( "unsafe function" );
					return false;
				}
			} elseif ( in_array( $this->tokens[ $newPtr ][ 'code' ], [ \T_DOUBLE_QUOTED_STRING, \T_HEREDOC ] ) ) {
				// It's a string that might have variables
				#var_dump( __FUNCTION__, 'encapsed vars', preg_match_all( self::REGEX_COMPLEX_VARS, $this->tokens[ $newPtr ][ 'content' ], $matches), $matches );
				if ( preg_match_all( self::REGEX_COMPLEX_VARS, $this->tokens[ $newPtr ][ 'content' ], $matches) ) {
					foreach ( $matches[0] as $var ) {
						// Get the variable in a format understood by _is_sanitized()
						$complex_var = $this->get_complex_variable_from_string( $var );
						// If it's not a $wpdb->table variable, check for sanitizing
						if ( 'wpdb' !== $complex_var[0] ) {
							// Where are we?
							$context = $this->get_context( $stackPtr );
							#var_dump( __FUNCTION__, 'variable from string', $var, $complex_var );

							// If we've found an unsanitized var then fail early
							if ( ! $this->_is_sanitized_var( $complex_var, $context ) ) {
								var_dump( "unsanitized interpolated variable found in expression! $context $var" );
								var_dump( $this->sanitized_variables );
								return false;
							}
						}
					}
				}

			} elseif ( \T_VARIABLE === $this->tokens[ $newPtr ][ 'code' ] ) {
				// If the expression contains an unsanitized variable and we haven't already found an escaping function,
				// then we can fail at this point.
				if ( '$wpdb' !== $this->tokens[ $newPtr ][ 'content' ] && !$this->is_sanitized_var( $newPtr ) ) {
					var_dump( "unsanitized var found in expression!", $this->get_complex_variable( $newPtr ) );
					return false;
				}
			} elseif ( in_array( $this->tokens[ $newPtr ][ 'code' ], Tokens::$castTokens ) ) {
				// We're safely casting to an int or bool
				var_dump( __FUNCTION__, "cast", $this->tokens[ $newPtr ][ 'content' ] );
				return true;
			} else {
				#var_dump( __FUNCTION__, "unknown token", $this->tokens[ $newPtr ] );
			}

			if ( !is_null( $endPtr ) && $newPtr > $endPtr ) {
				// We've run past the end, so exit
				return false;
			}
			++ $newPtr;
		}

		return true;
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
			var_dump( "on line $line_no" );
		}

		#if ( $this->is_wpdb_method_call( $stackPtr, $this->unsafe_methods ) ) {
		#	var_dump( "unsafe method call! " . $this->tokens[ $stackPtr ]['content'] );
		#	$condition = $this->phpcsFile->getCondition( $stackPtr, \T_FUNCTION );
		#	var_dump( "in function " . $this->phpcsFile->getDeclarationName( $condition ) );
		#}

		if ( $this->is_assignment( $stackPtr ) ) {
			var_dump( "assigning to " . $this->tokens[ $stackPtr ]['content'] );
			var_dump( $this->tokens[ $stackPtr ] );
/*			public function findNext(
        $types,
        $start,
        $end=null,
        $exclude=false,
        $value=null,
        $local=false
    ) 
*/
    		
    		$nextToken = $this->phpcsFile->findNext( Tokens::$assignmentTokens + Tokens::$emptyTokens, $stackPtr +1 , null, true, null, true );
    		#var_dump( "Next thing", $this->tokens[ $nextToken ] );

    		// Is it a call to $wpdb->prepare?
    		if ( $this->is_wpdb_method_call( $nextToken, ['prepare' => true] ) ) {
    			var_dump( '$wpdb->prepare() found!' );
    			#var_dump( 'we can assume this is sanitized:', $this->tokens[ $stackPtr ] );
    			$this->mark_sanitized_var( $stackPtr );
    			return;
    		}
    		// Is it a function call?
    		/*
    		elseif ( \T_STRING === $this->tokens[ $nextToken ][ 'code' ] && in_array( $this->tokens[ $nextToken ][ 'content' ], $this->escapingFunctions ) ) {
    			var_dump( "definitely a sanitizing function!", $this->tokens[ $nextToken ] );

    			$this->mark_sanitized_var( $stackPtr );
    		}*/
    		else {
    			if ( $this->expression_is_safe( $nextToken ) ) {
    				var_dump( "assigned a safe expression" );
    				$this->mark_sanitized_var( $stackPtr );
    			}
    		}

		}

		if ( 'T_STRING' === $this->tokens[ $stackPtr ][ 'type' ] ) {
			#var_dump( $this->phpcsFile->getDeclarationName( $stackPtr ), $this->tokens[ $stackPtr ] );
			#var_dump( $this->tokens[ $stackPtr ] );
			#return;
		}

		#if ( $this->is_in_function_call( $stackPtr, $this->escapingFunctions, false, true ) ) {
		#	var_dump( "var is in a nested escaping function!" );

		#}
    		#var_dump( "process_token escaping functions", $this->escapingFunctions );


		#return;

		// Check for $wpdb variable.
		if ( '$wpdb' !== $this->tokens[ $stackPtr ]['content'] ) {
			// if ( $this->is_sanitized( $stackPtr ) ) {
			// 	var_dump( $this->tokens[ $stackPtr ]['content'], "woohoo it's being sanitized!" );
			// } else {
			// 	var_dump( $this->tokens[ $stackPtr ]['content'] .  " is unsanitized :(" );
			// }
			// #return;
		}

		$is_object_call = $this->phpcsFile->findNext( \T_OBJECT_OPERATOR, ( $stackPtr + 1 ), null, false, null, true );
		if ( false === $is_object_call ) {
			return; // This is not a call to the wpdb object.
		}

		$methodPtr = $this->phpcsFile->findNext( array( \T_WHITESPACE ), ( $is_object_call + 1 ), null, true, null, true );
		$method    = $this->tokens[ $methodPtr ]['content'];

		var_dump( "method \$wpdb->$method" );
		#var_dump( PassedParameters::getParameters( $this->phpcsFile, $methodPtr ) );

		// If we're in a call to an unsafe db method like $wpdb->query then check all the parameters for safety
		if ( isset( $this->unsafe_methods[ $method ] ) ) {
			var_dump( "in an unsafe method, checking parameters" );
			foreach ( PassedParameters::getParameters( $this->phpcsFile, $methodPtr ) as $methodParam ) {
				var_dump( "checking parameter expression", $methodParam[ 'clean' ] );
				if ( $this->expression_is_safe( $methodParam[ 'start' ], $methodParam[ 'end' ] ) ) {
					var_dump( "it's safe!" );
				} else {
					var_dump( "nope it was unsafe!" );
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

		return; // FIXME

		$this->mergeFunctionLists();

		if ( ! isset( $this->methods['all'][ $method ] ) ) {
			return;
		}

		$endOfStatement   = $this->phpcsFile->findNext( \T_SEMICOLON, ( $stackPtr + 1 ), null, false, null, true );
		$endOfLineComment = '';
		for ( $i = ( $endOfStatement + 1 ); $i < $this->phpcsFile->numTokens; $i++ ) {

			if ( $this->tokens[ $i ]['line'] !== $this->tokens[ $endOfStatement ]['line'] ) {
				break;
			}

			if ( \T_COMMENT === $this->tokens[ $i ]['code'] ) {
				$endOfLineComment .= $this->tokens[ $i ]['content'];
			}
		}

		$whitelisted_db_call = false;
		if ( preg_match( '/db call\W*(?:ok|pass|clear|whitelist)/i', $endOfLineComment ) ) {
			$whitelisted_db_call = true;
		}

		// Check for Database Schema Changes.
		for ( $_pos = ( $stackPtr + 1 ); $_pos < $endOfStatement; $_pos++ ) {
			$_pos = $this->phpcsFile->findNext( Tokens::$textStringTokens, $_pos, $endOfStatement, false, null, true );
			if ( false === $_pos ) {
				break;
			}

			if ( preg_match( '#\b(?:ALTER|CREATE|DROP)\b#i', $this->tokens[ $_pos ]['content'] ) > 0 ) {
				$this->phpcsFile->addWarning( 'Attempting a database schema change is discouraged.', $_pos, 'SchemaChange' );
			}
		}

		// Flag instance if not whitelisted.
		if ( ! $whitelisted_db_call ) {
			$this->phpcsFile->addWarning( 'Usage of a direct database call is discouraged.', $stackPtr, 'DirectQuery' );
		}

		if ( ! isset( $this->methods['cachable'][ $method ] ) ) {
			return $endOfStatement;
		}

		$whitelisted_cache = false;
		$cached            = false;
		$wp_cache_get      = false;
		if ( preg_match( '/cache\s+(?:ok|pass|clear|whitelist)/i', $endOfLineComment ) ) {
			$whitelisted_cache = true;
		}
		if ( ! $whitelisted_cache && ! empty( $this->tokens[ $stackPtr ]['conditions'] ) ) {
			$scope_function = $this->phpcsFile->getCondition( $stackPtr, \T_FUNCTION );

			if ( false === $scope_function ) {
				$scope_function = $this->phpcsFile->getCondition( $stackPtr, \T_CLOSURE );
			}

			if ( false !== $scope_function ) {
				$scopeStart = $this->tokens[ $scope_function ]['scope_opener'];
				$scopeEnd   = $this->tokens[ $scope_function ]['scope_closer'];

				for ( $i = ( $scopeStart + 1 ); $i < $scopeEnd; $i++ ) {
					if ( \T_STRING === $this->tokens[ $i ]['code'] ) {

						if ( isset( $this->cacheDeleteFunctions[ $this->tokens[ $i ]['content'] ] ) ) {

							if ( \in_array( $method, array( 'query', 'update', 'replace', 'delete' ), true ) ) {
								$cached = true;
								break;
							}
						} elseif ( isset( $this->cacheGetFunctions[ $this->tokens[ $i ]['content'] ] ) ) {

							$wp_cache_get = true;

						} elseif ( isset( $this->cacheSetFunctions[ $this->tokens[ $i ]['content'] ] ) ) {

							if ( $wp_cache_get ) {
								$cached = true;
								break;
							}
						}
					}
				}
			}
		}

		if ( ! $cached && ! $whitelisted_cache ) {
			$message = 'Direct database call without caching detected. Consider using wp_cache_get() / wp_cache_set() or wp_cache_delete().';
			$this->phpcsFile->addWarning( $message, $stackPtr, 'NoCaching' );
		}

		return $endOfStatement;
	}

	/**
	 * Merge custom functions provided via a custom ruleset with the defaults, if we haven't already.
	 *
	 * @since 0.11.0 Split out from the `process()` method.
	 *
	 * @return void
	 */
	protected function mergeFunctionLists() {
		if ( ! isset( $this->methods['all'] ) ) {
			$this->methods['all'] = array_merge( $this->methods['cachable'], $this->methods['noncachable'] );
		}

		if ( $this->customCacheGetFunctions !== $this->addedCustomFunctions['cacheget'] ) {
			$this->cacheGetFunctions = $this->merge_custom_array(
				$this->customCacheGetFunctions,
				$this->cacheGetFunctions
			);

			$this->addedCustomFunctions['cacheget'] = $this->customCacheGetFunctions;
		}

		if ( $this->customCacheSetFunctions !== $this->addedCustomFunctions['cacheset'] ) {
			$this->cacheSetFunctions = $this->merge_custom_array(
				$this->customCacheSetFunctions,
				$this->cacheSetFunctions
			);

			$this->addedCustomFunctions['cacheset'] = $this->customCacheSetFunctions;
		}

		if ( $this->customCacheDeleteFunctions !== $this->addedCustomFunctions['cachedelete'] ) {
			$this->cacheDeleteFunctions = $this->merge_custom_array(
				$this->customCacheDeleteFunctions,
				$this->cacheDeleteFunctions
			);

			$this->addedCustomFunctions['cachedelete'] = $this->customCacheDeleteFunctions;
		}
	}

}
