<?php

namespace WordPressDotOrg\Code_Analysis\sniffs;

use WordPressCS\WordPress\Sniff;
use PHP_CodeSniffer\Util\Tokens;
use PHP_CodeSniffer\Util\Variables;
use PHPCSUtils\Utils\PassedParameters;

/**
 * Check for buggy/insecure use of wp_verify_nonce()
 */
class VerifyNonceSniff extends Sniff {

	/**
	 * Helper function to return the next non-empty token starting at $stackPtr inclusive.
	 */
	protected function next_non_empty( $stackPtr, $local_only = true ) {
		return $this->phpcsFile->findNext( Tokens::$emptyTokens, $stackPtr , null, true, null, $local_only );
	}

	protected function previous_non_empty( $stackPtr, $local_only = true ) {
		return $this->phpcsFile->findPrevious( Tokens::$emptyTokens, $stackPtr , null, true, null, $local_only );
	}

	protected function tokens_as_string( $start, $end ) {
		return $this->phpcsFile->getTokensAsString( $start, $end - $start + 1 );
	}

	/**
	 * Is $stackPtr part of the conditional expression in an `if` statement?
	 */
	protected function is_conditional_expression( $stackPtr ) {
		if ( isset( $this->tokens[ $stackPtr ][ 'nested_parenthesis' ] ) ) {
			foreach ( array_reverse( $this->tokens[ $stackPtr ][ 'nested_parenthesis' ], true ) as $start => $end ) {
				if ( isset( $this->tokens[ $start ][ 'parenthesis_owner' ] ) ) {
					$ownerPtr = $this->tokens[ $start ][ 'parenthesis_owner' ];
					if ( in_array( $this->tokens[ $ownerPtr ][ 'code' ], [ \T_IF, \T_ELSEIF ] ) ) {
						return $ownerPtr;
					}
				}
			}
		}

		return false;
	}

	/**
	 * Get the conditional expression part of an if/elseif statement.
	 */
	protected function get_expression_from_condition( $stackPtr ) {
		if ( isset( $this->tokens[ $stackPtr ][ 'parenthesis_opener' ] ) ) {
			return [ $this->tokens[ $stackPtr ][ 'parenthesis_opener' ], $this->tokens[ $stackPtr ][ 'parenthesis_closer' ] ];
		}
		return false;
	}

	/**
	 * Get the scope part of an if/else/elseif statement.
	 */
	protected function get_scope_from_condition( $stackPtr ) {
		if ( !in_array( $this->tokens[ $stackPtr ][ 'code' ], [ \T_IF, \T_ELSEIF, \T_ELSE ] ) ) {
			return false;
		}
		if ( isset( $this->tokens[ $stackPtr ][ 'scope_opener' ] ) ) {
			return [ $this->tokens[ $stackPtr ][ 'scope_opener' ], $this->tokens[ $stackPtr ][ 'scope_closer' ] ];
		} else {
			// if ( $foo ) bar();
			$start = $this->next_non_empty( $stackPtr + 1 );
			$end = $this->phpcsFile->findEndOfStatement( $start );
			return [ $start, $end ];
		}
		return false;
	}



	/**
	 * Does the given if statement have an 'else' or 'elseif'
	 */
	protected function has_else( $stackPtr ) {
		if ( $this->tokens[ $stackPtr ][ 'scope_closer' ] ) {
			$nextPtr = $this->next_non_empty( $this->tokens[ $stackPtr ][ 'scope_closer' ] + 1 );
			if ( $nextPtr && in_array( $this->tokens[ $nextPtr ][ 'code' ], [ \T_ELSE, \T_ELSEIF ] ) ) {
				return $nextPtr;
			}
		}
		return false;
	}

	/**
	 * Is the expression part of a return statement?
	 */
	protected function is_return_statement( $stackPtr ) {
		$start = $this->phpcsFile->findStartOfStatement( $stackPtr );
		if ( \T_RETURN === $this->tokens[ $start ][ 'code' ] ) {
			return $start;
		}

		return false;
	}

	/**
	 * Is the expression part of an assignment?
	 */
	protected function is_assignment_statement( $stackPtr ) {
		$start = $this->phpcsFile->findStartOfStatement( $stackPtr );
		while ( !empty( $this->tokens[ $start ][ 'nested_parenthesis' ] ) ) {
			$paren = array_key_first( $this->tokens[ $start ][ 'nested_parenthesis' ] );
			$start = $this->phpcsFile->findStartOfStatement( $paren - 1 );
		}
		return $this->is_assignment( $start );
	}

	/**
	 * Does the given scope contain an exit, die, wp_send_json_error(), or similar statement that's sufficient to handle a nonce failure?
	 */
	protected function scope_contains_error_terminator( $start, $end ) {

		$tokens_to_search =
			Tokens::$functionNameTokens +
			[ \T_RETURN => \T_RETURN ];

		$stackPtr = $this->phpcsFile->findNext( $tokens_to_search, $start, $end, false, null, false );
		while ( $stackPtr <= $end && $stackPtr ) {
			if ( in_array( $this->tokens[ $stackPtr ][ 'content' ], array(
					'exit',
					'die',
					'wp_send_json_error',
					'wp_nonce_ays',
					'return',
				) ) ) {
					return $stackPtr;
			}

			$stackPtr = $this->phpcsFile->findNext( $tokens_to_search, $stackPtr + 1, $end, false, null, false );
		}

		return false;
	}

	/**
	 * Does the given expression contain multiple 'and' clauses like `$foo && bar()` or `foo() and $bar`?
	 */
	protected function expression_contains_and( $start, $end ) {
		$tokens = [
			\T_BOOLEAN_AND => \T_BOOLEAN_AND,
			\T_LOGICAL_AND => \T_LOGICAL_AND,

		];
		return $this->phpcsFile->findNext( $tokens, $start, $end, false, null, false );
	}

	/**
	 * Does the given expression contain multiple 'or' clauses like `$foo || bar()` or `foo() or $bar`?
	 */
	protected function expression_contains_or( $start, $end ) {
		$tokens = [
			\T_BOOLEAN_OR => \T_BOOLEAN_OR,
			\T_LOGICAL_OR => \T_LOGICAL_OR,

		];
		return $this->phpcsFile->findNext( $tokens, $start, $end, false, null, false );
	}

	/**
	 * Is the expression immediately preceded by a boolean not `!`?
	 */
	protected function expression_is_negated( $stackPtr ) {
		$previous = $this->previous_non_empty( $stackPtr - 1 );
		if ( \T_BOOLEAN_NOT === $this->tokens[ $previous ][ 'code' ] ) {
			return $previous;
		}

		return false;
	}

	function find_functions_in_expression( $stackPtr, $endPtr = null ) {
		$out = array();

		$newPtr = $stackPtr;
		while( $newPtr = $this->phpcsFile->findNext( [ \T_STRING ], $newPtr, $endPtr, false, null, true ) ) {
			$lookahead = $this->next_non_empty( $newPtr + 1 );
			if ( $lookahead && ( is_null( $endPtr ) || $lookahead <= $endPtr ) ) {
				if ( \T_OPEN_PARENTHESIS === $this->tokens[ $lookahead ][ 'code' ] ) {
					$out[] = $this->tokens[ $newPtr ][ 'content' ];
				}
			}
			$newPtr = $lookahead + 1;
		}

		return $out;
	}

	/**
	 * Returns an array of tokens this test wants to listen for.
	 *
	 * @return array
	 */
	public function register() {
		return Tokens::$functionNameTokens;
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
		if ( 'wp_verify_nonce' === $this->tokens[ $stackPtr ][ 'content' ] ) {
			if ( $ifPtr = $this->is_conditional_expression( $stackPtr ) ) {
				// We're in a conditional, something like if ( wp_verify_nonce() )

				if ( $this->expression_is_negated( $stackPtr ) ) {
					// if ( !wp_verify_nonce() )

					list( $expression_start, $expression_end ) = $this->get_expression_from_condition( $ifPtr );
					list( $scope_start, $scope_end ) = $this->get_scope_from_condition( $ifPtr );

					// if ( $something && ! wp_verify_nonce( ... ) )
					if ( $this->expression_contains_and( $expression_start, $expression_end ) && $this->scope_contains_error_terminator( $scope_start, $scope_end ) ) {
						$andPtr = $this->expression_contains_and( $expression_start, $expression_end );
						if ( $andPtr < $stackPtr ) {
							// if ( ..something.. && ! wp_verify_nonce() ... )
							$operand_functions = array_count_values( $this->find_functions_in_expression( $expression_start, $andPtr ) );
							// if ( ... wp_verify_nonce() && ! wp_verify_nonce() ... )
							if ( isset( $operand_functions[ 'wp_verify_nonce' ] ) ) {
								// This is ok, and we will have already checked the previous wp_verify_nonce(), so skip.
								return;
							}

						} else {
							// if ( ... !wp_verify_nonce() && ..something.. )
							// This is ok since the nonce call comes before the &&
							return;
						}
						$this->phpcsFile->addError( 'Unsafe use of wp_verify_nonce() in expression %s.',
							$stackPtr,
							'UnsafeVerifyNonceNegatedAnd',
							[ $this->tokens_as_string( $expression_start, $expression_end ) ], //[ $unsafe_expression, $method, $methodParam[ 'clean' ], rtrim( "\n" . join( "\n", $extra_context ) ) ],
							0,
							false
						);

					}
				} else {
					// if ( wp_verify_nonce() )
					// In this case we want the else {} part
					$elsePtr = $this->has_else( $ifPtr );
					if ( $elsePtr ) {
						list( $expression_start, $expression_end ) = $this->get_expression_from_condition( $ifPtr );
						list( $scope_start, $scope_end ) = $this->get_scope_from_condition( $elsePtr );

						// if ( $something || wp_verify_nonce( ... ) )
						if ( $this->expression_contains_or( $expression_start, $expression_end ) && $this->scope_contains_error_terminator( $scope_start, $scope_end ) ) {

							$orPtr = $this->expression_contains_or( $expression_start, $expression_end );
							if ( $orPtr < $stackPtr ) {
								// if ( ..something.. || wp_verify_nonce() ... )
								$operand_functions = array_count_values( $this->find_functions_in_expression( $expression_start, $orPtr ) );
								// If the previous "something" was another wp_verify_nonce() call then we're fine, ignore
								if ( isset( $operand_functions[ 'wp_verify_nonce' ] ) ) {
									return;
								}
							} else {
								// if ( wp_verify_nonce || ..something.. )
								$operand_functions = array_count_values( $this->find_functions_in_expression( $orPtr, $expression_end ) );
								// If the next "something" is another wp_verify_nonce() call then we're fine, ignore
								if ( isset( $operand_functions[ 'wp_verify_nonce' ] ) ) {
									return;
								}
							}
							$this->phpcsFile->addError( 'Possibly unsafe use of wp_verify_nonce() in expression %s.',
								$stackPtr,
								'UnsafeVerifyNonceElse',
								[ $this->tokens_as_string( $expression_start, $expression_end ) ], // [ $unsafe_expression, $method, $methodParam[ 'clean' ], rtrim( "\n" . join( "\n", $extra_context ) ) ],
								0,
								false
							);
						}

					}
				}

			} else {

				if ( !$this->is_return_statement( $stackPtr ) && !$this->is_assignment_statement( $stackPtr ) ) {
					// wp_verify_nonce() used as an unconditional statement - most likely mistaken for check_admin_referer()
					$this->phpcsFile->addError( 'Unconditional call to wp_verify_nonce(). Consider using check_admin_referer() instead.',
					$stackPtr,
					'UnsafeVerifyNonceStatement',
					[],
					0,
					false
					);
				}

			}


		}
	}

}