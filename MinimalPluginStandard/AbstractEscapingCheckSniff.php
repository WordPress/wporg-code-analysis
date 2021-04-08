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

}