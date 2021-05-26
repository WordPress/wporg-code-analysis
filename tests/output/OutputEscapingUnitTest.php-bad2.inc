<?php

//echo $bar;


class Foo {
	public function __construct() {
//		add_action( 'admin_notices', array( $this, 'printMessages' ) );

		$this->saveCustomFields(0);
		$this->printMessages();
	}

	public function printMessages() {
		echo $this->message; // not detected
		//////////

		if ( did_action( 'admin_notices' ) !== 1 ) {
			return;
		}

		foreach ( array( 'updates', 'errors' ) as $type ) {
			if ( $this->options[ $type ] && ( self::DEBUG_MODE || $this->userMessageCount[ $type ] ) ) {
				$message = '';
				$class   = $type == 'updates' ? 'updated' : 'error';

				foreach ( $this->options[ $type ] as $messageData ) {
					if ( $messageData['mode'] == 'user' || self::DEBUG_MODE ) {
						$message .= '<p>' . $messageData['message'] . '</p>';
					}
				}

				require( dirname( __FILE__ ) . '/views/message.php' );

				$this->options[ $type ]          = array();
				$this->updatedOptions            = true;
				$this->userMessageCount[ $type ] = 0;
			}
		}
	}

	/**
	 * Queues up a message to be displayed to the user
	 * NOTE: In order to allow HTML in the output, any unsafe variables in $message need to be escaped before
	 * they're passed in, instead of escaping here.
	 *
	 * @param string $message The text to show the user
	 * @param string $type    'update' for a success or notification message, or 'error' for an error message
	 * @param string $mode    'user' if it's intended for the user, or 'debug' if it's intended for the developer
	 *
	 * @author Ian Dunn <ian@iandunn.name>
	 */
	protected function enqueueMessage( $message, $type = 'update', $mode = 'user' ) {
		//echo $message; - detects
		$this->message = $message;
		echo $this->message; // detects
		//////////

		if ( ! is_string( $message ) || empty( $message ) ) {
			return false;
		}

		if ( ! isset( $this->options[ $type . 's' ] ) ) {
			return false;
		}

		array_push( $this->options[ $type . 's' ], array(
			'message' => $message,
			'type'    => $type,
			'mode'    => $mode,
		) );

		if ( $mode == 'user' ) {
			$this->userMessageCount[ $type . 's' ] ++;
		}

		$this->updatedOptions = true;

		return true;
	}

	/**
	 * Saves values of the the custom post type's extra fields
	 * @param int $postID
	 * @author Ian Dunn <ian@iandunn.name>
	 */
	public function saveCustomFields( $postID ) {
//		if ( ! $postID ) {
			$this->enqueueMessage( $_GET['foo'] );
//		}
	}
}

$foo = new Foo();
