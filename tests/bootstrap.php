<?php

// Fake WP_Error class so the PHPCS class works
class WP_Error {
	var $code;
	var $message;
	var $data;

	function __construct( $code = '', $message = '', $data = '' ) {
		$this->code = $code;
		$this->message = $message;
		$this->data = $data;
	}

	public function __toString() {
		return var_export( $this, true );
	}
}

// Ditto
function get_temp_dir() {
	return '/tmp';
}

// Again so PHPCS class works
define( 'WPINC', 'yeahnah' );


require_once( dirname( __DIR__ ) . '/includes/class-phpcs.php' );
