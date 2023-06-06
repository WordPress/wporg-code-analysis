<?php

function unsafe_output_example_1( $foo ) {
	echo $foo;
}

function unsafe_output_example_2( $foo ) {
	print( addslashes( $foo ) );
}

function unsafe_output_example_3( ) {
	echo $_POST['foo'];
}

function unsafe_output_example_4() {
	echo trim( $_GET['bar'] );
}

function unsafe_output_example_5() {
	// Not an output escaping function!
	echo addslashes( $_REQUEST['foo'] );
}

function unsafe_output_example_6( $foo ) {
	// Unsafe but just a warning.
	echo trim( $foo );
}

function unsafe_output_example_7( $foo ) {
	echo esc_url_raw( $foo );
	echo esc_url_raw( $foo ) ?>
	?><img src="<?php echo esc_url_raw( $foo ) ?>" /><?php
}

