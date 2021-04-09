<?php

function safe_output_example_1( $foo ) {
	echo esc_html( $foo );
}

function safe_output_example_2( $foo ) {
	$esc_foo = esc_html( $foo );
	print( $esc_foo );
}