<?php

function unsafe_output_example_1( $foo ) {
	echo $foo;
}

function unsafe_output_example_2( $foo ) {
	print( addslashes( $foo ) );
}