<?php

function unsafe_output_example_1( $foo ) {
	echo $foo;
}

function unsafe_output_example_2( $foo ) {
	print( addslashes( $foo ) );
}

unsafe_output_example_1( $_GET['foo'] );
unsafe_output_example_2( $_GET['foo'] );

// todo - why isn't it detecting that ^ are unsafe?
