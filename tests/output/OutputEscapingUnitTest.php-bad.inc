<?php

function unsafe_output_example_1( $foo ) {
	echo $foo;
}

function unsafe_output_example_2( $foo ) {
	print( addslashes( $foo ) );

	//$bar = $_GET['foo'];
	// /Users/iandunn/vhosts/tools/wporg-code-analysis/tests/output/OutputEscapingUnitTest.php-bad2.inc
	//include __DIR__ . '/OutputEscapingUnitTest.php-bad2.inc';

}

//echo $_GET['foo'];
