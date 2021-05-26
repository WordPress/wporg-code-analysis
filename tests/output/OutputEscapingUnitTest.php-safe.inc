<?php

// This is not a real plugin.
// This merely contains secure examples of php code for testing.
return;

function safe_output_example_1( $foo ) {
	echo esc_html( $foo );
}

function safe_output_example_2( $foo ) {
	$esc_foo = esc_html( $foo );
	print( $esc_foo );
}

function safe_output_example_3() {
	#$this->indent = esc_html( $foo );
	echo $this->indent . htmlspecialchars("<?php " . $this->the_field_method . "( '" . $this->name ."'". $this->location_rendered_param . " ); ?>")."\n";
}
