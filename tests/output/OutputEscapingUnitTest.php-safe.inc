<?php

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

function safe_output_example_4( $foo ) {
	echo esc_js( $foo );
}

function safe_output_example_5( $foo ) {
	echo trim( esc_url( $foo ) );
}

?>

<p>safe output example 6</p>
<h2><?php echo(esc_html(foo())) ?></h2>

<?php
$foo = bar();

function safe_output_example_7( $data ) {
    $field_description = WC_Admin_Settings::get_field_description($data);
    $description = $field_description['description'];
    $tooltip_html = $field_description['tooltip_html'];

	// Safe because WC_Admin_Settings::get_field_description() uses kses.
	echo $tooltip_html;
}