<?php
namespace WordPressDotOrg\Code_Analysis;

use PHPUnit\Framework\TestCase;
use WordPressDotOrg\Code_Analysis\PHPCS;


class DirectDBTests extends TestCase {

	public $full_report;

	public function setUp() {
		
		$phpcs = new PHPCS();
		$phpcs->set_standard( dirname( dirname( __DIR__ ) ). '/sniffs/DirectDBSniff.php' );
		// phpcs --standard=PEAR --sniffs=Generic.PHP.LowerCaseConstant,PEAR.WhiteSpace.ScopeIndent /path/to/code

		$this->full_report = $phpcs->run_full_report( $path );

	}

	public function test_full_report() {
		var_dump( $this->full_report );
	}

}
