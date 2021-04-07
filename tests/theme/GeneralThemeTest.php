<?php
use PHPUnit\Framework\TestCase;
use PHP_CodeSniffer\Files\LocalFile;
use PHP_CodeSniffer\Ruleset;
use PHP_CodeSniffer\Config;
 
// This uses the entire MinimalThemeStandard ruleset, including external rules, to make sure we have coverage for things that otherwise would require a custom sniff.
class GeneralThemeTest extends TestCase {
	public function test_unsafe_code() {
		$fixtureFile = __FILE__ . '-bad.inc';
		$config = new Config( [ '--standard=' . dirname( dirname( __DIR__ ) ) . '/MinimalThemeStandard/ruleset.xml' ] );
		$ruleset = new Ruleset($config);
		$ruleset->populateTokenListeners();
		$phpcsFile = new LocalFile($fixtureFile, $ruleset, $config);
		$phpcsFile->process();
		$foundErrors = $phpcsFile->getErrors();
		$error_lines = array_keys($foundErrors);

		$this->assertEquals(
			[
				3,
				5,
			], 
			$error_lines );


	}

	public function test_safe_code() {
		$fixtureFile = __FILE__ . '-safe.inc';
		$config = new Config( [ '--standard=' . dirname( dirname( __DIR__ ) ) . '/MinimalThemeStandard/ruleset.xml' ] );
		$ruleset = new Ruleset($config);
		$ruleset->populateTokenListeners();
		$phpcsFile = new LocalFile($fixtureFile, $ruleset, $config);
		$phpcsFile->process();
		$foundErrors = $phpcsFile->getErrors();
		$lines = array_keys($foundErrors);

		$this->assertEquals(
			[],
			$lines);
	}
}