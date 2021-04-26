<?php
use PHPUnit\Framework\TestCase;
use PHP_CodeSniffer\Files\LocalFile;
use PHP_CodeSniffer\Ruleset;
use PHP_CodeSniffer\Config;

/**
 * @group plugin
 * @group output
 */
class OutputEscapingUnitTest extends TestCase {
	public function test_unsafe_code() {
		$fixtureFile = __FILE__ . '-bad.inc';
		$sniffFiles = [ dirname( dirname( __DIR__ ) ) . '/MinimalPluginStandard/Sniffs/OutputEscapingSniff.php' ];
		$config = new Config();
		$ruleset = new Ruleset($config);
		$ruleset->registerSniffs($sniffFiles, [], []);
		$ruleset->populateTokenListeners();
		$phpcsFile = new LocalFile($fixtureFile, $ruleset, $config);
		$phpcsFile->process();
		$foundErrors = $phpcsFile->getErrors();
		$error_lines = array_keys($foundErrors);

		$this->assertEquals(
			[
				4,
				8,
			],
			$error_lines );

		$warning_lines = array_keys( $phpcsFile->getWarnings() );
		$this->assertEquals(
			[
			],
			$warning_lines );

	}

	public function test_safe_code() {
		$fixtureFile = __FILE__ . '-safe.inc';
		$sniffFiles = [ dirname( dirname( __DIR__ ) ) . '/MinimalPluginStandard/Sniffs/OutputEscapingSniff.php' ];
		$config = new Config();
		$ruleset = new Ruleset($config);
		$ruleset->registerSniffs($sniffFiles, [], []);
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
