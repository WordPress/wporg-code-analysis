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
				12,
				16,
				21,
			],
			$error_lines
		);

		$warnings      = $phpcsFile->getWarnings();
		$warning_lines = array_keys( $warnings );
		$this->assertEquals(
			[
				4,
				8,
				26,
				30, 31, 32
			],
			$warning_lines
		);

		// Verify the error terminates at the correct offset.
		$this->assertEquals( 'Unescaped parameter esc_url_raw( $foo ) used in echo', $warnings[30][2][0]['message'] );
		$this->assertEquals( 'Unescaped parameter esc_url_raw( $foo ) used in echo', $warnings[31][2][0]['message'] );
		$this->assertEquals( 'Unescaped parameter esc_url_raw( $foo ) used in echo', $warnings[32][20][0]['message'] );
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
