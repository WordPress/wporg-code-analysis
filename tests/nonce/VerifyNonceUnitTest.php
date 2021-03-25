<?php
use PHPUnit\Framework\TestCase;
use PHP_CodeSniffer\Files\LocalFile;
use PHP_CodeSniffer\Ruleset;
use PHP_CodeSniffer\Config;
 
class VerifyNonceUnitTest extends TestCase {
	public function test_unsafe_code() {
		$fixtureFile = __FILE__ . '-bad.inc';
		$sniffFiles = [ dirname( dirname( __DIR__ ) ) . '/MinimalPluginStandard/Sniffs/VerifyNonceSniff.php' ];
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
				5,
				11,
				16,
				22,
				26,
				34,
				38,
			], 
			$error_lines );

	}

	public function test_safe_code() {
		$fixtureFile = __FILE__ . '-safe.inc';
		$sniffFiles = [ dirname( dirname( __DIR__ ) ) . '/MinimalPluginStandard/Sniffs/VerifyNonceSniff.php' ];
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