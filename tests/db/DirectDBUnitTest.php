<?php
use PHPUnit\Framework\TestCase;
use PHP_CodeSniffer\Files\LocalFile;
use PHP_CodeSniffer\Ruleset;
use PHP_CodeSniffer\Config;
 
class DisallowExtractSniffTest extends TestCase {
    public function test_unsafe_code() {
        $fixtureFile = __FILE__ . '-bad.inc';
        $sniffFiles = [ dirname( dirname( __DIR__ ) ) . '/MinimalPluginStandard/Sniffs/DirectDBSniff.php' ];
        $config = new Config();
        $ruleset = new Ruleset($config);
        $ruleset->registerSniffs($sniffFiles, [], []);
        $ruleset->populateTokenListeners();
        $phpcsFile = new LocalFile($fixtureFile, $ruleset, $config);
        $phpcsFile->process();
        $foundErrors = $phpcsFile->getErrors();
        var_dump( __FUNCTION__, $foundErrors );
        $lines = array_keys($foundErrors);

        // FIXME
        $this->assertEquals([7], $lines);
    }

    public function test_safe_code() {
        $fixtureFile = __FILE__ . '-safe.inc';
        $sniffFiles = [ dirname( dirname( __DIR__ ) ) . '/MinimalPluginStandard/Sniffs/DirectDBSniff.php' ];
        $config = new Config();
        $ruleset = new Ruleset($config);
        $ruleset->registerSniffs($sniffFiles, [], []);
        $ruleset->populateTokenListeners();
        $phpcsFile = new LocalFile($fixtureFile, $ruleset, $config);
        $phpcsFile->process();
        $foundErrors = $phpcsFile->getErrors();
        var_dump( __FUNCTION__, $foundErrors );
        $lines = array_keys($foundErrors);

        // FIXME
        $this->assertEquals([7], $lines);
    }
}