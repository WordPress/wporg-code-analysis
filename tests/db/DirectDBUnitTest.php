<?php
use PHPUnit\Framework\TestCase;
use PHP_CodeSniffer\Files\LocalFile;
use PHP_CodeSniffer\Ruleset;
use PHP_CodeSniffer\Config;

/**
 * @group plugin
 * @group directdb
 */
class DirectDBUnitTest extends TestCase {
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
		$error_lines = array_keys($foundErrors);

		$this->assertEquals(
			[
				14,
				22,
				30,
				38,
				45,
				52,
				59,
				66,
				75,
				82,
				97,
				106,
				113,
				120,
				140,
				159,
				168,
				181,
				200,
				221,
				258,
				270,
				292,
				310,
				316,
				328,
				335,
				342,
			],
			$error_lines );

		$warning_lines = array_keys( $phpcsFile->getWarnings() );
		$this->assertEquals(
			[
				89,
				149,
				188,
				191,
				196,
				203,
				207,
				278,
				279,
				280,
				281,
				301
			],
			$warning_lines );

		$expected =<<<'EOF'
Unescaped parameter $sql_query used in $wpdb->query($sql_query)
$sql_query assigned unsafely at line 327:
 $sql_query .= implode(" UNION ALL ", $sql_query_sel)
$sql_query_sel assigned unsafely at line 325:
 $sql_query_sel[] = "SELECT $new_post_id, '$meta_key', '$meta_value'"
$new_post_id used without escaping.
$meta_key assigned unsafely at line 323:
 $meta_key = sanitize_text_field($meta_info->meta_key)
Note: sanitize_text_field() is not a safe escaping function.
$meta_value assigned unsafely at line 324:
 $meta_value = addslashes($meta_info->meta_value)
Note: addslashes() is not a safe escaping function.
$meta_info->meta_key used without escaping.
$meta_info->meta_value used without escaping.
EOF;
		$this->assertEquals( $expected, $foundErrors[ 328 ][9][0][ 'message' ] );

		$expected =<<<'EOF'
Unescaped parameter $sql used in $wpdb->query($sql)
$sql assigned unsafely at line 334:
 $sql = $wpdb->prepare( $query, $meta_value )
$query assigned unsafely at line 333:
 $query = "SELECT * FROM $wpdb->postmeta WHERE meta_key = '$foo' AND meta_value = %s"
$foo used without escaping.
EOF;
		$this->assertEquals( $expected, $foundErrors[ 335 ][9][0][ 'message' ] );

		$expected =<<<'EOF'
Unescaped parameter $query used in $wpdb->get_results("
SELECT DISTINCT meta_value, post_id
FROM $wpdb->postmeta
WHERE meta_key = '_sku' AND meta_value  like '%$query%' LIMIT $this->limit
")
$query assigned unsafely at line 340:
 $query = filter_input(INPUT_POST, 'query', FILTER_SANITIZE_STRING)
Note: filter_input() is not a safe escaping function.
EOF;
		$this->assertEquals( $expected, $foundErrors[ 342 ][27][0][ 'message' ] );
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
		$lines = array_keys($foundErrors);

		$this->assertEquals(
			[
				446, // FIXME: this is a known bug. Need to find a way to fix it (false_positive_22)
			],
			$lines);
	}
}
