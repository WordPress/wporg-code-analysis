# WordPress.org Code Analysis

An experiment.


## Installation

1. Clone this repo in a local folder.

```sh
git clone https://github.com/WordPress/wporg-code-analysis
```

2. Run Composer to install dependencies.

```sh
cd wporg-code-analysis
composer install
```

## Usage

You can check code that's hosted in the WordPress.org/plugins repository, and code on your computer.

For normal use you do not need to install this as a WordPress plugin, nor does it require a WordPress install in order to work.


### Scan code from the WordPress.org/plugins repository

Pass the plugin's slug to the `check-plugin-by-slug.php` script:

`php bin/check-plugin-by-slug.php --slug=akismet --errors`

To show warnings also:

`php bin/check-plugin-by-slug.php --slug=akismet`

To scan a specific tag, rather than trunk:

`php bin/check-plugin-by-slug.php --slug=akismet --errors --tag=4.1.5`

To see results in different formats:

`php bin/check-plugin-by-slug.php --slug=akismet --report=full`

`php bin/check-plugin-by-slug.php --slug=akismet --report=json`

`php bin/check-plugin-by-slug.php --slug=akismet --report=summary` (default)

To check the most popular `n` plugins, omit the `slug` parameter and provide `number`:

`php bin/check-plugin-by-slug.php --number=3`

`php bin/check-plugin-by-slug.php --number=3 --page=2`

To check the newest `n` plugins:

`php bin/check-plugin-by-slug.php --report=full --errors --browse=new --number=3`


### Scan local code

To scan plugin source code in a local folder. Note that this only runs the `MinimalPluginStandard` sniff.

`bin/scan-dir.sh path/to/code`

By default, the script passes the `-n` and `-s` flags to PHPCS, so that warnings are hidden and sniff codes are shown. If you prefer, though, you can override that and pass your own [PHPCS arguments](https://github.com/squizlabs/PHP_CodeSniffer/wiki/Usage#getting-help-from-the-command-line). Pass them _before_ the directory:

```sh
# -a runs PHPCS interactively. By default PHPCS shows errors and warnings, but not sniff codes.
./bin/scan-dir.sh -a /path/to/my-plugin-source
```

```sh
# -n shows only errors, -s shows sniff codes, -a runs PHPCS interactively
./bin/scan-dir.sh -nsa /path/to/my-plugin-source
```


## Tests

To run the unit tests:

1. Run `composer install`, to install the dependencies.
1. Run `composer run test` to run the suite once, or `composer run test:watch` to run it continuously.


## Questions

### Do I need a WordPress site or local test environment?

No. The codesniffer rules are bundled into a WordPress plugin for one particular use case, but they work stand-alone as well. For example, after installation, this will work:

`phpcs --standard=./MinimalPluginStandard /path/to/my-plugin-source`

### How does this differ from WPCS and other PHP or WordPress coding standards?

In two main ways.

**One**, this tool is not intended to prescribe or encourage best practices. It is intended to answer the question, "does a plugin meet the bare minimum standards necessary in order for it to be safely installed on a WordPress site?" This includes plugins that might be old enough to pre-date newer WordPress practices and API functions.

In that sense, it intentionally ignores a great many things that other coding standards treat as errors or warnings. wporg-code-analysis is designed to be as quiet as possible, and only alert on code that is especially risky or vulnerable to security exploits. In other words, it will draw your attention to code that is likely to be rejected by the WordPress Plugin Review Team.

**Two**, this tool is smarter than most phpcs-based code sniffers at differentiating secure and insecure code. For example, DirectDBSniff can tell that this code is _secure_ (though not ideal):

```php
function secure_but_not_recommended( $ids, $status ) {
    global $wpdb;
    $in = "'" . join( "','", array_map( 'esc_sql', $ids) ) . "'";
    $sql = "SELECT * FROM $wpdb->posts WHERE ID IN ($in)";
    return $wpdb->get_results( $wpdb->prepare( $sql . " AND post_status = %s", $status ) );
}
```

and that this very similar code is _insecure_:

```php
function insecure_do_not_use( $ids, $status ) {
    global $wpdb;
    $in = "'" . join( "','", array_map( 'sanitize_text_field', $ids) ) . "'";
    $sql = "SELECT * FROM $wpdb->posts WHERE ID IN ($in)";
    return $wpdb->get_results( $wpdb->prepare( $sql . " AND post_status = %s", $status ) );
}
```

See the unit tests for other examples of [safe](https://github.com/WordPress/wporg-code-analysis/blob/trunk/tests/db/DirectDBUnitTest.php-safe.inc) and [unsafe](https://github.com/WordPress/wporg-code-analysis/blob/trunk/tests/db/DirectDBUnitTest.php-bad.inc) database code that the tool can correctly differentiate.
