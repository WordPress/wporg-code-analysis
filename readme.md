# WordPress.org Code Analysis

An experiment.

# Installation

1. Clone this repo in a local folder.

`git clone git clone https://github.com/WordPress/wporg-code-analysis`

2. Run Composer to install dependencies.

`cd wporg-code-analysis`
`composer install`

# Usage

For normal use you do not need to install this as a WordPress plugin, nor does it require a WordPress install in order to work.

To scan a plugin from the directory given its slug:

`php bin/check-plugin-by-slug.php --slug=akismet --errors`

To show warnings also:

`php bin/check-plugin-by-slug.php --slug=akismet`

To scan a specific tag, rather than trunk:

`php bin/check-plugin-by-slug.php --slug=akismet --errors --tag=4.1.5`

To scan plugin source code in a local folder:

`bin/scan-dir.sh path/to/code`

# Questions

## Do I need a WordPress site or local test environment?

No. The codesniffer rules are bundled into a WordPress plugin for one particular use case, but they work stand-alone as well. For example, after installation, this will work:

`phpcs --standard=./MinimalPluginStandard /path/to/my-plugin-source`

## How do I use this to check code in my own svn or git repo?

Install wporg-code-analysis as above. Then, with your plugin's source code checked out in a local working dir `/path/to/my-plugin-source`:

`bin/scan-dir.sh /path/to/my-plugin-source`

## How does this differ from WPCS and other PHP or WordPress coding standards?

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

