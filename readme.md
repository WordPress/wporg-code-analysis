# WordPress.org Code Analysis

An experiment.

* Clone this repo in a local folder.
* Run `composer install` to install dependencies.

For normal use you do not need to install this as a WordPress plugin, nor does it require a WordPress install in order to work.

To scan a plugin from the directory given its slug:

`php bin/check-plugin-by-slug.php --slug=akismet --errors`

To show warnings also:

`php bin/check-plugin-by-slug.php --slug=akismet`

To scan a specific tag, rather than trunk:

`php bin/check-plugin-by-slug.php --slug=akismet --errors --tag=4.1.5`

To scan plugin source code in a local folder:

`bin/scan-dir.sh path/to/code`

