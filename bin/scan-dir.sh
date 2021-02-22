#!/bin/zsh
# Usage:
# bin/scan-dir.sh path/to/source/code
DIR="$(dirname $(dirname $0) )"
$DIR/vendor/bin/phpcs --standard=$DIR/MinimalPluginStandard -n -s $@