#!/bin/zsh
# Usage:
# bin/scan-dir.sh path/to/source/code
DIR="$(dirname $(dirname $0) )/MinimalPluginStandard"
phpcs --standard=$DIR -n -s $@