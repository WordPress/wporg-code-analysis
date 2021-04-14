#!/bin/zsh
# See readme for usage.
DIR="$(dirname $(dirname $0) )"

# Add default flags if they only pass the folder. Otherwise let them specify whatever flags they want.
if [ "$#" -eq 1 ]; then
	$DIR/vendor/bin/phpcs --standard=$DIR/MinimalPluginStandard -n -s $@
else
	$DIR/vendor/bin/phpcs --standard=$DIR/MinimalPluginStandard $@
fi
