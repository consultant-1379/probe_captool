#!/bin/sh

if [ $# -ne 1 ] 
then 
	echo "Usage: captool.sh <parserInstance>"
	exit
fi
 
export LD_LIBRARY_PATH=./lib:$LD_LIBRARY_PATH

ulimit -c unlimited
bin/captool $1  > /var/log/ericsson/eniq-analysis/captool_$1.log 2>&1
