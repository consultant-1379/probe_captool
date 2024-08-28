#!/usr/bin/zsh
#
# $0 [files]

#TYPE="--inuse_objects"
#TYPE="--alloc_objects"
#BASE="--base=\$base"
LIMITS="--nodefraction=0 --edgefraction=0" # --nodecount=1000"

### Memory usage
mem_usage(){
local OPTS="--lines $LIMITS $TYPE $BASE --gif "
for i in ${${*}:-*heap}; do
  base=${base:-$i}
  google-pprof ${(e)=OPTS} bin/captool $i >$i${TYPE}.gif
done
}

### CPU profiling

REFTYPE="functions" 
#REFTYPE="lines"

#OUTTYPE="text"
OUTTYPE="gif"

FOCUS="FlowOutputStrict::process"

IGNORE="_mcount"

google-pprof \
		${=LIMITS} \
		--$REFTYPE \
		--$OUTTYPE \
		${FOCUS:+--focus=${FOCUS}} \
		${IGNORE:+--ignore=${IGNORE}} \
	bin/captool captool-prof >captool-prof-${REFTYPE}${FOCUS:+-${FOCUS}}.${OUTTYPE}
