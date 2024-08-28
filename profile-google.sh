#!/bin/sh

ulimit -c unlimited
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib
export HEAP_PROFILE_ALLOCATION_INTERVAL=100000000
#export CPUPROFILE="captool.prof"

#cat ../passive-Gn_00001_20081205202327.dump > pipe &
#cat ../x.pcap >pipe &
mergecap -a rogers/passive-Gn_0000* -w pipe &
bin/captool 2>&1 | tee captool.log
