#!/bin/sh
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:./lib
export GLIBCXX_FORCE_NEW=1

memory_leaks () {
valgrind \
-v \
--leak-check=full \
--show-reachable=yes \
--leak-resolution=high \
--tool=memcheck \
--track-origins=yes \
--read-var-info=yes \
--suppressions=valgrind.sup \
bin/captool \
2> out/valgrind
#--demangle=no \
}

heap_usage () {
valgrind \
-v \
--tool=massif \
--massif-out-file=valgrind.massif \
#--time-unit=B \
bin/captool
ms_print valgrind.massif > valgrind.massif.out
}

memory_leaks
