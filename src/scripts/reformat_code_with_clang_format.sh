#!env bash

# Exclude:
# netmap_plugin/netmap_includes/net/netmap.h
# netmap_plugin/netmap_includes/net/netmap_user.h
# libpatricia/patricia.c
# libpatricia/patricia.h

# for i in `find . |egrep "\.cpp$"`; do clang-format -i $i ;done
# for i in `find . |egrep "\.c$"`; do clang-format -i $i ;done
# for i in `find . |egrep "\.h$"`; do clang-format -i $i ;done

