#!/bin/sh

# Exclude:
#  src/plugins/netmap/netmap_includes/net/netmap.h
#  src/plugins/netmap/netmap_includes/net/netmap_user.h
#  src/libpatricia/patricia.c
#  src/libpatricia/patricia.h

FILES=$(find src -iname '*.[ch]' -or -iname '*.cpp' | grep -vE "netmap_includes|libpatricia")

# Format the code style defined in .clang-format or _clang-format
clang-format -i -style=file ${FILES} || (echo 'clang-format failed'; exit 1);
