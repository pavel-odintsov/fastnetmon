#!/bin/bash

script_dir=`dirname "$0"`

find $script_dir/.. -type f | egrep -v 'fastnetmon.pb.cc|.git|build'> /tmp/file_list

for i in `cat /tmp/file_list` ; do
    grep -Hi "$1" $i
done

