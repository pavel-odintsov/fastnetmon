#/usr/bin/bash

# If you want to prevent some code from automatic reformatting, please add it to .clang_formatter_excludes file

echo "We will reformat all your code"

for file in `find /home/odintsov/repos/fastnetmon_community/src -type f | egrep '\.(c|cpp|hpp|h)$' | egrep -vf /home/odintsov/repos/fastnetmon_community/src/.clang_formatter_excludes`;
do
    echo "Reformattting $file";
    clang-format -style=file -i $file;
done

