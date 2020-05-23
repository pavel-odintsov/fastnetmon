#/usr/bin/bash

echo "We will reformat all your code"
for file in `find /home/odintsov/repos/fastnetmon_github/src -type f | egrep '\.(c|cpp|hpp|h)$' | egrep -vf /home/odintsov/repos/fastnetmon_github/src/.clang_formatter_excludes`;
do
    echo "Reformattting $file";
    clang-format -style=file -i $file;
done

