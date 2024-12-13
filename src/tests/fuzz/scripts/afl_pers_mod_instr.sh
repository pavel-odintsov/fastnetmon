#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <file>"
  echo "Example: $0 sflow_plugin/sflow_collector.cpp"
  echo "Example: $0 netflow_plugin/netflow_collector.cpp" 
  exit 1
fi

FILE=$1

# Проверяем, что файл существует
if [ ! -f "$FILE" ]; then
  echo "Error: File $FILE does not exist."
  exit 1
fi

# ADd __AFL_FUZZ_INIT() in beginnig of file
sed -i '1i __AFL_FUZZ_INIT();' "$FILE"

# Change  while(true) by while(__AFL_LOOP(10000))
sed -i 's/while\s*(\s*true\s*)/while (__AFL_LOOP(10000))/' "$FILE"

sed -i 's/char \s*udp_buffer\s*\[\s*udp_buffer_size\s*\]/unsigned char * udp_buffer = __AFL_FUZZ_TESTCASE_BUF;/' "$FILE"

sed -i 's/int received_bytes = recvfrom([^;]*);/int received_bytes = __AFL_FUZZ_TESTCASE_LEN;/' "$FILE"

echo "Instrumentation completed for file: $FILE"
