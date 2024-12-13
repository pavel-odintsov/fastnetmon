#!/bin/bash

# Check if two arguments are provided
if [ $# -ne 1 ]; then
  echo "Usage: $0 <./bin>"
  echo "Example: $0 ../../../build_fuzz_harness/parse_sflow_v5_packet_fuzz"
  echo "Example: $0 ../../../build_fuzz_harness/process_netflow_packet_v5_fuzz"
  exit 1
fi
TARGET_PROGRAM="$1"

ASAN_OPTIONS="detect_odr_violation=0:abort_on_error=1:symbolize=0"
TIME_STOP=3600

INPUT_DIR="./input"
OUTPUT_DIR="./output"
DIR_NAME=$(basename $1)_dir
DICT="/AFLplusplus/dictionaries/pcap.dict"
MINIMIZE_SCRIPT=/src/tests/fuzz/scripts/minimize_out.sh

SESSION_NAME="$DIR_NAME"


if [ ! -d "$DIR_NAME" ]; then
    echo "Work directory '$DIR_NAME' does not exist. Creating it..."
    mkdir -p "$DIR_NAME"
fi

cd $DIR_NAME
TARGET_PROGRAM=../"$1"

if [ ! -d "$INPUT_DIR" ]; then
    echo "Input directory '$INPUT_DIR' does not exist. Creating it..."
    mkdir -p "$INPUT_DIR"
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    echo "Output directory '$OUTPUT_DIR' does not exist. Creating it..."
    mkdir -p "$OUTPUT_DIR"
fi

if [ ! -f "$TARGET_PROGRAM" ]; then
    echo "Target program '$TARGET_PROGRAM' not found."
    exit 1
fi

if [ ! -x "$MINIMIZE_SCRIPT" ]; then
    echo "Minimization script not found or not executable."
    exit 1
fi

echo core | tee /proc/sys/kernel/core_pattern

wget https://raw.githubusercontent.com/catalyst/openstack-sflow-traffic-billing/refs/heads/master/examples/sample-sflow-packet -O input/1

tmux new-session -d -s $SESSION_NAME -n master
tmux send-keys -t ${SESSION_NAME}:master "ASAN_OPTIONS=$ASAN_OPTIONS AFL_EXIT_ON_TIME=$TIME_STOP afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -x $DICT -m none -M master -- ./$TARGET_PROGRAM " C-m
tmux new-window -t $SESSION_NAME -n slave
tmux send-keys -t ${SESSION_NAME}:slave "ASAN_OPTIONS=$ASAN_OPTIONS AFL_EXIT_ON_TIME=$TIME_STOP afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -x $DICT -m none  -S slave -- ./$TARGET_PROGRAM " C-m
tmux select-window -t ${SESSION_NAME}:slave
tmux attach-session -t $SESSION_NAME


# Wait for all afl-fuzz processes to finish
while pgrep -x "afl-fuzz" > /dev/null; do
    echo "Waiting for afl-fuzz processes to finish..."
    sleep 10
done

echo "All afl-fuzz processes have completed. Stopping tmux sessions."
tmux kill-session -t $SESSION_NAME

echo "Starting minimization."
$MINIMIZE_SCRIPT $OUTPUT_DIR $TARGET_PROGRAM

