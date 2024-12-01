#!/bin/bash

SESSION_NAME="afl_fuzz"

INPUT_DIR="./input"
OUTPUT_DIR="./output"
TARGET_PROGRAM="./fastnetmon"

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
    cp /src/build/fastnetmon .
    exit 1
fi


echo "1" >> "$INPUT_DIR"/1
echo "a" >> "$INPUT_DIR"/2
cp /src/fastnetmon.conf "$INPUT_DIR"/3


tmux new-session -d -s $SESSION_NAME -n afl1

tmux send-keys -t ${SESSION_NAME}:afl1 "afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -m none -M master -- $TARGET_PROGRAM --configuration_check --configuration_file @@" C-m

tmux new-window -t $SESSION_NAME -n afl2

tmux send-keys -t ${SESSION_NAME}:afl2 "afl-fuzz -i $INPUT_DIR -o $OUTPUT_DIR -m none  -S fuzzer02 -- $TARGET_PROGRAM --configuration_check --configuration_file @@" C-m

tmux select-window -t ${SESSION_NAME}:afl1

tmux attach-session -t $SESSION_NAME
