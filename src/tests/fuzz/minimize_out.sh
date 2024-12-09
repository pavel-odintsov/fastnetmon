#!/bin/bash
export ASAN_OPTIONS=detect_odr_violation=0:abort_on_error=1:symbolize=0
# Check if two arguments are provided
if [ $# -ne 2 ]; then
  echo "Usage: $0 <path to out directory> <path to binary>"
  exit 1
fi

# Get arguments
out_dir="$1"
binary="$2"
index=1

# Check if the out directory exists
if [ ! -d "$out_dir" ]; then
  echo "Error: Directory $out_dir does not exist!"
  exit 1
fi

# Check if the binary exists and is executable
if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
  echo "Error: Binary file $binary does not exist or is not executable!"
  exit 1
fi

# Create output directory if it doesn't exist
if [ ! -d "new_out" ]; then
  mkdir new_out
  echo "Directory new_out has been created."
fi

# Check if there are files in the out directory
if [ -z "$(ls -A "$out_dir")" ]; then
  echo "No files found in $out_dir!"
  exit 1
fi

# Iterate over files in the out directory
for file in "$out_dir"/*/crashes/*; do
  # Check if the current item is a file
  if [ -f "$file" ]; then
    echo "Processing file: $file"
    casr-san -o "new_out/$index.casrep" -- "$binary" "$file"
    ((index++))
  else
    echo "Skipped (not a file): $file"
  fi
done

casr-cluster -c  "new_out" out-cluster
