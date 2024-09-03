#!/bin/bash

total_lines=0
effective_lines=0

echo "Check total and effective code lines of all C files in src/"
echo "=====START"

for file in $(find src -name "*.c"); do
  file_total_lines=$(wc -l < "$file")
  total_lines=$((total_lines + file_total_lines))
  
  file_effective_lines=$(grep -v '^\s*$' "$file" | grep -v '^\s*//' | grep -v '^\s*/\*' | grep -v '^\s*\*' | wc -l)
  effective_lines=$((effective_lines + file_effective_lines))
  
  echo "$file: Total Lines = $file_total_lines, Effective Lines = $file_effective_lines"
done

echo "=====FINISHED"
echo "Total lines of code: $total_lines"
echo "Total effective lines of code: $effective_lines"
