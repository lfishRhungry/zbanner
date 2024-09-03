#!/bin/bash
set -e
set -o pipefail

# Function to format a file
format_file() {
    local file="$1"
    echo "Formatting $file"
    $FORMAT_CMD "$file"
}

# Check if clang-format is installed
if ! command -v clang-format &> /dev/null; then
    echo "error: clang-format is not installed. Please install it to proceed."
    exit 1
fi

# Extract version info from printed content
VERSION=$(clang-format --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

echo "clang-format version: $VERSION"

# Get major version number
MAJOR_REV=$(echo $VERSION | cut -d '.' -f 1)

# Check if MAJOR_REV is integer
if ! [[ $MAJOR_REV =~ ^[0-9]+$ ]]; then
    MAJOR_REV=0
fi

if [ $MAJOR_REV -lt 5 ]; then
    echo "error: need at least clang-format version 5.x"
    exit 1
fi

FORMAT_CMD="clang-format -i -style=file"

# No files passed, format everything
if [ $# -eq 0 ]; then
    echo "Formatting all C code files in src/"
    echo "=====START IT====="
    find ./src -type f -name '*.c' -o -name '*.h' | while read file; do
        format_file "$file"
    done
    echo "=====FINISHED====="
    exit 0
fi

# File names passed, format only those files
echo "Formatting specified source files"
echo "=====START IT====="
for file in "$@"; do
    if [ -f "$file" ]; then
        format_file "$file"
    else
        echo "warning: $file does not exist and will be skipped."
    fi
done

echo "=====FINISHED====="
