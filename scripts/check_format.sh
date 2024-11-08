#!/bin/bash

cd "$(dirname "$0")"
cd ..

set -e
set -o pipefail

CLANG_FORMAT=clang-format

# check if clang-format is installed
if ! command -v $CLANG_FORMAT &> /dev/null; then
    echo "error: $CLANG_FORMAT is not installed. Please install it to proceed."
    exit 1
fi

# extract major version of clang-format
VERSION=$($CLANG_FORMAT --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
MAJOR_REV=$(echo $VERSION | cut -d '.' -f 1)

# check MAJOR_REV
if ! [[ $MAJOR_REV =~ ^[0-9]+$ ]]; then
    MAJOR_REV=0
fi

if [ $MAJOR_REV -lt 5 ]; then
    echo "error: need at least clang-format version 5.x"
    exit 1
fi

echo "Checking styles of all C files in src/"

# find all source and header files in C
files_to_lint=$(find ./src -type f -name '*.c' -or -name '*.h')

fail=0

# check if formatted
for f in ${files_to_lint}; do
    d="$(diff -u "$f" <($CLANG_FORMAT -style=file "$f") || true)"
    if ! [ -z "$d" ]; then
        printf "The file %s is not compliant with the coding style:\n%s\n" "$f" "$d"
        fail=1
    fi
done

if [ $fail -eq 1 ]; then
    exit 1
else
    echo "All files are compliant with the coding style."
    exit 0
fi
