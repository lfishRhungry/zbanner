#!/bin/bash

CLANG_FORMAT=clang-format-6.0

files_to_lint=$(find ./src -type f -name '*.c' -or -name '*.h')

fail=0
for f in ${files_to_lint}; do
  d="$(diff -u "$f" <($CLANG_FORMAT -style=file "$f") || true)"
  if ! [ -z "$d" ]; then
    printf "The file %s is not compliant with the coding style:\n%s\n" "$f" "$d"
    fail=1
  fi
done