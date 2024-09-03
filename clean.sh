#!/bin/bash
set -e
set -o pipefail

echo "=====Cleaning build and binary files of xtate..."

if [ -d "./build" ]; then
    rm -rf ./build/*
    echo "=====Build directory cleaned."
else
    echo "=====Build directory does not exist, nothing to clean."
fi

if [ -d "./bin" ]; then
    rm -rf ./bin/*
    echo "=====Binary directory cleaned."
else
    echo "=====Binary directory does not exist, nothing to clean."
fi

echo "=====Clean succeeded!"
