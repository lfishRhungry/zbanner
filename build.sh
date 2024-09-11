#!/bin/bash
set -e
set -o pipefail

echo "=====Cleaning previous build and binary directories..."
rm -rf ./build/*
rm -rf ./bin/*

mkdir -p ./build
mkdir -p ./bin
cd ./build

if [[ "$1" == "debug" ]]; then
    echo "=====Configuring project for Debug build..."
    cmake -DCMAKE_BUILD_TYPE=Debug ..
else
    echo "=====Configuring project for Release build..."
    cmake ..
fi

echo "=====Building the project..."
make -j$(nproc)

cd ..

if [[ "$1" == "debug" ]]; then
    echo "=====Copying debug executable to ./bin/ directory..."
    cp ./build/xtate_debug ./bin/
else
    echo "=====Copying release executable to ./bin/ directory..."
    cp ./build/xtate ./bin/
fi

echo "=====Build and copy process completed successfully!"
