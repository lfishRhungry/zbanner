#!/bin/bash
set -e
set -o pipefail

echo "=====Cleaning previous build and binary directories..."
rm -rf ./build/*
rm -rf ./bin/*

mkdir -p ./build
mkdir -p ./bin
cd ./build

if [ $# -eq 0 ]; then
    echo "=====Configuring project for default building in release..."
    cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
elif [ $# -eq 1 ]; then
    if [[ "$1" == "debug" ]]; then
        echo "=====Configuring project for default building in debug..."
        cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
    else
        echo "=====Configuring project for building in release with compiler $1..."
        cmake -DCMAKE_C_COMPILER=$1 -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
    fi
elif [ $# -eq 2 ]; then
    if [[ "$1" == "debug" ]]; then
        echo "=====Configuring project for building in debug with compiler $2..."
        cmake -DCMAKE_C_COMPILER=$2 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
    elif [[ "$2" == "debug" ]]; then
        echo "=====Configuring project for building in debug with compiler $1..."
        cmake -DCMAKE_C_COMPILER=$1 -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
    else
        echo "=====Error: wrong parameters..."
        exit 1
    fi
else
    echo "=====Error: wrong parameter count..."
    exit 1
fi


if [ $? -ne 0 ]; then
    echo "=====Error: failed to generate building solution..."
    exit 1
fi


echo "=====Building the project..."
make -j$(nproc)

cd ..

if [[ "$1" == "debug" || "$2" == "debug" ]]; then
    echo "=====Copying debug executable to ./bin/ directory..."
    cp ./build/xtate_debug ./bin/
else
    echo "=====Copying release executable to ./bin/ directory..."
    cp ./build/xtate ./bin/
fi

echo "=====Build and copy process completed successfully!"
