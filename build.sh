cd ./build
rm -rf ./*

mkdir release
mkdir debug

cd ./debug
cmake -DCMAKE_BUILD_TYPE=Debug ../..
make -j8

cd ../release
cmake ../..
make -j8

cd ../..
cp ./build/release/xtate ./bin/
cp ./build/debug/xtate_debug ./bin/