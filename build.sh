rm -rf ./build/*
rm -rf ./build/*
rm -rf ./bin/*
cd ./build

if [[ "$1" = "debug" ]];then
cmake -DCMAKE_BUILD_TYPE=Debug ..
else
cmake ..
fi

make -j8
cd ..

if [[ "$1" = "debug" ]];then
cp ./build/xtate_debug ./bin/
else
cp ./build/xtate ./bin/
fi
