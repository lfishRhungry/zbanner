@del .\bin\*
@cd .\build
@rmdir /s /q .\release
@rmdir /s /q .\debug

@md release debug

@cd .\release
@cmake ..\..
@make -j8

@cd ..\debug
@cmake -DCMAKE_BUILD_TYPE=Debug ..\..
@make -j8

cd ..\..
copy .\build\release\xtate .\bin
copy .\build\debug\xtate_debug .\bin