![state_poster](screenshots/poster.jpg)

# XTATE

Welcome to Xtate -- A modular all-stack network scanner for next-generation internet surveys!

PS: Xtate was originally designed to do all scans in complete stateless manner, but follow-up modules make it more than stateless.

## Build

Xtate could be built both on Linux and Windows with CMake because of cross-platform code.
If any error happened in CMake, trying to modify and use `Makefile` is a good idea.
I'm sorry about my fail to be a CMake professor...

### Depencendies

Dependent libraries for building:

- OpenSSL>=1.1.1
- PCRE2 8bits

Dependent libraries for running:

- libpcap(Linux)
- winpcap/npcap(Windows)
- PFRING driver(optional on Linux)
- lua5.3/5.4(optional for lua probe support)

They can be installed on Windows in some way you like but always easier on Linux like Ubuntu22:

```
sudo apt install libpcre2-dev libssl-dev liblua5.X-0 libpcap-dev
```

### Compile On Linux

Suggest compile suites:

- GCC
- Clang

With dependencies installed we can build xtate by CMake with parameters or with given script quickly:

```
./build.sh [debug]
```

### Compile On Windows

Suggest compile suites:

- MSVC
- MinGW-w64

Generate a Visual Studio solution with MSVC as compiler:

```
cd build
cmake .. -DVCPKG_TARGET_TRIPLET=x64-windows
```

Generate a Makefile with MinGW-w64 as compiler:

```
cd build
cmake .. \
    -G "Unix Makefiles" \
    -DCMAKE_BUILD_TYPE=<Debug/Release> \
    -DVCPKG_TARGET_TRIPLET=x64-windows
make -j4
```

## Intro

Use `xtate --intro` to see the workflow of xtate.

## Usage

Use `xtate --usage` to see the basic usages of xtate.

## Helps

Use `xtate --help` to see all parameters and help of xtate.

Use `xtate --list-scan` to see all ScanModules with sub-parameters and help.

Use `xtate --list-probe` to see all ProbeModules with sub-parameters and help.

Use `xtate --list-out` to see all OutputModules with sub-parameters and help.

# Author

Xtate was created by lfishRhungry:
- email: chenchiyu14@nudt.edu.cn

Xtate referenced and was born from
[ZMap](https://github.com/zmap/zmap),
[Masscan](https://github.com/robertdavidgraham/masscan/tree/master)
and [Masscan-ng](https://github.com/bi-zone/masscan-ng).

Thanks to Robert Graham, Zakir Durumeric and Konstantin Molodyakov for their greate code and rigorous style.
I've learned about coding more than just finishing my worthless graduate thesis.

# License

Copyright (c) 2024 lfishRhungry

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
