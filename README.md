![state_poster](screenshots/poster.jpg)

# XTATE

Welcome to Xtate -- A modular all-stack network scanner for next-generation internet surveys!

## Build

Xtate could be build through CMake both on Linux and Windows because of cross-platform source code but with some dependencies:

- OpenSSL>=3.0 (dependent while compiling)
- PCRE2 8bits (dependent while compiling)
- lua>=5.3
- libpcap(Linux)
- winpcap/npcap(Windows)
- PFRING driver(optional on Linux)

They can be installed easily on Ubuntu22 by:

```
sudo apt install libpcre2-dev libpcre3-dev libssl-dev liblua5.X-dev libpcap-dev
```

And can also be installed in some ways on Windows.

With dependencies installed we can build xtate both release and debug version by CMake or executing `build.sh` on Linux.

For old version of Ubuntu(maybe 20), use `Makefile` is a good idea.(I'm failed to be a CMake professor...)

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

Xtate referenced and was born from [ZMap](https://github.com/zmap/zmap), [Masscan](https://github.com/robertdavidgraham/masscan/tree/master) and [Masscan-ng](https://github.com/bi-zone/masscan-ng). Thanks to Robert Graham, Zakir Durumeric and Konstantin Molodyakov for their greate code and rigorous style. I learned a lot more about coding skills than just finishing my worthless graduate thesis.

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
