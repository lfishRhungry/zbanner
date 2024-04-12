
# XSTATE: God is Stateless

Welcome to Xtate -- A modular all-stack network scanner running on a completely stateless mode for next-generation Internet-scale surveys!

BONUS: Xtate has stateful ScanModule to support stateful scanning now.

## Dependencies

Xtate could be build with CMake both on Linux and Windows because of cross-platform source code but with some dependencies:

- OpenSSL>=3.0
- PCRE2(8bits)

They can be installed easily on Ubuntu22 by:

```
sudo apt install libpcre2-dev libssl-dev
```

And can also be installed in some ways on Windows.

NOTE: Xtate will load lua and pcap(winpcap, npcap and libpcap) libraries dynamicly while running. These are tricks from Masscan. So we should install lua to use some modules written in lua. As for pcap, just close the README and stop scanning if not installed.

## Build

With dependencies installed we can build xtate both release and debug version by executing `build.sh` on Linux or `build.bat` on Windows.

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
