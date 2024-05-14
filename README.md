![state_poster](screenshots/poster.jpg)

# XTATE

Welcome to Xtate -- A modular all-stack network scanner for next-generation internet surveys!

Xtate provides basic ability of super fast asychronous packet sending/receiving and highly extensible architecture.
It allows adding self-define ScanModules or ProbeModules to do different scan task with specific strategy.
All modules could work in a packet send rate which takes up more than 90% of a gigabit of bandwidth in pcap mode and 90% of a 10 gigabit of bandwidth in PFRING mode.

Xtate focuses on large-scale active measurement of obtaining information about protocol themselves and corresponding underlying characteristics in real time.
In other words, Xtate is not good at being a crawler or concentrating on content level detection like other specialized scanners. 
(Although Xtate has that abilities...)

Xtate was originally designed to do all scans for UDP and TCP in complete stateless manner, even obtaining responses over TCP with our **ZBanner** tech.
But some new added features and modules make it be more than stateless.

For example, Xtate could do stateful TCP connection and even get HTTPS reponses after finishing TLS handshake with an improved user space stack what we called **light-state TCP stack** that optimized for large-scale scanning.
However, being fast and concise is always our target.

In addition, Xtate supports IPv6 addresses and can be built on Windows and Linux with optional dependencies.

## Papers

Some of the Scan and Probe modules with original technology are derived from our papers.
I hope that Xtate will be used more in academic research.
And I would be honored if you would cite our papers related to xtate.

- ZBanner: Fast Stateless Scanning Capable of Obtaining Responses over TCP

```
@misc{chen2024zbanner,
      title={ZBanner: Fast Stateless Scanning Capable of Obtaining Responses over TCP}, 
      author={Chiyu Chen and Yuliang Lu and Guozheng Yang and Yi Xie and Shasha Guo},
      year={2024},
      eprint={2405.07409},
      archivePrefix={arXiv},
      primaryClass={cs.NI}
}
```

## Intro/Design

Unlike existing high-speed asynchronous scanners, Xtate enables richer scanning strategies by dividing the scanning process at a fine-grained level into individual functional modules.
This is how Xtate working internally (or you can check it by `xtate --intro`):

```
+--------------------------------------------------------------------------------------------------+
|                                                                                                  |
|                                                                                                  |
|                                 Tx Threads                                         Tx Threads    |
|     New Targets Generation     ------------->        ScanModule Transmit          ----------->   |
|   +-------------------------+                   +----------------------------+                   |
|   | 1.Address Randomization |  ------------->   | (ProbeModule Hello Making) |    ----------->   |
|   | 2.Scan Rate Control     |                   | (Timeout Event Creating)   |                   |
|   +-------------------------+  ------------->   +----------------------------+    ----------->   |
|                                                                                                  |
|                                                                                ^                 |
|                                                                                |                 |
|       Packets need to be send   +-----------------------+  Send in priority    |                 |
|   +---------------------------->| Pakcets Sending Queue +----------------------+                 |
|   |                             +-----------------------+                                        |
|   |                                                                                              |
|   |                                                                                              |
|   |          ScanModule Handling                                                                 |
|   |   +------------------------------+   Handle Threads   ScanModule Validation                  |
|   |   |  1.ProbeModule Validation    |   <-------------  +---------------------+                 |
|   |   |  2.ProbeModule Parsing       |                   | 1.Record            |    Rx  Thread   |
|   |   |  3.OutputModule save results |   <-------------  | 2.Deduplication     |  <-----------   |
|   |   |  4.More packets to send      |                   | 3.Timeout handling  |                 |
|   +---+    (ProbeModule Hello Making)|   <-------------  +---------------------+                 |
|       +------------------------------+                                                           |
|                                                                                                  |
+--------------------------------------------------------------------------------------------------+
```

The most important of these are the Scan module and the Probe module.
The Scan module is responsible for tasks in the network, transport and sometimes data-link layers during the scanning process (e.g., underlying packet construction, verification, etc.), while the Probe module is responsible for tasks above the transport layer (e.g., payload generation, content detection, etc.).
A Scan module can be used alone (e.g. `icmp-echo` ScanModule), or paired with different Probe modules (e.g., `zbanner` ScanModulea and `http` ProbeModule). By clever design, Probe modules can even be nested with other Probe modules (e.g., `tcp-state` ScanModule, `tls-state` ProbeModule and `http` ProbeModule).
Both Scan modules and Probe modules have own sub-parameters and you can check details by `--list-scan` or `--list-probe`.

This is what ScanModules, ProbeModules and "all-stack" mean (or you can check it by `xtate --intro`):

```
+-----------------------------------------------------------------------+
|   Free supporting for new scan strategies and protocols through       |
|   flexible ScanModules and ProbeModules creating and combination      |
|                                                                       |
|                                                                       |
|      +--------------------+           +-------------------------+     |
|      |  Application Layer +---------->|                         |     |
|      +--------------------+           |     ProbeModules        |     |
|                                       |                         |     |
|      +--------------------+           |       e.g. HTTP         |     |
|      | Presentation Layer +---------->|            DNS          |     |
|      +--------------------+           |            Netbios      |     |
|                                       |            TLS          |     |
|      +--------------------+           |                         |     |
|      |   Session Layer    +---------->|                         |     |
|      +--------------------+           +-------------------------+     |
|                                                                       |
|      +--------------------+           +-------------------------+     |
|      |   Transport Layer  +---------->|                         |     |
|      +--------------------+           |      ScanModules        |     |
|                                       |                         |     |
|      +--------------------+           |       e.g. TCP          |     |
|      |   Network Layer    +---------->|            UDP          |     |
|      +--------------------+           |            ICMP         |     |
|                                       |            NDP          |     |
|      +--------------------+           |            ARP          |     |
|      |   Data-link Layer  +---------->|                         |     |
|      +--------------------+           +-------------------------+     |
|                                                                       |
|      +--------------------+                                           |
|      |   Physical Layer   +---------->     Stop kidding!!!            |
|      +--------------------+                                           |
|                                                                       |
|                                                                       |
+-----------------------------------------------------------------------+
```

Xtate allows and encourages users to write their own modules to accomplish specific scanning tasks.

## Basic Usage

Use `xtate --usage` to see the basic usages of xtate.
But actually you can do much more than these if you know xtate deeply by reading helps.

```
usage format:
  xtate [options] [-ip IPs -p PORTs [-scan SCANMODULE [-probe PROBEMODULE]]]

original examples of xtate:

  xtate -p 80,8000-8100 -range 10.0.0.0/8 --rate=10000
      use default TcpSyn ScanModule to scan web ports on 10.x.x.x at 10kpps.

  xtate -p 80 -range 10.0.0.0/8 -scan zbanner -probe http
      use ZBanner ScanModule to grab http banners with http ProbeModule.

  xtate -p u:80 -range 10.0.0.0/8 -scan udp -probe echo -show fail
      use UdpProbe ScanModule to scan UDP 80 port with echo ProbeModule and also
      show failed results.

  xtate -p s:38412 -range 10.0.0.0/8 -scanmodule sctp-init -show fail
      use SctpInit ScanModule to scan SCTP 38412(36412) port and also show faile
      d results.

  xtate -range 10.0.0.0/8 -scanmodule icmp-echo -timeout 6
      use IcmpEcho ScanModule to do ping scan with a 6s timeout.

  xtate -range 192.168.0.1/24 -scanmodule arp-req -lan
      do ARP scan with LAN mode in local network.

  xtate -range fe80::1/120 -scanmodule ndp-ns -src-ip fe80::2 -fake-router-mac
      do NDP NS scan with a link-local source IP in local network.
```

## Typical Modules

### Typical Scan Modules

Some scan modules would carry probe modules in same type for different performing.

I only mention some typicals of them here which do not contain much basic ones like `tcp-syn`, `icmp-echo`, etc. Details are in the help document.

- `zbanner`: Send probe payload after construct complete TCP connection and grab the response banner.
All of these happen in **completely stateless manner** so that ZBanner could work in high-speed pachet send rate.
It accept tcp type probe module.
ZBanner tech was born from our research papar.

- `tcp-state`: Do scanning with an user space light weight stack what we called light-state TCP stack.
Actually it's stateful scan module and accept state type of probe module.
Light-state tcp stack was born from our research paper.
It has basic tcp funtions in large-scale scanning scenario and could touch upper layer service over TLS by pairing with `tls-state` probe module.

- `udp`: Send probe payload in type of udp and try to grab valid response.


### Generalizable Probe Modules

However, writing modules in C is not an easy task although it helps writter understand more about principle.
So I try to provide some highly generalizable Scan and Probe modules.
These allows you to just use simple commands, regular expressions, or lua scripts to accomplish most of scanning tasks for POC.

I only present some typicals of them here.
Details are in the help document.

- `hello`: Hello probe use static content set by user and reports banner. We can set a regex to match the response as successed. It is tcp type probe and we have udp and state type version, too.

- `recog`: Recog probe is like Hello probe but use a fingerprint file in Recog xml format to match the response by a bunch of regex. It is useful for version detection. It is tcp type probe and we have udp and state type version, too.

- `http`: For the most import application protocol, we provide Http probe for self-defined http header. We also can set a regex to match the response. It is tcp type probe and we have state type version, too.

- `lua-tcp`: Let a specified lua script with proper implementation as a tcp type probe. It will save a lot of time for use for writing simple probes.

- `lua-udp`: The udp type version of `lua-tcp`.


## Helps in Detail

Xtate embeds more detailed helps into the program, and I recommend using the compiled binary to view them.

Use `xtate --help | less` to see all parameters and help of xtate.

Use `xtate --list-scan | less` to see all ScanModules with sub-parameters and help.

Use `xtate --list-probe | less` to see all ProbeModules with sub-parameters and help.

Use `xtate --list-out | less` to see all OutputModules with sub-parameters and help.

## Build

Xtate could be built both on Linux and Windows with CMake because of cross-platform code and optional dependencies.
If any error happened in CMake, trying to modify and use `Makefile` is a good idea.
I'm sorry about my fail to be a CMake professor...

### Depencendies

Dependent libraries for building:

- OpenSSL>=1.1.1 (optional or use `-DWITH_OPENSSL=<ON/OFF>` to switch explicitly)
- PCRE2 8bits (optional or use `-DWITH_PCRE2=<ON/OFF>` to switch explicitly)
- LibXml2 (optional or use `-DWITH_LIBXML2=<ON/OFF>` to switch explicitly)

Optional dependencies for building won't be compiled with if Cmake didn't find the packages on your system or you can switch off it by CMake parameters.

Dependent libraries for running:

- libpcap(Linux)
- winpcap/npcap(Windows)
- PFRING driver(optional on Linux)
- lua5.3/5.4(optional for lua probe support)

All of them can be installed on Windows in some way you like but always easier on Linux like Ubuntu22:

```
sudo apt install libpcap-dev libssl-dev libpcre2-dev libxml2-dev liblua5.X-0
```

Use `xtate --version` to check details of version, binary info after building.

### Compile On Linux

Recommended compile suites:

- GCC
- Clang

With dependencies installed we can build xtate by CMake with parameters or with given script quickly:

```
./build.sh [debug]
```

### Compile On Windows

Recommended compile suites:

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

# Author

Xtate was created by lfishRhungry:

- email: chenchiyu14@nudt.edu.cn

Xtate was born in:

- College of Electronic Engineering, [National University of Defense Technology](https://english.nudt.edu.cn/).
- Anhui Province Key Laboratory of Cyberspace Security Situation Awareness and Evaluation.

Xtate was born from:

- [Masscan](https://github.com/robertdavidgraham/masscan/tree/master)

And referenced:

- [ZMap](https://github.com/zmap/zmap),
- [Masscan-ng](https://github.com/bi-zone/masscan-ng)
- Other excellent open-source projects (noted in the code).

Thanks to Robert Graham, Zakir Durumeric and Konstantin Molodyakov for their greate code and rigorous style.
I've learned more than just finishing my worthless graduate thesis.

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
