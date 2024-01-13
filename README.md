
# ZBANNER: A Completely Stateless Banner Grabber

```
 sdSSSSSSSbs   .S_SSSs     .S_SSSs     .S_sSSs     .S_sSSs      sSSs   .S_sSSs    
 YSSSSSSSS%S  .SS~SSSSS   .SS~SSSSS   .SS~YS%%b   .SS~YS%%b    d%%SP  .SS~YS%%b   
        S%S   S%S   SSSS  S%S   SSSS  S%S   `S%b  S%S   `S%b  d%S'    S%S   `S%b  
       S&S    S%S    S%S  S%S    S%S  S%S    S%S  S%S    S%S  S%S     S%S    S%S  
      S&S     S%S SSSS%P  S%S SSSS%S  S%S    S&S  S%S    S&S  S&S     S%S    d*S  
      S&S     S&S  SSSY   S&S  SSS%S  S&S    S&S  S&S    S&S  S&S_Ss  S&S   .S*S  
     S&S      S&S    S&S  S&S    S&S  S&S    S&S  S&S    S&S  S&S~SP  S&S_sdSSS   
    S*S       S&S    S&S  S&S    S&S  S&S    S&S  S&S    S&S  S&S     S&S~YSY%b   
   S*S        S*S    S&S  S*S    S&S  S*S    S*S  S*S    S*S  S*b     S*S   `S%b  
 .s*S         S*S    S*S  S*S    S*S  S*S    S*S  S*S    S*S  S*S.    S*S    S%S  
 sY*SSSSSSSP  S*S SSSSP   S*S    S*S  S*S    S*S  S*S    S*S   SSSbs  S*S    S&S  
sY*SSSSSSSSP  S*S  SSY    SSS    S*S  S*S    SSS  S*S    SSS    YSSP  S*S    SSS  
              SP                 SP   SP          SP                  SP          
              Y                  Y    Y           Y                   Y           
                                                                                  

```

ZBanner is an Internet-scale port scanner and banner grabber.
It scans port and grabs banner in completely stateless mode.
Of cause asychronously too.

The tool is developed based on the code of [Masscan](https://github.com/robertdavidgraham/masscan) and some thoughts of [ZMap](https://github.com/zmap/zmap).
These two are both great tools and still maintained now.
I have always held both authors in high esteem because of the many knowledge and skills I have learned from their code.
(I will keep some Masscan style of code naming for respect and convenient for some time to come)

ZBanner is a variant of Masscan until now and has most of the capabilities of it.
Actually some main code was modified and new things were added,
also I will drop many no stateless functions in the future.
However, you'd better know the basic method and usages of Masscan.
Contents only about ZBanner are followed.

## Completely Stateless Mode

Unlike scan on application-layer with TCP/IP stack of system or user mode,
ZBanner sends application-layer probes and obtain banners completely stateless after the target port was identified open (received SYNACK).

## Stateless Probe Module

Aka application-layer request module.

Achieve what you want by implementing your StatelessProbe.

Possibly can do:

- Get banner of specific protocol;
- Service identification;
- Detect application-layer vuln;
- Integrate other probes;
- etc.

Now ZBanner contains some probes from [LZR](https://github.com/stanford-esrg/lzr) and can do fast identification of application-layer services.

## Multi Transmiting Threads

Multi-threads model was rewritten and I dropped supporting for multi NICs of Masscan.
ZBanner supports any number of transmiting threads just like ZMap now and is as fast as it.

## Main Usages of ZBanner

Do TCP SYN scan and get banners statelessly if ports are open:

```
zbanner 10.0.0.0/8 -p110 --stateless
```

Specify rate(pps) and time(sec) to wait after done:

```
zbanner 10.0.0.0/8 -p110 --stateless --rate 300000 --wait 15
```

Specify application-layer probe:

```
zbanner 10.0.0.0/8 -p80 --stateless --probe getrequest
```

List all application-layer probes:

```
zbanner --list-probes
```

Output banner in result:

```
zbanner 10.0.0.0/8 -p110 --stateless --capture stateless
```

The captured "Banner" could be any results of probe's verification.

Save receive packets to pcap file for analysis:

```
zbanner 10.0.0.0/8 -p110 --stateless --pcap result.pcap
```

Also save status output:

```
zbanner 10.0.0.0/8 -p110 --stateless --pcap result.pcap -oX result.xml
```

Set deduplication window for SYN-ACK:

```
zbanner 10.0.0.0/8 -p110 --dedupwin1 65535
```

Set deduplication window for response with data:

```
zbanner 10.0.0.0/8 -p110 --stateless --dedupwin2 65535
```

Also use `--dedupwin` to set both window. Default win are 100M.

Do not deduplicating for SYN-ACK:

```
zbanner 10.0.0.0/8 -p110 --nodedup1
```

Do not deduplicating for response with data:

```
zbanner 10.0.0.0/8 -p110 --stateless --nodedup2
```

Also use `--nodedup` to ban deduplicating for all.

Do not send RST for SYN-ACK:

```
zbanner 10.0.0.0/8 -p110 --noreset1
```

Do not send RST for response with data:

```
zbanner 10.0.0.0/8 -p110 --stateless --noreset2
```

Also use `--noreset` to ban reset for all.

Work with LZR:

```
zbanner 10.0.0.0/8 -p 80 --noreset1 --feedlzr | \
lzr --handshakes http -sendInterface eth0 -f results.json
```

Use multi transmit thread:

```
zbanner 10.0.0.0/8 -p110 --noreset1 --tx-count 3
```

use `--stack-buf-count` to set callback queue and packet buffer entries count:

```
zbanner 10.0.0.0/8 -p110 --stack-buf-count 2048
```

`--stack-buf-count` must be power of 2 and do not exceed RTE_RING_SZ_MASK.


## Tips

1. Do not use stateless-banners mode with `--banners` mode.

2. Use default null probe while no probe was specified.

3. Supported output and save method in stateless mode:
    - output to stdout;
    - output to XML file(`-oX`): most detailed result with statistic info;
    - output to grepable file(`-oG`);
    - output to json file(`-oJ`);
    - output to list file(`-oL`);
    - output to binary file(`-oB`): a light and special format of masscan with info like list file.
    Can not keep 'reponsed' state data in stateless mode.
    - save a pcap file(`--pcap`): raw result for later analysis.

4. Statistic result `responsed`(aka a PortStatus) is number of responsed target in application-layer.
It's useful just in stateless mode.

5. Use `--interactive` to also print result to cmdline while saving to file.

6. Use `--nostatus` to switch off status printing.

7. Use `--ndjson-status` to get status in details.

8. Default configuration locate: `/etc/zbanner/zbanner.conf`.

## TODOs

- [x] Make banner grabbing completely stateless and very fast.
- [x] Display number of responsed hosts in stateless mode.
- [x] Add stateless probe module. Make it easy to define application-layer probe by self. 
- [x] Make deduplication table for stateless probe.
- [x] Filt out, display and do statistics for SYN-ACK with zero window.
- [x] Drop multi-NICs support of Masscan, use multi-tx-threads to send packets faster.
- [ ] Make a script for generating template of probe module by name.
- [ ] Add all probes of LZR to probe module.
- [ ] Use `Sendmmsg` to send packets in batch for possible better performance referring to ZMap.
- [ ] Try to use Lua to write StatelessProbe.
- [ ] Add some interesting probe.
- [ ] Make it possible to load probe from Nmap's probes database.
- [ ] Drop no stateless functions like `--banners` mode of Masscan.
- [ ] Update compilation config of multi-platform. I dropped multi-platform compilation temporarily.
- [ ] Migrate all parameters to new method and add help for all.

# Authors

The original Masscan was created by Robert Graham:
- email: robert_david_graham@yahoo.com
- twitter: @ErrataRob

ZBanner was written by lfishRhungry:
- email: shineccy@aliyun.com

# License

Copyright (c) 2023 lfishRhungry

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
