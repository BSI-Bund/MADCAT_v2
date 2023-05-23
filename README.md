```
                             ▄▄▄               ▄▄▄▄▄▄
                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀
                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀
                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀
                         ▀▀██▓█▓▓█         ████▓███▀▀
                  ▄            ▀▀▀▀                          ▄
                ▀▀█                                         ▐██▌
                  ██▄     ____------▐██████▌------___     ▄▄██
                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__
             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__
         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__
     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__
         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__
      --      __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    -- bsi
         __ --                                                   --__
```
In recent years, mass attacks on Internet users have steadily increased. Again and again new methods and patterns of attack come to light. One outstandig example was a major incident that affected 900,000 connections in Germany. However, many of these attempted attacks remain undetected or are not reported, because they do not lead to a correspondingly large impairment. Therefore, it is necessary to collect data on attacks and attempted attacks on the Internet. A well-known and widespread means of detecting such attempted attacks are honeypots. In addition, it is also possible to collect data on the longer-term, temporal development of mass attacks and thus make better forecasts of future developments.
For this purpose MADCAT (Mass Attack Detection Connection Acceptance Tools) has been developed as a universal, honeypot-like thread detetecion suite with low interaction. A honeypot is a server that simulates or emulates common network services. Honeypots are used to obtain information about attack patterns and attacker behavior. If such a honeypot service is accessed, the corresponding actions are recorded and an alarm is triggered if necessary. The idea behind the operation of honeypot systems is to offer one or more services that are not in productive use by users and therefore cannot be found and accessed during normal operation. An attacker who searches for vulnerabilities in network components and cannot distinguish between real servers and honeypots will therefore probably be registered by a honeypot. Usually at least the IP address of the attacker, the time of the attack and the actions of the attacker are logged like used access data. Furthermore, in the case of simulated web forms or command lines and other services the inputs may be recorded in order to be able to trace the attempted attack.
MADCAT is similar to a honeypot, because it records all contact attempts without being limited to certain services. Low interaction indicates that in the current version of MADCAT v1 answers to contact attempts are only given to the extent that is technically absolutely necessary to establish a connection between potential attacker and sensor in order to detect attack vectors if feasible. For MADCAT v2 a higher level of interaction with attackers is planned, e.g. to register unauthorized username/password combinations used by them.

 # 1. Requirements

To compile and run MADCAT you need to have a Linux OS installed. It has been developed and tested on Ubuntu 22.04. Additionally you need to install the following packages:

### MADCAT Binaries ###

Build Essentials, Compiler, etc:
```
sudo apt-get install gcc cmake build-essential libssl-dev
```
#### PCAP: ####
```
sudo apt-get install libpcap0.8 libpcap-dev
```
#### LUA: ####
```
sudo apt-get install liblua5.1-0 liblua5.1-0-dev
```
#### SSL: ####
```
sudo apt-get install libssl1.1 libssl-dev
```

### Python Postprocessors ###

#### Python 3: ####
```
sudo apt-get install python3-dev
```
#### Conntrack Tools: ####
```
sudo apt-get install conntrack
```

### Monitoring ###

##### Audit Deamon: ####
```
sudo apt-get install auditd audispd-plugins audit.d
```
#### Net Tools ####
```
sudo apt-get install net-tools
```
#### PIP: ####
```
sudo apt install python3-pip
```
#### PS Utils: ####
```
sudo pip3 install psutil
```
#### LUA Parser ####
```
sudo pip3 install luaparser
```

### Recommended for testing and debuging ###
```
sudo apt-get install gdb pkg-config strace valgrind
```

 # 2. How to compile

MADCAT is compiled with cmake and make. It is also prepared for cross-compilation for the target architectures armhf and aarch64.
Example commands can be found in "run_cmake+make.sh"

 # 3. How to use

To succesfull run MADCAT you need a dedicated interface. An example configuration can be found in ./etc/madcat/config.lua, which must be customized for your needs and your environment.

For the TCP Module to work with all destination ports yout need to set a DNAT-Rule.Given your local hostaddress is 192.168.1.100 and
the configured port MADCAT is running on is 65535 on interface enp0s8, this would be something like:

```
sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 1:65534 -j DNAT --to 192.168.1.100:65535
```

For the UDP Module, especially when using its proxy functionality, you need to drop outbound ICMP destination unrechable messages:

```
sudo iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
```

It is imporant to run the MADCAT Modules and Python Processors in the right order and with proper piping in the configured FIFOs and logs.
Given the binaries located in /opt/madcat, the config in /etc/madact/config.lua and data directory /data, the content of an example
run script can be found in ./scripts/run_madcat.sh.
The content of the resulting logfile is intended to be send to e.g. an Elastic-Stack Server via filebeat for further analysis and visualization,
but can also be analysed by any other means, of course (e.g. Python, Scilab, etc.)

Monitoring is configured by /etc/madcat/monitoring_config.py, which is directly sourced by monitoring.py and thus can be run directly as root.

 # 4. FAQ's

If you encounter e.g. libc-releated errors in your cross compiling evironment, see ./documentation/in_case_of_linking_problems.md

 # 5. Links & Licenses

MADCAT has been released under GPLv3, see LICENSE.md

RSP - A Really Simple Proxy by Giles Thomas
GitHub: https://github.com/gpjt/rsp
LICENSE: MIT
Documentation: http://www.gilesthomas.com/2013/08/writing-a-reverse-proxyloadbalancer-from-the-ground-up-in-c-part-0/
Gratefully adopted and modified for MADCAT with special thanks to Giles Thomas.

apt-check Macro by Michiel Sikkes <michiel@eyesopened.nl>, Michael Vogt <mvo@debian.org>, Scott James Remnant <scott@ubuntu.com>
Git: https://git.launchpad.net/update-notifier/tree/data/apt_check.py
LICENSE: GPLv2

libdict_c by ChaosFoxOverlord
GitHub: https://github.com/ChaosFoxOverlord/dict_c
LICENSE: GPLv3

 https://www.bsi.bund.de

 https://github.com/BSI-Bund/

 https://www.gilesthomas.com/

 https://www.elastic.co/

 https://www.elastic.co/de/beats/filebeat
 
 # 6. Major changes in MADCAT 2.3.x
 
* JSON output from modules written in C is now managed by libdict_c, ensuring always correct JSON.

* New enrichment in the enrichment processor to transfer connection metadata to and from e.g. a possibly existing backend with higher interaction honeypots.

* New enrichment in the enrichment processor to split long payloads, as too large JSON objects may not be accepted by the backend (e.g. Elastic Stack).

* Support for multiple (file) outputs by the enrichment processor.

* Improved mapping of TCP SYNs in the TCP post processor to complete connections (flow), using conntrack.

* Improved error handling of the TCP postprocessor: read errors no longer cause the FIFO to be closed, but only the position where the error occurred is output.

* The RAW module now outputs the Ether-Type and for IPv4 / IPv6 the IP addresses and now recognizes all IANA registered protocols.

