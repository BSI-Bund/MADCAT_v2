#!/bin/bash
#Set iptables rules for TCP- and UDP-Modules
sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 1:65534 -j DNAT --to 192.168.1.100:65535
sudo iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
# Start Enrichment Processor, piping results to /data/madcat.log
sudo /usr/bin/python3 /opt/madcat/enrichment_processor.py /etc/madcat/config.lua  2>>/data/error.enrichment.log 1>>/data/madcat.log &
# Give Enrichment Processor time to start up and open /tmp/logs.erm as configured
sleep 1
# Start UDP-, ICMP-, RAW-Module, let them pipe results to Enrichment Processor FIFO.
sudo /opt/madcat/udp_ip_port_mon /etc/madcat/config.lua 2>>/data/error.udp.log 1>>/tmp/logs.erm &
sudo /opt/madcat/icmp_mon /etc/madcat/config.lua 2>> /data/error.icmp.log 1>>/tmp/logs.erm &
sudo /opt/madcat/raw_mon /etc/madcat/config.lua 2>> /data/error.raw.log 1>>/tmp/logs.erm &
# Start TCP-Module
sudo /opt/madcat/tcp_ip_port_mon /etc/madcat/config.lua 2>>/data/error.tcp.log 1>>/dev/null &
# Give TCP-Module some time to start up and open configured FIFOs /tmp/confifo.tpm and /tmp/hdrfifo.tpm
sleep 1
# Start TCP Postprocessor, let it pipe results to Enrichment Processor FIFO.
sudo /usr/bin/python3 /opt/madcat/tcp_ip_port_mon_postprocessor.py /etc/madcat/config.lua 2>>/data/error.tcppost.log 1>>/tmp/logs.erm &
