--*******************************************************************************
-- This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
--    MADCAT is free software: you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation, either version 3 of the License, or
--    (at your option) any later version.
--    MADCAT is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--    You should have received a copy of the GNU General Public License
--    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.
--
-- Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
--    MADCAT ist Freie Software: Sie können es unter den Bedingungen
--    der GNU General Public License, wie von der Free Software Foundation,
--    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
--    veröffentlichten Version, weiter verteilen und/oder modifizieren.
--    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
--    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
--    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
--    Siehe die GNU General Public License für weitere Details.
--    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
--    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
--*******************************************************************************/
--MADCAT - Mass Attack Detecion Connection Acceptance Tool
--BSI 2020-2023
--
-- Config File
--
-- This sample config file is a merged config file for all modules (TCP-, UDP-, ICMP-, RAW-(Port)Monitor and Python (post-)processors).
-- This can be done if identical parameters have identical values (e.g. "hostaddress" or "user")
-- Values, which are unique to at least one module, like "path_to_save_udp-data", are ignored by other modules.
--

loglevel = "2" --optional: loglevel (0: Default logging no source IPs to stderr, 1: Full logging, >=2: Debug)
user = "madcat" --user to drop privileges to.
group = "madcat" --group is only needed by python modules
--TCPv4 configuration
hostaddress = "192.168.2.55" --address to listen on
--TCPv6 configuration
--hostaddress_v6 ="2003:c2:ef11:288e:99b5:adcc:3077:3996"
--TCPv4/v6 shared configuration
--interface = "lo" --interface to listen on, choose loopback device for local test, even on external IP
interface = "enp92s0" --interface to listen on, choose loopback device for local test, even on external IP
tcp_listening_port = "65535" --TCP-Port to listen on
tcp_connection_timeout = "5" --Timout for TCP-Connections

--LEGACY v1: Paths for Files containing Payload: Must end with trailing "/", will be handled as prefix otherwise.
-- RAW Module does not save files, beacause it is not a legacy module.
path_to_save_tcp_streams = "/data/tpm/"
path_to_save_udp_data = "/data/upm/"
path_to_save_icmp_data = "/data/ipm/"
--max_file_size = "10000" --optional: Max. Size for payloads to be saved as file or jsonized.
bufsize = "16384" --optional: Receiving Buffer size for UDP or ICMP Module
udpproxy_connection_timeout = "5" --Timeout for UDP "Connections". Optional.

proxy_wait_restart = "2" --optional: time to wait before a crashed TCP proxy restarts, e.g. because backend has failed

--Optional filter expresion for RAW module, defaults to none (empty string).
--Syntax: https://www.tcpdump.org/manpages/pcap-filter.7.html
--Example for catching IPv6 inbound and no IPv6 multicast packets:
raw_pcap_filter_exp = "(not ip6 multicast) and inbound and ip6"
-- raw_pcap_filter_exp = ""

--TCP Proxy configuration
tcpproxy = { -- [<listen port>] = { "<backend IP>", <backend Port> },
             [222]   = { "192.168.2.55", 22 },
             --[2222]  = { "192.168.2.50", 222 },
             --[2224]  = { "192.168.2.50", 224 },
             --[2223]  = { "192.168.2.50", 223 },
             --[80]    = { "192.168.2.50", 8080 },
             --[6400] = { "192.168.2.50", 6400 },
             --[443]  = { "81.169.210.243", 443},
             --[1] = {"1.1.1.1", 1},
             --[65534] = {"2.2.2.2", 2},
             --[65533] = {"2.2.2.2", 3}
           }

--UDP Proxy configuration
udpproxy_tobackend_addr = "192.168.2.55" --Local address to communicate to backends with. Mandatory, if "udpproxy" is configured.
udpproxy = { -- [<listen port>] = { "<backend IP>", <backend Port> },
--            [64000] = { "192.168.2.50", 55555 },
            [533]   = { "8.8.4.4", 53},
            [534]   = { "8.8.8.8", 53}
           }

--TCP Postprocessor configuration
---- Timing based matching
con_wait = 10 --Default 10: Time to wait before a connection is processed as no_syn to ensure that the matching SYN is really not present in syn_dict. 10 is default.
syn_timeout =  10 --Default 60 + CON_WAIT, 10 if conntrack is enabled (timeouts are inherited from conntrack table): Time after which a SYN not yet matched with a connection is interpreted as SYN-SCAN. 60 + DEF_CON_WAIT is default. 
syn_wait_proxy =  10 --Default 30 + SYN_TIMEOUT, 10 if conntrack is enabled (timeouts are inherited from conntrack table): Time to wait before a connection proxied by TCP/IP Portmonitor is processed to ensure that the matching Connection-Object is present in con_dict.
----advanced connection tracking:
enable_conntrack = 1 --Enable connection tracking (0 = False, 1 = True)
ct_status_grace_time = 10 --How long to keep connection status in ct_dict after it timeout (real time will be system closed connection timeout + ct_status_grace_time)
----"event_type": "no_syn" prevention:
syn_empty_queue = 0 --Wait for a connection to be marked as "no_syn" until the SYN-Queue is empty (0 = False, 1 = True). Mostly useless if conntrack is enabled.
best_guess = 0 --Enable Best Guess Method for Connection Objects with altered src_port because of use of DNAT. Uses only src_ip and dest_port for matching to prevent objects with "event_type": "no_syn" (0 = False, 1 = True). Mostly useless if conntrack is enabled.
best_guess_timeout = 60 --Time to wait before using Best Guess Method. Default is syn_timeout-10, smaller then syn_timeout, of course.
----Input FIFOs for TCP Postprocessor:
header_fifo = "/tmp/header_json.tpm" --Named pipe with TCP-IP Header information, namely SYN
connection_fifo = "/tmp/connect_json.tpm" --Named pipe with connection information

--Enrichtment Processor configuration
madcatlog_fifo = "/tmp/logs.erm" --Named pipe for MADCAT logs
dns_server = "resolver1.opendns.com" --DNS Serer for external IP encrichtment
extip_dnsname = "myip.opendns.com" --DNS name which returns own IP
acquire_interval = 300 --Interval for data aquisition
enr_split_hd_lines = 32 --Number of lines in hexdump-style output before split. Set to 0 to disable. Line length parameters for splitting are not configurable via config file, thus statical configured in python script.
enr_timeout =  5 --Timout for gracefull shutdown
enr_output_files = { --Optional: Output in (multiple) files for e.g. multiple filebeat instances. If not configured or empty, output defaults to STDOUT. STDOUT can be configured explicitly by adding "<STDOUT>" to the list.
--                        "/tmp/log1.txt",
--                        "/tmp/log2.txt",
                        "<STDOUT>"
                   }
enr_ip_server_backend = "127.0.0.1:10000" --Dummy entry for enrichment_processor using module ip_server.client.py
