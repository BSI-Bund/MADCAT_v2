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
--    Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
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
--BSI 2020-2021-2021
--
-- Config File
--
-- This sample config file is a merged config file for all modules (TCP-, UDP-, ICMP-, RAW-(Port)Monitor and Python (post-)processors).
-- This can be done if identical parameters have identical values (e.g. "hostaddress" or "user")
-- Values, which are unique to at least one module, like "path_to_save_udp-data", are ignored by other modules.
--

loglevel = "0" --optional: loglevel (0: Default logging no source IPs to stderr, 1: Full logging, >=2: Debug)
user = "user" --user to drop privileges to.
group = "user" --group is only needed by python modules
interface = "enp9s0" --interface to listen on, choose loopback device for local test, even on external IP
-- interface = "wlp8s0" --interface to listen on, choose loopback device for local test, even on external IP
hostaddress = "192.168.2.99" --address to listen on
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
-- raw_pcap_filter_exp = "(not ip6 multicast) and inbound and ip6"
raw_pcap_filter_exp = "(not ip6 multicast) and inbound and ip6"

--TCP Proxy configuration
--tcpproxy = { -- [<listen port>] = { "<backend IP>", <backend Port> },
--           [222]   = { "192.168.2.50", 22 },
--            [2222]  = { "192.168.2.50", 222 },
--            [80]    = { "192.168.2.50", 8080 },
--            [6400] = { "192.168.2.50", 6400 },
--            [443]  = { "81.169.210.243", 443}
--           }

--UDP Proxy configuration
udpproxy_tobackend_addr = "192.168.2.99" --Local address to communicate to backends with. Mandatory, if "udpproxy" is configured.
udpproxy = { -- [<listen port>] = { "<backend IP>", <backend Port> },
            [64000] = { "192.168.2.50", 55555 },
            [533]   = { "8.8.4.4", 53},
            [534]   = { "8.8.8.8", 53},
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
enr_timeout =  5 --Timout for gracefull shutdown
