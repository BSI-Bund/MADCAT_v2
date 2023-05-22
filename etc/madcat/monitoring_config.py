#!/usr/bin/python3
#coding=utf8
#*******************************************************************************
# This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
#    MADCAT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#    MADCAT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    You should have received a copy of the GNU General Public License
#    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.
#
# Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
#    MADCAT ist Freie Software: Sie können es unter den Bedingungen
#    der GNU General Public License, wie von der Free Software Foundation,
#    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
#    veröffentlichten Version, weiter verteilen und/oder modifizieren.
#    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
#    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
#    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
#    Siehe die GNU General Public License für weitere Details.
#    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
#    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
#*******************************************************************************/
## MADCAT - Mass Attack Detecion Connection Acceptance Tool
 # Monitoring Module Configuration
 #
 #
 # BSI 2020-2021
##

########################## CONFIGURATION ##########################
## Only in this section changes are allowed (global configuration variables beginning with ""), thus for configuration purposes ;-)
## Timing
TIME_HEARTBEAT = 300

## System
CHECK_CPU = True
CPU_LOAD_ALERT = 80

CHECK_MEM = True
MEM_USED_ALERT = 80

CHECK_DISK = True
DISK_USED_ALERT = 80
DISK_LIST = ["/"]

CHECK_ALTERED = True #Alerst, when files listed in ALTERED_LIST are, well, altered in the time window defined by ALTERFILES_ALERT
ALTEREDTIME_ALERT = 3600
ALTERED_LIST = ["/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers"]

CHECK_AUDITD_EXE = True #Enable checking with auditd, using "aureport -x --summary". See auditd config in /etc/auditd
AUDITD_LIST = ["wget", "curl"] #Filter list for "aureport -x --summary" output. Set to [""] to log all entries
#AUDITD_LIST = [""]

#Reads the local database, thus configure a regular cron-job for "apt-get update"!
CHECK_UPDATES = True #Alerts, when security Updates are avaible
CHECK_LASTLOGIN = True #Alerts, when a login is active

## MADCAT
CHECK_LASTLOG = True #Alerst, when log has not been written since LOGTIME_ALERT seconds
LOGTIME_ALERT = 600
LOG_LIST = ["/data/portmonitor.log",
            "/var/log/syslog"]

CHECK_MCVERSIONS = True #Does not alert, just informational
MCVERSION_LIST = ["/opt/portmonitor/monitoring/monitoring.py",
                "/opt/portmonitor/tcp_ip_port_mon",
                "/opt/portmonitor/udp_ip_port_mon",
                "/opt/portmonitor/icmp_mon",
                "/opt/portmonitor/raw_mon",
                "/opt/portmonitor/tcp_ip_port_mon_postprocessor.py"]

## General
CHECK_PROCESSES = True #Alerts, when process is not running
PROCESS_LIST = ["auditd",
                "sshd", 
                "tcp_ip_port_mon", 
                "udp_ip_port_mon", 
                "icmp_mon"]

CHECK_NETWORKUSAGE = True #Alerts, when network usage exceeds the average of NETUSAGE_ALERT Bytes per second, measured in TIME_HEARTBEAT seconds
NETUSAGE_ALERT = 1000000
NETWORK_LIST = ["wlp8s0", "enp9s0"]
#NETWORK_LIST = [ "enp2s0", "enx0008bbfd87f4"]

CHECK_LISTNERS = True
#Whitelist of ports on which listners are allowed, empty to prevent alerts and set it to informational ("None")
WHITELISTED_PORTS = [22,
                    65535,
                    53]

CHECK_EXT_IP  = True
DNS_SERVER = "resolver1.opendns.com" #DNS Serer for external IP
EXTIP_DNSNAME = "myip.opendns.com"  #DNS name which returns own IP