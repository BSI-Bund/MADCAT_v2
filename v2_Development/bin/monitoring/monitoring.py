#!/usr/bin/python3
# coding=utf8
# *******************************************************************************
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
#    Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
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
# *******************************************************************************/
# MADCAT - Mass Attack Detecion Connection Acceptance Tool
# Monitoring Module
#
#
# BSI 2020-2021
##
########################## IMPORTS ##########################
import sys
import os
import signal
from datetime import datetime
from time import strftime
import time
import locale
import threading
import json
import psutil
import multiprocessing
import socket
import apt
import apt_pkg
import subprocess

########################## IMPORT CONFIGURATION ##########################

sys.path.append("/etc/madcat")  # Append path to monitoring_config.py
import monitoring_config as DEF

########################## DEFAULT CONFIGURATION ##########################
############ This is a sample content of a monitoring_config.py: ##########
'''
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

CHECK_LISTNERS = True
#Whitelist of ports on which listners are allowed, empty to prevent alerts and set it to informational ("None")
WHITELISTED_PORTS = [22,
                    65535,
                    53]

CHECK_EXT_IP  = True
DNS_SERVER = "resolver1.opendns.com" #DNS Serer for external IP
EXTIP_DNSNAME = "myip.opendns.com"  #DNS name which returns own IP
'''
########################## Locale Time Settings (lastlog): ###############
lastlogin_time_format = "%a %b %d %H:%M:%S %z %Y"
lang = 'de_DE'
enc = 'UTF-8'

########################## Version and Mascott strings ###################
GLOBAL_VERSION = "MADCAT - Mass Attack Detecion Connection Acceptance Tools\nMonitoring Module v2.0.12\n  for MADCAT v2.1.x\nBSI 2020-2021\n"
GLOBAL_MASCOTT = "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n bsi   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__"

########################## Locks for output and globals ##################
stderr_lock = threading.Lock()
stdout_lock = threading.Lock()
# APT Helper
SYNAPTIC_PINFILE = "/var/lib/synaptic/preferences"
DISTRO = subprocess.check_output(["lsb_release", "-c", "-s"],
                                 universal_newlines=True).strip()

########################## Logging ##########################


def eprint(*args, **kwargs):
    stderr_lock.acquire()
    print(*args, file=sys.stderr, **kwargs, flush=True)
    stderr_lock.release()
    return

########################## Signal Handler for gracefull shutdown #########


def signal_handler(signum, frame):
    # Evil,mean Hack to get a dictonary of signals
    SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) for n in dir(
        signal) if n.startswith('SIG') and '_' not in n)
    # Log time, PID and Signal
    logtime = datetime.now().astimezone().isoformat()
    eprint("\n" + logtime + " [PID " + str(os.getpid()) + "] Signal " +
           SIGNALS_TO_NAMES_DICT[signum] + " received. Shutting down. Bye!")
    sys.exit()  # Terminate whole process including threads
    return

########################## Checks ##########################


alerts = dict()
messages = dict()


def check_cpu():
    if not DEF.CHECK_CPU:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    output = dict(zip(range(0, multiprocessing.cpu_count()),
                  psutil.cpu_percent(interval=None, percpu=True)))
    sumload = 0.0
    messages_str = ""
    for key, value in output.items():
        sumload += value
        messages_str += "CPU_" + str(key) + " " + str(value) + "\n"
    average = sumload / multiprocessing.cpu_count()
    output['average'] = average
    if average > DEF.CPU_LOAD_ALERT:
        alerts['cpuload'] = 1
        messages['cpuload'] = messages_str
    else:
        alerts['cpuload'] = 0
    return output


def check_mem():
    if not DEF.CHECK_MEM:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    output = psutil.virtual_memory()._asdict()
    messages['memused'] = ""
    if output['percent'] > DEF.MEM_USED_ALERT:
        alerts['memused'] = 1
        messages['memused'] = str(output['free']) + \
            "/" + str(output['total']) + "\n"
    else:
        alerts['memused'] = 0
    return output


def check_disk():
    if not DEF.CHECK_DISK:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    output = dict()
    alerts['diskused'] = 0
    messages['diskused'] = ""
    for disk in DEF.DISK_LIST:
        output[disk] = dict()
        output[disk]['status'] = dict(
            zip(["total", "used", "free"], psutil.disk_usage(disk)))
        used_percent = output[disk]['status']['used'] / \
            output[disk]['status']['total'] * 100
        output[disk]['status']['used_percent'] = used_percent
        if used_percent > DEF.DISK_USED_ALERT:
            alerts['diskused'] += 1
            messages['diskused'] += disk + "\n"
    return output


def check_updates():
    if not DEF.CHECK_UPDATES:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    messages['secupdates'] = ""
    output = print_result(get_update_packages())
    # substract 'avaible' entry
    alerts['secupdates'] = len(output['security updates'].values()) - 1
    if len(output['security updates'].values()) - 1 > 0:
        messages_list = list(map(str, (output['security updates'].keys())))
        messages_list.remove('avaible')
        messages['secupdates'] = "\n".join(messages_list)
    return output


def check_lastlogin():
    if not DEF.CHECK_LASTLOGIN:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    global lang, enc
    output = dict()
    alerts['unknownentry'] = 0
    alerts['activelogin'] = 0
    messages['activelogin'] = ""
    time_now = time.time()
    lastlog = list(str(subprocess.check_output(['lastlog'])).split("\\n"))[
        1::]  # Put output in list conaining rows and discard header
    for row in lastlog:
        # collum[0] is the user name
        collum = list(filter(None, row.split(" ")))
        if len(collum) < 5:  # Discard all never logged in users and trailing "'"
            continue
        if len(collum) == 8:  # local login
            output[collum[0]] = dict()
            output[collum[0]]['port'] = collum[1].lstrip()
            output[collum[0]]['from'] = "local"
            timestring = " ".join(collum[2::])  # Rejoins timestring
            timestring = unicode_reencode(timestring)
            output[collum[0]]['time'] = datetime.strptime(
                timestring, lastlogin_time_format).astimezone().isoformat()
            continue
        if len(collum) == 9:  # remote login
            output[collum[0]] = dict()
            output[collum[0]]['port'] = collum[1].lstrip()
            output[collum[0]]['from'] = collum[2].lstrip()
            timestring = " ".join(collum[3::])  # Rejoins timestring
            timestring = unicode_reencode(timestring)
            output[collum[0]]['time'] = datetime.strptime(
                timestring, lastlogin_time_format).astimezone().isoformat()
            continue
        output["UNKNOWN ENTRY " + collum[0]] = str(row)
        alerts['unknownentry'] += 1
        messages['activelogin'] += "UNKNOWN ENTRY " + str(row) + "\n"
    # Lists currently active logins
    who = list(str(subprocess.check_output(
        ['who']).decode('ascii')).split("\n"))
    who = list(filter(None, who))  # Discard empty strings
    msg_line = list()
    alerts['activelogin'] += len(who)
    try:
        for activelogin in who:
            msg = ", ".join(
                map(str, filter(None, activelogin.split(" ")))) + " (who)\n"
            messages['activelogin'] += msg
            msg_line.append(msg)
    except BaseException:
        pass

    # Logins since last heartbeat
    for user in output.keys():
        # Time Format in Output (time zone offset discarded):
        # 2017-01-10T12:52:35 -> %Y-%m-%dT%H:%M:%S
        time_logged = time.mktime(
            datetime.strptime(
                output[user]['time'].split('+')[0],
                '%Y-%m-%dT%H:%M:%S').timetuple())
        if(time_now - time_logged <= DEF.TIME_HEARTBEAT):
            # If user has NOT been reported by who, increment alert for active
            # logins
            time_w_o_sec = output[user]['time'].split('+')[0].split('T')[1].split(
                ":")[0] + ":" + output[user]['time'].split('+')[0].split('T')[1].split(":")[1]
            found_who = False
            for line in msg_line:
                if user in line and output[user]['port'] in line and time_w_o_sec in line:
                    found_who = True
            if not found_who:
                alerts['activelogin'] += 1

            messages['activelogin'] += str(user +
                                           ", " +
                                           output[user]['port'] +
                                           " " +
                                           output[user]['from'] +
                                           ", " +
                                           output[user]['time'].split('+')[0].split('T')[0] +
                                           ", " +
                                           output[user]['time'].split('+')[0].split('T')[1] +
                                           " (lastlog)\n")
    return output


def check_lastlog():
    if not DEF.CHECK_LASTLOG:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    output = dict()
    alerts['lastlogtime'] = 0
    messages['lastlogtime'] = ""
    for file in DEF.LOG_LIST:
        output[file] = dict()
        try:
            lastaccess = datetime.fromtimestamp(os.path.getmtime(file))
            output[file]['time'] = lastaccess.astimezone().isoformat()
            if time.time() - time.mktime(lastaccess.timetuple()) > DEF.LOGTIME_ALERT:
                alerts['lastlogtime'] += 1
                messages['lastlogtime'] += file + "\n"
        except BaseException:
            alerts['lastlogtime'] += 1
            messages['lastlogtime'] += file + " NOT FOUND\n"
    return output


def check_altered():
    if not DEF.CHECK_ALTERED:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    output = dict()
    alerts['alteredfiles'] = 0
    messages['alteredfiles'] = ""
    for file in DEF.ALTERED_LIST:
        output[file] = dict()
        try:
            lastaccess = datetime.fromtimestamp(os.path.getmtime(file))
            output[file]['time'] = lastaccess.astimezone().isoformat()
            if time.time() - time.mktime(lastaccess.timetuple()) < DEF.ALTEREDTIME_ALERT:
                alerts['alteredfiles'] += 1
                messages['alteredfiles'] += file + "\n"
        except BaseException:
            alerts['alteredfiles'] += 1
            messages['alteredfiles'] += file + " NOT FOUND\n"
    return output


def check_mcversions():
    if not DEF.CHECK_MCVERSIONS:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    output = dict()
    for binary in DEF.MCVERSION_LIST:
        output[binary] = dict()
        try:
            version = list(str(subprocess.check_output(
                [binary, 'version'])).split("\\n"))
            version = list(filter(lambda x: ' v' in x, version))
            output[binary]['version'] = str(version[0])
        except BaseException:
            output[binary]['version'] = "ERROR " + binary + " not found"
    return output


def check_processes():
    if not DEF.CHECK_PROCESSES:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    output = dict()
    alerts['processdown'] = 0
    messages['processesdown'] = ""
    # Iterate over the all the running process
    for processName in DEF.PROCESS_LIST:
        output[processName] = dict()
        output[processName]['running'] = 0
        for proc in psutil.process_iter():
            try:
                # Check if process name contains the given name string.
                if processName.lower() in proc.name().lower():
                    output[processName]['running'] += 1
                    # Acquire PIDs. If number of running processes is
                    # sufficent, outcomment the rest of this block
                    '''
                    try: #pidof returns != 0 if process not found. We want to have an empty list and not a crashdump...
                        pidof = str(list(str(subprocess.check_output(["pidof",processName]).decode('ascii')).split("\n"))[0]).split()
                    except:
                        pass
                    #Output pids in dict (or list, if first three lines from here on are outcommented)
                    pidof = dict(zip(range(0, len(pidof)), pidof))
                    for pid in pidof:
                       pidof[pid] = int(pidof[pid])
                    output[processName]['pid'] = pidof
                    '''
                else:
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        if output[processName]['running'] == 0:
            alerts['processdown'] += 1
            messages['processesdown'] += processName + "\n"
    return output


net_tx_prev = {}
net_rx_prev = {}
net_time_prev = 0
net_firstrun = True


def check_netusage():
    if not DEF.CHECK_NETWORKUSAGE:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    global net_tx_prev
    global net_rx_prev
    global net_time_prev
    global net_firstrun
    output = dict()
    net_tx_total = 0
    net_rx_total = 0
    if net_firstrun:
        net_time_prev = time.time()
    alerts['netusage'] = 0
    messages['netusage'] = ""
    i = 0
    for nic in DEF.NETWORK_LIST:
        net_io = psutil.net_io_counters(pernic=True, nowrap=True)[nic]
        net_tx = net_io.bytes_sent
        net_rx = net_io.bytes_recv
        output[i] = dict()
        output[i]["nic"] = nic
        output[i]["tx_bytes"] = net_tx
        output[i]["rx_bytes"] = net_rx

        if net_firstrun:  # First run?
            # initialiaze with actuall values
            net_tx_prev[nic] = net_tx
            net_rx_prev[nic] = net_rx

        output[i]["tx_bytes_sec"] = (
            net_tx - net_tx_prev[nic]) / (time.time() - net_time_prev)
        output[i]["rx_bytes_sec"] = (
            net_rx - net_rx_prev[nic]) / (time.time() - net_time_prev)
        net_tx_total += (net_tx - net_tx_prev[nic]) / \
            (time.time() - net_time_prev)
        net_rx_total += (net_rx - net_rx_prev[nic]) / \
            (time.time() - net_time_prev)

        if output[i]["tx_bytes_sec"] > DEF.NETUSAGE_ALERT:
            alerts['netusage'] += 1
            messages['netusage'] += nic + " TX;"
        if output[i]["rx_bytes_sec"] > DEF.NETUSAGE_ALERT:
            alerts['netusage'] += 1
            messages['netusage'] += nic + " RX;"

        # Save values
        net_tx_prev[nic] = net_tx
        net_rx_prev[nic] = net_rx
        i += 1
    output['tx_bytes_sec_total'] = net_tx_total
    output['rx_bytes_sec_total'] = net_rx_total
    net_time_prev = time.time()
    net_firstrun = False
    return output


def check_listners():
    if not DEF.CHECK_LISTNERS:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    output = dict()
    alerts['listner'] = 0
    messages['listner'] = ""
    # Put output in list conaining rows and discard header
    netstat = list(str(subprocess.check_output(
        ['netstat', '-tulpne']).decode('ascii')).split("\n"))[2::]
    i = 0
    for row in netstat:
        collum = list(filter(None, row.split(" ")))
        # udp or tcp listner
        if len(collum) >= 5 and (
                "udp" in collum[0].lstrip() or "tcp" in collum[0].lstrip()):
            output[i] = dict()
            output[i]['port'] = collum[0].lstrip()
            output[i]['recv-q'] = collum[1].lstrip()
            output[i]['send-q'] = collum[2].lstrip()
            output[i]['local address'] = collum[3].lstrip()
            output[i]['foreign address'] = collum[4].lstrip()
            if "tcp" in collum[0].lstrip():  # tcp state collum present
                output[i]['state'] = collum[5].lstrip()
                state = 1
            else:  # no state collum present
                state = 0
            output[i]['user'] = collum[5 + state].lstrip()
            output[i]['inode'] = collum[6 + state].lstrip()
            output[i]['pid/program name'] = collum[7 + state].lstrip()
            try:  # optional: extra parameters
                output[i]['extra'] = collum[8 + state].lstrip()
            except BaseException:
                pass

            if len(DEF.WHITELISTED_PORTS) > 0:  # Is the ports whitelist enabled?
                if (not int(str(collum[3]).split(
                        ":")[-1]) in DEF.WHITELISTED_PORTS) and len(DEF.WHITELISTED_PORTS) > 0:
                    alerts['listner'] += 1
                    messages['listner'] += output[i]['pid/program name'] + "\n"
                    output[i]['rogue'] = 1
                else:
                    output[i]['rogue'] = 0
            else:
                alerts['listner'] = None
                output[i]['rogue'] = None
            i += 1
            continue
        try:
            output["UNKNOWN ENTRY " + collum[0]] = str(row)
            alerts['unknownentry'] += 1
            messages['listner'] += "UNKNOWN ENTRY " + str(row) + "\n"
        except BaseException:  # ignore trailing empty entry
            continue
        i += 1
    return output


auditd_exe_persist = dict()


def check_auditd_exe():
    if not DEF.CHECK_AUDITD_EXE:
        return {"INFO": "check disabled"}
    global alerts
    global messages
    global auditd_exe_persist
    output = {'exe': dict()}
    alerts['auditd_exe'] = 0
    messages['auditd'] = {'exe': ""}
    aureport = list(str(subprocess.check_output(['/sbin/aureport', '-x', '--summary']).decode(
        'ascii')).split("\n"))[5::]  # Put output in list conaining rows and discard header
    for row in aureport:
        for filter_str in DEF.AUDITD_LIST:
            collum = row.split(" ")
            if (not len(collum) == 3 and not len(collum) == 0) and not (
                    "(deleted)" in collum and len(collum) == 4):
                if collum == ['']:
                    continue
                output["UNKNOWN ENTRY " + collum[0]] = str(row)
                alerts['unknownentry'] += 1
                messages['auditd']['exe'] += "UNKNOWN ENTRY " + str(row) + "\n"
                continue
            num_exec = int(collum[0])
            binary = collum[2]
            if filter_str not in binary:
                continue
            try:
                last_num_exec = auditd_exe_persist[binary]
            except BaseException:
                auditd_exe_persist[binary] = num_exec
                continue
            if last_num_exec < num_exec:
                output['exe'][binary] = num_exec - last_num_exec
                alerts['auditd_exe'] += num_exec - last_num_exec
                auditd_exe_persist[binary] = num_exec
                if "(deleted)" in collum:
                    messages['auditd']['exe'] += binary + " (deleted)\n"
                else:
                    messages['auditd']['exe'] += binary + "\n"
    return output


ext_ip_persist = {"ext_ip": "0.0.0.0"}


def check_ext_ip():
    if not DEF.CHECK_EXT_IP:
        return {"INFO": "check disabled"}
    alerts['ext_ip'] = 0
    messages['ext_ip'] = ""
    # Get external IP from DEF_DNS_SERVER using dig, so no additional package
    # has to be installed/imported
    try:
        ext_ip = str(subprocess.check_output(
            ["dig", "@" + DEF.DNS_SERVER, "A", DEF.EXTIP_DNSNAME, "+short"]).decode('ascii').strip())
        if ext_ip != ext_ip_persist['ext_ip']:
            messages['ext_ip'] += "Acquired new external IP"
            ext_ip_persist['ext_ip'] = ext_ip
    except Exception as err:
        # if external IP could be aquired in the past:
        if "0.0.0.0" != ext_ip_persist['ext_ip']:
            messages['ext_ip'] += "DNS Resolution failed using old value. Error Message: " + \
                str(err)
            alerts['ext_ip'] += 1
        else:
            messages['ext_ip'] += "Initial DNS Resolution failed. Error Message: " + \
                str(err)
            alerts['ext_ip'] += 1
    return ext_ip_persist['ext_ip']

########################## Main ##########################


def main(argv):
    # intialize Signal Handler for gracefull shutdown (SIGINT)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        if argv[1] == "version":
            print(GLOBAL_MASCOTT)  # print mascott
            print(GLOBAL_VERSION)  # print version string
            return
    except BaseException:
        pass

    eprint(GLOBAL_MASCOTT)  # print mascott
    eprint(GLOBAL_VERSION)  # print version string
    eprint(
        "================= Configuration [PID " + str(os.getpid()) + "]: =================")
    eprint("For alert configuration see config file.")
    eprint("\nHeartbeat time in seconds: " + str(DEF.TIME_HEARTBEAT))
    eprint("Checks enabled (True/False): ")
    eprint("System:")
    eprint("\tCPU: \t\t\t\t" + str(DEF.CHECK_CPU))
    eprint("\tMemory: \t\t\t" + str(DEF.CHECK_MEM))
    eprint("\tDiskspace: \t\t\t" + str(DEF.CHECK_DISK))
    eprint("\t\tDisks to check: " + str(DEF.DISK_LIST))
    eprint("\tAvaible updates: \t\t" + str(DEF.CHECK_UPDATES) +
           "\n\t\tReads the local database, thus configure a regular cron-job for \"apt-get update\"!")
    eprint("\tLast logins: \t\t\t" + str(DEF.CHECK_LASTLOGIN))
    eprint("\tRunning processes: \t\t" + str(DEF.CHECK_PROCESSES))
    eprint("\t\tProcesses to check: " + str(DEF.PROCESS_LIST))
    eprint("\tNetwork usage: \t\t\t" + str(DEF.CHECK_NETWORKUSAGE))
    eprint("\t\tNetwork interface list: " + str(DEF.NETWORK_LIST))
    eprint("\tNetwork listners: \t\t" + str(DEF.CHECK_LISTNERS))
    eprint("\t\tWhitelisted ports: " + str(DEF.WHITELISTED_PORTS))
    eprint("\tLast time log(s) changed: \t" + str(DEF.CHECK_LASTLOG))
    eprint("\t\tLogs to check: " + str(DEF.LOG_LIST))
    eprint("\tCheck for altered files: \t" + str(DEF.CHECK_ALTERED))
    eprint("\t\tFiles to check: " + str(DEF.ALTERED_LIST))
    eprint("\tCheck auditd summary: \t\t" + str(DEF.CHECK_AUDITD_EXE))
    eprint("\t\tBinaries to check: " + str(DEF.AUDITD_LIST))
    eprint("\tCheck external IP: \t\t" + str(DEF.CHECK_EXT_IP))
    eprint("\t\tDNS Name @ DNS Server: " +
           str(DEF.EXTIP_DNSNAME) + " @ " + str(DEF.DNS_SERVER))
    eprint("MADCAT: ")
    eprint("\tMADCAT binaries version: \t" + str(DEF.CHECK_MCVERSIONS))
    eprint("\t\tMADCAT binary list: " + str(DEF.MCVERSION_LIST))
    eprint("\t\tMADCAT binary list: " + str(DEF.MCVERSION_LIST))
    eprint("==============================================================")
    logtime = datetime.now().astimezone().isoformat()
    eprint("\n" + logtime + " [PID " +
           str(os.getpid()) + "]" + " Starting up...")

    global alerts
    global messages
    global lang, enc

    # Set locale to system default local for appropriate dealing with
    # timestring formats
    lang, enc = locale.getdefaultlocale()
    locale.setlocale(locale.LC_TIME, (lang, enc))

    firstrun = True
    while True:
        logtime = datetime.now().astimezone().isoformat()
        unixtime = int(time.time())
        eprint(logtime + " [PID " + str(os.getpid()) + "]" + " Checking...")
        json_dict = {
            'time': logtime,
            'unixtime': unixtime,
            'origin': 'MADCAT Monitoring',
            'hostname': socket.gethostname()}  # reset json output
        alerts = {'unknownentry': 0, 'monitoring_restarted': 0}  # reset alerts
        if firstrun:
            alerts['monitoring_restarted'] = 1
            firstrun = False

        # CPU usage, memory, diskspace, avaible updates, last logins, altered
        # files

        eprint("CPU...")
        json_dict['cpu'] = check_cpu()
        eprint("Memory...")
        json_dict['memory'] = check_mem()
        eprint("Diskspace...")
        json_dict['diskspace'] = check_disk()
        eprint("Updates...")
        json_dict['updates'] = check_updates()
        eprint("Last Logins...")
        json_dict['lastlogin'] = check_lastlogin()
        eprint("Altered Files...")
        json_dict['filesaltered'] = check_altered()

        # auditd
        eprint("Audit Deamon...")
        json_dict['auditd'] = check_auditd_exe()

        # MADCAT-log last modified, versions
        eprint("Logfiles...")
        json_dict['lastlog'] = check_lastlog()
        eprint("Versions...")
        json_dict['madcat versions'] = check_mcversions()

        # Processes running and PID(s), network usage, external IP
        eprint("Processes...")
        json_dict['processes'] = check_processes()
        eprint("Network...")
        json_dict['network usage'] = check_netusage()
        eprint("Listners...")
        json_dict['network listners'] = check_listners()
        eprint("External IP...")
        json_dict['ext_ip'] = check_ext_ip()

        # Append Alerts and Messages
        json_dict['messages'] = messages
        json_dict['alerts'] = alerts
        json_dict['alerts']['alerts_raised'] = sum(alerts.values())

        stdout_lock.acquire()
        print(json.dumps(json_dict), flush=True)
        stdout_lock.release()

        eprint("...Done")

        time.sleep(DEF.TIME_HEARTBEAT)

######################### Helper functions #####################

# Silly method for decoding strings with special characters


def unicode_reencode(str):
    return str.encode(
        'latin-1').decode('unicode_escape').encode('latin-1').decode('utf-8')

########################## APT Helper ##########################
# Modified /usr/lib/update-notifier/apt-check
# https://git.launchpad.net/update-notifier/tree/COPYING


def clean(cache, depcache):
    # unmark (clean) all changes from the given depcache
    # mvo: looping is too inefficient with the new auto-mark code
    # for pkg in cache.Packages:
    #    depcache.MarkKeep(pkg)
    depcache.init()


def saveDistUpgrade(cache, depcache):
    # this functions mimics a upgrade but will never remove anything
    depcache.upgrade(True)
    if depcache.del_count > 0:
        clean(cache, depcache)
    depcache.upgrade()


def get_update_packages():
    # Return a list of dict about package updates

    pkgs = []

    apt_pkg.init()
    # force apt to build its caches in memory for now to make sure
    # that there is no race when the pkgcache file gets re-generated
    apt_pkg.config.set("Dir::Cache::pkgcache", "")

    try:
        cache = apt_pkg.Cache(apt.progress.base.OpProgress())
    except SystemError as e:
        sys.stderr.write("Error: Opening the cache (%s)" % e)
        sys.exit(-1)

    depcache = apt_pkg.DepCache(cache)
    # read the pin files
    depcache.read_pinfile()
    # read the synaptic pins too
    if os.path.exists(SYNAPTIC_PINFILE):
        depcache.read_pinfile(SYNAPTIC_PINFILE)
    # init the depcache
    depcache.init()

    try:
        saveDistUpgrade(cache, depcache)
    except SystemError as e:
        sys.stderr.write("Error: Marking the upgrade (%s)" % e)
        sys.exit(-1)

    # use assignment here since apt.Cache() doesn't provide a __exit__ method
    # on Ubuntu 12.04 it looks like
    # aptcache = apt.Cache()
    for pkg in cache.packages:
        if not (depcache.marked_install(pkg) or depcache.marked_upgrade(pkg)):
            continue
        inst_ver = pkg.current_ver
        cand_ver = depcache.get_candidate_ver(pkg)
        if cand_ver == inst_ver:
            continue
        record = {"name": pkg.name,
                  "security": isSecurityUpgrade(pkg, depcache),
                  "current_version": inst_ver.ver_str if inst_ver else '-',
                  "candidate_version": cand_ver.ver_str if cand_ver else '-',
                  "priority": cand_ver.priority_str}
        pkgs.append(record)

    return pkgs


def isSecurityUpgrade(pkg, depcache):

    def isSecurityUpgrade_helper(ver):
        # check if the given version is a security update (or masks one)
        security_pockets = [("Ubuntu", "%s-security" % DISTRO),
                            ("gNewSense", "%s-security" % DISTRO),
                            ("Debian", "%s-updates" % DISTRO)]

        for (file, index) in ver.file_list:
            for origin, archive in security_pockets:
                if (file.archive == archive and file.origin == origin):
                    return True
        return False
    inst_ver = pkg.current_ver
    cand_ver = depcache.get_candidate_ver(pkg)

    if isSecurityUpgrade_helper(cand_ver):
        return True

    # now check for security updates that are masked by a
    # canidate version from another repo (-proposed or -updates)
    for ver in pkg.version_list:
        if (inst_ver and
                apt_pkg.version_compare(ver.ver_str, inst_ver.ver_str) <= 0):
            continue
        if isSecurityUpgrade_helper(ver):
            return True

    return False


def print_result(pkgs):

    # Print package updates in a table

    security_updates = list(filter(lambda x: x.get('security'), pkgs))
    output = dict()
    output['Check Time'] = strftime('%m/%d/%Y %H:%M:%S')
    if not pkgs:
        output['avaible'] = False
        output['security updates'] = dict()
        output['security updates']['avaible'] = len(security_updates)
    else:
        # Updates are available
        output['avaible'] = True
        output['security updates'] = dict()
        output['security updates']['avaible'] = len(security_updates)
        # List available security updates
        for pkg in security_updates:
            output['security updates'][pkg.get('name')] = dict()
            output['security updates'][pkg.get(
                'name')]['current'] = pkg.get('current_version')
            output['security updates'][pkg.get(
                'name')]['latest'] = pkg.get('candidate_version')
    return output


########################## Execute Main ##########################

# call "def main(argv)" as function with command line arguments
if __name__ == "__main__":
    main(sys.argv)
