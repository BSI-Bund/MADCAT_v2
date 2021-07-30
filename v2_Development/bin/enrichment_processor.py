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
# Enrichment processor for MADCAT
#
#
# BSI 2018-2021
##

from datetime import datetime
from signal import Signals
import sys
import os
import signal
import subprocess
import pwd
import grp
import time
import threading
import json
from luaparser import ast, astnodes

########################## DEFAULT CONFIGURATION ##########################
# Only in this section changes are allowed (global configuration variables
# beginning with "DEF_"), thus for configuration purposes ;-)
DEF_MADCATLOG_FIFO = "/tmp/logs.erm"  # Named pipe for MADCAT logs
# DNS Serer for external IP encrichtment
DEF_DNS_SERVER = "resolver1.opendns.com"
DEF_EXTIP_DNSNAME = "myip.opendns.com"  # DNS name which returns own IP
DEF_ACQUIRE_INTERVAL = 600  # Interval for data aquisition

DEF_TIMEOUT = 0.1  # Timout for gracefull shutdown
# User and Group to drop priviliges to.
DEF_USER = "user"
DEF_GROUP = "user"

########################## Version and Mascott strings ###################
GLOBAL_VERSION = "MADCAT - Mass Attack Detecion Connection Acceptance Tool\nEnrichment processor v2.1.7\n  for TCP/IP Portmonitor v2.1.x\nBSI 2018-2021\n"
GLOBAL_MASCOTT = "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n bsi   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__"

########################## Semaphore ##########################
GLOBAL_SHUTDOWN = False  # Semaphore to indicate shutdown

########################## Other globals ##########################
GLOBAL_ENRICHMENT = dict()

############# Globals and Locks for output and enrichment data ############
stderr_lock = threading.Lock()
stdout_lock = threading.Lock()
data_aquisiton_lock = threading.Lock()
total_count = 0

########################## SIGINT Signal Hander ##########################
# ...for gracefull shutdown


def signal_handler_sigint(signum, frame):
    global GLOBAL_SHUTDOWN, DEF_TIMEOUT
    logtime = datetime.now().astimezone().isoformat()

    if not GLOBAL_SHUTDOWN:  # prevent re-triggering of this block
        GLOBAL_SHUTDOWN = True  # Set semaphore, that shutdown is in progress
        eprint(
            "\n" +
            logtime +
            " " +
            Signals(signum).name +
            " received. Shutdown in " +
            str(DEF_TIMEOUT) +
            "sec, re-trigger to speed up...")
        # Wait for the same time, a SYN would be accepted as a SYN-Scan, to
        # catch all SYN-Scans in line and give the connections a last chance to
        # catch up.
        time.sleep(DEF_TIMEOUT + 0.1)
        logtime = datetime.now().astimezone().isoformat()
        eprint(logtime + " [PID " + str(os.getpid()) + "]" + " ...bye!\n")
        sys.exit()  # Terminate whole process including threads
    else:  # fast shutdown, send SIGABRT
        os.kill(os.getpid(), signal.SIGABRT)
    return

# ...for fast shutdown (SIGABRT and re-triggert SIGINT)


def signal_handler_sigabrt(signum, frame):
    global GLOBAL_SHUTDOWN
    abrt_time = 0.1  # Wait time before fast shutdown
    logtime = datetime.now().astimezone().isoformat()
    if GLOBAL_SHUTDOWN:
        eprint(
            "\n" +
            logtime +
            " " +
            Signals(signum).name +
            " received. Shutdown re-triggered, fast shutdown in " +
            str(abrt_time) +
            "sec...")
    else:
        eprint("\n" + logtime + " " + Signals(signum).name +
               " received. Fast shutdown in " + str(abrt_time) + "sec...")
    GLOBAL_SHUTDOWN = True  # Set semaphore, that shutdown is in progress
    time.sleep(abrt_time)
    logtime = datetime.now().astimezone().isoformat()
    eprint(logtime + " [PID " + str(os.getpid()) + "]" + " ...bye!\n")
    sys.exit()  # Terminate whole process including threads
    return

########################## Drop root priviliges ##########################


def drop_privileges(uid_name, gid_name):
    logtime = datetime.now().astimezone().isoformat()
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
           " ...trying to Drop root priviliges...")

    if os.getuid() != 0:  # if not root do nothing
        eprint(logtime +
               " [PID " +
               str(os.getpid()) +
               "]" +
               " ...nothing to do. Running with UID: " +
               str(os.getuid()) +
               " GID: " +
               str(os.getgid()))
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)
    eprint(logtime +
           " [PID " +
           str(os.getpid()) +
           "]" +
           " ...done. Running with UID: " +
           str(os.getuid()) +
           " GID: " +
           str(os.getgid()))

    return

########################## Print on STDERR ##########################


def eprint(*args, **kwargs):
    stderr_lock.acquire()
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()
    stderr_lock.release()
    return

################# Acquire data for enrichment #######################


def acquire():
    global GLOBAL_ENRICHMENT
    GLOBAL_ENRICHMENT = {"dest_ip": "0.0.0.0"}
    firstrun = True
    while True:
        # if first run, lock already has been aquired by main to ensure
        # enrichment starts after first data aquisition
        if firstrun:
            firstrun = False
        else:
            data_aquisiton_lock.acquire()
        # Get external IP from DEF_DNS_SERVER using dig, so no additional
        # package has to be installed/imported
        logtime = datetime.now().astimezone().isoformat()
        try:
            ext_ip = str(subprocess.check_output(
                ["dig", "@" + DEF_DNS_SERVER, "A", DEF_EXTIP_DNSNAME, "+short"]).decode('ascii').strip())
            if ext_ip != GLOBAL_ENRICHMENT['dest_ip']:
                eprint(logtime + " [PID " + str(os.getpid()) +
                       "]" + " Acquired new external IP: " + ext_ip)
                GLOBAL_ENRICHMENT['dest_ip'] = ext_ip
            else:
                eprint(logtime + " [PID " + str(os.getpid()) +
                       "]" + " External IP stayed the same: " + ext_ip)
        except Exception as err:
            # if external IP could be aquired in the past:
            if "0.0.0.0" != GLOBAL_ENRICHMENT['dest_ip']:
                eprint(logtime +
                       " [PID " +
                       str(os.getpid()) +
                       "]" +
                       " ERROR: DNS Resolution failed using old value " +
                       GLOBAL_ENRICHMENT['dest_ip'] +
                       " as external IP, retrying in " +
                       str(DEF_ACQUIRE_INTERVAL) +
                       ". Error Message: " +
                       str(err))
            else:
                eprint(
                    logtime +
                    " [PID " +
                    str(
                        os.getpid()) +
                    "]" +
                    " ERROR: Initial DNS Resolution failed, thus leaving destination IP as it is, retrying in " +
                    str(DEF_ACQUIRE_INTERVAL) +
                    "sec.. Error Message: " +
                    str(err))
        # eprint(GLOBAL_ENRICHMENT['dest_ip']) #DEBUG
        data_aquisiton_lock.release()
        time.sleep(DEF_ACQUIRE_INTERVAL)
    return

############ Read MADCAT Logs from FIFO and enrich ##################

# Some possible KeyErrors are not catched, because if they occur somthings
# terribley wrong with the input, so this thread should crash and throw
# the occurring exception for logging


def enrich():
    global total_count
    logtime = datetime.now().astimezone().isoformat()
    # Make FIFO for MADCAT logs
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
           " Creating FIFO: %s" % DEF_MADCATLOG_FIFO)
    try:
        os.unlink(DEF_MADCATLOG_FIFO)
    except BaseException:
        pass
    try:
        os.mkfifo(DEF_MADCATLOG_FIFO)
    except Exception as err:
        eprint(logtime + " [PID " + str(os.getpid()) + "]" +
               " Failed to create FIFO: %s %s" % (DEF_MADCATLOG_FIFO, err))
        exit(1)

    logs = open(DEF_MADCATLOG_FIFO, 'r')
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
           " Reading from FIFO: " + DEF_MADCATLOG_FIFO)

    while True:
        # Read Log from fifo
        logline = logs.readline()
        if len(logline) <= 3:  # Three characters is a minmal JSON Object + newline: "{}\n" and should be skipped, including empty lines "\n"
            time.sleep(0.1)
            continue

        try:
            json_dict = json.loads(logline)  # unmarshal JSON from FiFo
        except Exception as err:
            eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " ERROR: Parsing JSON from FIFO failed. Length " +
                   str(len(logline)) +
                   ", content:" +
                   logline)
            continue

        # No "try...execept" here, Errors *shall* be thrown.
        # If that happens somethings seriously wrong, so the stacktrace is needed to fix errors,
        # e.g. a missing 'event_type'-Key as "KeyError: 'event_type'":

        # Skip, if event was send by RAW Monitor Module
        if not json_dict['event_type'] == 'RAW':
            # Enrichtment
            data_aquisiton_lock.acquire()
            # if external IP could be aquired:
            if "0.0.0.0" != GLOBAL_ENRICHMENT['dest_ip']:
                # if key "IP" does not exist in MADCAT output (does not for
                # "no_syn" event type)...
                if 'IP' not in json_dict:
                    # ...preserve destination ip from ip header and add "src_addr" for convinience
                    json_dict['IP'] = {
                        'dest_addr': json_dict['dest_ip'],
                        'src_addr': json_dict['src_ip']}
                # Write external IP to "dest_ip"
                json_dict['dest_ip'] = GLOBAL_ENRICHMENT['dest_ip']
            data_aquisiton_lock.release()

        # Output to STDOUT
        stdout_lock.acquire()
        print(json.dumps(json_dict))
        sys.stdout.flush()
        stdout_lock.release()
        total_count += 1
    return


########################## Configure Threads ##########################
# All threads are deamonized to make them exit with the parent process
# Thread for gattering enrichment data
# Argument: Path to the named pipe containing header information
enrich_th = threading.Thread(target=enrich)
enrich_th.setDaemon(True)
# Argument: Path to the named pipe containing header information
aquisition_th = threading.Thread(target=acquire)
aquisition_th.setDaemon(True)

########################## Main ##########################


def main(argv):
    global GLOBAL_SHUTDOWN
    global DEF_MADCATLOG_FIFO
    global DEF_DNS_SERVER
    global DEF_EXTIP_DNSNAME
    global DEF_ACQUIRE_INTERVAL
    global DEF_TIMEOUT
    global DEF_USER
    global DEF_GROUP

    logtime = datetime.now().astimezone().isoformat()
    starttime = time.time()
    pid_fp = open("/var/run/madcat/enrichment.pid", "w")
    pid_fp.write(str(os.getpid()))
    pid_fp.close()

    try:
        if argv[1] == "version":
            print(GLOBAL_MASCOTT)  # print mascott
            print(GLOBAL_VERSION)  # print version string
            return
    except BaseException:
        pass

    try:
        os.mkdir("/var/run/madcat", 777)
    except BaseException:
        pass
    try:
        pid_fp = open("/var/run/madcat/enrichment.pid", "w")
        pid_fp.write(str(os.getpid()))
        pid_fp.close()
    except BaseException:
        pass

    eprint(GLOBAL_MASCOTT)  # print mascott
    eprint(GLOBAL_VERSION)  # print version string

    config_txt = ""
    try:
        eprint(logtime + " [PID " + str(os.getpid()) + "]" +
               " Parsing Config File \"" + argv[1] + "\"...")
        config_file = open(argv[1], 'r')
        config_txt = config_file.read()
        config_file.close()
    except BaseException:
        eprint(logtime +
               " [PID " +
               str(os.getpid()) +
               "]" +
               " No config file given as parameter or not found. Using default values.")

    if len(config_txt) > 0:  # Parse config
        config_tree = ast.parse(config_txt)
        config_list = json.loads(ast.to_pretty_json(config_tree))[
            'Chunk']['body']['Block']['body']
        for item in config_list:  # only strings and numbers are relevant for config
            key = item['Assign']['targets'][0]['Name']['id']
            value_list = item['Assign']['values'][0]
            if 'String' in value_list:
                value = value_list['String']['s']
            elif 'Number' in value_list:
                if 'n' in value_list['Number']:
                    value = value_list['Number']['n']
                else:
                    value = 0

            if key in "enr_timeout":
                DEF_TIMEOUT = int(value)
                eprint("\t" + key + " = " + str(value))
            if key in "acquire_interval":
                DEF_ACQUIRE_INTERVAL = int(value)
                eprint("\t" + key + " = " + str(value))
            if key in "dns_server":
                DEF_DNS_SERVER = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "extip_dnsname":
                DEF_EXTIP_DNSNAME = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "madcatlog_fifo":
                DEF_MADCATLOG_FIFO = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "user":
                DEF_USER = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "group":
                DEF_GROUP = str(value)
                eprint("\t" + key + " = " + str(value))
        eprint(logtime + " [PID " + str(os.getpid()) + "]" +
               " ...done. Not configured values fall back to default values!.")
    else:
        eprint(logtime + " [PID " + str(os.getpid()) + "]" +
               " ...nothing found. Values fall back to default values!")

    eprint(
        "================= Configuration [PID " + str(os.getpid()) + "]: =================")
    eprint("Named pipe to be opened for MADCAT logs:\n %s " %
           DEF_MADCATLOG_FIFO)
    eprint("DNS Serer for external IP encrichtment:\n %s" % DEF_DNS_SERVER)
    eprint("DNS name which returns own IP:\n  %s" % DEF_EXTIP_DNSNAME)
    eprint("Interval for data aquisition:\n  " + str(DEF_ACQUIRE_INTERVAL))
    eprint("User and Group to drop priviliges to:\n  " +
           DEF_USER + ":" + DEF_GROUP)
    eprint("==============================================================")
    eprint("\n" + logtime + " [PID " +
           str(os.getpid()) + "]" + " Starting up...")

    # intialize Signal Handler for gracefull shutdown (SIGINT)
    signal.signal(signal.SIGINT, signal_handler_sigint)
    # intialize Signal Handler for fast shutdown (SIGABRT)
    signal.signal(signal.SIGABRT, signal_handler_sigabrt)

    # Start threads for data acquisition and enrichtment
    # Wait for fist acquisition, release in aquistion thread
    data_aquisiton_lock.acquire()
    aquisition_th.start()
    enrich_th.start()

    time.sleep(1)
    drop_privileges(DEF_USER, DEF_GROUP)

    logtime = datetime.now().astimezone().isoformat()
    eprint(logtime + " [PID " + str(os.getpid()) + "]" + " Running.")
    # Sleep and wait for "death by signal" (unfortunetly their is no signal
    # "CHOCOLATE")...
    old_count = 0
    firstrun = True
    while True:
        # Check Threads every second. If one died try a graceful shutdown
        logtime = datetime.now().astimezone().isoformat()
        if not enrich_th.is_alive():
            eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                   " Enrichment thread died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
        if not aquisition_th.is_alive():
            eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                   " Acquisition thread died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
        time.sleep(1)
        time_elapsed = int(time.time() - starttime)
        if firstrun or not time_elapsed % 60:
            eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " Total Inputs received: " +
                   str(total_count) +
                   " Last 60sec: " +
                   str(total_count -
                       old_count))
            old_count = total_count
            firstrun = False
    return

# =========================================================================================


# call "def main(argv)" as function with command line arguments
if __name__ == "__main__":
    main(sys.argv)
