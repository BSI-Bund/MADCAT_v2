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
# *******************************************************************************/
# MADCAT - Mass Attack Detecion Connection Acceptance Tool
# Enrichment processor for MADCAT
#
#
# BSI 2018-2023
##

from datetime import datetime
from fileinput import close
from pickle import GLOBAL
from signal import Signals
import sys
import os
import signal
import subprocess
import pwd
import grp
import time
import threading
import random
import string
import json
from luaparser import ast, astnodes

#Import IP Server Client:
try:
    import ip_server.client
    GLOBAL_IP_SERVER_CLIENT_PRESENT = True
except ModuleNotFoundError:
    GLOBAL_IP_SERVER_CLIENT_PRESENT = False

########################## DEFAULT CONFIGURATION ##########################
# Only in this section changes are allowed (global configuration variables
# beginning with "DEF_"), thus for configuration purposes ;-)
DEF_MADCATLOG_FIFO = "/tmp/logs.erm"  # Named pipe for MADCAT logs
# DNS Serer for external IP encrichtment
DEF_DNS_SERVER = "resolver1.opendns.com"
DEF_EXTIP_DNSNAME = "myip.opendns.com"  # DNS name which returns own IP
DEF_ACQUIRE_INTERVAL = 600  # Interval for data aquisition

# Number of lines in hexdump-style output before split. Set to 0 to disable.
DEF_ENR_SPLIT = 0
# Line length parameters for splitting are not configurable via config
# file, thus statical configured here:
DEF_LINE_LENGTH_HD = 79  # One hexdump line is max. length in Bytes, including escaped linebreak, e.g.: 00000000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|\n
# Thus, one hex string line is 32 Bytes, e.g.: 474554202f20485454502f312e310d0a
DEF_LINE_LENGTH_STR = 32

# Timeout for gracefull shutdown
DEF_TIMEOUT = 0.1
# User and Group to drop priviliges to.
DEF_USER = "madcat"
DEF_GROUP = "madcat"

# Output files. Not configured or empty, output defaults to STDOUT.
DEF_OUTPUT_FILES = None

# Backend IP Server
DEF_IP_SERVER_HOST = "10.10.10.10:10000"

########################## Version and Mascott strings ###################
GLOBAL_VERSION = "MADCAT - Mass Attack Detecion Connection Acceptance Tools\nEnrichment processor v2.3.6\n  for TCP/IP Portmonitor v2.3.x\nBSI 2018-2023\n"
GLOBAL_MASCOTT = "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n bsi   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__"

########################## Semaphore ##########################
GLOBAL_SHUTDOWN = False  # Semaphore to indicate shutdown

########################## Other globals ##########################
GLOBAL_ENRICHMENT = dict()
GLOBAL_OUTPUT_STDOUT = True
GLOBAL_OUTPUT_FILES = False
GLOBAL_OUTPUT_FILE_HANDLES = list()

############# Globals and Locks for output and enrichment data ############
GLOBAL_STDERR_LOCK = threading.Lock()
GLOBAL_OUTPUT_LOCK = threading.Lock()
GLOBAL_DATA_AQUISITON_LOCK = threading.Lock()
GLOBAL_TOTAL_COUNT = 0
GLOBAL_SPLIT_COUNT = 0

########################## SIGINT Signal Hander ##########################
# ...for gracefull shutdown


def signal_handler_sigint(signum, frame):
    global GLOBAL_SHUTDOWN, DEF_TIMEOUT
    global GLOBAL_OUTPUT_FILE_HANDLES
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
        for file in GLOBAL_OUTPUT_FILE_HANDLES:
            file.close()
        sys.exit()  # Exit process including threads
    else:  # fast shutdown, send SIGABRT
        os.kill(os.getpid(), signal.SIGABRT)
    return

# ...for fast shutdown (SIGABRT and re-triggert SIGINT)


def signal_handler_sigabrt(signum, frame):
    global GLOBAL_SHUTDOWN
    global GLOBAL_OUTPUT_FILE_HANDLES
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
    for file in GLOBAL_OUTPUT_FILE_HANDLES:
        file.close()
    os.killpg(os.getpgid(0), signal.SIGTERM)  # Terminate whole process including threads
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
    GLOBAL_STDERR_LOCK.acquire()
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()
    GLOBAL_STDERR_LOCK.release()
    return

################# Acquire data for enrichment #######################


def acquire():
    global GLOBAL_ENRICHMENT, GLOBAL_IP_SERVER_CLIENT_PRESENT, GLOBAL_DATA_AQUISITON_LOCK
    global DEF_DNS_SERVER, DEF_EXTIP_DNSNAME, DEF_ACQUIRE_INTERVAL
    GLOBAL_ENRICHMENT = {"dest_ip": "0.0.0.0"}
    firstrun = True
    data_changed = False
    backend_sync_th = None
    while True:
        # if first run, lock already has been aquired by main to ensure
        # ext_ip enrichment starts after first data aquisition
        if firstrun:
            firstrun = False
        else:
            GLOBAL_DATA_AQUISITON_LOCK.acquire()
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
                data_changed = True
            else:
                eprint(logtime + " [PID " + str(os.getpid()) +
                       "]" + " External IP stayed the same: " + ext_ip)
                data_changed = False
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
        GLOBAL_DATA_AQUISITON_LOCK.release()

        #Sync acquired data with backend using a thread, if data has changed and ip_server.client - Module is present and configured
        if data_changed and GLOBAL_IP_SERVER_CLIENT_PRESENT:
            if backend_sync_th is None: #Never started, so start it
                #Backend synchronisation, no arguments
                backend_sync_th = threading.Thread(target=sync_with_backend_th, daemon=True)
                backend_sync_th.start()
            else:
                if backend_sync_th.is_alive(): #Still running, so do nothing, just warn.
                    eprint(
                    logtime +
                    " [PID " +
                    str(
                        os.getpid()) +
                    "]" +
                    " WARNING: Backend Sync Thread still alive. Is there a synchronisation problem?")
                else: #Restart
                    eprint(
                    logtime +
                    " [PID " +
                    str(
                        os.getpid()) +
                    "]" +
                    " INFO: Starting Backend Sync Thread")
                    #Backend synchronisation, no arguments
                    backend_sync_th = threading.Thread(target=sync_with_backend_th, daemon=True)
                    backend_sync_th.start()

        time.sleep(DEF_ACQUIRE_INTERVAL)
    return

def sync_with_backend_th():
    if GLOBAL_IP_SERVER_CLIENT_PRESENT:
        logtime = datetime.now().astimezone().isoformat()
        eprint(
        logtime +
        " [PID " +
        str(
            os.getpid()) +
        "]" +
        " Syncing with Backend...")
        while True:
            #Send Update, on Error send_update will retry itself a couple of times
            retval = ip_server.client.send_update(GLOBAL_ENRICHMENT['dest_ip'], human_readable=False)
            if retval == ip_server.client.PROT_UPDATE_OK:
                break
            else: #On Error retry every tenth of acquire interval
                logtime = datetime.now().astimezone().isoformat()
                eprint(
                logtime +
                " [PID " +
                str(
                    os.getpid()) +
                "]" +
                " WARNING: Syncing with Backend failed, retrying in " + str(DEF_ACQUIRE_INTERVAL / 10) + " seconds...")
                time.sleep(DEF_ACQUIRE_INTERVAL / 10)
    return

############ Read MADCAT Logs from FIFO and enrich ##################

# Some possible KeyErrors are not catched, because if they occur somthings
# terribley wrong with the input, so this thread should crash and throw
# the occurring exception for logging

def enrich():
    global GLOBAL_TOTAL_COUNT
    global GLOBAL_OUTPUT_FILES
    global GLOBAL_OUTPUT_FILE_HANDLES
    global GLOBAL_OUTPUT_STDOUT
    logtime = datetime.now().astimezone().isoformat()

    # Open Output files (append!), if configured
    if GLOBAL_OUTPUT_FILES:
        for file in DEF_OUTPUT_FILES:
            try:
                eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                    " Appending to output file " + file)
                GLOBAL_OUTPUT_FILE_HANDLES.append(open(file,"a"))
            except BaseException as err:
                eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                    " ERROR: Opening of output file " + file + " failed " + str(err))

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
 
    random.seed(time.time())
    while True:
        # Read Log from fifo
        logline = logs.readline()
        if len(logline) <= 3:  # Three characters is a minmal JSON Object + newline: "{}\n" and should be skipped, including empty lines "\n"
            time.sleep(0.1)
            continue

        # json_dict = json.loads(logline)  # unmarshal JSON from FiFo
        json_dict_list = list()
        try:
            # unmarshal JSON from FiFo
            json_dict_list.append(json.loads(logline))
        except json.decoder.JSONDecodeError as err:
            eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " ERROR: Parsing JSON from FIFO failed. " +
                   "Message: " +
                   err.msg +
                   ", position: " +
                   str(err.pos) +
                   ", line: " +
                   str(err.lineno) +
                   ", length: " +
                   str(len(logline)) +
                   ", data: " +
                   logline)
            continue
       
        #Parallel enrichment in separate threads, because ip_server querys/updates are blocking
        enrich_child_th = threading.Thread(target=enrich_child, args=(json_dict_list,), daemon=True)
        enrich_child_th.start()

    return

def enrich_child(json_dict_list):
    global GLOBAL_TOTAL_COUNT
    global GLOBAL_OUTPUT_FILES
    global GLOBAL_OUTPUT_FILE_HANDLES
    global GLOBAL_OUTPUT_STDOUT
    # No "try...execept" here, Errors *shall* be thrown.
    # If that happens somethings seriously wrong, so the stacktrace is needed to fix errors,
    # e.g. a missing 'event_type'-Key as "KeyError: 'event_type'":

    # Enrichments to skip, if event was send by RAW Monitor Module
    if not json_dict_list[0]['event_type'] == 'RAW':
        # External IP Enrichment; runs first, to ensure that aquire has been run
        json_dict_list = ext_ip(json_dict_list)
    # Backend ID enrichtment:
    if GLOBAL_IP_SERVER_CLIENT_PRESENT:
        json_dict_list = backend_id(json_dict_list)
    # Payload split enrichment as last enrichment,
    # because if it splits, json_dict_list gets longer, 
    # thus it would become more "work" for other enrichments:
    json_dict_list = payload_split(json_dict_list)

    GLOBAL_OUTPUT_LOCK.acquire()
    if GLOBAL_OUTPUT_FILES:
        for file in GLOBAL_OUTPUT_FILE_HANDLES:
            for json_dict in json_dict_list:
                print(json.dumps(json_dict), file=file)
            file.flush()
    if GLOBAL_OUTPUT_STDOUT: # Output to STDOUT
        for json_dict in json_dict_list:
            print(json.dumps(json_dict))
        sys.stdout.flush()
    GLOBAL_OUTPUT_LOCK.release()
    GLOBAL_TOTAL_COUNT += 1
    return json_dict_list

def ext_ip(json_dict_list):
    GLOBAL_DATA_AQUISITON_LOCK.acquire() #Blocks, if acquire did not run or while it is running
    # if external IP could be aquired:
    if "0.0.0.0" != GLOBAL_ENRICHMENT['dest_ip']:
        # if key "IP" does not exist in MADCAT output (does not for
        # "no_syn" event type)...
        for json_dict in json_dict_list:
            if 'IP' not in json_dict:
                # ...preserve destination ip from ip header and add "src_addr" for convinience
                json_dict['IP'] = {
                    'dest_addr': json_dict['dest_ip'],
                    'src_addr': json_dict['src_ip']}
            # Write external IP to "dest_ip"
            json_dict['dest_ip'] = GLOBAL_ENRICHMENT['dest_ip']
    GLOBAL_DATA_AQUISITON_LOCK.release()
    return json_dict_list

def backend_id(json_dict_list):
    for json_dict in json_dict_list:
        try: # get proxy entries from event
            proxy_ip = json_dict['FLOW']['proxy_ip']
            proxy_port = json_dict['FLOW']['proxy_port']
            backend_ip = json_dict['FLOW']['backend_ip']
            backend_port = json_dict['FLOW']['backend_port']

            #### DEBUG TEST: Send fale Backend ID Update 0x090a0b0c0d0e for this proxy->backend connection to ip_server ###
            #ip_server.client.send_idupdate(9938739662094, backend_port, backend_ip, proxy_port, proxy_ip, human_readable=True, retry=False)
            #### DEBUG TEST END ####

            #try to fetch ID
            backend_id = ip_server.client.send_idquery(backend_port, backend_ip, proxy_port, proxy_ip, human_readable=True, retry=True)

            try: #if Lookup was succesfull, Backend ID is returned as int, thus convert to hex in a string
                backend_id = hex(backend_id)
            except TypeError: #Else Backend ID contains a string discribing the error
                #try to fetch ID again after 10 seconds
                logtime = datetime.now().astimezone().isoformat()
                key_s = proxy_ip + ":" + str(proxy_port) + ">" + backend_ip + ":" + str(backend_port)
                eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " WARNING: Fetching Backend ID failed for " + key_s +
                   " with: " + backend_id + ". Retrying in 10 sec...")
                time.sleep(10) #TODO: Make configurable or leave static?
                backend_id = ip_server.client.send_idquery(backend_port, backend_ip, proxy_port, proxy_ip, human_readable=True, retry=True)
                try: #if Lookup was succesfull, Backend ID is returned as int, thus convert to hex in a string
                    backend_id = hex(backend_id)
                except TypeError: #Else Backend ID contains a string discribing the error
                    logtime = datetime.now().astimezone().isoformat()
                    eprint(logtime + 
                       " [PID " +
                       str(os.getpid()) +
                       "]" +
                       " WARNING: Fetching Backend ID finally failed for " + key_s +
                       " with: " + backend_id)
                    backend_id = backend_id
            
            json_dict['FLOW']['backend_id'] = backend_id 

        except KeyError: #No Proxy entries in event
            pass
    return json_dict_list


def payload_split(json_dict_list):
    global DEF_ENR_SPLIT, DEF_LINE_LENGTH_HD, DEF_LINE_LENGTH_STR
    global GLOBAL_SPLIT_COUNT
    logtime = datetime.now().astimezone().isoformat()
    split = False
    if not DEF_ENR_SPLIT < 1:
        json_dict_list_new = list()
        for json_dict in json_dict_list:
            if json_dict["event_type"] == "syn_scan" or json_dict["event_type"] == "proxy_flow":
                continue
            try:
                len_hd = len(json_dict["FLOW"]["payload_hd"])  # payload_hd length
            except KeyError as err:
                eprint(logtime + " [PID " + str(os.getpid()) + "]" + 
                       " Error: Payload not found (%s) in JSON-Object:\n%s" % (str(err), str(json_dict)))
                return json_dict_list
            # Split payload hexdump and payload string, if configured length is
            # exceeded and hexdump is not empty
            if not len_hd < 1 and len_hd > DEF_LINE_LENGTH_HD * DEF_ENR_SPLIT:
                # number of parts
                num_parts = int(
                    len_hd / (DEF_LINE_LENGTH_HD * DEF_ENR_SPLIT)) + 1
                # length of a hexdump split in bytes
                len_split_hd = DEF_LINE_LENGTH_HD * DEF_ENR_SPLIT
                # length of a string split in bytes
                len_split_str = DEF_LINE_LENGTH_STR * DEF_ENR_SPLIT
                payload_hd = json_dict["FLOW"]["payload_hd"]
                payload_str = json_dict["FLOW"]["payload_str"]
                split = True
                for part in range(1, num_parts + 1):
                    if part == 1:  # First element in list is the original element including first part of split
                        json_dict_list_new.append(json_dict_list[0])
                        json_dict_list_new[0]["SPLIT"] = dict()
                        # Object is splittet
                        json_dict_list_new[0]["SPLIT"]["split"] = True
                        # This is the first part...
                        json_dict_list_new[0]["SPLIT"]["part"] = 1
                        # ...of a total of num_parts
                        json_dict_list_new[0]["SPLIT"]["total"] = num_parts
                        json_dict_list_new[0]["SPLIT"]["tag"] = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
                        json_dict_list_new[0]["FLOW"]["payload_hd"] = payload_hd[0:len_split_hd]
                        json_dict_list_new[0]["FLOW"]["payload_str"] = payload_str[0:len_split_str]
                        # Make a "blueprint" of following parts, intendet to
                        # contain rest(s) of payload, by making a shallow copy
                        json_dict_part = json_dict_list[0].copy()
                        # root elements are included in a shallow copy
                        json_dict_part["event_type"] = "split"
                        # Remove unecessary root elments from the following
                        # parts
                        try:
                            json_dict_part.pop("IP")
                        except BaseException:
                            pass
                        try:
                            json_dict_part.pop("UDP")
                        except BaseException:
                            pass
                        try:
                            json_dict_part.pop("TCP")
                        except BaseException:
                            pass
                        try:
                            json_dict_part.pop("RAW")
                        except BaseException:
                            pass
                    else:  # following parts
                        json_dict_list_new.append(json_dict_part.copy())
                        # Make a deep copy of both SPLIT and FLOW from original
                        # element
                        json_dict_list_new[part - 1]["SPLIT"] = json_dict_list[0]["SPLIT"].copy()
                        json_dict_list_new[part - 1]["FLOW"] = json_dict_list[0]["FLOW"].copy()
                        # This is the n'th part...
                        json_dict_list_new[part - 1]["SPLIT"]["part"] = part
                        # ...of a total of num_parts
                        json_dict_list_new[part - 1]["SPLIT"]["total"] = num_parts
                        # Split payload, beloning to actual part
                        start_hd = len_split_hd * (part - 1)
                        end_hd = len_split_hd * part
                        start_str = len_split_str * (part - 1)
                        end_str = len_split_str * part
                        if not end_hd > len(payload_hd):  # full line
                            json_dict_list_new[part - 1]["FLOW"]["payload_hd"] = payload_hd[start_hd:end_hd]
                        else:  # partial line, "the rest"
                            json_dict_list_new[part - 1]["FLOW"]["payload_hd"] = payload_hd[start_hd:]
                        if not end_str > len(payload_str):  # full line
                            json_dict_list_new[part - 1]["FLOW"]["payload_str"] = payload_str[start_str:end_str]
                        else:  # partial line, "the rest"
                            json_dict_list_new[part - 1]["FLOW"]["payload_str"] = payload_str[start_str:]

    if split:  # if split return list with parts
        GLOBAL_SPLIT_COUNT += 1
        return json_dict_list_new
    else:  # if not split, set SPLIT.split to False and return "as it was"
        json_dict_list[0]["SPLIT"] = dict()
        json_dict_list[0]["SPLIT"]["split"] = False
        return json_dict_list


########################## Configure main Threads ##########################
# All threads are deamonized to make them exit with the parent process
# Thread for gattering enrichment data

# Argument: Path to the named pipe containing header information
enrich_th = threading.Thread(target=enrich, daemon=True)
#enrich_th.setDaemon(True) #Deprecated since 3.10

# Argument: Path to the named pipe containing header information
aquisition_th = threading.Thread(target=acquire, daemon=True)
#aquisition_th.setDaemon(True) #Deprecated since 3.10

#Info: Backend sync thread spawning is beeing handled by aquisition thread.

########################## Main ##########################


def main(argv):
    global GLOBAL_MASCOTT
    global GLOBAL_VERSION
    global GLOBAL_SHUTDOWN
    global GLOBAL_OUTPUT_FILES
    global GLOBAL_OUTPUT_STDOUT
    global GLOBAL_IP_SERVER_CLIENT_PRESENT
    global DEF_MADCATLOG_FIFO
    global DEF_DNS_SERVER
    global DEF_EXTIP_DNSNAME
    global DEF_ACQUIRE_INTERVAL
    global DEF_ENR_SPLIT
    global DEF_TIMEOUT
    global DEF_USER
    global DEF_GROUP
    global DEF_OUTPUT_FILES
    global DEF_IP_SERVER_HOST

    logtime = datetime.now().astimezone().isoformat()
    starttime = time.time()
    try:
        os.mkdir("/var/run/madcat/")
    except FileExistsError:
        pass
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
        ip_server_client_configured = False
        for item in config_list:  # only strings and numbers are relevant for config
            key = item['Assign']['targets'][0]['Name']['id']
            value_list = item['Assign']['values'][0]
            if 'String' in value_list:
                try:
                    value = value_list['String']['s']
                except KeyError: #empty String
                    value = ""
            elif 'Number' in value_list:
                if 'n' in value_list['Number']:
                    value = value_list['Number']['n']
                else:
                    value = 0
            elif 'Table' in value_list:
                value = value_list

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
            if key in "enr_split_hd_lines":
                DEF_ENR_SPLIT = int(value)
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
            if key in "enr_output_files": #value is a parsed Lua-Table!
                    DEF_OUTPUT_FILES = list()
                    GLOBAL_OUTPUT_STDOUT = False #if configured, set STDOUT output to false
                    try:
                        eprint("\tenr_output_files:")
                        for field in value['Table']['fields']:
                            eprint("\t\t" + field['Field']['value']['String']['s'])
                            try: #numbers are ignored, because filenames must be strings
                                if field['Field']['value']['String']['s'] == "<STDOUT>":
                                    GLOBAL_OUTPUT_STDOUT = True #if STDOUT is explicitly set, set STDOUT output back to true
                                    continue
                                DEF_OUTPUT_FILES.append(field['Field']['value']['String']['s'])
                                GLOBAL_OUTPUT_FILES = True
                                continue
                            except KeyError:
                                pass
                    except KeyError: #empty table, set back STDOUT output to true as default
                        DEF_OUTPUT_FILES = None
                        GLOBAL_OUTPUT_FILES = False
                        GLOBAL_OUTPUT_STDOUT = True
            if key in "enr_ip_server_backend":
                ip_server_client_configured = True
                if GLOBAL_IP_SERVER_CLIENT_PRESENT:
                    DEF_IP_SERVER_HOST = str(value)
                    ip_server.client.config(DEF_IP_SERVER_HOST, "\tBACKEND SYNC: ")
                    eprint("\t" + key + " = " + str(value))
                else:
                    eprint("\tWARNING: " + key + " = " + str(value) + " set, but module ip_server.client NOT present! Backend synchronisation deactivated!")
        if not ip_server_client_configured:
            eprint("\tWARNING: \"enr_ip_server_backend\" NOT set, but module ip_server.client present! Backend synchronisation deactivated!")
            GLOBAL_IP_SERVER_CLIENT_PRESENT = False
        eprint(logtime + " [PID " + str(os.getpid()) + "]" +
               " ...done. Not configured values fall back to default values!")
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
    eprint("Payload max hexdump lines:\n  " + str(DEF_ENR_SPLIT))
    eprint("User and Group to drop priviliges to:\n  " +
           DEF_USER + ":" + DEF_GROUP)
    eprint("Output Files:")
    if GLOBAL_OUTPUT_FILES: #Configured Output files + evtl. STDOUT
        for item in DEF_OUTPUT_FILES:
            eprint("  " + item)
        if GLOBAL_OUTPUT_STDOUT:
            eprint("  <STDOUT>")
    elif GLOBAL_OUTPUT_STDOUT: #STDOUT ouput only
        eprint("  <STDOUT>")
    else: #default, if misconfigured (should never occur)
        eprint("  <unconfigured, falling back to default STDOUT output>")
        GLOBAL_OUTPUT_STDOUT = True
    eprint("==============================================================")
    eprint("\n" + logtime + " [PID " +
           str(os.getpid()) + "]" + " Starting up...")

    # intialize Signal Handler for gracefull shutdown (SIGINT)
    signal.signal(signal.SIGINT, signal_handler_sigint)
    # intialize Signal Handler for fast shutdown (SIGABRT)
    signal.signal(signal.SIGABRT, signal_handler_sigabrt)

    # Start threads for data acquisition and enrichtment
    # Wait for fist acquisition, release in aquistion thread
    GLOBAL_DATA_AQUISITON_LOCK.acquire()
    aquisition_th.start()
    enrich_th.start()

    time.sleep(1)
    drop_privileges(DEF_USER, DEF_GROUP)

    logtime = datetime.now().astimezone().isoformat()
    eprint(logtime + " [PID " + str(os.getpid()) + "]" + " Running.")
    # Sleep and wait for "death by signal" (unfortunetly their is no signal
    # "CHOCOLATE")...
    old_GLOBAL_TOTAL_COUNT = 0
    old_GLOBAL_SPLIT_COUNT = 0
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
                   str(GLOBAL_TOTAL_COUNT) +
                   " / Split Payloads: " +
                   str(GLOBAL_SPLIT_COUNT) +
                   "; Last 60sec Inputs: " +
                   str(GLOBAL_TOTAL_COUNT -
                       old_GLOBAL_TOTAL_COUNT) +
                   " / Splits: " +
                   str(GLOBAL_SPLIT_COUNT -
                       old_GLOBAL_SPLIT_COUNT))
            old_GLOBAL_TOTAL_COUNT = GLOBAL_TOTAL_COUNT
            old_GLOBAL_SPLIT_COUNT = GLOBAL_SPLIT_COUNT
            firstrun = False
    return

# =========================================================================================


# call "def main(argv)" as function with command line arguments
if __name__ == "__main__":
    main(sys.argv)
