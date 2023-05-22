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
# TCP Connection- and SYN-JSON data postprocessor for TCP/IP Portmonitor
#
#
# BSI 2018-2023
##

from datetime import datetime
from signal import Signals
import sys
import os
import signal
import pwd
import grp
import time
import threading
import json
from luaparser import ast, astnodes
import subprocess

########################## DEFAULT CONFIGURATION ##########################
DEF_HOSTADDRESS = "WARNING: \"hostaddress\" is not set, thus making conntrack unusable if enabled!"
# Time to wait before a connection is processed to ensure that the
# matching SYN is present in syn_dict. Nothing to to with ICBMs. 10 +
# DEF_CON_WAIT is default.
DEF_CON_WAIT = 10
# Time after which a SYN not yet matched with a connection is interpreted
# as SYN-SCAN. 60 + DEF_CON_WAIT is default.
DEF_SYN_TIMEOUT = 60 + DEF_CON_WAIT
# Time to wait before a connection proxied by TCP/IP Portmonitor is
# processed to ensure that the matching Connection is present in con_dict.
# 30 + DEF_SYN_TIMEOUT is default.
DEF_SYN_WAIT_PROXY = 30 + DEF_SYN_TIMEOUT


DEF_ENABLE_CONNTRACK = False  # Enable connection tracking
# How long to keep connection status in ct_dict after it timeout (real
# time will be system closed connection timeout + ct_status_grace_time)
DEF_CT_STATUS_GRACE_TIME = 5

DEF_BEST_GUESS = False  # Enable Best Guess Method for Connection Objects with altered src_port because of use of DNAT. Uses only src_ip and dest_port for matching to prevent objects with "event_type": "no_syn"
# Time to wait before using Best Guess Method. Default is syn_timeout-10,
# smaller then syn_timeout, of course.
DEF_BEST_GUESS_TIMEOUT = DEF_SYN_TIMEOUT - 10
# Wait for a connection to be marked as no_syn until the SYN-Dict is empty
DEF_SYN_EMPTY_QUEUE = False

# Named pipe with TCP-IP Header information, namely SYN
DEF_HEADER_FIFO = "/tmp/header_json.tpm"
# Named pipe with connection information
DEF_CONNECTION_FIFO = "/tmp/connect_json.tpm"
# User and Group to drop priviliges to.
DEF_USER = "madcat"
DEF_GROUP = "madcat"

########################## Version and Mascott strings ###################
GLOBAL_VERSION = "MADCAT - Mass Attack Detecion Connection Acceptance Tool\nTCP Connection and SYN JSON-data postprocessor v2.3.0\n  for TCP/IP Portmonitor >= v2.3.x\nBSI 2018-2023\n"
GLOBAL_MASCOTT = "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n bsi   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__"

########################## Semaphore, etc. ##########################
GLOBAL_SHUTDOWN = False  # Semaphore to indicate shutdown
GLOBAL_CT_LASTUPDATE = time.time()
GLOBAL_CT_INTERVAL = 1
GLOBAL_NO_SYN_COUNT = 0
GLOBAL_SYN_SCAN_COUNT = 0
GLOBAL_FLOW_COUNT = 0
GLOBAL_HDR_COUNT = 0
GLOBAL_HDR_WARN_COUNT = 0
GLOBAL_CON_COUNT = 0
GLOBAL_CON_WARN_COUNT = 0

########################## Global dictonarys and their locks #############
syn_dict = {}  # Dictonary containing SYNs
syn_dict_lock = threading.Lock()  # Lock for the SYN Dictonary
con_dict = {}  # Dictonary containing connections (Dionaea stile)
con_dict_lock = threading.Lock()  # Lock for the Cocnnecion Dictonary
# Dictonary conaining connection tracking information for connection
# objects (conid)
ct_con_dict = {}
# Lock for Connection Tracking Dictonary (conid)
ct_con_dict_lock = threading.Lock()
# Dictonary conaining connection tracking information for TCP-SYN objects
# (synid)
ct_syn_dict = {}
# Lock for Connection Tracking Dictonary (synid)
ct_syn_dict_lock = threading.Lock()
# Trigger matching incoming connections with SYNs. SYN-Scans are handeled by a timout and therefore checked every second.
# Event-driven action is e.g. required for the Dictonary holding
# connections and new conntrack entries
con_dict_evt = threading.Event()
ct_con_dict_evt = threading.Event()
ct_syn_dict_evt = threading.Event()
output_accepted_con_th_firstrun_evt = threading.Event()

########################## Locks for output ##########################
stderr_lock = threading.Lock()
stdout_lock = threading.Lock()

########################## SIGINT Signal Hander ##########################
# ...for gracefull shutdown


def signal_handler_sigint(signum, frame):
    global GLOBAL_SHUTDOWN, DEF_SYN_TIMEOUT
    logtime = datetime.now().astimezone().isoformat()

    if not GLOBAL_SHUTDOWN:  # prevent re-triggering of this block
        GLOBAL_SHUTDOWN = True  # Set semaphore, that shutdown is in progress
        eprint(
            "\n" +
            logtime +
            " " +
            Signals(signum).name +
            " received. Shutdown in " +
            str(DEF_SYN_TIMEOUT) +
            "sec, re-trigger to speed up...")
        # Wait for the same time, a SYN would be accepted as a SYN-Scan, to
        # catch all SYN-Scans in line and give the connections a last chance to
        # catch up.
        time.sleep(DEF_SYN_TIMEOUT + 0.1)
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

########################## Print on STDERR ##########################


def eprint(*args, **kwargs):
    stderr_lock.acquire()
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()
    stderr_lock.release()
    return

########################## Fill SYN dictonary with data from corresponding


def build_syn_dict():
    global syn_dict, syn_dict_lock, GLOBAL_SHUTDOWN, DEF_HEADER_FIFO, DEF_HEADER_FIFO, GLOBAL_HDR_COUNT, GLOBAL_HDR_WARN_COUNT
    logtime = datetime.now().astimezone().isoformat()
    hdrfifo = open(DEF_HEADER_FIFO, "r")  # Open SYN-FiFo
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
        " INPUT HEADER (TCP-SYNs): Thread started and running")
    while True:  # Reading Loop
        # eprint("build_syn_dict")
        hdrjson = hdrfifo.readline()  # Read JSON output from FiFo. Blocking!
        logtime = datetime.now().astimezone().isoformat()
        #eprint(logtime + " [PID " + str(os.getpid()) + "]" + " INPUT: header")
        # To prevent false "not found"s: During Shutdown no (new) SYNs are
        # acquired, but connections.
        if GLOBAL_SHUTDOWN:
            continue
        syn_dict_lock.acquire()  # Acquire lock on SYN dict
        try:
            hdrobj = json.loads(hdrjson)  # unmarshal JSON from FiFo
            GLOBAL_HDR_COUNT += 1
        except json.decoder.JSONDecodeError as err:
            if err.pos == 0 and err.lineno == 1 and len(hdrjson) == 0:
                logtime = datetime.now().astimezone().isoformat()
                eprint(logtime + " [PID " + str(os.getpid()) +
                        "]" + " Error: Parsing JSON at Postion 0, Line 1 with length 0. " + DEF_HEADER_FIFO + " closed?")
                if not GLOBAL_SHUTDOWN:  # prevent re-triggering
                    os.kill(os.getpid(), signal.SIGINT)
                return
            eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " ERROR: Parsing JSON from HEADER FIFO failed. " +
                   "Message: " +
                   err.msg +
                   ", position: " +
                   str(err.pos) +
                   ", line: " +
                   str(err.lineno) +
                   ", length: " +
                   str(len(hdrjson)) +
                   ", data: " +
                   hdrjson)
            syn_dict_lock.release()
            continue

        # Build ID (aka tag) from source address, destination port and source
        # port
        synid = str(hdrobj.get("IP").get("src_addr")) + "_" + \
            str(hdrobj.get("TCP").get("dest_port")) + \
            "+" + str(hdrobj.get("TCP").get("src_port"))
        if synid in syn_dict.keys():
            GLOBAL_HDR_WARN_COUNT += 1
            #eprint(logtime + " [PID " + str(os.getpid()) + "]" + " Warning: Duplicate SYN: " + synid)
        syn_dict.update({synid: hdrobj})  # append SYN to dictonary
        #eprint("synid: " + synid)

        syn_dict_lock.release()  # release lock
        # eprint("SYN:") #DEBUG
        # eprint(syn_dict) #DEBUG
        # eprint("") #DEBUG
    return

########################## Fill Connection dictonary with data from corres


def build_con_dict():
    global con_dict, con_dict_lock, con_dict_evt, ct_con_dict, ct_con_dict_evt, ct_con_dict_lock, GLOBAL_SHUTDOWN, DEF_CONNECTION_FIFO, DEF_ENABLE_CONNTRACK, DEF_CONNECTION_FIFO, GLOBAL_CON_COUNT, GLOBAL_CON_WARN_COUNT
    logtime = datetime.now().astimezone().isoformat()
    confifo = open(DEF_CONNECTION_FIFO, "r")  # open Connection-FiFo
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
           " INPUT CONNETIONS: Thread started and running")
    while True:  # Reading loop
        conjson = confifo.readline()  # Read JSON output from FiFo. Blocking!
        logtime = datetime.now().astimezone().isoformat()
        con_dict_lock.acquire()  # Aquire lock on Connection dictonary

        try:
            conobj = json.loads(conjson)  # unmarshal JSON from FiFo
            GLOBAL_CON_COUNT += 1
        except json.decoder.JSONDecodeError as err:
            if err.pos == 0 and err.lineno == 1 and len(conjson) == 0:
                logtime = datetime.now().astimezone().isoformat()
                eprint(logtime + " [PID " + str(os.getpid()) +
                        "]" + " Error: Parsing JSON at Postion 0, Line 1 with length 0. " + DEF_CONNECTION_FIFO + " closed?")
                if not GLOBAL_SHUTDOWN:  # prevent re-triggering
                    os.kill(os.getpid(), signal.SIGINT)
                return
            eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " ERROR: Parsing JSON from CONNECTION FIFO failed. " +
                   "Message: " +
                   err.msg +
                   ", position: " +
                   str(err.pos) +
                   ", line: " +
                   str(err.lineno) +
                   ", length: " +
                   str(len(conjson)) +
                   ", data: " +
                   conjson)
            con_dict_lock.release()
            continue

        # Build ID (aka tag) from source address, destination port and source
        # port
        conid = str(conobj.get("src_ip")) + "_" + \
            str(conobj.get("dest_port")) + "+" + str(conobj.get("src_port"))

        if DEF_ENABLE_CONNTRACK:
            con_time = conobj.get("unixtime")
            if GLOBAL_CT_LASTUPDATE < con_time:
                ct_con_dict_evt.clear()
                ct_con_dict_evt.wait()

            ct_con_dict_lock.acquire()
            conobj['ct_status'] = "None"
            for ct_time in list(ct_con_dict.keys()):
                try:
                    new_conid = str(conobj.get("src_ip")) + "_" + \
                        str(conobj.get("dest_port")) + "+" + \
                        str(ct_con_dict[ct_time][conid]['org_src_port'])
                except BaseException as err:
                    conobj.update({"ct_status": "Failed"})
                    #eprint("DEBUG: Error fetching ct_status: ", repr(err))
                    continue
                if new_conid != conid:
                    # Repair conobj
                    conobj.update(
                        {"src_port": ct_con_dict[ct_time][conid]['org_src_port']})
                    conobj.update({"ct_status": "Changed"})
                    #eprint("DEBUG: ct_status changed from conid: " + str(conid) + " to:"+ str(new_conid) +"): Conntrack table:\n" + str(conntrack) + "\n") #XXX
                    # Correct ID so it will match with SYN
                    conid = new_conid
                    break
                else:
                    conobj.update({"ct_status": "Found"})
                    break

            ct_con_dict_lock.release()

        con_dict.update({conid: conobj})  # append Connection to dictonary

        con_dict_lock.release()  # release lock
        con_dict_evt.set()  # indicate new entry in dictonary
    return

########################## Print connections including their SYNs (if feas


def output_accepted_con():
    global DEF_CON_WAIT, GLOBAL_SHUTDOWN, DEF_SYN_TIMEOUT, DEF_SYN_EMPTY_QUEUE, DEF_BEST_GUESS, DEF_BEST_GUESS_TIMEOUT, GLOBAL_NO_SYN_COUNT, GLOBAL_FLOW_COUNT
    global con_dict, con_dict_lock, con_dict_evt, syn_dict, syn_dict_lock, output_accepted_con_th_firstrun_evt

    logtime = datetime.now().astimezone().isoformat()
    eprint(logtime +
           " [PID " +
           str(os.getpid()) +
           "]" +
           " OUTPUT CONNECTIONS: Thread started, waiting " +
           str(DEF_CON_WAIT) +
           "sec for input threads to gather old data in FIFOs...")
    time.sleep(DEF_CON_WAIT)
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
           " OUTPUT CONNECTIONS: ...running")
    while True:
        con_dict_evt.wait()  # Wait for new entry in con_dict
        con_dict_evt.clear()  # Indicate event has been seen
        while len(con_dict) > 0:  # Repeat till every connection has been processed
            logtime = datetime.now().astimezone().isoformat()
            con_dict_lock.acquire()  # Aquire Locks for Connection and...
            syn_dict_lock.acquire()  # Lock SYN dictonary
            con_dict_keys = list(con_dict.keys())  # Snapshot keys
            syn_dict_keys = list(syn_dict.keys())  # Snapshot keys
            # eprint("output_accept_con") #DEBUG
            for conid in con_dict_keys:  # Iterate over connections
                found = False  # Set boolean, that a match between SYN and Connection has been found to false in the beginning
                # Moved downwards for speedup
                for synid in syn_dict_keys:  # Iterate over SYNs and...
                    # for synid in syn_dict: #Debug: Provoke "RuntimeError: dictionary changed size during iteration" for error handling test
                    # Try a best guess match w/o matching source port (NAT!),
                    # if SYN has not been found if 2x DEF_CON_WAIT is over.
                    best_guess = False
                    try:  # conid may have already been matched and was therefore deleted.
                        if (DEF_BEST_GUESS and con_dict.get(conid).get(
                                "unixtime") + DEF_BEST_GUESS_TIMEOUT < time.time()):
                            if (conid.split('+')[0] == synid.split('+')[0]):
                                best_guess = True
                    except BaseException:
                        pass
                    # ...search for matching tag (aka. id)
                    if (conid == synid or best_guess) and not found:
                        # complete JSON output
                        found = True  # if a match has been made, set found to true
                        # Combine connection information and Information from SYN (e.g. TCP/IP Headers) to one JSON Object. Set connection.type to "accept",
                        # to indicate, that a complete connection (full 3-Way
                        # Handshake) has been made and a TCP-Stream might have
                        # been recorded
                        output = {}  # begin new JSON output
                        output.update({"origin": "MADCAT",
                                       "timestamp": con_dict.get(conid).get("timestamp"),
                                       "src_ip": con_dict.get(conid).get("src_ip"),
                                       # Take src_port from syn_dict, in case
                                       # of a best_guess match it is the true
                                       # value.
                                       "src_port": syn_dict.get(synid).get("TCP").get("src_port"),
                                       "dest_ip": con_dict.get(conid).get("dest_ip"),
                                       "dest_port": con_dict.get(conid).get("dest_port"),
                                       "proto": con_dict.get(conid).get("proto"),
                                       "event_type": con_dict.get(conid).get("event_type"),
                                       "unixtime": con_dict.get(conid).get("unixtime"),
                                       "FLOW": con_dict.get(conid).get("FLOW"),
                                       "IP": syn_dict.get(synid).get("IP"),
                                       "TCP": syn_dict.get(synid).get("TCP"),
                                       "ct_status": con_dict.get(conid).get("ct_status"),
                                       })
                        if DEF_BEST_GUESS:
                            output.update({"best_guess_match": best_guess, })
                        stdout_lock.acquire()
                        # Marshal JSON and print to STDOUT
                        print(json.dumps(output))
                        sys.stdout.flush()
                        stdout_lock.release()
                        # Delete Matched connection and ...
                        del con_dict[conid]
                        del syn_dict[synid]  # ...SYN from dictonarys
                        GLOBAL_FLOW_COUNT += 1
                        continue  # Go to next entry in SYN dictonary

                # Print Connection without matching SYN. If they appear, it might be a problem with timouts and timing.
                # A corresponding "connection.type" : "syn_scan" (really) SHOULD exist.
                # These connections are identified by the "header" : "no_syn" tag.
                # 1st line: Only not found cons are processed and to prevent false "not_syns"s: During Shutdown no "no_syns" are put out
                # 2nd line: Wait a minimum of DEF_CON_WAIT + DEF_SYN_TIMOUT before processing connection w/o SYN to ensure SYN is really not present.
                # 3rd line: Under the prequisite that DEF_SYN_EMPTY_QUEUE [D] is set to true do process only [P] if syn_dict is empty [E] (e.g. it is filled [F] -> len(syn_dict) != 0) as follows:
                    #   D       E   not E = F       D and F     not (D and F) = P
                    #
                    #   0       0       1           0               1
                    #   0       1       0           0               1
                    #   1       0       1           1               0
                    #   1       1       0           0               1
                    #
                    #   P = not (DEF_SYN_EMPTY_QUEUE and len(syn_dict) != 0
                if ((not found) and (not GLOBAL_SHUTDOWN)
                        and con_dict.get(conid).get("unixtime") + DEF_CON_WAIT + DEF_SYN_TIMEOUT < time.time()) \
                        and (not (DEF_SYN_EMPTY_QUEUE and len(syn_dict) != 0)):

                    # "incomplete" JSON output
                    output = {}  # Begin "incomplete"JSON output
                    # Compose JSON object, containing only the connection data and the "no_syn" tag event_type
                    # src_ip and dest_ip are copied to "IP" to preserve them if
                    # an enrichment ist done (enrichment processor)

                    output.update({"origin": "MADCAT",
                                   "timestamp": con_dict.get(conid).get("timestamp"),
                                   "src_ip": con_dict.get(conid).get("src_ip"),
                                   "src_port": con_dict.get(conid).get("src_port"),
                                   "dest_ip": con_dict.get(conid).get("dest_ip"),
                                   "dest_port": con_dict.get(conid).get("dest_port"),
                                   "proto": con_dict.get(conid).get("proto"),
                                   "event_type": "no_syn",
                                   "unixtime": con_dict.get(conid).get("unixtime"),
                                   "FLOW": con_dict.get(conid).get("FLOW"),
                                   "IP": {
                                       "src_addr": con_dict.get(conid).get("src_ip"),
                                       "dest_addr": con_dict.get(conid).get("dest_ip")
                                   },
                                   "ct_status": con_dict.get(conid).get("ct_status"),
                                   })

                    stdout_lock.acquire()
                    # Marshal JSON and print to STDOUT
                    print(json.dumps(output))
                    sys.stdout.flush()
                    stdout_lock.release()
                    logtime = datetime.now().astimezone().isoformat()
                    GLOBAL_NO_SYN_COUNT += 1
                    del con_dict[conid]  # Delete Un-Matched connection
            con_dict_lock.release()  # Release locks
            syn_dict_lock.release()
            output_accepted_con_th_firstrun_evt.set()
            time.sleep(1)
    return

########################## Print SYNs as SYN-Scans after configured timeou


def output_syn_scans():
    global DEF_ENABLE_CONNTRACK, DEF_SYN_TIMEOUT, DEF_SYN_WAIT_PROXY, GLOBAL_SYN_SCAN_COUNT, GLOBAL_CT_LASTUPDATE
    #global syn_scan_dict
    global syn_dict, syn_dict_lock, ct_syn_dict, ct_syn_dict_lock, output_accepted_con_th_firstrun_evt, ct_syn_dict_evt

    logtime = datetime.now().astimezone().isoformat()
    eprint(logtime +
           " [PID " +
           str(os.getpid()) +
           "]" +
           " OUTPUT SYN-SCANS: Thread started, waiting a max. of " +
           str(int(3 *
                   DEF_CON_WAIT)) +
           "sec for input threads / firstrun of output connections thread to gather old data in FIFOs...")
    output_accepted_con_th_firstrun_evt.wait(timeout=3 * DEF_CON_WAIT)
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
           " OUTPUT SYN-SCANS: ...running")
    while True:  # Loop checking for SYNs without connection after syn_timout
        syn_dict_lock.acquire()  # Aquire lock on SYN dictonarys
        for synid in list(
                syn_dict.keys()):  # Iterate over items in SYN dictonary
            # Check if specific SYN exceeded timeout. Check for proxied = true is ommited for backward compatibility reasons.
            # This is possible,because proxy_timout should in any case be
            # greater than syn_timeout.
            if "ct_status" not in syn_dict[synid].keys():
                syn_dict[synid].update({"ct_status": "None"})
            if DEF_ENABLE_CONNTRACK:
                syn_time = syn_dict.get(synid).get("unixtime")
                if GLOBAL_CT_LASTUPDATE < syn_time:
                    ct_syn_dict_evt.clear()
                    ct_syn_dict_evt.wait()
                if synid in ct_syn_dict.keys():
                    syn_dict[synid].update({"ct_status": "Found"})
            #eprint(syn_dict.get(synid).get("ct_status") + " synid: " + synid + " @ " + str(ct_syn_dict.keys()))

            # 1st line: respect SYN_TIMEOUT if not proxied
            # 2nd line: else respect SYN_WAIT_PROXY
            # 3rd line: Under the prequisite, that Conntrack is enabled only
            # process if synid is not in ct_syn_dict.keys(), thus connection is
            # no longer active.
            if (
                syn_dict.get(synid).get("unixtime") +
                DEF_SYN_TIMEOUT < time.time() and syn_dict.get(synid).get("TCP").get("proxied") == "false") or (
                syn_dict.get(synid).get("unixtime") +
                    DEF_SYN_WAIT_PROXY < time.time()):
                if not (DEF_ENABLE_CONNTRACK and synid in ct_syn_dict.keys()):

                    output = {}  # Begin new JSON output
                    # Build (pseudo-)Header from IP- and TCP-Header Information
                    # and append IP- and TCP-Header information
                    output.update({"origin": "MADCAT",
                                   "timestamp": syn_dict.get(synid).get("timestamp"),
                                   "src_ip": syn_dict.get(synid).get("IP").get("src_addr"),
                                   "src_port": syn_dict.get(synid).get("TCP").get("src_port"),
                                   "dest_ip": syn_dict.get(synid).get("IP").get("dest_addr"),
                                   "dest_port": syn_dict.get(synid).get("TCP").get("dest_port"),
                                   "proto": "TCP",
                                   "event_type": "syn_scan",
                                   "unixtime": syn_dict.get(synid).get("unixtime"),
                                   "IP": syn_dict.get(synid).get("IP"),
                                   "TCP": syn_dict.get(synid).get("TCP"),
                                   "ct_status": syn_dict.get(synid).get("ct_status")})
                    stdout_lock.acquire()
                    # Marshal JSON and print to STDOUT
                    print(json.dumps(output))
                    sys.stdout.flush()
                    stdout_lock.release()
                    logtime = datetime.now().astimezone().isoformat()
                    del syn_dict[synid]  # Delete outdated SYN from dictonary
                    GLOBAL_SYN_SCAN_COUNT += 1

        syn_dict_lock.release()  # release locks
        time.sleep(1)  # Iterate every second to recognize timed out SYNs
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

########################## Conntrack lookup ##########################

conntrack = list() #XXX
def build_conntrack_dict():
    global DEF_HOSTADDRESS, DEF_CT_STATUS_GRACE_TIME, GLOBAL_CT_LASTUPDATE, GLOBAL_CT_INTERVAL
    global ct_con_dict, ct_con_dict_lock, ct_con_dict_evt, ct_syn_dict, ct_syn_dict_lock, ct_syn_dict_evt, conntrack #XXX
    logtime = datetime.now().astimezone().isoformat()
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
           " CONNTRACK LOOKUP: Thread started and running")
    ct_con_dict_evt.clear()
    ct_syn_dict_evt.clear()
    while(1):
        ct_time = time.time()
        ct_con_dict_lock.acquire()
        ct_syn_dict_lock.acquire()

        # Cleanup ct_syn_dict after timeout + DEF_CT_STATUS_GRACE_TIME expired
        del_entry = list()  # initialize / reset list of dictonary entries marked for deletion
        for synid in list(ct_syn_dict):
            timeout = ct_syn_dict[synid]['timeout']
            # Find new entries and mark them as seen.
            if ct_syn_dict[synid]['new']:
                ct_syn_dict[synid]['new'] = False
            else:  # Entry has not been updated, so decrese timeout "manually"
                ct_syn_dict[synid]['timeout'] -= 1
            if timeout <= 0:  # Count down grace time
                if timeout <= -1 * DEF_CT_STATUS_GRACE_TIME:
                    del_entry.append(ct_syn_dict[synid]['conid'])
                    del(ct_syn_dict[synid])
                else:
                    ct_syn_dict[synid]['timeout'] -= 1

        # Cleanup ct_con_dict
        for timestamp in list(ct_con_dict.keys()):
            for conid in list(ct_con_dict[timestamp].keys()):
                if conid in del_entry:
                    del(ct_con_dict[timestamp][conid])
            if len(ct_con_dict[timestamp]) == 0:
                del ct_con_dict[timestamp]

        # Generate new entry
        ct_con_dict[ct_time] = dict()
        # save time before calling conntrack to ensure it is lower than the
        # time of an incoming packet in other threads.
        GLOBAL_CT_LASTUPDATE = time.time()
        try:
            conntrack = list(
                str(
                    subprocess.check_output(
                        [
                            'conntrack',
                            '-L',
                            '-ptcp',
                            '-d',
                            DEF_HOSTADDRESS],
                        stderr=subprocess.DEVNULL).decode('ascii')).split("\n"))  # Put output in list conaining rows
        except BaseException:
            eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " CONNTRACK LOOKUP: ERROR: conntrack not found. Try: \"apt-get install conntrack\"")
            exit(-1)
        for row in conntrack:  # Parse conntrack output
            # ctid_con as conid:
            # Conntrack output in row.split() contains 15 data fields, resulting in conid "[A]_[B]+[C]" -> [src_ip]_[dest_port]+[src_port]
            # So with DNAT [D] and [C] may differ if a port is allready in use, so that instead of [C]=[D],
            # [C]!=[D] is present in connection objects as src_port and thus no matching synid can be found.
            # [B] is resolved in TCP Module by making use of getsockopt(..., SO_ORIGINAL_DST, ...)
            #
            # ctid_syn as synid [X]_[Y=B]+[Z=D]:
            # Only established and closed TCO connections are of intressed to determine if a connection object
            # must (or should, because of libpcap packet loss under high load) be present at some time
            # Other fields:
            # Hostaddress [h] is given by config MADCAT config thus the address the TCP Module binds to.
            # Listening Port [l] is given by DNAT config and thus MADCAT config and therefore the port TCP Module binds to.
            # Timeout for this connection is in [T]-
            #
            #   0     1     2[T]       3[S]        ORiGgin: 4[X]               5[h]             6[D][Z]      7[B][Y]    RePLy:   8[h]               9[A]             10[l]          11[C]            12           13        14
            #['tcp', '6', '431999', 'ESTABLISHED', 'src=192.168.2.178', 'dst=192.168.2.99', 'sport=51064', 'dport=45000', 'src=192.168.2.99', 'dst=192.168.2.178', 'sport=65535', 'dport=51064',  '[ASSURED]',  'mark=0', 'use=1']
            #['tcp', '6', '9',      'CLOSE',       'src=192.168.2.178', 'dst=192.168.2.99', 'sport=43750', 'dport=55555', 'src=192.168.2.99', 'dst=192.168.2.178', 'sport=65535', 'dport=43750',  '[ASSURED]',  'mark=0', 'use=1']
            #['tcp', '6', '7',      'CLOSE',       'src=192.168.2.178', 'dst=192.168.2.99', 'sport=51292', 'dport=45000', 'src=192.168.2.99', 'dst=192.168.2.178', 'sport=65535', 'dport=51292',  'mark=0',     'use=1']
            #
            # or:
            #
            #   0     1     2[T]    3[S]      Origin: 4                   5[h]             6[D]         7[B]          RePLy:   8               9[h]             10[A]             11[l]           12[C]            13        14
            #['tcp', '6', '119', 'SYN_SENT', 'src=192.168.2.178', 'dst=192.168.2.99', 'sport=33392', 'dport=62985', '[UNREPLIED]',       'src=192.168.2.99', 'dst=192.168.2.178', 'sport=65535', 'dport=33392', 'mark=0', 'use=1']

            if len(row) > 0:
                ct_row_split = row.split()
                if len(ct_row_split) < 14:
                    eprint(ct_row_split)
                if len(ct_row_split) >= 14:
                    status = ct_row_split[3]  # [S]
                    if status == "ESTABLISHED" or status == "CLOSE":
                        org_src_ip = ct_row_split[4].split('=')[1]  # [X]
                        rpl_dst_ip = ct_row_split[9].split('=')[1]  # [A]
                        org_dest_port = ct_row_split[7].split('=')[1]  # [B]
                        rpl_dest_port = ct_row_split[11].split('=')[1]  # [C]
                        org_src_port = ct_row_split[6].split('=')[1]  # [D]
                        timeout = ct_row_split[2]  # [T]

                        # for conid lookup generate ctid_con = conid for con-lookup
                        # [A]_[B]+[C] = ...
                        ctid_con = rpl_dst_ip + "_" + org_dest_port + "+" + rpl_dest_port

                        # add entry with ct_time as primary key:
                        ct_con_dict[ct_time][ctid_con] = dict()
                        ct_con_dict[ct_time][ctid_con]['org_src_port'] = int(
                            org_src_port)

                        # for synid lookup generate ctid_syn like a synid for
                        # closed and established entrys only:
                        ctid_syn = org_src_ip + "_" + org_dest_port + \
                            "+" + org_src_port  # [X]_[B=Y]+[D=Z]

                        # add/update entry with ctid_syn = synid as primary
                        # key:
                        ct_syn_dict[ctid_syn] = dict()
                        ct_syn_dict[ctid_syn]['timeout'] = int(timeout)  # [T]
                        ct_syn_dict[ctid_syn]['conid'] = ctid_con  # [T]
                        ct_syn_dict[ctid_syn]['new'] = True  # [T]

                    if status == "SYN_SENT":

                        org_src_ip = ct_row_split[4].split('=')[1]  # [X]
                        rpl_dst_ip = ct_row_split[10].split('=')[1]  # [A]
                        org_dest_port = ct_row_split[7].split('=')[1]  # [B]
                        rpl_dest_port = ct_row_split[12].split('=')[1]  # [C]
                        org_src_port = ct_row_split[6].split('=')[1]  # [D]
                        timeout = ct_row_split[2]  # [T]

                        # for conid lookup generate ctid_con = conid for con-lookup
                        # [A]_[B]+[C] = ...
                        ctid_con = rpl_dst_ip + "_" + org_dest_port + "+" + rpl_dest_port

                        # add entry with ct_time as primary key:
                        ct_con_dict[ct_time][ctid_con] = dict()
                        ct_con_dict[ct_time][ctid_con]['org_src_port'] = int(
                            org_src_port)  # [D]
                        # ct_con_dict[ct_time][ctid_con]['timeout'] =
                        # int(timeout) #[T]

                        # SYN_SENTs ar not needed for synid lookup generated
                        # with ctid_syn like a synid, but for deletion of
                        # entrys in ct_con_dict:
                        ctid_syn = org_src_ip + "_" + org_dest_port + \
                            "+" + org_src_port  # [X]_[B=Y]+[D=Z]

                        # add/update entry with ctid_syn = synid as primary
                        # key:
                        ct_syn_dict[ctid_syn] = dict()
                        ct_syn_dict[ctid_syn]['timeout'] = int(timeout)  # [T]
                        ct_syn_dict[ctid_syn]['conid'] = ctid_con  # [T]
                        ct_syn_dict[ctid_syn]['new'] = True  # [T]

        ct_syn_dict_lock.release()
        ct_con_dict_lock.release()
        ct_con_dict_evt.set()
        ct_syn_dict_evt.set()

        time.sleep(GLOBAL_CT_INTERVAL)
    return


########################## Configure Threads ##########################
# All threads are deamonized to make them exit with the parent process
# Threads for data acquisition
syn_dict_th = threading.Thread(target=build_syn_dict, daemon=True)
#syn_dict_th.setDaemon(True) #Deprecated since 3.10
con_dict_th = threading.Thread(target=build_con_dict, daemon=True)
#con_dict_th.setDaemon(True) #Deprecated since 3.10
ct_dict_th = threading.Thread(target=build_conntrack_dict, daemon=True)
#ct_dict_th.setDaemon(True) #Deprecated since 3.10
# Threads for generating JSON and cleaning up dictonarys
output_syn_scans_th = threading.Thread(target=output_syn_scans, daemon=True)
#output_syn_scans_th.setDaemon(True) #Deprecated since 3.10
output_accepted_con_th = threading.Thread(target=output_accepted_con, daemon=True)
#output_accepted_con_th.setDaemon(True) #Deprecated since 3.10

########################## Main ##########################


def main(argv):
    global GLOBAL_SHUTDOWN, GLOBAL_FLOW_COUNT, GLOBAL_SYN_SCAN_COUNT, GLOBAL_NO_SYN_COUNT, GLOBAL_HDR_COUNT, GLOBAL_CON_COUNT, GLOBAL_HDR_WARN_COUNT, GLOBAL_CON_WARN_COUNT
    global DEF_HOSTADDRESS
    global DEF_CON_WAIT
    global DEF_SYN_TIMEOUT
    global DEF_SYN_WAIT_PROXY
    global DEF_ENABLE_CONNTRACK
    global DEF_CT_STATUS_GRACE_TIME
    global DEF_BEST_GUESS
    global DEF_BEST_GUESS_TIMEOUT
    global DEF_SYN_EMPTY_QUEUE
    global DEF_HEADER_FIFO
    global DEF_CONNECTION_FIFO
    global DEF_USER
    global DEF_GROUP
    global output_accepted_con_th_firstrun_evt, syn_dict, con_dict, ct_syn_dict
    #global no_syn_dict, syn_scan_dict

    logtime = datetime.now().astimezone().isoformat()
    starttime = time.time()

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
        pid_fp = open("/var/run/madcat/tcppost.pid", "w")
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
                if 's' in value_list['String']:
                    value = value_list['String']['s']
            elif 'Number' in value_list:
                if 'n' in value_list['Number']:
                    value = value_list['Number']['n']
                else:
                    value = 0
            if key in "hostaddress":
                DEF_HOSTADDRESS = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "con_wait":
                DEF_CON_WAIT = int(value)
                eprint("\t" + key + " = " + str(value))
            if key in "syn_timeout":
                DEF_SYN_TIMEOUT = int(value)
                eprint("\t" + key + " = " + str(value))
            if key in "syn_wait_proxy":
                DEF_SYN_WAIT_PROXY = int(value)
                eprint("\t" + key + " = " + str(value))
            if key in "syn_empty_queue":
                DEF_SYN_EMPTY_QUEUE = bool(value)
                eprint("\t" + key + " = " + str(value))
            if key in "header_fifo":
                DEF_HEADER_FIFO = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "connection_fifo":
                DEF_CONNECTION_FIFO = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "user":
                DEF_USER = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "group":
                DEF_GROUP = str(value)
                eprint("\t" + key + " = " + str(value))
            if key in "best_guess":
                DEF_BEST_GUESS = bool(value)
                eprint("\t" + key + " = " + str(value))
            if key in "best_guess_timeout":
                DEF_BEST_GUESS_TIMEOUT = int(value)
                eprint("\t" + key + " = " + str(value))
            if key in "enable_conntrack":
                DEF_ENABLE_CONNTRACK = bool(value)
                eprint("\t" + key + " = " + str(value))
            if key in "ct_status_grace_time":
                DEF_CT_STATUS_GRACE_TIME = int(value)
                eprint("\t" + key + " = " + str(value))

        eprint(logtime + " [PID " + str(os.getpid()) + "]" +
               " ...done. Not configured values fall back to default values!.")
    else:
        eprint(logtime + " [PID " + str(os.getpid()) + "]" +
               " ...nothing found. Values fall back to default values!")

    eprint(
        "================== Configuration [PID " + str(os.getpid()) + "]: ================")
    eprint(
        "Hostaddress TCP Portmonitor is listening at:\n " +
        str(DEF_HOSTADDRESS))
    eprint(
        "Time after which a SYN not yet matched with a connection is interpreted as SYN-SCAN:\n %.1fsec " %
        DEF_SYN_TIMEOUT)
    eprint(
        "Time to wait before a connection is processed to ensure that the matching SYN is present:\n %.1fsec" %
        DEF_CON_WAIT)
    eprint(
        "Time to wait before a SYN on a proxied port of TCP Module is processed to ensure that the matching Connection-Object is present:\n %.1fsec" %
        DEF_SYN_WAIT_PROXY)
    eprint("Connection tracking enabled:\n|" + str(DEF_ENABLE_CONNTRACK))
    if DEF_ENABLE_CONNTRACK:
        eprint("---> Connection tracking status grace time:\n ---> " +
               str(DEF_CT_STATUS_GRACE_TIME) + "sec")
    eprint(
        "Wait for a connection to be marked as \"no_syn\" until the SYN-Queue is empty:\n " +
        str(DEF_SYN_EMPTY_QUEUE))
    eprint(
        "Enable Best Guess Method for Connection Objects with altered src_port because of use of DNAT:\n|" +
        str(DEF_BEST_GUESS))
    if DEF_BEST_GUESS:
        eprint("---> Time to wait before using Best Guess Method:\n ---> " +
               str(DEF_BEST_GUESS_TIMEOUT))
    eprint(
        "Named pipe with TCP/IP Header information, namely SYN:\n " +
        DEF_HEADER_FIFO)
    eprint("Named pipe with connection information:\n " + DEF_CONNECTION_FIFO)
    eprint("User and Group to drop priviliges to:\n " +
           DEF_USER + ":" + DEF_GROUP)
    eprint("==============================================================")
    eprint("\n" + logtime + " [PID " +
           str(os.getpid()) + "]" + " Starting up...")

    # intialize Signal Handler for gracefull shutdown (SIGINT)
    signal.signal(signal.SIGINT, signal_handler_sigint)
    # intialize Signal Handler for fast shutdown (SIGABRT)
    signal.signal(signal.SIGABRT, signal_handler_sigabrt)

    # Start threads for data acquisition
    syn_dict_th.start()
    con_dict_th.start()
    # Start threads for generating output and cleaning up dictonarys
    output_accepted_con_th_firstrun_evt.clear()
    output_accepted_con_th.start()
    output_syn_scans_th.start()
    # If connection tracking is enabled, start respective thread, else drop
    # root priviliges.
    if(DEF_ENABLE_CONNTRACK):
        if os.getuid() != 0:  # if not root abort
            eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " ERROR: Connection tracking is enabled, thus must run as root!")
            os.kill(os.getpid(), signal.SIGINT)
        eprint(logtime +
               " [PID " +
               str(os.getpid()) +
               "]" +
               " WARNING: Connection tracking is enabled, thus root priviliges can not be dropped!")
        ct_dict_th.start()
    else:
        # Give threads some time to start up before dropping priviliges
        time.sleep(1)
        drop_privileges(DEF_USER, DEF_GROUP)

    logtime = datetime.now().astimezone().isoformat()
    eprint(logtime + " [PID " + str(os.getpid()) + "]" +
           " MAIN THREAD WATCHDOG: Running.")
    # Sleep and wait for "death by signal" (unfortunetly their is no signal
    # "CHOCOLATE")...
    firstrun = True
    while True:
        # Check Threads every second. If one died try a graceful shutdown
        logtime = datetime.now().astimezone().isoformat()
        if not syn_dict_th.is_alive():
            eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                   " Thread build_syn_dict died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
        if not con_dict_th.is_alive():
            eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                   " Thread build_con_dict died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
        if not output_accepted_con_th.is_alive():
            eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                   " Thread output_accepted_con died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
        if not output_syn_scans_th.is_alive():
            eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                   " Thread output_syn_scans died, shutting down...")
            os.kill(os.getpid(), signal.SIGINT)
        if(DEF_ENABLE_CONNTRACK):
            if not ct_dict_th.is_alive():
                eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                       " Thread ct_dict_th died, shutting down...")
                os.kill(os.getpid(), signal.SIGINT)
        time.sleep(1)
        time_elapsed = int(time.time() - starttime)
        if firstrun or not time_elapsed % 10:
            eprint(logtime +
                   " [PID " +
                   str(os.getpid()) +
                   "]" +
                   " ##### Statistics after " +
                   str(time_elapsed) +
                   "sec. Time elapsed #####")
            eprint("-------------------------")
            eprint("syn_dict len   : " + str(len(syn_dict)))
            eprint("con_dict len   : " + str(len(con_dict)))
            eprint("ct_syn_dict len: " + str(len(ct_syn_dict)))
            eprint("ct_con_dict len: " + str(len(ct_con_dict)))
            eprint("-------------------------")
            eprint("flow_count     : " + str(GLOBAL_FLOW_COUNT))
            eprint("syn_scan_count : " + str(GLOBAL_SYN_SCAN_COUNT))
            eprint("no_syn_count   : " + str(GLOBAL_NO_SYN_COUNT))
            eprint("-------------------------")
            eprint("hdr_count      : " + str(GLOBAL_HDR_COUNT))
            eprint("con_count      : " + str(GLOBAL_CON_COUNT))
            eprint("hdr_warn_count : " + str(GLOBAL_HDR_WARN_COUNT))
            eprint("con_warn_count : " + str(GLOBAL_CON_WARN_COUNT))
            eprint("-------------------------")
        firstrun = False
    return

# ========================================================================================


# call "def main(argv)" as function with command line arguments
if __name__ == "__main__":
    main(sys.argv)
