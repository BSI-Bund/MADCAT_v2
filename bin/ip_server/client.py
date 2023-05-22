#!/bin/python3
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
# IP Server Client Dummy Module
# 
# This is a dummy module which can be extended to e.g. exchange external IP addresses and event IDs
# between MADCAT and a possibly existing honeypot backend when using the proxy functionality of MADCAT.
#
# BSI 2023
##
import sys

########################## config ##########################
GLOBAL_CONFIG=dict()
GLOBAL_CONFIG['log_preamble'] = ""


########################## Version and Mascott strings ###################
GLOBAL_VERSION = "MADCAT - Mass Attack Detecion Connection Acceptance Tools\nIP Server Client Dummy Module\n BSI 2023\n"
GLOBAL_MASCOTT = "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n bsi   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__"

############# Globals, Constants, Locks  ############
CONST_EMPTY_IP = b'\x00\x00\x00\x00'

######################### Protocol #########################
"""Server Response Codes:"""
PROT_SERVER_RESPCODE_LEN = 1

PROT_UPDATE_OK = b'\x00'
PROT_IDUPDATE_OK = b'\x01'

PROT_QUERY_NOTFOUND = b'\x7f'
PROT_IDQUERY_NOTFOUND = b'\x7e'

PROT_QUERY_ERROR = b'\xfe'
PROT_IDQUERY_ERROR = b'\xfd'

PROT_GENERAL_ERROR = b'\xff'

#General Server Error, detected on client side (No Route to Host, Connection refused, etc.)
PROT_SERVER_ERROR = b'\xef'

########################## Helper ##########################

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()
    return

def retval_btoa(retval):
    if retval == PROT_UPDATE_OK:
        return "UPDATE OK"
    if retval == PROT_IDUPDATE_OK:
        return "ID UPDATE OK"
    
    if retval == PROT_QUERY_NOTFOUND:
        return "QUERY NOTFOUND"
    if retval == PROT_IDQUERY_NOTFOUND:
        return "ID QUERY NOTFOUND"
    
    if retval == PROT_QUERY_ERROR:
        return "QUERY ERROR"
    if retval == PROT_IDQUERY_ERROR:
        return "ID QUERY ERROR"
    
    if retval == PROT_GENERAL_ERROR:
        return "GENERAL ERROR"
    if retval == PROT_SERVER_ERROR:
        return "SERVER ERROR"
    if retval == b'':
        return "SERVER RESPONSE EMPTY"
    
    return "UNKNOWN RESPONSE CODE " + str(retval)

######################### API ##############################

#(IP) Update Dummy
def send_update(ext_ip, lan_ip=CONST_EMPTY_IP, human_readable=True, retry=True, log_preamble=GLOBAL_CONFIG["log_preamble"]):
    if human_readable:
        return retval_btoa(PROT_UPDATE_OK)
    else:
        return PROT_UPDATE_OK

#ID Update Dummy
def send_idupdate(eventid, backend_port, backend_ip, proxy_port ,proxy_ip=CONST_EMPTY_IP, human_readable=True, retry=True, log_preamble=GLOBAL_CONFIG["log_preamble"]):
    if human_readable:
        return retval_btoa(PROT_IDUPDATE_OK)
    else:
        return PROT_IDUPDATE_OK

#(IP) Query Dummy
def send_query(lan_ip=CONST_EMPTY_IP, human_readable=True, retry=True, log_preamble=GLOBAL_CONFIG["log_preamble"]):
    if human_readable:
        return "0.0.0.0"
    else:
        return CONST_EMPTY_IP

#ID Query Dummy
def send_idquery(backend_port, backend_ip, proxy_port ,proxy_ip=CONST_EMPTY_IP, human_readable=True, retry=True, log_preamble=GLOBAL_CONFIG["log_preamble"]):
    if human_readable:
        return "0x000000000000"
    else:
        return b'\x00\x00\x00\x00\x00\x00'

#sets config, takes address and port in the form 10.10.10.10:10000
def config(address_port, log_preamble=""):
    address_port = address_port.split(':')
    GLOBAL_CONFIG["address"] = address_port[0]
    GLOBAL_CONFIG["port"] = int(address_port[1])
    GLOBAL_CONFIG["log_preamble"] = log_preamble

if __name__ == "__main__":
    eprint("This is a dummy module which can be extended to e.g. exchange external IP addresses and event IDs between\n\
           \rMADCAT and a possibly existing honeypot backend when using the proxy functionality of MADCAT.")
    sys.exit(0)
