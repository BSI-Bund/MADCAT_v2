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
# Central MADCAT Lua-Config Parser for use in bashscripts
#
#
# BSI 2018-2023
##

import sys
import os
import json
from datetime import datetime
from luaparser import ast, astnodes, builder

########################## Version and Mascott strings ###################
GLOBAL_VERSION = "MADCAT - Mass Attack Detecion Connection Acceptance Tools\nCentral MADCAT Lua-Config Parser v1.0.1\n  BSI 2023\n"
GLOBAL_MASCOTT = "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n bsi   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__"

########################## Print on STDERR ##########################


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    sys.stderr.flush()
    return

########################## Main ##########################

def main(argv):
    logtime = datetime.now().astimezone().isoformat()
    syntax_help = GLOBAL_MASCOTT + "\n\n" + GLOBAL_VERSION + "\nSyntax:\n" +\
                "\t" + sys.argv[0] + " MADCAT_LUA_CONFIG_FILE [CONFIG_ITEM]\n\n" +\
                "Output (on STDOUT):\n" +\
                "\tWith (single!) CONFIG_ITEM as paramter (e.g. loglevel or tcpproxy, etc): Value of the config item in bash parsable form.\n" +\
                "\tWithout CONFIG_ITEM as parameter: All Key (config Item) - Value (value of the config Item) pairs, one per line."
    config_txt = ""
    delimiter_values = '_'
    delimiter_lines = ';'

    try:
        given_key = argv[2]
    except IndexError:
        given_key = None

    try:
        if given_key == None:
            eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                    " INFO: Parsing Config File \"" + argv[1] + "\"...")
        else:
            eprint(logtime + " [PID " + str(os.getpid()) + "]" +
                    " INFO: Parsing Config File \"" + argv[1] + "\" for \"" + given_key + "\"...")
        config_file = open(argv[1], 'r')
        config_txt = config_file.read()
        config_file.close()
    except BaseException as err:
        eprint(logtime +
                " [PID " +
                str(os.getpid()) +
                "]" +
                " ERROR: No config file given as parameter or not found / readable " + str(err.args) + ". Quitting.\n" + syntax_help)
        sys.exit(-1)


    if len(config_txt) > 0:  # Parse config
        try:
            config_tree = ast.parse(config_txt)
            config_list = json.loads(ast.to_pretty_json(config_tree))[
            'Chunk']['body']['Block']['body']
        except BaseException as err:
            eprint(logtime +
                " [PID " +
                str(os.getpid()) +
                "]" +
                " ERROR: Parsing of MADCAT central Lua config file " + str(err.args) + " failed. Quitting.\n" + syntax_help )
            sys.exit(-2)

        for item in config_list:  # only strings and numbers
            key = item['Assign']['targets'][0]['Name']['id']
            value_list = item['Assign']['values'][0]
            if 'String' in value_list:
                try:
                    value = value_list['String']['s']
                except KeyError:
                    value = ""
            elif 'Number' in value_list:
                if 'n' in value_list['Number']:
                    value = value_list['Number']['n']
                else:
                    value = 0
            elif 'Table' in value_list:
                value = ""
                if key == "tcpproxy" or key=="udpproxy": #tcpproxy and udpproxy configuration only! (key/value pairs, value is a nested table)
                    try:
                        first_line = True
                        for field in value_list['Table']['fields']:
                            if not first_line:
                                value += delimiter_lines
                            else:
                                first_line = False
                            value += str(field['Field']['key']['Number']['n']) + delimiter_values
                            for field_item in field['Field']['value']['Table']['fields']:
                                try: #Backend IP String is first
                                    value += field_item['Field']['value']['String']['s'] + delimiter_values
                                except KeyError:
                                    pass
                                try: #Backend Port is second (no delimiter)
                                    value += str(field_item['Field']['value']['Number']['n'])
                                except KeyError:
                                    pass
                    except KeyError: #empty table
                        pass
                else: #Parsing of other, non nested Lua-Tables w/o key/value pairs in config (e.g. enr_output_files)
                    try:
                        first_line = True
                        for field in value_list['Table']['fields']:
                            if not first_line:
                                value += delimiter_lines
                            else:
                                first_line = False
                            try: #String...
                                value += field['Field']['value']['String']['s']
                                continue
                            except KeyError:
                                pass
                            try: #... or number
                                value += str(field['Field']['value']['Number']['n'])
                                continue
                            except KeyError:
                                pass
                    except KeyError: #empty table
                        pass

            if given_key == None:
                print(key + " " + str(value))
            if key == given_key:
                print(str(value))

# call "def main(argv)" as function with command line arguments
if __name__ == "__main__":
    main(sys.argv)