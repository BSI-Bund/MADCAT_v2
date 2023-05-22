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
# Truncate filebeat logs and preserve unsend entries
#
#
# BSI 2021
##

########################## IMPORTS ##########################
import sys
import os
import subprocess
import shutil

########################## CONFIGURATION ##########################
# log_dict contains key:value pairs containing filebeat log file and data file designated
# to be send by filebeat in the form filebeat_log:data_file, thus matching
# them.
log_dict = {
    "/var/log/filebeat/filebeat": "/data/portmonitor.log",
    "/var/log/filebeat_monitoring/filebeat": "/data/monitoring.log",
    "/var/log/filebeat_logging/filebeat": "/var/log/madcat_json.log",
}

temp_file = "/tmp/truncate.tmp"


########################## Main ##########################
def main(argv):
    for filebeat_log, data_file in log_dict.items():
        print("Processing " + filebeat_log + " harvesting " + data_file)
        try:
            lastoffset = int(list(str(subprocess.check_output('grep' + ' \"Update existing file for harvesting: ' +
                             data_file + '\" ' + filebeat_log + " | tail -n1", shell=True).decode('ascii')).split(" "))[-1])
            print("\tLast offset in filebeat log: " + str(lastoffset))

            dd = str(
                subprocess.check_output(
                    'dd iflag=skip_bytes skip=' +
                    str(lastoffset) +
                    ' if=' +
                    data_file +
                    ' of=' +
                    temp_file +
                    ' 2>/dev/null',
                    shell=True).decode('ascii')).split("\\n")

            print("\tReplacing " + data_file + " with truncated version")
            os.remove(data_file)
            shutil.move(temp_file, data_file)
            print("\tDone.")
        except BaseException:
            pass


########################## Execute Main ##########################

# call "def main(argv)" as function with command line arguments
if __name__ == "__main__":
    main(sys.argv)
