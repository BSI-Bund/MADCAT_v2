/*******************************************************************************
This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.

    MADCAT is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    MADCAT is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.

 Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.

    MADCAT ist Freie Software: Sie können es unter den Bedingungen
    der GNU General Public License, wie von der Free Software Foundation,
    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.

    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License für weitere Details.

    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
*******************************************************************************/
/* MADCAT - Mass Attack Detecion Connection Acceptance Tool
 * ICMP monitor.
 *
 *
 * BSI 2018-2023
*/

#include "icmp_mon.helper.h"

//Helper Functions


#include "madcat.helper.h"
#include "udp_ip_port_mon.icmp_mon.helper.h"

void print_help_icmp(char* progname) //print help message
{
    fprintf(stderr, "SYNTAX:\n    %s path_to_config_file\n\
        Sample content of a config file:\n\n\
            \thostaddress = \"127.1.1.1\"\n\
            \tuser = \"madcat\"\n\
            \tpath_to_save_icmp_data = \"./ipm/\" --Must end with trailing \"/\", will be handled as prefix otherwise\n\
            \t--bufsize = \"1024\" --optional\n\
            \tloglevel = 0 --optional: loglevel (0: Standard, 1: Debug)\n\
        ", progname);

    fprintf(stderr, "\nLEGACY SYNTAX (pre v1.1.5)t: %s hostaddress path_to_save_icmp-data user [buffer_size]\n\tBuffer Size defaults to %d Bytes.\n \
\tPath to directory MUST end with a trailing slash, e.g.  \"/path/to/my/dir/\"\n\n \
\tMust be run as root, but the priviliges will be droped to user after the socket has been opened.\n", progname, DEFAULT_BUFSIZE);
    return;
}

//Generic Signal Handler for gracefull shutdown
void sig_handler_icmp(int signo)
{
    char stop_time[64] = ""; //Human readable stop time (actual time zone)
    time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
    fprintf(stderr, "\n%s Received Signal %s, shutting down...\n", stop_time, strsignal(signo));
    // Free
    free(saved_buffer(0));
    dict_free(json_dict("false"));
    //exit parent process
    exit(signo);
    return;
}


