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
 * RAW monitor.
 *
 *
 * BSI 2018-2021
*/

#include "raw_mon.h"
#include "raw_mon.helper.h"

//Helper Functions

#include "madcat.helper.h"

void print_help_raw(char* progname) //print help message
{

    fprintf(stderr, "SYNTAX:\n    %s path_to_config_file\n\
        Sample content of a config file:\n\n\
            \tinterface = \"enp0s8\"\n\
            \tuser = \"hf\"\n\
            \tloglevel = 0 --optional: loglevel (0: Standard, 1: Debug)\n\
            \tmax_file_size = \"1024\" --optional: Max. size of payloads in JSON-Output\n\
            \t--Optional filter expresion for RAW module, defaults to none (empty string).\n\
            \t--Syntax: https://www.tcpdump.org/manpages/pcap-filter.7.html\n\
            \traw_pcap_filter_exp = \"(not ip6 multicast) and inbound and ip6\"\n"\
            , progname);

    return;
}

//Generic Signal Handler for gracefull shutdown
void sig_handler_raw(int signo)
{
    char stop_time[64] = ""; //Human readable stop time (actual time zone)
    time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
    fprintf(stderr, "\n%s [PID %d] Received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));
    //Free pcap data structures
    pcap_close(handle); //Close PCAP Session handle
    free(filter_exp); //The configured PCAP Filter string
    free(packet); //The Packet from pcap
    //free json object
    free(json_do(true, ""));
    //exit parent process
    exit(signo);
    return;
}

void drop_root_privs(struct user_t user, const char* entity) // if process is running as root, drop privileges
{
    if (getuid() == 0) {
        fprintf(stderr, "%s droping priviliges to user %s...", entity, user.name);
        get_user_ids(&user); //Get traget user UDI + GID
        CHECK(setgid(user.gid), == 0); // Drop GID first for security reasons!
        CHECK(setuid(user.uid), == 0);
        if (getuid() == 0 || getgid() == 0) //Test if uid/gid is still 0
            fprintf(stderr, "...nothing to drop. WARNING: Running as root!\n");
        else
            fprintf(stderr,"SUCCESS. UID: %d\n", getuid());
        fflush(stderr);
    }
    return;
}

int init_pcap(char* dev, pcap_t **handle, const char* filter_exp)
{
    char log_time[64] = ""; //Human readable start time (actual time zone)
    char log_time_unix[64] = ""; //Unix timestamp (UTC)
    struct timeval begin;
    gettimeofday(&begin, NULL);
    time_str(NULL, 0, log_time, sizeof(log_time)); //Get Human readable string only

    char errbuf[PCAP_ERRBUF_SIZE];// Error string
    struct bpf_program fp; // The compiled filter
    bpf_u_int32 mask;     // Our netmask
    bpf_u_int32 net;     // Our IP

    fprintf(stderr, "%s [PID %d] Trying to set PCAP Filter Expression (fails if not root): \"%s\": ", log_time, getpid(), filter_exp);
    fflush(stderr);

    // Find the properties for the device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        return -1;
    // Open the session in non-promiscuous mode
    *handle = pcap_open_live(dev, BUFSIZ, 0, 100, errbuf);
    if (handle == NULL)
        return -2;
    // Compile and apply the filter
    if(strlen(filter_exp) > 0) {
        if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "ERROR compiling expression, ABORTING.\n");
            fflush(stderr);
            abort();
        }
        if (pcap_setfilter(*handle, &fp) == -1) {
            fprintf(stderr, "ERROR setting expression, ABORTING.\n");
            fflush(stderr);
            abort();
        }
        free(fp.bf_insns);
    }

    fprintf(stderr, "SUCCESS.\n");
    fflush(stderr);

    return 0;
}
