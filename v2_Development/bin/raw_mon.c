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
 * TCP-IP port monitor.
 *
 * Example Netfilter Rule to work properly:
 *       iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 1:65534 -j DNAT --to 192.168.8.42:65535
 * Listening Port is 65535 and hostaddress is 192.168.8.42 in this example.
 *
 * BSI 2018-2021
*/

//Header includes, defintions and globals
#include "madcat.common.h"
#include "madcat.helper.h"
#include "raw_mon.h"

//Main

int main(int argc, char *argv[])
{

    //Display Mascott and Version
    if (argc == 2 && strcmp(argv[1], "version") == 0) {
        fprintf(stdout, "\n%s%s\n", MASCOTT, VERSION);
        exit(0);
    }
    fprintf(stderr, "\n%s%s\n", MASCOTT, VERSION);

    loglevel = 0; //Default Loglevel 0: Standard, 1: Debug

    //pseudo constant empty string e.g. for initialization of json_data_node_t and checks. Not used #define here, because this would lead to several instances of an empty constant string with different addresses.
    EMPTY_STR[0] = 0;
    //Start time
    char log_time[64] = ""; //Human readable start time (actual time zone)
    char log_time_unix[64] = ""; //Unix timestamp (UTC)
    long double log_time_double = time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time)); //Get time

    //Register Signal Handlers
    signal(SIGUSR1, sig_handler_raw); //register handler as callback function used by CHECK-Macro
    CHECK(signal(SIGINT, sig_handler_raw), != SIG_ERR); //register handler for SIGINT
    CHECK(signal(SIGTERM, sig_handler_raw), != SIG_ERR); //register handler for SIGTERM

    //Parse command line.
    char interface[64]= "";
    int max_file_size = -1;
    filter_exp = EMPTY_STR;

    // Checking if number of arguments is one (config file).
    if (argc != 2) {
        print_help_raw(argv[0]);
        return -1;
    }

    if (argc == 2) { //read config file
        lua_State *luaState = lua_open();
        if (luaL_dofile(luaState, argv[1]) != 0) {
            fprintf(stderr, "%s [PID %d] Error parsing config file: %s\n\tRun without command line arguments for help.\n", log_time, getpid(), lua_tostring(luaState, -1));
            exit(1);
        }

        fprintf(stderr, "%s [PID %d] Parsing config file: %s\n", log_time, getpid(), argv[1]);

        strncpy(interface, get_config_opt(luaState, "interface"), sizeof(interface));
        interface[sizeof(interface)-1] = 0;  //copy interface and ensure null termination of this string. Ugly.
        fprintf(stderr,"\tInterface: %s\n", interface);

        strncpy(user.name, get_config_opt(luaState, "user"), sizeof(user.name));
        user.name[sizeof(user.name)-1] = 0;
        fprintf(stderr, "\tuser: %s\n", user.name);

        long int filter_exp_len = strlen(get_config_opt(luaState, "raw_pcap_filter_exp"));
        filter_exp = malloc(filter_exp_len + 1);
        filter_exp[0] = 0;
        strncpy(filter_exp, get_config_opt(luaState, "raw_pcap_filter_exp"), filter_exp_len + 1);
        filter_exp[filter_exp_len] = 0;
        fprintf(stderr, "\tPCAP Filter expression: %s\n", filter_exp);

        //check if mandatory string parameters are present, bufsize is NOT mandatory, the rest are numbers and are handled otherwise
        if(strlen(interface) == 0 || strlen(user.name) == 0) {
            fprintf(stderr, "%s [PID %d] Error in config file: %s\n", log_time, getpid(), argv[1]);
            print_help_raw(argv[0]);
            return -1;
        }

        if(get_config_opt(luaState, "max_file_size") != EMPTY_STR) { //if optional parameter is given, set it.
            max_file_size = atoi(get_config_opt(luaState, "max_file_size"));
        }
        fprintf(stderr, "\tmax_file_size: %d\n", max_file_size);

        if(get_config_opt(luaState, "loglevel") != EMPTY_STR) { //if optional parameter is given, set it.
            loglevel = atoi(get_config_opt(luaState, "loglevel")); //convert string type to integer type (loglevel)
        }
        fprintf(stderr, "\tloglevel: %d\n", loglevel);

        fflush(stderr);
        lua_close(luaState);
    }

    fprintf(stderr, "%s [PID %d] Starting on interface %s\n", \
            log_time, getpid(), interface);

    //Init pcap , drop priviliges, sniff for SYN-Packets and log them

#if DEBUG >= 2
    fprintf(stderr, "*** DEBUG [PID %d] Initialize PCAP\n", getpid());
#endif
    CHECK(init_pcap(interface, &handle, filter_exp), == 0); //Init libpcap

    fprintf(stderr, "%s [PID %d] ", log_time, getpid());
    drop_root_privs(user, "Sniffer"); //drop priviliges

    struct json_data_node_t json_data; //JSON Data structure for output generation
    //Link (POINTERS!!!) timestamp(s) in JSON Data Structure to timestamp variables (multiple times to match the data model of other modules)

    char* payload_str = 0; //Payload as string
    unsigned char* payload_hd_str = 0; //Payload as string in HexDump Format
    char * payload_sha1_str = 0;
    unsigned char payload_sha1[SHA_DIGEST_LENGTH]; //SHA1 of payload
    bool size_exceeded = false; //max file size exceeded?
    fprintf(stderr, "%s [PID %d] Sniffing...\n", log_time, getpid());
    while (1) {
        //Sniff packet
        packet = 0;
        packet = (unsigned char*) pcap_next(handle, &header); //Wait for and grab Packet (see PCAP_FILTER) (Maybe of maybe not BLOCKING!)

        //Test if something went wrong
        if (packet == 0) continue;
        if (!(header.len > ETHERNET_HEADER_LEN)) continue;

        //Preserve actuall time of Connection attempt, linked to timestamps in json_data
        json_data.timeasdouble = time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time));
        json_data.unixtime = log_time_unix;
        json_data.timestamp = log_time;
        json_data.start = log_time;
        fprintf(stderr, "%s [PID %d] RAW Packet received\n", log_time, getpid());

        //Set pointer and length to address layer 3 directly in received data
        int packet_len = header.len - ETHERNET_HEADER_LEN;
        unsigned char* packet_layer3 = (unsigned char*) packet + ETHERNET_HEADER_LEN;

        if (packet_len > max_file_size && max_file_size > 0)
            size_exceeded = true;
        else
            size_exceeded = false;

#if DEBUG >= 2
        fprintf(stdout, "\n%s\n", hex_dump(packet_layer3, packet_len, false));
#endif

        json_data.bytes_toserver = packet_len; //Len is defined here as layer 3 protokoll data + encapsulated protocols and their payload

        //Process packet data
        //Compute SHA1 of packet
        SHA1(packet_layer3, (size_exceeded ? max_file_size : packet_len), payload_sha1);
        payload_sha1_str = print_hex_string(payload_sha1, SHA_DIGEST_LENGTH);  //must be freed
        //Make HexDump output out of binary packet contents
        payload_hd_str = hex_dump(packet_layer3, (size_exceeded ? max_file_size : packet_len), true); //must be freed
        payload_str = print_hex_string(packet_layer3, (size_exceeded ? max_file_size : packet_len)); //must be freed

        //Assumption of IP (v4 or v6) to determine version
        struct iphdr *iphdr = (struct iphdr *)(packet + ETHERNET_HEADER_LEN); //IPv4 header structure will do for version determination (for the moment)
        char proto_str[6] = "";
        json_data.proto = iphdr->version; //May have other values than 4 or 6 if not an IP Packet, handle with care, it's RAW!
        snprintf(proto_str, 6, "%d", json_data.proto);

        //Begin new global JSON output and open JSON object
        //At this point I would like to honestly apologize for the nested double use of the ternary operator, it IS bad style. But I always wanted to do this to annoy you all.
        json_data.duration = time_str(NULL, 0, log_time, sizeof(log_time)) - json_data.timeasdouble;
        json_data.end = log_time;
        json_do(true, "{\
\"origin\":\"MADCAT\", \
\"timestamp\":\"%s\", \
\"proto\":\"%s\", \
\"event_type\":\"%s\", \
\"unixtime\": %s, \
\"FLOW\": { \
\"start\":\"%s\",\
\"end\":\"%s\", \
\"duration\":%Lf,  \
\"state\":\"%s\", \
\"reason\":\"%s\", \
\"bytes_toserver\": %lld,\
\"payload_hd\":\"%s\",\
\"payload_str\":\"%s\",\
\"payload_sha1\":\"%s\"\
},\
\"RAW\": {\
\"pcap_filter\":\"%s\"\
}}",\
                json_data.timestamp, \
                json_data.proto == 4 ? "IPv4" : json_data.proto == 6 ? "IPv6" : proto_str,\
                "RAW",\
                json_data.unixtime, \
                json_data.start,\
                json_data.end,\
                json_data.duration,\
                "closed",\
                "closed",\
                json_data.bytes_toserver,\
                payload_hd_str,\
                payload_str,\
                payload_sha1_str,\
                filter_exp\
               );
        //JSON Ouput and close JSON object
        fprintf(stdout,"%s\n", json_do(false, "")); //print json output for logging
        fflush(stdout);

        free(payload_sha1_str);
        free(payload_str);
        free(payload_hd_str);
    }

    return 0;
}
