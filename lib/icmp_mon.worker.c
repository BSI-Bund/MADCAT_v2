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
 * ICMP Monitor.
 *
 * BSI 2018-2023
*/

#include "icmp_mon.worker.h"
#include "icmp_mon.helper.h"
#include "icmp_mon.parser.h"

int worker_icmp(unsigned char* buffer, int recv_len, char* hostaddress, char* data_path)
{
    struct ipv4icmp_t ipv4icmp; //struct to save IP-Header contents of intrest

    FILE *file = 0;
    char* payload_hd_str = 0; //Payload as string in HexDump Format
    char* payload_str = 0; //Payload as string
    unsigned char payload_sha1[SHA_DIGEST_LENGTH]; //SHA1 of payload
    char * payload_sha1_str = 0;
    char file_name[2*PATH_LEN] = ""; //double path length for concatination purposes. PATH_LEN *MUST* be enforced when combinating path and filename!
    char log_time[64] = "";
    char stop_time[64] = "";
    char unix_time[64] = "";
    char* hex_string = 0; //Hex string containing ICMP-Data
    //Variables for inner packet analysis
    bool tainted = false; //indicate errors while parsing
    unsigned char* proto = 0; //protocol number of inner packet
    int data_bytes = 0; //Bytes of data in inner packet (e.g. ICMP_UNREACH)
    int data_offset = 0; //Data after end of 8-Byte ICMP-Header + data_offset, covering the parsed and JSONized data, is going to be dumped in a file.
    //beginning time
    long double unix_timeasdouble = time_str(unix_time, sizeof(unix_time), log_time, sizeof(log_time)); //...generate string with current time

    if (recv_len < 24) { //Minimum 20 Byte IP Header + 4 Byte ICMP Header. Should never happen.
        fprintf(stderr, "%s ALERT: Paket to short for ICMP over IPv4, dumping %d Bytes of data:\n", log_time, recv_len);
        print_hex(stderr, buffer, recv_len); //Dump malformed paket for analysis
        return -1;
    }
    //Check IPv4 Header
    ipv4icmp.ver = (uint8_t) (buffer[0] & 0b11110000) >> 4; //IPv4 should have set it's version field to, well, "4".
    ipv4icmp.ihl = (uint8_t) ((buffer[0] & 0b00001111) * 32) / 8; //IP Header length is given in multipels of 32 bit or 4 Byte, respectivly
    ipv4icmp.proto = (uint8_t) buffer[9]; //Proto should be 1 (ICMP), cause it's a RAW IP/ICMP Socket.
    //Fetch IPs and convert them to strings.
    ipv4icmp.src_ip = *(uint32_t*) (buffer+12);
    ipv4icmp.src_ip_str = inttoa(ipv4icmp.src_ip);
    ipv4icmp.dest_ip = *(uint32_t*) (buffer+16);
    ipv4icmp.dest_ip_str = inttoa(ipv4icmp.dest_ip);
    //Ignore Pakets, that have not been addressed to the IP given by the command line
    if(strcmp(ipv4icmp.dest_ip_str, hostaddress) != 0 && strcmp("0.0.0.0", hostaddress) !=0) {
        free(ipv4icmp.src_ip_str);
        free(ipv4icmp.dest_ip_str);
        return -1;
    }
    //Things that should never ever happen.
    if( ipv4icmp.ver != 4 || ipv4icmp.ihl < 20 || ipv4icmp.ihl > 60 || (ipv4icmp.ihl + ICMP_HEADER_LEN) > recv_len  || ipv4icmp.proto != 1 ) {
        fprintf(stderr, "%s ALERT: Malformed Paket. Dumping %d Bytes of data:\n", log_time, recv_len);
        print_hex(stderr, buffer, recv_len);
        free(ipv4icmp.src_ip_str);
        free(ipv4icmp.dest_ip_str);
        return -1;
    }

    // ...and Parse ICMP-Header
    ipv4icmp.icmp_hdr = buffer + ipv4icmp.ihl;
    //Fetch type and code by using the value from IP Header Length-Field,
    // which has been check by the if statement above, so it should be save to use for addressing
    ipv4icmp.type = *(uint8_t*) ipv4icmp.icmp_hdr;
    ipv4icmp.code = *(uint8_t*) (ipv4icmp.icmp_hdr + sizeof(uint8_t));
    ipv4icmp.icmp_check = ntohs(*(uint16_t*) (ipv4icmp.icmp_hdr + 2*sizeof(uint8_t)));
    ipv4icmp.data = ipv4icmp.icmp_hdr + ICMP_HEADER_LEN;
    ipv4icmp.data_len = recv_len - (ipv4icmp.ihl + ICMP_HEADER_LEN);
    //Log connection
    if(loglevel > 0) {
        fprintf(stderr, "%s Received packet from %s to %s, type %u, code %u, with %ld Bytes of DATA.\n", log_time, \
                ipv4icmp.src_ip_str, ipv4icmp.dest_ip_str, ipv4icmp.type, ipv4icmp.code, ipv4icmp.data_len);
    } else {
        fprintf(stderr, "%s Received packet from %s to %s, type %u, code %u, with %ld Bytes of DATA.\n", log_time, \
                "<masked by default loglevel>", ipv4icmp.dest_ip_str, ipv4icmp.type, ipv4icmp.code, ipv4icmp.data_len);
    }



    //Open new JSON and log connection to STDOUT in json-format (Suricata-alike)
    json_value.string = "MADCAT";
    dict_update(json_dict(true), JSON_STR, json_value, 1, "origin");
    json_value.string = log_time;
    dict_update(json_dict(false), JSON_STR, json_value, 1, "timestamp");
    json_value.floating = atof(unix_time);
    dict_update(json_dict(false), JSON_FLOAT, json_value, 1, "unixtime");
    json_value.string = ipv4icmp.src_ip_str;
    dict_update(json_dict(false), JSON_STR, json_value, 1, "src_ip");
    json_value.string = ipv4icmp.dest_ip_str;
    dict_update(json_dict(false), JSON_STR, json_value, 1, "dest_ip");
    
    //Move to [ICMP][type] / [ICMP][code]?
    json_value.integer = ipv4icmp.type;
    dict_update(json_dict(false), JSON_INT, json_value, 1, "icmp_type");
    json_value.integer = ipv4icmp.code;
    dict_update(json_dict(false), JSON_INT, json_value, 1, "icmp_code");

    json_value.string = "ICMP";
    dict_update(json_dict(false), JSON_STR, json_value, 1, "proto");
    json_value.string = "flow";
    dict_update(json_dict(false), JSON_STR, json_value, 1, "event_type");

    //Analyze Headers in ICMP-Payload
    /******************************************
    1. Analyze IP Header
    2. Analyze ICMP Header in detail
        A. Switch-case for types of intrest
            i) if inner packet ist present (ICMP_UNREACH):
                Analyze whole inner packet.
                    a) UDP
                    b) TCP
                    c) default = ???
    4. Dump rest of packet
    ******************************************/

    //Analyze IP Header
    analyze_ip_header(buffer, recv_len, NULL);
    //Analyze ICMP Header
    json_value.integer = ipv4icmp.type;
    dict_update(json_dict(false), JSON_INT, json_value, 2, "ICMP", "type");
    json_value.integer = ipv4icmp.code;
    dict_update(json_dict(false), JSON_INT, json_value, 2, "ICMP", "code");
    json_value.hex.number = ipv4icmp.icmp_check;
    json_value.hex.format = HEX_FORMAT_04;
    dict_update(json_dict(false), JSON_HEX, json_value, 2, "ICMP", "checksum");

    switch(ipv4icmp.type) {
        case MY_ICMP_ECHOREPLY: //print type_str, identifier and sequence
            json_value.string = "echoreply";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            json_value.hex.number = ntohs(*(uint16_t*) (ipv4icmp.icmp_hdr + 2*sizeof(uint16_t)));
            json_value.hex.format = HEX_FORMAT_04;
            dict_update(json_dict(false), JSON_HEX, json_value, 2, "ICMP", "id");
            json_value.integer = ntohs(*(uint16_t*) (ipv4icmp.icmp_hdr + 3*sizeof(uint16_t)));
            dict_update(json_dict(false), JSON_HEX, json_value, 2, "ICMP", "seq");
            break;
        case MY_ICMP_ECHO:  //print type_str, identifier and sequence
            json_value.string = "echo";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            json_value.hex.number = ntohs(*(uint16_t*) (ipv4icmp.icmp_hdr + 2*sizeof(uint16_t)));
            json_value.hex.format = HEX_FORMAT_04;
            dict_update(json_dict(false), JSON_HEX, json_value, 2, "ICMP", "id");
            json_value.integer = ntohs(*(uint16_t*) (ipv4icmp.icmp_hdr + 3*sizeof(uint16_t)));
            dict_update(json_dict(false), JSON_HEX, json_value, 2, "ICMP", "seq");
            break;
        case MY_ICMP_UNREACH:
            json_value.string = "unreach";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            json_value.hex.number = *(uint32_t*) (ipv4icmp.icmp_hdr + 2*sizeof(uint16_t));
            json_value.hex.format = HEX_FORMAT_08;
            dict_update(json_dict(false), JSON_HEX, json_value, 2, "ICMP", "unused");

            switch(ipv4icmp.code) {
                case MY_ICMP_NET_UNREACH:
                    json_value.string = "net_unreach";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_HOST_UNREACH:
                    json_value.string = "host_unreach";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_PROT_UNREACH:
                    json_value.string = "prot_unreach";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_PORT_UNREACH:
                    json_value.string = "port_unreach";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_FRAG_NEEDED:
                    json_value.string = "frag_needed";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_SR_FAILED:
                    json_value.string = "sr_failed";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_NET_UNKNOWN:
                    json_value.string = "net_unknown";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_HOST_UNKNOWN:
                    json_value.string = "host_unknown";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_HOST_ISOLATED:
                    json_value.string = "host_isolated";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_NET_ANO:
                    json_value.string = "net_ano";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_HOST_ANO:
                    json_value.string = "host_ano";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_NET_UNR_TOS:
                    json_value.string = "net_unr_tos";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_HOST_UNR_TOS:
                    json_value.string = "host_unr_tos";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_PKT_FILTERED:
                    json_value.string = "pkt_filtered";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_PREC_VIOLATION:
                    json_value.string = "prec_vioalation";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                case MY_ICMP_PREC_CUTOFF:
                    json_value.string = "prec_cutoff";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    break;
                default:
                    json_value.string = "tainted/unkown";
                    dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "code_str");
                    tainted = true;
                    break;
            } //End of switch(ipv4icmp.code)
            //Analyze inner IP-Header
            struct dict* json_unreach = dict_new();
            tainted = analyze_ip_header(ipv4icmp.data, recv_len, &json_unreach);
            if(tainted) { //if inner IP-Header is tainted (e.g. < 20Bytes), also set tainted = true and break
                if(!dict_append(json_unreach, dict_get(json_dict(false), 1, "ICMP")->value.object))
                    dict_free(json_unreach);
                tainted = true;
                break;
            }
            //10th Byte (count begins at 0, so it's data+9) contains the protocol number of inner IP-Header
            //It has been parsed by above analyze_ip_headeripv4icmp.data + 4, recv_len) and therefore checked, so this access should be okay.
            proto = ipv4icmp.data + 9;
            switch(*proto) {
                case 6: //TCP: data_offset is the whole length of inner packet minus number of data bytes after the IP/TCPs headers.
                    data_bytes = analyze_tcp_header(ipv4icmp.data, ipv4icmp.data_len, &json_unreach);
                    if(data_bytes < 0) {
                        tainted = true;
                        break;
                    }
                    data_offset = ipv4icmp.data_len - data_bytes;
                    break;
                case 17: //UDP: data_offset is the whole length of inner packet minus number of data bytes after the IP/UDP headers.
                    data_bytes = analyze_udp_header(ipv4icmp.data, ipv4icmp.data_len, &json_unreach);
                    if(data_bytes < 0) {
                        tainted = true;
                        break;
                    }
                    data_offset = ipv4icmp.data_len - data_bytes;
                    break;
                case 1: //TODO: ICMP in ICMP
                default: //protocol unknown or tainted
                    tainted = true;
                    break;
            }
            json_value.object = json_unreach;
            if(!dict_append(json_unreach, dict_get(json_dict(false), 1, "ICMP")->value.object))
                dict_free(json_unreach);
            break;
        case MY_ICMP_SOURCEQUENCH:
            json_value.string = "sourcequench";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_REDIRECT:
            json_value.string = "redirect";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_ALTHOST:
            json_value.string = "althost";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_RTRADVERT:
            json_value.string = "rtradvert";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_RTRSOLICIT:
            json_value.string = "rtrsolicit";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_TIMXCEED:
            json_value.string = "timxceed";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_PARAMPROB:
            json_value.string = "paramprob";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_TSTAMP:
            json_value.string = "tstamp";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_TSTAMPREPLY:
            json_value.string = "tstampreply";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_IREQ:
            json_value.string = "ireq";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_IREQREPLY:
            json_value.string = "ireqreply";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_MASKREQ:
            json_value.string = "maskreq";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_MASKREPLY:
            json_value.string = "maskreply";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_PHOTURIS:
            json_value.string = "photuris";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_EXTECHO:
            json_value.string = "extecho";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        case MY_ICMP_EXTECHOREPLY:
            json_value.string = "extechoreply";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            break;
        default:
            json_value.string = "tainted/unknown";
            dict_update(json_dict(false), JSON_STR, json_value, 2, "ICMP", "type_str");
            tainted = true;
            break;
    } //End of switch(ipv4icmp.type)
    //if some data has been received (payload or tainted), that has not been parsed into JSON object yet, save the rest of datagram in a file
    // e.g. TCP or UDP data in ICPM_UNREACH or data at the end of an ICMP Echo-Request/-Reply
    // Also dump all data, if packet is marked as tainted
    if(ipv4icmp.data_len - data_offset > 0 || tainted) { //payload data is left or tainted
        //Generate filename LinuxTimeStamp-milisecends_destinationAddress-destinationPort_sourceAddress-sourcePort.tpm
        sprintf(file_name, "%s%s_%s_%s-%u_%u.ipm", data_path, log_time, ipv4icmp.dest_ip_str, ipv4icmp.src_ip_str, ipv4icmp.type, ipv4icmp.code);
        file_name[PATH_LEN-1] = 0; //Enforcing PATH_LEN
        file = fopen(file_name,"wb"); //Open File
        //Write when -and only WHEN - nothing went wrong data to file
        if (file != 0) {
            if(loglevel > 0) {
                fprintf(stderr, "%s FILENAME: %s\n", log_time, file_name);
            } else {
                fprintf(stderr, "%s FILENAME: %s%s_%s_%s-%u_%u.ipm\n", log_time, \
                        data_path, log_time, ipv4icmp.dest_ip_str,  "<masked by default loglevel>", ipv4icmp.type, ipv4icmp.code);
            }
            fwrite(ipv4icmp.data + data_offset, ipv4icmp.data_len - data_offset, 1, file);
            CHECK(fflush(file), == 0);
            fclose(file);
        } else {
            //if somthing went wrong, log it.
            if(loglevel>0) {
                fprintf(stderr, "%s ERROR: Could not write to file %s\n", log_time, file_name);
            } else {
                fprintf(stderr, "%s ERROR: Could not write to file %s%s_%s_%s-%u_%u.ipm\n", log_time, \
                        data_path, log_time, ipv4icmp.dest_ip_str,  "<masked by default loglevel>", ipv4icmp.type, ipv4icmp.code);
            }

        }
    }

    //End time
    long double duration = time_str(NULL, 0, stop_time, sizeof(stop_time)) - unix_timeasdouble; //...generate string with current time

    //Compute SHA1 of payload
    SHA1(ipv4icmp.data, ipv4icmp.data_len, payload_sha1);
    payload_sha1_str = print_hex_string(payload_sha1, SHA_DIGEST_LENGTH);
    //Make HexDump output out of binary payload
    payload_hd_str = hex_dump(ipv4icmp.data, ipv4icmp.data_len, true);  //must be freed
    payload_str = print_hex_string(ipv4icmp.data, ipv4icmp.data_len); //must be freed

    //Close ICMP JSON object with tainted status and "flow" part.
    json_value.boolean = tainted;
    dict_update(json_dict(false), JSON_BOOL, json_value, 2, "ICMP", "tainted");
    json_value.string = log_time;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "start");
    json_value.string = stop_time;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "end");
    json_value.floating = duration;
    dict_update(json_dict(false), JSON_FLOAT, json_value, 2, "FLOW", "duration");
    json_value.integer = ipv4icmp.data_len;
    dict_update(json_dict(false), JSON_INT, json_value, 2, "FLOW", "bytes_toserver");
    json_value.string = payload_hd_str;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "payload_hd");
    json_value.string = payload_str;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "payload_str");
    json_value.string = payload_sha1_str;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "payload_sha1");

    //free str allocated by strndup() in function char *inttoa(uint32_t) and char *print_hex_string(const unsigned char*, unsigned int)
    free(ipv4icmp.src_ip_str);
    free(ipv4icmp.dest_ip_str);
    free(payload_hd_str);
    free(payload_str);
    free(payload_sha1_str);
    if(hex_string) free(hex_string);
    return ipv4icmp.data_len;
}
