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
 *
 * BSI 2018-2023
*/
#include "icmp_mon.parser.h"
#include "icmp_mon.helper.h"

//Helper function to parse IP Options. Returns tainted status, puts option data in hex string.
bool parse_ipopt(int opt_cpclno, const char* opt_name, \
                 unsigned char** opt_ptr_ptr, const unsigned char* beginofoptions_addr, const unsigned char* endofoptions_addr, struct dict** json)
{
    int opt_len = *(*opt_ptr_ptr+1);
    if((*opt_ptr_ptr + opt_len) > endofoptions_addr) return true; //Check length, signal tainted in case of failure
    if(json == NULL) {
        struct dict* dict_temp = json_dict(false);
        json = &dict_temp;
    }
    //Option data to hex string
    char* hex_string = print_hex_string(*opt_ptr_ptr + 2, opt_len - 2);  //Extract option data as hex string. Has to be freed!
    json_value.string = hex_string;
    dict_update(*json, JSON_STR, json_value, 3, "IP", "ip_options", opt_name); //JSON Output
    free(hex_string);
    *opt_ptr_ptr += opt_len; //set pointer to next option
    return false; //Option not tainted.
}

bool analyze_ip_header(const unsigned char* packet, int recv_len, struct dict** json) //indicates tainted IP-Header
{
    struct iphdr *iphdr = (struct iphdr *)(packet);

    if(recv_len - (IP_OR_TCP_HEADER_MINLEN) <= 0 || iphdr->version != 4 ) return true; //Malformed Paket
    if(json == NULL) {
        struct dict* dict_temp = json_dict(false);
        json = &dict_temp;
    }
    bool tainted = false; //Is somethin unparsable inside the packet / options?

    char* ip_saddr = inttoa(iphdr->saddr); //Must be freed!
    char* ip_daddr = inttoa(iphdr->daddr); //Must be freed!

    json_value.integer = iphdr->ihl*4;
    dict_update(*json, JSON_INT, json_value, 2, "IP", "hdr_len");
    json_value.integer = iphdr->version;
    dict_update(*json, JSON_INT, json_value, 2, "IP", "version");
    json_value.hex.number = iphdr->tos;
    json_value.hex.format = HEX_FORMAT_02;
    dict_update(*json, JSON_HEX, json_value, 2, "IP", "tos");
    json_value.integer = ntohs(iphdr->tot_len);
    dict_update(*json, JSON_INT, json_value, 2, "IP", "tot_len");
    json_value.hex.number = ntohs(iphdr->id);
    json_value.hex.format = HEX_FORMAT_04;
    dict_update(*json, JSON_HEX, json_value, 2, "IP", "id");
    json_value.hex.number = ntohs(iphdr->frag_off);
    json_value.hex.format = HEX_FORMAT_04;
    dict_update(*json, JSON_HEX, json_value, 2, "IP", "flags");
    json_value.integer = iphdr->ttl;
    dict_update(*json, JSON_INT, json_value, 2, "IP", "ttl");
    json_value.integer = iphdr->protocol;
    dict_update(*json, JSON_INT, json_value, 2, "IP", "protocol");
    json_value.hex.number = ntohs(iphdr->check);
    json_value.hex.format = HEX_FORMAT_04;
    dict_update(*json, JSON_HEX, json_value, 2, "IP", "checksum");
    json_value.string = ip_saddr;
    dict_update(*json, JSON_STR, json_value, 2, "IP", "src_addr");
    json_value.string = ip_daddr;
    dict_update(*json, JSON_STR, json_value, 2, "IP", "dest_addr");

    //Parse IP options
    if (iphdr->ihl > 5) { //If Options/Padding present (IP Header longer than 5*4 = 20Byte)
        bool eol = false; //EOL reached ?
        //calculate begin / end of options
        const unsigned char* beginofoptions_addr = (unsigned char*) packet + IP_OR_TCP_HEADER_MINLEN;
        const unsigned char* endofoptions_addr = packet + iphdr->ihl*4;
        if(endofoptions_addr > (packet + recv_len)) {
            //Malformed Paket
            endofoptions_addr = (packet + recv_len); //Repair end of options address
            tainted = true; //mark as tainted, thus do not parse, just dump hexstring
        }
        //set pointer to beginning of options
        unsigned char* opt_ptr = (unsigned char*) beginofoptions_addr;
        while(!tainted && !eol && opt_ptr < (packet + iphdr->ihl*4)) {
            switch(*opt_ptr) {
            case MY_IPOPT_EOOL: //EOL is only one byte, so this is hopefully going to be easy.
                json_value.string = "";
                dict_update(*json, JSON_STR, json_value, 3, "IP", "ip_options", "eol");
                opt_ptr++;
                eol = true;
                break;
            case MY_IPOPT_NOP: //NOP is only one byte, so this is going to be easy, too
                json_value.string = "";
                dict_update(*json, JSON_STR, json_value, 3, "IP", "ip_options", "nop");
                opt_ptr++;
                break;
            case MY_IPOPT_SEC:
                tainted =  parse_ipopt(MY_IPOPT_SEC, "sec", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_LSR:
                tainted =  parse_ipopt(MY_IPOPT_LSR, "lsr", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_TS:
                tainted =  parse_ipopt(MY_IPOPT_TS, "ts", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_ESEC:
                tainted =  parse_ipopt(MY_IPOPT_ESEC, "esec", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_CIPSO:
                tainted =  parse_ipopt(MY_IPOPT_CIPSO, "cipso", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_RR:
                tainted =  parse_ipopt(MY_IPOPT_RR, "rr", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_SID:
                tainted =  parse_ipopt(MY_IPOPT_SID, "sid", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_SSR:
                tainted =  parse_ipopt(MY_IPOPT_SSR, "ssr", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_ZSU:
                tainted =  parse_ipopt(MY_IPOPT_ZSU, "zsu", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_MTUP:
                tainted =  parse_ipopt(MY_IPOPT_MTUP, "mtup", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_MTUR:
                tainted =  parse_ipopt(MY_IPOPT_MTUR, "mtur", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_FINN:
                tainted =  parse_ipopt(MY_IPOPT_FINN, "finn", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_VISA:
                tainted =  parse_ipopt(MY_IPOPT_VISA, "visa", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_ENCODE:
                tainted =  parse_ipopt(MY_IPOPT_ENCODE, "encode", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_IMITD:
                tainted =  parse_ipopt(MY_IPOPT_IMITD, "IMITD", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_EIP:
                tainted =  parse_ipopt(MY_IPOPT_EIP, "eip", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_TR:
                tainted =  parse_ipopt(MY_IPOPT_TR, "tr", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_ADDEXT:
                tainted =  parse_ipopt(MY_IPOPT_ADDEXT, "addext", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_RTRALT:
                tainted =  parse_ipopt(MY_IPOPT_RTRALT, "rtralt", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_SDB:
                tainted =  parse_ipopt(MY_IPOPT_SDB, "sdb", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_UN:
                tainted =  parse_ipopt(MY_IPOPT_UN, "un", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_DPS:
                tainted =  parse_ipopt(MY_IPOPT_DPS, "dps", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_UMP:
                tainted =  parse_ipopt(MY_IPOPT_UMP, "ump", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_QS:
                tainted =  parse_ipopt(MY_IPOPT_QS, "qs", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_IPOPT_EXP:
                tainted =  parse_ipopt(MY_IPOPT_EXP, "exp", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            default:
                tainted = true; //Somthing is wrong or not implemented, so this will break the while-loop.
                break;
            } //End of switch statement
        } //End of loop

        //output tainted status, hex output (even if not tainted, cause padding might be usefull too) and close json
        char* hex_string = print_hex_string(opt_ptr, endofoptions_addr-opt_ptr);
        json_value.boolean = tainted;
        dict_update(*json, JSON_BOOL, json_value, 3, "IP", "ip_options", "tained");
        json_value.string = hex_string;
        dict_update(*json, JSON_STR, json_value, 3, "IP", "ip_options", "padding_hex");
        free(hex_string);
    } //End of if
    //free
    free(ip_saddr);
    free(ip_daddr);
    return tainted;
}

//returns amount of data bytes in buffer, regarding rec_len, NOT UDP length field, to prevent errors.
int analyze_udp_header(const unsigned char* packet, int recv_len, struct dict** json)
{
    struct iphdr *iphdr = (struct iphdr *)(packet);

    int data_len = recv_len - (iphdr->ihl*4 + UDP_HEADER_LEN);
    if(data_len <= 0) return -1; //Malformed Paket
    unsigned char* data = (unsigned char*) packet + recv_len - data_len;
    char* payload_sha1_str = NULL;
    char* payload_hd_str = NULL;
    char* payload_str = NULL;
    unsigned char payload_sha1[SHA_DIGEST_LENGTH];

    struct udphdr *udphdr = (struct udphdr *) (packet + iphdr->ihl*4);

    
    if(json == NULL) {
        struct dict* dict_temp = json_dict(false);
        json = &dict_temp;
    }

    json_value.integer = ntohs(udphdr->source);
    dict_update(*json, JSON_INT, json_value, 2, "UDP", "src_port");
    json_value.integer = ntohs(udphdr->dest);
    dict_update(*json, JSON_INT, json_value, 2, "UDP", "dest_port");
    json_value.integer = ntohs(udphdr->len);
    dict_update(*json, JSON_INT, json_value, 2, "UDP", "len");
    json_value.integer = ntohs(udphdr->check);
    dict_update(*json, JSON_INT, json_value, 2, "UDP", "checksum");

    json_value.integer = data_len;
    dict_update(*json, JSON_INT, json_value, 2, "FLOW", "bytes_toserver");

    //Compute SHA1 of payload
    SHA1(data, data_len, payload_sha1);
    payload_sha1_str = print_hex_string(payload_sha1, SHA_DIGEST_LENGTH);
    //Make HexDump output out of binary payload
    payload_hd_str = hex_dump(data, data_len, true);  //must be freed
    payload_str = print_hex_string(data, data_len); //must be freed

    json_value.string = payload_hd_str;
    dict_update(*json, JSON_STR, json_value, 2, "FLOW", "payload_hd");
    json_value.string = payload_str;
    dict_update(*json, JSON_STR, json_value, 2, "FLOW", "payload_str");
    json_value.string = payload_sha1_str;
    dict_update(*json, JSON_STR, json_value, 2, "FLOW", "payload_sha1");

    free(payload_hd_str);
    free(payload_sha1_str);
    free(payload_str);

    return data_len; //return number of data bytes after header in buffer
}

//Helper function to parse TCP Options having a length. Returns tainted status, puts option data in hex string
bool parse_tcpopt_w_length(int opt_kind, int opt_len, const char* opt_name, \
                           unsigned char** opt_ptr_ptr, const unsigned char* beginofoptions_addr, const unsigned char* endofoptions_addr, struct dict** json)
{
    if( *(*opt_ptr_ptr+1) != opt_len || (*opt_ptr_ptr + opt_len) > endofoptions_addr) return true; //Check length, signal tainted in case of failure
    if(json == NULL) {
        struct dict* dict_temp = json_dict(false);
        json = &dict_temp;
    }

    //Option data to hex string
    char* hex_string = print_hex_string(*opt_ptr_ptr + 2, opt_len - 2);  //Extract option data as hex string. Has to be freed!
    json_value.string = hex_string;
    dict_update(*json, JSON_STR, json_value, 3, "TCP", "tcp_options", opt_name); //JSON Output
    free(hex_string);
    *opt_ptr_ptr += opt_len; //set pointer to next option
    return false; //Option not tainted.
}

int analyze_tcp_header(const unsigned char* packet, int recv_len, struct dict** json) //returns number of data bytes in this particular packet, regarding recv_len.
{
    struct iphdr *iphdr = (struct iphdr *) packet;
    if(recv_len - (iphdr->ihl*4 + IP_OR_TCP_HEADER_MINLEN) < 0) return -1; //Malformed Paket

    struct tcphdr *tcphdr = (struct tcphdr *) (packet + iphdr->ihl*4);

    //calculate eventually exisiting data bytes in SYN (yes, this would be akward)
    long int data_bytes = recv_len - (iphdr->ihl*4 + tcphdr->doff*4);

    if(json == NULL) {
        struct dict* dict_temp = json_dict(false);
        json = &dict_temp;
    }

    //Append header JSON
    json_value.integer = ntohs(tcphdr->source);
    dict_update(*json, JSON_INT, json_value, 2, "TCP", "src_port");
    json_value.integer = ntohs(tcphdr->dest);
    dict_update(*json, JSON_INT, json_value, 2, "TCP", "dest_port");
    json_value.integer = (unsigned int) ntohl(tcphdr->seq);
    dict_update(*json, JSON_INT, json_value, 2, "TCP", "seq");
    json_value.integer = (unsigned int) ntohl(tcphdr->ack_seq);
    dict_update(*json, JSON_INT, json_value, 2, "TCP", "ack_seq");
    json_value.integer = tcphdr->doff*4;
    dict_update(*json, JSON_INT, json_value, 2, "TCP", "hdr_len");
    json_value.integer = tcphdr->res1 & 0b1111;
    dict_update(*json, JSON_INT, json_value, 2, "TCP", "res1");
    json_value.boolean = tcphdr->res2 & 0b01;
    dict_update(*json, JSON_BOOL, json_value, 2, "TCP", "ecn");
    json_value.boolean = tcphdr->res2 & 0b10;
    dict_update(*json, JSON_BOOL, json_value, 2, "TCP", "cwr");
    json_value.boolean = tcphdr->urg;
    dict_update(*json, JSON_BOOL, json_value, 2, "TCP", "urg");
    json_value.boolean = tcphdr->ack;
    dict_update(*json, JSON_BOOL, json_value, 2, "TCP", "ack");
    json_value.boolean = tcphdr->psh;
    dict_update(*json, JSON_BOOL, json_value, 2, "TCP", "psh");
    json_value.boolean = tcphdr->rst;
    dict_update(*json, JSON_BOOL, json_value, 2, "TCP", "rst");
    json_value.boolean = tcphdr->syn;
    dict_update(*json, JSON_BOOL, json_value, 2, "TCP", "syn");
    json_value.boolean = tcphdr->fin;
    dict_update(*json, JSON_BOOL, json_value, 2, "TCP", "fin");
    json_value.hex.number = tcphdr->res1 << 11 | tcphdr->res2 << 7 | tcphdr->urg << 5 | tcphdr->ack << 4 | tcphdr->psh << 3 | tcphdr->rst << 2 | tcphdr->syn << 1 | tcphdr->fin;
    json_value.hex.format = HEX_FORMAT_STD;
    dict_update(*json, JSON_HEX, json_value, 2, "TCP", "tcp_flags");
    json_value.integer = ntohs(tcphdr->window);
    dict_update(*json, JSON_INT, json_value, 2, "TCP", "window");
    json_value.hex.number = ntohs(tcphdr->check);
    json_value.hex.format = HEX_FORMAT_02;
    dict_update(*json, JSON_HEX, json_value, 2, "TCP", "checksum");
    json_value.hex.number = ntohs(tcphdr->urg_ptr);
    json_value.hex.format = HEX_FORMAT_02;
    dict_update(*json, JSON_HEX, json_value, 2, "TCP", "urg_ptr");


    //Parse TCP options
    if (tcphdr->doff > 5) { //If Options/Padding present (TCP Header longer than 5*4 = 20Byte)
        bool eol = false; //EOL reached ?
        bool tainted = false; //Is somethin unparsable inside the packet / options?
        //calculate begin / end of options
        const unsigned char* beginofoptions_addr = (unsigned char*) packet + iphdr->ihl*4 + IP_OR_TCP_HEADER_MINLEN;
        const unsigned char* endofoptions_addr = packet + iphdr->ihl*4 + tcphdr->doff*4;
        //Malformed Paket? : End of header (tcpheader->doff) may be tainted.
        if(endofoptions_addr > (packet + recv_len)) {
            endofoptions_addr = (packet + recv_len); //Repair end of options address
            tainted = true; //mark as tainted, thus do not parse, just dump hexstring
        }
        //set pointer to beginning of options
        unsigned char* opt_ptr = (unsigned char*) beginofoptions_addr;
        while(!tainted && !eol && opt_ptr < (packet + iphdr->ihl*4 + tcphdr->doff*4)) {
            switch(*opt_ptr) {
            case MY_TCPOPT_NOP: //NOP is only one byte, so this is hopefully going to be easy.
                json_value.string = "";
                dict_update(*json, JSON_STR, json_value, 3, "TCP", "tcp_options", "nop");
                opt_ptr++;
                break;
            case MY_TCPOPT_EOL: //EOL is only one byte, so this is going to be easy, too
                json_value.string = "";
                dict_update(*json, JSON_STR, json_value, 3, "TCP", "tcp_options", "eol");
                opt_ptr++;
                eol = true;
                break;
            case MY_TCPOPT_MSS:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_MSS, MY_TCPOLEN_MSS, "mss",&opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_WINDOW:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_WINDOW, MY_TCPOLEN_WINDOW, "window", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_SACK_PERM:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_SACK_PERM, MY_TCPOLEN_SACK_PERM, "sack_perm", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_ECHO:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_ECHO, MY_TCPOLEN_ECHO, "echo", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_ECHOREPLY:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_ECHOREPLY, MY_TCPOLEN_ECHOREPLY, "echo_reply", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_TIMESTAMP:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_TIMESTAMP, MY_TCPOLEN_TIMESTAMP, "timestamp", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_CC:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_CC, MY_TCPOLEN_CC, "cc", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_CCNEW:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_CCNEW, MY_TCPOLEN_CCNEW, "ccnew", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_CCECHO:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_CCECHO, MY_TCPOLEN_CCECHO, "ccecho", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_MD5:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_MD5, MY_TCPOLEN_MD5, "md5", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_SCPS:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_SCPS, MY_TCPOLEN_SCPS, "scps", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_SNACK:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_SNACK, MY_TCPOLEN_SNACK, "snack", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_RECBOUND:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_RECBOUND, MY_TCPOLEN_RECBOUND, "recbound", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_CORREXP:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_CORREXP, MY_TCPOLEN_CORREXP, "correxp", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_QS:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_QS, MY_TCPOLEN_QS, "qs", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            case MY_TCPOPT_USER_TO:
                tainted = parse_tcpopt_w_length(MY_TCPOPT_USER_TO, MY_TCPOLEN_USER_TO, "user_TO", &opt_ptr, beginofoptions_addr, endofoptions_addr, json);
                break;
            default:
                tainted = true; //Somthing is wrong or not implemented, so this will break the while-loop.
                break;
            } //End of switch statement
        } //End of loop

        //output tainted status, hex output (even if not tainted, cause padding might be usefull too) and close json
        char* hex_string = print_hex_string(opt_ptr, endofoptions_addr-opt_ptr);
        json_value.boolean = tainted;
        dict_update(*json, JSON_BOOL, json_value, 3, "TCP", "tcp_options", "tained");
        json_value.string = hex_string;
        dict_update(*json, JSON_STR, json_value, 3, "TCP", "tcp_options", "padding_hex");
        free(hex_string);
    } //End of "tcp options present"
    
    return data_bytes; //return number of data bytes at end of packet
}

