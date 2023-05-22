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
 * UDP port monitor.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2023
*/

#include "udp_ip_port_mon.parser.h"
#include "udp_ip_port_mon.helper.h"

//Helper function to parse IP Options. Returns tainted status, puts option data in hex string.
bool parse_ipopt(int opt_cpclno, const char* opt_name, \
                 unsigned char** opt_ptr_ptr, const unsigned char* beginofoptions_addr, const unsigned char* endofoptions_addr)
{
    int opt_len = *(*opt_ptr_ptr+1);
    if((*opt_ptr_ptr + opt_len) > endofoptions_addr) return true; //Check length, signal tainted in case of failure
    //Option data to hex string
    char* hex_string = print_hex_string(*opt_ptr_ptr + 2, opt_len - 2);  //Extract option data as hex string. Has to be freed!
    dict_update(json_dict(false), JSON_STR, json_value, 3, "IP", "ip_options", opt_name); //JSON Output
    free(hex_string);
    *opt_ptr_ptr += opt_len; //set pointer to next option
    return false; //Option not tainted.
}

int analyze_ip_header(const unsigned char* packet, int recv_len)
{
    if(recv_len - (IP_OR_TCP_HEADER_MINLEN) <= 0) return -1; //Malformed Paket

    struct iphdr *iphdr = (struct iphdr *)(packet);
    char* ip_saddr = inttoa(iphdr->saddr); //Must be freed!
    char* ip_daddr = inttoa(iphdr->daddr); //Must be freed!

    //printf("\n\nlength: %d\n version:%x\n TOS: %x\n tot_len: %d\nid: 0x%x\n flags: 0x%04x\n ttl: %d\n protocol: %d\n check: 0x%04x\n src_addr: %s dst_addr: %s\n\n",
    json_value.integer = iphdr->ihl*4;
    dict_update(json_dict(false), JSON_INT, json_value, 2, "IP", "hdr_len");
    json_value.integer = iphdr->version;
    dict_update(json_dict(false), JSON_INT, json_value, 2, "IP", "version");
    json_value.hex.number = iphdr->tos;
    json_value.hex.format = HEX_FORMAT_02;
    dict_update(json_dict(false), JSON_HEX, json_value, 2, "IP", "tos");
    json_value.integer = ntohs(iphdr->tot_len);
    dict_update(json_dict(false), JSON_INT, json_value, 2, "IP", "tot_len");
    json_value.hex.number = ntohs(iphdr->id);
    json_value.hex.format = HEX_FORMAT_04;
    dict_update(json_dict(false), JSON_HEX, json_value, 2, "IP", "id");
    json_value.hex.number = ntohs(iphdr->frag_off);
    json_value.hex.format = HEX_FORMAT_04;
    dict_update(json_dict(false), JSON_HEX, json_value, 2, "IP", "flags");
    json_value.integer = iphdr->ttl;
    dict_update(json_dict(false), JSON_INT, json_value, 2, "IP", "ttl");
    json_value.integer = iphdr->protocol;
    dict_update(json_dict(false), JSON_INT, json_value, 2, "IP", "protocol");
    json_value.hex.number = ntohs(iphdr->check);
    json_value.hex.format = HEX_FORMAT_04;
    dict_update(json_dict(false), JSON_HEX, json_value, 2, "IP", "checksum");
    json_value.string = ip_saddr;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "IP", "src_addr");
    json_value.string = ip_daddr;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "IP", "dest_addr");

    //Parse IP options
    if (iphdr->ihl > 5) { //If Options/Padding present (IP Header longer than 5*4 = 20Byte)
        bool eol = false; //EOL reached ?
        bool tainted = false; //Is somethin unparsable inside the packet / options?
        //calculate begin / end of options
        const unsigned char* beginofoptions_addr = (unsigned char*) packet + ETHERNET_HEADER_LEN + IP_OR_TCP_HEADER_MINLEN;
        const unsigned char* endofoptions_addr = packet + ETHERNET_HEADER_LEN + iphdr->ihl*4;
        if(endofoptions_addr > (packet + recv_len)) {
            //Malformed Paket
            endofoptions_addr = (packet + recv_len); //Repair end of options address
            tainted = true; //mark as tainted, thus do not parse, just dump hexstring
        }
        //set pointer to beginning of options
        unsigned char* opt_ptr = (unsigned char*) beginofoptions_addr;
        while(!tainted && !eol && opt_ptr < (packet + ETHERNET_HEADER_LEN + iphdr->ihl*4)) {
            switch(*opt_ptr) {
                case MY_IPOPT_EOOL: //EOL is only one byte, so this is hopefully going to be easy.
                    json_value.string = "";
                    dict_update(json_dict(false), JSON_STR, json_value, 3, "IP", "ip_options", "eol");
                    opt_ptr++;
                    eol = true;
                    break;
                case MY_IPOPT_NOP: //NOP is only one byte, so this is going to be easy, too
                    json_value.string = "";
                    dict_update(json_dict(false), JSON_STR, json_value, 3, "IP", "ip_options", "nop");
                    opt_ptr++;
                    break;
                case MY_IPOPT_SEC:
                    tainted =  parse_ipopt(MY_IPOPT_SEC, "sec", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_LSR:
                    tainted =  parse_ipopt(MY_IPOPT_LSR, "lsr", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_TS:
                    tainted =  parse_ipopt(MY_IPOPT_TS, "ts", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_ESEC:
                    tainted =  parse_ipopt(MY_IPOPT_ESEC, "esec", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_CIPSO:
                    tainted =  parse_ipopt(MY_IPOPT_CIPSO, "cipso", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_RR:
                    tainted =  parse_ipopt(MY_IPOPT_RR, "rr", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_SID:
                    tainted =  parse_ipopt(MY_IPOPT_SID, "sid", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_SSR:
                    tainted =  parse_ipopt(MY_IPOPT_SSR, "ssr", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_ZSU:
                    tainted =  parse_ipopt(MY_IPOPT_ZSU, "zsu", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_MTUP:
                    tainted =  parse_ipopt(MY_IPOPT_MTUP, "mtup", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_MTUR:
                    tainted =  parse_ipopt(MY_IPOPT_MTUR, "mtur", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_FINN:
                    tainted =  parse_ipopt(MY_IPOPT_FINN, "finn", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_VISA:
                    tainted =  parse_ipopt(MY_IPOPT_VISA, "visa", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_ENCODE:
                    tainted =  parse_ipopt(MY_IPOPT_ENCODE, "encode", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_IMITD:
                    tainted =  parse_ipopt(MY_IPOPT_IMITD, "IMITD", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_EIP:
                    tainted =  parse_ipopt(MY_IPOPT_EIP, "eip", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_TR:
                    tainted =  parse_ipopt(MY_IPOPT_TR, "tr", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_ADDEXT:
                    tainted =  parse_ipopt(MY_IPOPT_ADDEXT, "addext", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_RTRALT:
                    tainted =  parse_ipopt(MY_IPOPT_RTRALT, "rtralt", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_SDB:
                    tainted =  parse_ipopt(MY_IPOPT_SDB, "sdb", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_UN:
                    tainted =  parse_ipopt(MY_IPOPT_UN, "un", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_DPS:
                    tainted =  parse_ipopt(MY_IPOPT_DPS, "dps", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_UMP:
                    tainted =  parse_ipopt(MY_IPOPT_UMP, "ump", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_QS:
                    tainted =  parse_ipopt(MY_IPOPT_QS, "qs", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                case MY_IPOPT_EXP:
                    tainted =  parse_ipopt(MY_IPOPT_EXP, "exp", &opt_ptr, beginofoptions_addr, endofoptions_addr);
                    break;
                default:
                    tainted = true; //Somthing is wrong or not implemented, so this will break the while-loop.
                    break;
            } //End of switch statement
        } //End of loop

        //output tainted status, hex output (even if not tainted, cause padding might be usefull too) and close json
        char* hex_string = print_hex_string(opt_ptr, endofoptions_addr-opt_ptr);
        json_value.boolean = tainted;
        dict_update(json_dict(false), JSON_BOOL, json_value, 3, "IP", "ip_options", "tained");
        json_value.string = hex_string;
        dict_update(json_dict(false), JSON_STR, json_value, 3, "IP", "ip_options", "padding_hex");
        free(hex_string);
    } //End of if
    //free
    free(ip_saddr);
    free(ip_daddr);
    return 0;
}

int analyze_udp_header(const unsigned char* packet, int recv_len)
{
    struct iphdr *iphdr = (struct iphdr *)(packet);

    if(recv_len - (iphdr->ihl*4 + UDP_HEADER_LEN) <= 0) return -1; //Malformed Paket

    struct udphdr *udphdr = (struct udphdr *) (packet + iphdr->ihl*4);

    json_value.integer = ntohs(udphdr->source);
    dict_update(json_dict(false), JSON_INT, json_value, 2, "UDP", "src_port");
    json_value.integer = ntohs(udphdr->dest);
    dict_update(json_dict(false), JSON_INT, json_value, 2, "UDP", "dest_port");
    json_value.integer = ntohs(udphdr->len);
    dict_update(json_dict(false), JSON_INT, json_value, 2, "UDP", "len");
    json_value.integer = ntohs(udphdr->check);
    dict_update(json_dict(false), JSON_INT, json_value, 2, "UDP", "checksum");
    return 0;
}

