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
 * ICMP monitor parser headerfile.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2023
*/


#ifndef TCP_IP_PORT_MON_PARSER_H
#define TCP_IP_PORT_MON_PARSER_H

#include "tcp_ip_port_mon.h"

//IPv6 Extension Header definitions
#define IPV6_EXT_HOPBYHOP 0
#define IPV6_EXT_ROUTINGHDR 43
#define IPV6_EXT_DESTOPTHDR 60
#define IPV6_EXT_MOBILITY 135
#define IPV6_EXT_RES1 253
#define IPV6_EXT_RES2 254
#define IPV6_EXT_FRAGHDR 44
#define IPV6_EXT_SHIM6 140
#define IPV6_EXT_AUTHHDR 51
#define IPV6_EXT_HIPHDR 139
#define IPV6_EXT_ESPHDR 50
#define IPV6_EXT_NONEXTHDR 59
//Padding
#define IPV6_PAD1 0
#define IPV6_PADN 1
//IPv6 Upper Layer Headers
#define IPV6_ULH_IPV4 4
#define IPV6_ULH_IPV6 41
#define IPV6_ULH_TCP 6
#define IPV6_ULH_UDP 17
#define IPV6_ULH_ICMPV6 58

struct ipv6_ext_hdr_t {
    uint8_t nexthdr;
    uint8_t len_oct;
    unsigned char data[1];
};

struct ipv6_opt_t {
    uint8_t type;
    uint8_t len_oct;
    unsigned char value[1];
};

#define MAX_HEADERS_PROCESSED 64

/**
 * \brief Parse IP Options
 *
 *     Parses IP Options and returns false in case of an error.
 *
 * \param opt_cpclno Option Number as defined by IANA
 * \param opt_name Option Name
 * \param opt_ptr_ptr Pointer to options number in raw data
 * \param beginofoptions_addr Beginning Address of options
 * \param endofoptions_addr End Address of options
 *
 * \return true for success, fals in case of an error.
 *
 */
bool parse_ipopt(int opt_cpclno, \
                 const char* opt_name, \
                 unsigned char** opt_ptr_ptr, \
                 const unsigned char* beginofoptions_addr, \
                 const unsigned char* endofoptions_addr);


/**
  * \brief Parse and analyze IP Header
  *
  *     Parses and analyzes a IP Header
  *
  * \param packet Pointer to the raw packet data
  * \param caplen length of raw packet data
  *
  * \return <0 in case of an error, IPv4 ID field in case of success.
  *
  */
int analyze_ip_header(const unsigned char* packet, \
                      bpf_u_int32 caplen);

/**
  * \brief Parse and analyze IP Header
  *
  *     Parses and analyzes a IP Header
  *
  * \param packet Pointer to the raw packet data
  * \param caplen length of raw packet data
  *
  * \return <0 in case of an error, IPv6 Flow label in case of success.
  *
  */
long int analyze_ipv6_header(const unsigned char* packet, \
                      bpf_u_int32 caplen);

/**
  * \brief Parse TCP Options
  *
  *     Parses TCP Options and returns false in case of an error.
  *
  * \param opt_kind Option Number as defined by IANA/RFCs
  * \param opt_len Option length as defined by IANA/RFCs
  * \param opt_name Option Name
  * \param opt_ptr_ptr Pointer to options number in raw data
  * \param beginofoptions_addr Beginning Address of options
  * \param endofoptions_addr End Address of options
  *
  * \return true for success, fals in case of an error.
  *
  */
bool parse_tcpopt_w_length(int opt_kind, \
                           int opt_len, \
                           const char* opt_name, \
                           unsigned char** opt_ptr_ptr, \
                           const unsigned char* beginofoptions_addr, \
                           const unsigned char* endofoptions_addr);

/**
  * \brief Parse and analyze TCP Header
  *
  *     Parses and analyzes a TCP Header by calling analyze_tcp_header_w_flags
  *
  * \param packet Pointer to the raw packet data
  * \param caplen length of raw packet data
  *
  * \return Number of bytes in TCP Payload, <0 in case of an error.
  *
  */
int analyze_tcp_header(const unsigned char* packet, bpf_u_int32 caplen);

/**
  * \brief Parse and analyze TCP Header and returns Flags
  *
  *     Parses and analyzes a TCP Header and returns TCP-Flags in tcp_flags
  *
  * \param packet Pointer to the raw packet data
  * \param caplen length of raw packet data
  * \param tcp_flags Pointer to uint16_t to store TCP-Flags in.
  *
  * \return Number of bytes in TCP Payload, <0 in case of an error.
  *
  */
int analyze_tcp_header_w_flags(const unsigned char* packet, bpf_u_int32 caplen, uint16_t* tcp_flags);

#endif
