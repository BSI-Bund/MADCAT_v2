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
 * BSI 2018-2021
*/

#ifndef UDP_IP_PORT_MON_H
#define UDP_IP_PORT_MON_H

#include "madcat.common.h"

#define VERSION "MADCAT - Mass Attack Detecion Connection Acceptance Tool\nUDP-IP Port Monitor v2.1.4\nBSI 2018-2021\n"


#define UDP_HEADER_LEN 8
#define IP_OR_TCP_HEADER_MINLEN 20 // Minimum Length of an IP-Header or a TCP-Header is 20 Bytes
#define DEFAULT_BUFSIZE 9000 //Ethernet jumbo frame limit
#define ETHERNET_HEADER_LEN 14 //Length of an Ethernet Header
#define PCN_STRLEN 6 //listen- and backend-port string length in proxy_conf_udp_node_t

/* IP options as definde in Wireshark*/
//Original names cause redifinition warnings, so prefix "MY" has been added
#define MY_IPOPT_COPY              0x80

#define MY_IPOPT_CONTROL           0x00
#define MY_IPOPT_RESERVED1         0x20
#define MY_IPOPT_MEASUREMENT       0x40
#define MY_IPOPT_RESERVED2         0x60

/* REF: http://www.iana.org/assignments/ip-parameters */
#define MY_IPOPT_EOOL      (0 |MY_IPOPT_CONTROL)
#define MY_IPOPT_NOP       (1 |MY_IPOPT_CONTROL)
#define MY_IPOPT_SEC       (2 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 791/1108 */
#define MY_IPOPT_LSR       (3 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)
#define MY_IPOPT_TS        (4 |MY_IPOPT_MEASUREMENT)
#define MY_IPOPT_ESEC      (5 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 1108 */
#define MY_IPOPT_CIPSO     (6 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* draft-ietf-cipso-ipsecurity-01 */
#define MY_IPOPT_RR        (7 |MY_IPOPT_CONTROL)
#define MY_IPOPT_SID       (8 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)
#define MY_IPOPT_SSR       (9 |MY_IPOPT_COPY|MY_IPOPT_CONTROL)
#define MY_IPOPT_ZSU       (10|MY_IPOPT_CONTROL)                  /* Zsu */
#define MY_IPOPT_MTUP      (11|MY_IPOPT_CONTROL)                  /* RFC 1063 */
#define MY_IPOPT_MTUR      (12|MY_IPOPT_CONTROL)                  /* RFC 1063 */
#define MY_IPOPT_FINN      (13|MY_IPOPT_COPY|MY_IPOPT_MEASUREMENT)   /* Finn */
#define MY_IPOPT_VISA      (14|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Estrin */
#define MY_IPOPT_ENCODE    (15|MY_IPOPT_CONTROL)                  /* VerSteeg */
#define MY_IPOPT_IMITD     (16|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Lee */
#define MY_IPOPT_EIP       (17|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 1385 */
#define MY_IPOPT_TR        (18|MY_IPOPT_MEASUREMENT)              /* RFC 1393 */
#define MY_IPOPT_ADDEXT    (19|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Ullmann IPv7 */
#define MY_IPOPT_RTRALT    (20|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 2113 */
#define MY_IPOPT_SDB       (21|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* RFC 1770 Graff */
#define MY_IPOPT_UN        (22|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Released 18-Oct-2005 */
#define MY_IPOPT_DPS       (23|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Malis */
#define MY_IPOPT_UMP       (24|MY_IPOPT_COPY|MY_IPOPT_CONTROL)       /* Farinacci */
#define MY_IPOPT_QS        (25|MY_IPOPT_CONTROL)                  /* RFC 4782 */
#define MY_IPOPT_EXP       (30|MY_IPOPT_CONTROL) /* RFC 4727 */

sem_t *conlistsem; //Semaphore for thread safe list operations on struct udpcon_data_t udpcon_data_t->list.
pthread_t cleanup_t_id; //Cleanup thread ID.

typedef struct my_uint128_t {
    uint64_t high; //64 high bits
    uint64_t low; //64 low bits
    char* str; //pointer to string representation, may be malloc outside this structure
    char __str[2*12+1]; //string representation, if not malloced outside structe, char* str points to this array.
    bool malloced; //Set to true if char* str points to a malloced string outside this strcuture, false if char __str[25] is used
    uint64_t masked_id; //GDPR conformant masked ID, derived from high ^ low ^ sessionkey, thus not 100% collision free. SAY GDPR ONE MORE TIME!!! ;-)
} udpcon_id_t;


struct ipv4udp_t {
    uint8_t  type;
    uint8_t  ihl;
    uint8_t  proto;
    uint32_t src_ip;
    char*    src_ip_str;
    uint32_t dest_ip;
    char*    dest_ip_str;
    uint16_t src_port;
    uint16_t dest_port;
    void*    data;
    int      data_len;
};

struct proxy_conf_udp_node_t { //linked list element to hold proxy configuration items
    struct proxy_conf_udp_node_t* next;

    uint16_t listenport;
    char     listenport_str[PCN_STRLEN];
    uint16_t backendport;
    char     backendport_str[PCN_STRLEN];
    char*    backendaddr;
};

struct proxy_conf_udp_t { //proxy configuration
    struct proxy_conf_udp_node_t* portlist; //head pointer to linked list with proxy configuration items
    bool portmap[65536]; //map of ports used to proxy network traffic
    int  num_elements;
    char proxy_ip[INET6_ADDRSTRLEN]; //IP used to communicate with backends
    int  proxy_timeout; //timout of UDP "Connections"
} *pc; //globally defined to be easly accesible inside rsp-proxy to check if root priviliges can be dropped (ports <1023)

struct udpcon_data_t {
    struct udpcon_data_node_t *list;
} *uc;

struct udpcon_data_node_t {
    struct udpcon_data_node_t *next;
    struct udpcon_data_node_t *prev;

    udpcon_id_t id_tobackend;
    udpcon_id_t id_fromclient;

    struct sockaddr_in* backend_socket ;
    int backend_socket_fd;
    struct sockaddr_in* client_socket;
    int client_socket_fd;
    struct sockaddr_in client_localport;

    long long int last_seen;
    long double min_rtt;
    bool proxied;

    char* src_ip;
    int   src_port;
    char* dest_ip;
    int   dest_port;
    char* timestamp;
    long long int unixtime;
    long double timeasdouble;
    char* start;
    char* end;
    long double duration;
    long long unsigned int bytes_toserver;
    long long unsigned int bytes_toclient;
    char* proxy_ip;
    int   proxy_port;
    char* backend_ip;
    int   backend_port;

    unsigned char* payload;
    long long unsigned int payload_len;
    unsigned char* first_dgram;
    long unsigned int first_dgram_len;

};

#endif