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
 * TCP monitor library headerfile.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2023
*/


#ifndef TCP_IP_PORT_MON_HELPER_H
#define TCP_IP_PORT_MON_HELPER_H

#include "tcp_ip_port_mon.common.h"
#include "madcat.helper.h"

//Capture only TCP-SYN's, for some sytems (Linux Kernel >= 5?) own host IPv4 or IPv6 has to be appended,
//thus the final filter string looks like "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0 & dst host 1.2.3.4"
#define PCAP_FILTER "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0 and dst host "
//Currently, TCPDump (and Wireshark) do not support embedded protocol BPF filters under IPv6
//Because IPv6 extension headers may be present, it is currently unsafe to detect TCP-Flags by using fixed offsets.
//Thus the final filter string looks like "ip6 and dst host 2021:1234:5678:9abc:def0::1"
//A filter string conataining "ip6 and tcp" does not wort, because the first extension header is evaluated by "tcp".
//Thus, if there are extensions headers present, and so the first one is not the Upper Layer Header containing TCP-Data, it will be discarded!
#define PCAP_FILTER_v6 "ip6 and dst host "
#define HEADER_FIFO "/tmp/header_json.tpm"
#define CONNECT_FIFO "/tmp/connect_json.tpm"
#define HEADER_FIFO_v6 "/tmp/header_json_v6.tpm"
#define CONNECT_FIFO_v6 "/tmp/connect_json_v6.tpm"

#define PCN_STRLEN 6 //listen- and backport string length in proxy_conf_tcp_node_t
#define STR_BUFFER_SIZE 65536 //Generic string buffer size

struct proxy_conf_tcp_node_t { //linked list element to hold proxy configuration items
    struct proxy_conf_tcp_node_t* next;

    uint16_t listenport;
    char     listenport_str[PCN_STRLEN];
    uint16_t backendport;
    char     backendport_str[PCN_STRLEN];
    char*    backendaddr;

    pid_t pid; //Process ID of corresponding proxy.
};

struct proxy_conf_tcp_t { //proxy configuration
    struct proxy_conf_tcp_node_t* portlist; //head pointer to linked list with proxy configuration items
    bool portmap[65536]; //map of ports used to proxy network traffic
    int num_elements;
};
extern struct proxy_conf_tcp_t *pc; //globally defined to be easly accesible by functions

struct json_data_t { //json_data structure...
    struct json_data_node_t *list;
};
extern struct json_data_t *jd; //..defined globally as "jd" for easy access in all functions

struct json_data_node_t { //json data list element
    struct json_data_node_t *next; //next element in list
    struct json_data_node_t *prev; //prev element in list
    uintptr_t id; //id, usally originating from a pointer (void*) to e.g. an epoll handler structure

    //all variables of json output, exepct constant string values e.g. "proxy_flow" or "closed"
    char* src_ip;
    int   src_port;
    char* dest_ip;
    char* dest_port;
    char* timestamp;
    char* unixtime;
    long double timeasdouble;
    long double duration;
    long double min_rtt;
    long double last_recv;
    bool firstpacket;
    char* start;
    char* end;
    long long unsigned int bytes_toserver;
    long long unsigned int bytes_toclient;
    char* proxy_ip;
    int   proxy_port;
    char* backend_ip;
    char* backend_port;

};


//Helper Functions:
/**
 * \brief Print TCP help message
 *
 *     Prints usage of tcp_ip_mon
 *
 * \param progname  Binary name
 * \return void
 *
 */
void print_help_tcp(char* progname); //print TCP help message

/**
 * \brief Initializes PCAP sniffing
 *
 *     Initializes PCAP sniffing of TCP-SYNs.
 *     Returns 0 on succes, otherwise returns:
 *     -1: pcap_lookupnet failed
 *     -2: pcap_open_live failed
 *     -3: pcap_compile failed
 *     -4: pcap_setfilter failed
 *
 *     See documentation of libpcap for further infomation.
 *
 * \param dev Name of the device to start PCAP-Sniffing on
 * \param dev_addr IP Address of this interface
 * \param handle PCAP Handle to be initialized
 * \param pcap_filter_str Filter-Rules for sniffing
 * \return 0 und success, <0 if an error occured
 *
 */
int init_pcap(char* dev, char* dev_addr, pcap_t **handle, char* pcap_filter_str);

/**
 * \brief Drops root priviliges
 *
 *     Trys to drop root privilges to a specific user and
 *     prints result to STDERR, if silent is set to false.
 *
 * \param user User to drop the priviliges to
 * \param entity String for output to identify e.g. the Thread which droped priviliges
 * \param silent Turns silent mode on if set to true, thus dropping priviliges silently
 * \return void
 *
 */
void drop_root_privs(struct user_t user, const char* entity, bool silent);
//Signal Handler:

/**
 * \brief Generic signal handler
 *
 *     Signal handler helper function with common frees, etc. for parents and childs
 *
 * \return void
 *
 */

void sig_handler_common();

/**
 * \brief Signal Handler for parent watchdog
 *
 *     Signal Handler for parent watchdog
 *
 * \return void
 *
 */
void sig_handler_parent(int signo);

/**
  * \brief Signal Handler for listner Thread
  *
  *     Signal Handler for Listner Parent to prevent childs becoming Zombies
  *
  * \return void
  *
  */
void sig_handler_sigchld(int signo); //Signal Handler for Listner Parent to prevent childs becoming Zombies

/**
  * \brief Signal Handler for PCAP childs
  *
  *     Signal Handler for PCAP (Sniffer) childs
  *
  * \return void
  *
  */
void sig_handler_pcapchild(int signo);

/**
  * \brief Signal Handler for listner thread childs
  *
  *     Signal Handler for listner thread childs
  *
  * \return void
  *
  */
void sig_handler_listnerchild(int signo);

/**
  * \brief Signal Handler for proxy childs
  *
  *     Signal Handler for proxy childs
  *
  * \return void
  *
  */
void sig_handler_proxychild(int signo);

/**
  * \brief Debug Signal Handler
  *
  *     Debug Signal Handler for SIGUSR1 to initiate gracefull shutdown, e.g. by CHECK-Macro
  *
  * \return void
  *
  */
void sig_handler_shutdown(int signo);

//Helper functions for proxy configuration:

/**
  * \brief Reads proxy configuration from parsed LUA-File
  *
  *     Reads proxy configuration for configuration item name
  *     from parsed LUA-File (by luaL_dofile(...) )and
  *     saves config items in linked list pc
  *     Returns number of read elements.
  *
  * \param L Lua State structure from luaL_dofile(...)
  * \param name String containing the name of the configuration Item
  * \param pc Linked List containing proxy configuration
  * \return void
  *
  */
int get_config_table(lua_State* L, char* name, struct proxy_conf_tcp_t* pc); //read proxy configuration from parsed LUA-File by luaL_dofile(...). Returns number of read elements.

/**
  * \brief Initializes linked list conataining proxy configuration
  *
  *     Initializes linked list conataining proxy configuration
  *
  * \return Pointer to linked list conaining proxy configuration
  *
  */
struct proxy_conf_tcp_t* pctcp_init(); //initialize proxy configuration

/**
  * \brief Pushes new proxy config Item to linked List
  *
  *     Pushes new proxy config Item to linked List pc
  *
  * \param pc Linked List containing proxy configuration
  * \param listenport Port to listen on
  * \param backendaddr IP Address of backend
  * \param backendport Port backend is listening on
  * \return void
  *
  */
void pctcp_push(struct proxy_conf_tcp_t* pc, int listenport, char* backendaddr, int backendport); //push new proxy configuration item to linked list

/**
  * \brief Gets proxy config from linked List
  *
  *     Gets proxy configuration for a specific port
  *
  * \param pc Linked List containing proxy configuration
  * \param listenport Port to listen on
  * \return Linked list element, containing proxy configuration
  *
  */
struct proxy_conf_tcp_node_t* pctcp_get_lport(struct proxy_conf_tcp_t* pc, int listenport); //get proxy configuration for listenport

/**
  * \brief Gets proxy config from linked List
  *
  *     Gets proxy configuration for a specific proxy-child PID
  *
  * \param pc Linked List containing proxy configuration
  * \param pid Proxy-Child PID
  * \return Linked list element, containing proxy configuration
  *
  */
struct proxy_conf_tcp_node_t* pctcp_get_pid(struct proxy_conf_tcp_t* pc, pid_t pid); //get proxy configuration for proxy with Process ID "pid"

/**
  * \brief Frees an element of the proxy configuration list
  *
  *     Frees an element of the proxy configuration list
  *
  * \param pctcp_node Linked list element to be freed
  * \return void
  *
  */
void pctcp_free_list(struct proxy_conf_tcp_node_t* pctcp_node); //free list with proxy configuration(s)

/**
  * \brief Prints current proxy configuration
  *
  *     Prints current proxy configuration, stored in a linked list
  *
  * \param pc Linked list conatining proxy configuration items
  * \return void
  *
  */
void pctcp_print(struct proxy_conf_tcp_t* pc); //print proxy configuration

//Helper functions for json data structure and double linked list (the List does not need to be thread-safe, because every process has it's own copy):

/**
  * \brief Initializes JSON Data linked list
  *
  *     Initializes JSON Data linked list,
  *     holding results
  *
  * \return Pointer to the new JSON Data linked list
  *
  */
struct json_data_t* jd_init();

/**
  * \brief Pushes JSON Data element to a linked list
  *
  *     Pushes JSON Data element to a linked list
  *     with ID id
  *
  * \param jd linked list
  * \param id ID for the pushed element
  * \return void
  *
  */
void jd_push(struct json_data_t* jd, long long unsigned int id);

/**
  * \brief Gets a JSON Data linked list element
  *
  *     Fetches a JSON Data linked list element,
  *     identified by ID and returns it, if found.
  *
  * \param jd Linked list
  * \param id ID to search for
  * \return Linked list element, 0 if not found
  *
  */
struct json_data_node_t* jd_get(struct json_data_t* jd, uintptr_t id);

/**
  * \brief Removes a JSON Data linked list element
  *
  *     Removes a JSON Data linked list element,
  *     identified by ID and returns true if found, false otherwise
  *
  * \param jd Linked list
  * \param id ID of the element to remove from list
  * \return True if element could be deleted, False if not found
  *
  */
bool jd_del(struct json_data_t* jd, uintptr_t id);

/**
  * \brief Removes all JSON Data elements from a linked list
  *
  *     Deletes recursively all JSON Data linked list elements after the list element specified,
  *     including the one specified.
  *
  * \param jd_node Linked list elment
  * \param id ID of the element to remove from list
  * \return void
  *
  */
void jd_free_list(struct json_data_node_t* jd_node);

/**
  * \brief Prints all JSON Data elements in a linked list
  *
  *     Prints all JSON Data elements in a linked list
  *     to STDERR
  *
  * \param jd Linked list
  * \return void
  *
  */
void jd_print_list(struct json_data_t* jd);

/********* Conntrack *********/
#ifdef CT_ENABLED
/*
* Usage of conntrack is experimental,
* thus using conntrack in heavy load scenarios may have a severe perfomance impact
* and may lead to errors!
* Using of conntrack lookup in TCP Postprocessing instead is adviced!
*/
//Conntrack definitions:

struct nfct_handle *ct_handle;
struct nf_conntrack *ct_filter;
in_port_t ct_org_srcport;
in_port_t ac_srcport;
int ct_lookup_state;
#define CT_LOOKUP_TRUE  0
#define CT_LOOKUP_FALSE 1
#define CT_LOOKUP_FAIL  2

//Conntrack functions:
int conntrack_init();
int conntrack_query(in_addr_t ipv4_dst, in_port_t dest_port, in_addr_t ipv4_src, in_port_t src_port);
void conntrack_close();
int conntrack_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data);
#endif

#endif
