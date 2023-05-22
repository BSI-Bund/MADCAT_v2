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
 * UDP monitor library headerfile.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2023
*/


#ifndef UDP_IP_PORT_MON_HELPER_H
#define UDP_IP_PORT_MON_HELPER_H

#include "udp_ip_port_mon.h"
#include "madcat.helper.h"
#include "udp_ip_port_mon.icmp_mon.helper.h"

//Helper Functions:
/**
 * \brief Print UDP help message
 *
 *     Prints usage of udp_ip_mon
 *
 * \param progname  Binary name
 * \return void
 *
 */
void print_help_udp(char* progname); //print UDP help message

//Helper Functions:

/**
 * \brief Prints Results in JSON-Format from linked list to STDOUT
 *
 *     Reads
 *     Prints Results in JSON-Format to STDOUT, using libdict_c functions
 *     Takes a linked list element uc_node as argument.
 *
 * \param us_node  Linked list element, containing the results to be printed
 * \return void
 *
 */
void json_out(struct udpcon_data_node_t* uc_node);

/**
  * \brief Signal Handler
  *
  *     Generic Signal Handler for gracefull shutdown
  *
  * \param signo Signal Number
  * \return void
  *
  */
void sig_handler_udp(int signo);

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
int get_config_table(lua_State* L, char* name, struct proxy_conf_udp_t* pc);

/**
  * \brief Initializes linked list conataining proxy configuration
  *
  *     Initializes linked list conataining proxy configuration
  *
  * \return Pointer to linked list conaining proxy configuration
  *
  */
struct proxy_conf_udp_t* pcudp_init();

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
void pcudp_push(struct proxy_conf_udp_t* pc, int listenport, char* backendaddr, int backendport); //push new proxy configuration item to linked list

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
struct proxy_conf_udp_node_t* pcudp_get_lport(struct proxy_conf_udp_t* pc, int listenport); //get proxy configuration for listenport

/**
  * \brief Frees an element of the proxy configuration list
  *
  *     Frees an element of the proxy configuration list
  *
  * \param pcudp_node Linked list element to be freed
  * \return void
  *
  */
void pcudp_free_list(struct proxy_conf_udp_node_t* pcudp_node);

/**
  * \brief Prints current proxy configuration
  *
  *     Prints current proxy configuration, stored in a linked list
  *
  * \param pc Linked list conatining proxy configuration items
  * \return void
  *
  */
void pcudp_print(struct proxy_conf_udp_t* pc); //print proxy configuration

//udp connection structures and double linked list

/**
  * \brief Initializes double linked list for UDP connection tracking
  *
  *     Initializes double linked list for UDP connection tracking
  *
  * \return Double Linked list struct udpcon_data_t
  *
  */
struct udpcon_data_t* uc_init();

/**
  * \brief Frees an element of the UDP connection tracking list
  *
  *     Frees an element of the UDP connection tracking list
  *
  * \param uc_node Linked list element to be freed
  * \return void
  *
  */
void uc_free_list(struct udpcon_data_node_t* uc_node);

/**
  * \brief Pushes a new element to the UDP connection tracking list
  *
  *     Pushes a new element to the UDP connection tracking list with ID id
  *
  * \param uc Linked list containing UDP connection tracking information
  * \param id ID of the new connection
  * \param uc_node New linked list element
  *
  */
struct udpcon_data_node_t* uc_push(struct udpcon_data_t* uc, udpcon_id_t id);

/**
  * \brief Gets an element from the UDP connection tracking list
  *
  *     Gets an element from the UDP connection tracking list with ID id.
  *     Returns 0 if ID does not exists
  *
  * \param uc Linked list containing UDP connection tracking information
  * \param id ID of the connection to retrieve
  * \param uc_node Linked list element with specified ID or 0 if not found
  *
  */
struct udpcon_data_node_t* uc_get(struct udpcon_data_t* uc, udpcon_id_t id);

/**
  * \brief Deletes an element from the UDP connection tracking list
  *
  *     Deletes the element from the UDP connection tracking list with ID id.
  *     Returns False if ID does not exists, True on success
  *
  * \param uc Linked list containing UDP connection tracking information
  * \param id ID of the connection to remove
  * \param uc_node Returns False if ID does not exists, True on success
  *
  */
bool uc_del(struct udpcon_data_t* uc, udpcon_id_t id);

/**
  * \brief Removes all elements in the UDP connection tracking list older than timeout
  *
  *     Frees all elements in the specified UDP connection tracking list, using uc_del(...),
  *     if timout has been exceeded for this elements.
  *     Returns Number of deleted elements in this list.
  *
  * \param uc Linked list containing UDP connection tracking information
  * \param timeout If elements are older than timeout, they are going to be deleted
  * \param uc_node Returns Number of deleted elements in this list.
  *
  */
int uc_cleanup(struct udpcon_data_t* uc, long long int timeout);

/**
  * \brief Prints current UDP connection tracking list
  *
  *     Prints current UDP connection tracking list to STDERR
  *
  * \param uc Linked list conatining UDP connection tracking information
  * \return void
  *
  */
void uc_print_list(struct udpcon_data_t* uc);
////Long ID functions, slower but collision free IDs:



/**
  * \brief Generates an ID for a connection
  *
  *     Generates a (long) uint128_t-like ID for a connection, using IP and Port touples as Input.
  *     The deprecated short ID function, was faster but not collision free.
  *     Of course an id only containing the remote IP would do, have only 64bit and would be collision free,
  *     but would also be prone to programatical erros and not so suitable for logging- and debugging purposes.
  *     So I decided to use 128bit long IDs, which also may be a good preparation for development of future features (e.g. IPv6 functionality).
  *     Because uint128_t is not supported by every target architecture, the udpcon_id_t has to be defined for this purpose.
  *
  * \param src_ip Souce IP of the connection
  * \param src_port Source Port
  * \param dest_ip Destination IP of the connection
  * \param dest_port Destination Port
  * \param output udpcon_id_t, to save the long ID
  * \return pointer to udpcon_id_t, containing the long ID
  *
  */
udpcon_id_t* uc_genlid(char* src_ip, uint64_t src_port, char* dest_ip, uint64_t dest_port, udpcon_id_t* output);

/**
  * \brief Checks, if two (long) connection IDs are equal
  *
  *     Checks, if two (long) connection IDs are equal
  *
  * \param id_1 First ID to check for equality
  * \param id_2 Second ID to check for equality
  * \return true if id_1 equals id_2, else false
  *
  */
bool uc_eqlid(udpcon_id_t* id_1, udpcon_id_t* id_2);

/**
  * \brief Converts a (long) ID to a string
  *
  *     Converts a (long) ID to a string
  *
  * \param id ID to convert to string
  * \param out_25B String of minimum 25Bytes, to save the string equaivalent of the ID
  * \return pointer to the String, containing the string equivalent of the ID
  *
  */
char* uc_strlid(udpcon_id_t* id, char* out_25B);

/**
  * \brief Generates a 64bit random value
  *
  *     Reads random 64bit value from /dev/random, used e.g. for session key used e.g. to mask IDs
  *     for standard loglevel 0. Uses actual time as seed and rand() function as backup.
  *
  * \return 64bit random Integer
  *
  */
uint64_t rand64(); //Reads random 64bit value from /dev/random, used e.g. for session key used to mask IDs for standard loglevel 0. Uses actual time as seed and rand() function as backup.

#endif
