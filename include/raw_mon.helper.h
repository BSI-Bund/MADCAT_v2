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
 * Example Netfilter Rule to work properly:
 *       iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 1:65534 -j DNAT --to 192.168.8.42:65535
 * Listening Port is 65535 and hostaddress is 192.168.8.42 in this example.
 *
 * BSI 2018-2023
*/

#ifndef RAW_MON_HELPER_H
#define RAW_MON_HELPER_H

#include "madcat.helper.h"

/**
 * \brief Print RAW help message
 *
 *     Prints usage of raw_mon
 *
 * \param progname  Binary name
 * \return void
 *
 */
void print_help_raw(char* progname);

/**
 * \brief Signal Handler for RAW parent
 *
 *     Signal Handler for RAW parent for gracefull shutdown
 *
 * \param signo Signal Number
 * \return void
 *
 */
void sig_handler_raw(int signo);

/**
  * \brief Signal Handler for RAW childs
  *
  *     Signal Handler for RAW childs
  *
  * \param signo Signal Number
  * \return void
  *
  */
void sig_handler_raw_childs(int signo);

/**
 * \brief Drops root priviliges
 *
 *     Trys to drop root privilges to a specific user and
 *     prints result to STDERR
 *
 * \param user User to drop the priviliges to
 * \param entity String for output to identify e.g. the Thread which droped priviliges
 * \return void
 *
 */
void drop_root_privs(struct user_t user, const char* entity);

/**
 * \brief Initializes PCAP sniffing with filter
 *
 *     Initializes PCAP sniffing, using configured filter
 *     Returns 0 on succes, otherwise returns:
 *     -1: pcap_lookupnet failed
 *     -2: pcap_open_live failed
 *
 *     Aborts, if pcap_compile failed or pcap_setfilter failed
 *
 *     For filter expressions see https://www.tcpdump.org/manpages/pcap-filter.7.html
 *     See documentation of libpcap for further infomation.
 *
 * \param dev  Name of the device to start PCAP-Sniffing on
 * \param handle PCAP Handle to be initialized
 * \param filter_exp Configured filter
 * \return 0 und success, <0 if an error occured
 *
 */
int init_pcap(char* dev, pcap_t **handle, const char* filter_exp);

#endif