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
 * TCP monitor worker headerfile.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2021
*/


#ifndef TCP_IP_PORT_MON_WORKER_H
#define TCP_IP_PORT_MON_WORKER_H

#include "madcat.common.h"
#include "tcp_ip_port_mon.h"

//Connection worker:

/**
  * \brief Handels incoming TCP connections
  *
  *     Handels a TCP connection, which is not proxied and
  *     writes out payloads and results in JSON-Format to a FiFo.
  *
  * \param dst_addr Destination IP of connection
  * \param dest_port Destination Port of connection
  * \param src_addr Source IP of connection
  * \param src_port Source Port of connection
  * \param timeout Desired connection timeout
  * \param data_path Path to save payload data to
  * \param max_file_size Maximum size of payload-files
  * \param s Socket of connection
  * \param confifo FiFo to write JSON-output to
  * \return number of received bytes in case of success, <0 in case of an error.
  *
  */
long int worker_tcp(char* dst_addr, \
                    int dest_port, \
                    char* src_addr, \
                    int src_port, \
                    long double timeout, \
                    char* data_path, \
                    int max_file_size, \
                    int s,\
                    FILE* confifo);

#endif

