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

#ifndef RAW_MON_H
#define RAW_MON_H

//Global includes, defines, definitons
#include "madcat.common.h"
#include "madcat.helper.h"
#include "raw_mon.helper.h"

#define VERSION "MADCAT - Mass Attack Detecion Connection Acceptance Tool\nRAW Monitor v2.1.3\nBSI 2018-2021\n" //Version string
#define ETHERNET_HEADER_LEN 14 //Length of an Ethernet Header


//Variabels for PCAP sniffing
char* filter_exp; //The configured PCAP Filter string
pcap_t *handle; //pcap Session handle
struct pcap_pkthdr header; // The pcap header it gives back
unsigned char* packet; //The Packet from pcap

struct json_data_node_t { //json data list element
    //all variables of json output, except constant string values e.g. "proxy_flow" or "closed"
    char* timestamp;
    char* unixtime;
    long double timeasdouble;
    long double duration;
    char* start;
    char* end;
    long long unsigned int bytes_toserver;
    int  proto;
};

#endif