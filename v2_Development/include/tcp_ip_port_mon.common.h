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
 * TCP-, UDP- and ICMP monitor library headerfile.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2021
*/


#ifndef TCP_IP_PORT_MON_COMMON_TCP_H
#define TCP_IP_PORT_MON_COMMON_TCP_H

#include "madcat.common.h"

//#define CT_ENABLED //Enable compiling of conntrack functions
#ifdef CT_ENABLED
//Includes for conntrack
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#endif

// Global Variables and Definitions
char hostaddr[INET6_ADDRSTRLEN]; //Hostaddress to bind to. Globally defined to make it visible to functions for filtering.
//Global Variables and definitions
int pcap_pid; //PID of the Child doing the PCAP-Sniffing. Globally defined, cause it's used in CHECK-Makro.
int listner_pid; //PID of the Child doing the TCP Connection handling. Globally defined, cause it's used in CHECK-Makro.
//semaphores for output globally defined for easy access inside functions
sem_t *hdrsem; //Semaphore for named pipe containing TCP/IP data
sem_t *consem; //Semaphore for named pipe containing connection data
FILE* confifo; //FILE* confifo is globally defined to be reachabel for proxy-childs and listner-childs and signal handlers
FILE* hdrfifo; //FILE* confifo is globally defined to be reachabel for pcap-childs and signal handlers
int openfd; //Socket FD is globally defined to be reachabel for listner-childs and signal handlers
pcap_t *handle; //pcap Session handle

struct con_status_t {   //Connection status
    char tag[80];       //The connection tag is a buffer with a min. size of 80 Bytes.
    char start[64];     //Time string: Start of connection
    char end[64];       //Time string: End of connection
    long double timeasdouble;  //Unix timestamp: Start of connection
    char state[16];     //State is either "closed\0", "open\0" or "n/a\0"
    char reason[16];    //Reason is either "timeout\0", "size exceeded\0" or "n/a\0". Usefull states like "FIN send\0" and "FIN recv\0" are not detectable.
    long int data_bytes;//received bytes
};


#endif
