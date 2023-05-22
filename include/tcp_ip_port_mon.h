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
 *       iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 1:65534 -j DNAT --to 192.168.1.100:65535
 * Listening Port is 65535 and hostaddress is 192.168.1.100 in this example.
 *
 * BSI 2018-2023
*/

#ifndef TCP_IP_PORT_MON_H
#define TCP_IP_PORT_MON_H

//Global includes, defines, definitons

#include "tcp_ip_port_mon.helper.h"
#include "tcp_ip_port_mon.parser.h"
#include "tcp_ip_port_mon.worker.h"
#include "rsp.h"

#define VERSION "MADCAT - Mass Attack Detecion Connection Acceptance Tool\nTCP-IP Port Monitor v2.3.0\nBSI 2018-2023\n" //Version string

#define CHUNK_SIZE 512 //Chunks for receiving
//Minium of maximum path lengths of Linux common file systems
#define DEFAULT_BUFSIZE 9000 //Ethernet jumbo frame limit
#define ETHERNET_HEADER_LEN 14 //Length of an Ethernet Header
#define IP_OR_TCP_HEADER_MINLEN 20 // Minimum Length of an IP-Header or a TCP-Header is 20 Bytes
#define IPv6_HEADER_MINLEN 40 // Minimum Length of an IPv6-Header is 40 Bytes

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

/*
 *  TCP option as defined e.g. in wireshark
 */
//To raise self-esteem, the prefix "MY" has also been added here.
#define MY_TCPOPT_NOP              1       /* Padding */
#define MY_TCPOPT_EOL              0       /* End of options */
#define MY_TCPOPT_MSS              2       /* Segment size negotiating */
#define MY_TCPOPT_WINDOW           3       /* Window scaling */
#define MY_TCPOPT_SACK_PERM        4       /* SACK Permitted */
//#define MY_TCPOPT_SACK             5       /* SACK Block */ //not yet implemented, thread as "tainted"
#define MY_TCPOPT_ECHO             6
#define MY_TCPOPT_ECHOREPLY        7
#define MY_TCPOPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */
#define MY_TCPOPT_CC               11
#define MY_TCPOPT_CCNEW            12
#define MY_TCPOPT_CCECHO           13
#define MY_TCPOPT_MD5              19      /* RFC2385 */
#define MY_TCPOPT_SCPS             20      /* SCPS Capabilities */
#define MY_TCPOPT_SNACK            21      /* SCPS SNACK */
#define MY_TCPOPT_RECBOUND         22      /* SCPS Record Boundary */
#define MY_TCPOPT_CORREXP          23      /* SCPS Corruption Experienced */
#define MY_TCPOPT_QS               27      /* RFC4782 Quick-Start Response */
#define MY_TCPOPT_USER_TO          28      /* RFC5482 User Timeout Option */
#define MY_TCPOPT_MPTCP            30      /* RFC6824 Multipath TCP */ //not yet implemented, thread as "tainted"
#define MY_TCPOPT_TFO              34      /* RFC7413 TCP Fast Open Cookie */ //not yet implemented, thread as "tainted"
#define MY_TCPOPT_EXP_FD           0xfd    /* Experimental, reserved */ //not yet implemented, thread as "tainted"
#define MY_TCPOPT_EXP_FE           0xfe    /* Experimental, reserved */ //not yet implemented, thread as "tainted"
/* Non IANA registered option numbers */
#define MY_TCPOPT_RVBD_PROBE       76      /* Riverbed probe option */ //not yet implemented, thread as "tainted"
#define MY_TCPOPT_RVBD_TRPY        78      /* Riverbed transparency option */ //not yet implemented, thread as "tainted"

/*
 *     TCP option lengths as defined in wireshark
 */
#define MY_TCPOLEN_NOP            1
#define MY_TCPOLEN_EOL            1
#define MY_TCPOLEN_MSS            4
#define MY_TCPOLEN_WINDOW         3
#define MY_TCPOLEN_SACK_PERM      2
//#define MY_TCPOLEN_SACK_MIN       2 //not yet implemented, thread as "tainted"
#define MY_TCPOLEN_ECHO           6
#define MY_TCPOLEN_ECHOREPLY      6
#define MY_TCPOLEN_TIMESTAMP     10
#define MY_TCPOLEN_CC             6
#define MY_TCPOLEN_CCNEW          6
#define MY_TCPOLEN_CCECHO         6
#define MY_TCPOLEN_MD5           18
#define MY_TCPOLEN_SCPS           4
#define MY_TCPOLEN_SNACK          6
#define MY_TCPOLEN_RECBOUND       2
#define MY_TCPOLEN_CORREXP        2
#define MY_TCPOLEN_QS             8
#define MY_TCPOLEN_USER_TO        4
#define MY_TCPOLEN_MPTCP_MIN      3 //not yet implemented, thread as "tainted"
#define MY_TCPOLEN_TFO_MIN        2 //not yet implemented, thread as "tainted"
#define MY_TCPOLEN_EXP_MIN        2 //not yet implemented, thread as "tainted"
/* Non IANA registered option numbers */
#define MY_TCPOLEN_RVBD_PROBE_MIN 3 //not yet implemented, thread as "tainted"
#define MY_TCPOLEN_RVBD_TRPY_MIN 16 //not yet implemented, thread as "tainted"


// Macro to check if an error occured, translate it, report it to STDERR, calling shutdown callback function to exit with error and dump core.
#define CHECK(result, check)                                                                                                                                            \
({                                                                                                                                                                      \
                typeof(result) retval = (result);                                                                                                                       \
                if (!(retval check)) {                                                                                                                                  \
                        fprintf(stderr, "ERROR: Return value from function call '%s' is NOT %s at %s:%d.\n\tERRNO(%d): %s\n",                                           \
                                         #result, #check, __FILE__, __LINE__, errno, strerror(errno));                                                                  \
                        kill(getpid(), SIGUSR1);                                                                                                                        \
                }                                                                                                                                                       \
                retval;                                                                                                                                                 \
        })

// Global Variables and Definitions
extern char hostaddr[INET6_ADDRSTRLEN]; //Hostaddress to bind to. Globally defined to make it visible to functions for filtering.
//Global Variables and definitions
extern pid_t pcap_pid; //PID of the Child doing the PCAP-Sniffing. Globally defined, cause it's used in CHECK-Makro.
extern pid_t listner_pid; //PID of the Child doing the TCP Connection handling. Globally defined, cause it's used in CHECK-Makro.
//semaphores for output globally defined for easy access inside functions
extern sem_t *hdrsem; //Semaphore for named pipe containing TCP/IP data
extern sem_t *consem; //Semaphore for named pipe containing connection data
extern FILE* confifo; //FILE* confifo is globally defined to be reachabel for both proxy-childs and accept-childs

#endif