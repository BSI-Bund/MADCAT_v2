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


#ifndef MADCAT_COMMON_H
#define MADCAT_COMMON_H

#define DEBUG 0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <pwd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/file.h>
#include <openssl/sha.h>
#include <lua5.1/lauxlib.h>
#include <lua5.1/lualib.h>
#include <sys/stat.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <pthread.h>

// Macro to check if an error occured, translate it, report it to STDERR, calling shutdown callback function to exit with error and dump core.
#define CHECK(result, check)                                                            \
        ({                                                                 \
                typeof(result) retval = (result);                                           \
                if (!(retval check)) {                                                      \
                        fprintf(stderr, "ERROR: Return value from function call '%s' is NOT %s at %s:%d.\n\tERRNO(%d): %s\n",          \
                                        #result, #check, __FILE__, __LINE__, errno, strerror(errno)); \
                        kill(getpid(), SIGUSR1);                                            \
                }                                                                       \
                retval;                                                                     \
        })

#define MASCOTT "                             ▄▄▄               ▄▄▄▄▄▄\n                 ▀▄▄      ▄▓▓█▓▓▓█▌           ██▓██▓▓██▄     ▄▀\n                    ▀▄▄▄▓█▓██   █▓█▌         █▓   ▓████████▀\n                       ▀███▓▓(o)██▓▌       ▐█▓█(o)█▓█████▀\n                         ▀▀██▓█▓▓█         ████▓███▀▀\n                  ▄            ▀▀▀▀                          ▄\n                ▀▀█                                         ▐██▌\n                  ██▄     ____------▐██████▌------___     ▄▄██\n                 __█ █▄▄--   ___------▀▓▓▀-----___   --▄▄█ █▀__\n             __--   ▀█  ██▄▄▄▄    __--▄▓▓▄--__   ▄▄▄▄██  ██▀   --__\n         __--     __--▀█ ██  █▀▀█████▄▄▄▄▄▄███████  ██ █▀--__      --__\n     __--     __--    __▀▀█  █  ██  ██▀▀██▀▀██  ██  █▀▀__    --__      --__\n         __--     __--     ▀███ ██  ██  ██  ██ ████▀     --__    --__\n bsi   --     __--             ▀▀▀▀▀██▄▄██▄▄██▀▀▀▀           --__    --\n         __ --                                                   --__\n"
#define PATH_LEN 4097 //Maximum Linux path lenght of 4096 + 1 for \0

//pseudo constant empty string e.g. for initialization of json_data_node_t and checks. Not used #define here, because this would lead to several instances of an empty constant string with different addresses.
char EMPTY_STR[1];

int loglevel; //Default Loglevel 0 logging no IPs to stderr, 1: Full logging
uint64_t sessionkey; //Sessionkey is used e.g. in UDP Module to mask IDs GDPR conformant if loglevel == 0.

//struct holding user UID and PID to drop priviliges to.
struct user_t {
    char name[33]; //Linux user names may be up to 32 characters long + 0-Termination.
    uid_t   uid;        /* user ID */
    gid_t   gid;        /* group ID */
};
struct user_t user; //globally defined, used to drop priviliges in arbitrarry functions. May become local, if not needed.

//struct holding json for output
typedef struct {
    char* str;
} json_struct;

#endif
