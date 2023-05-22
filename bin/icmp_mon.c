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
 * ICMP monitor.
 *
 * BSI 2018-2023
 */

//Header includes, defintions and globals
#include "madcat.common.h"
#include "madcat.helper.h"
#include "icmp_mon.h"
#include "icmp_mon.helper.h"
#include "icmp_mon.parser.h"
#include "icmp_mon.worker.h"
#include "udp_ip_port_mon.icmp_mon.helper.h"

int main(int argc, char *argv[])
{
    //Display Mascott and Version
    if (argc == 2 && strcmp(argv[1], "version") == 0) {
        fprintf(stdout, "\n%s%s\n", MASCOTT, VERSION);
        exit(0);
    }
    fprintf(stderr, "\n%s%s\n", MASCOTT, VERSION);

    loglevel = 0; //Default Loglevel 0: Standard, 1: Debug

    char log_time[64] = "";
    time_str(NULL, 0, log_time, sizeof(log_time)); //...generate string with current time

    //pseudo constant empty string e.g. for initialization of json_data_node_t and checks. Not used define here, because this would lead to several instances of an empty constant string with different addresses.
    EMPTY_STR[0] = 0;

    //Parse command line
    char hostaddr[INET6_ADDRSTRLEN] = "";
    char data_path[PATH_LEN] = "";
    int bufsize = DEFAULT_BUFSIZE;

    signal(SIGUSR1, sig_handler_icmp); //register handler as callback function used by CHECK-Macro
    CHECK(signal(SIGINT, sig_handler_icmp), != SIG_ERR); //register handler for SIGINT
    CHECK(signal(SIGTERM, sig_handler_icmp), != SIG_ERR); //register handler for SIGTERM

    // Checking if number of argument is
    // 4 or 5 or not.(PROG addr port conntimeout)
    if (argc != 2  && (argc < 4 || argc > 5)) {
        print_help_icmp(argv[0]);
        return -1;
    }

    if (argc == 2) { //read config file
        lua_State *luaState = lua_open();
        if (luaL_dofile(luaState, argv[1]) != 0) {
            fprintf(stderr, "%s [PID %d] Error parsing config file: %s\n\tRun without command line arguments for help.\n", log_time, getpid(), lua_tostring(luaState, -1));
            exit(1);
        }

        fprintf(stderr, "%s Parsing config file: %s\n", log_time, argv[1]);

        strncpy(hostaddr, get_config_opt(luaState, "hostaddress"), sizeof(hostaddr));
        hostaddr[sizeof(hostaddr)-1] = 0;
        fprintf(stderr, "\tHostaddress: %s\n", hostaddr);

        strncpy(user.name, get_config_opt(luaState, "user"), sizeof(user.name));
        user.name[sizeof(user.name)-1] = 0;
        fprintf(stderr, "\tuser: %s\n", user.name);

        strncpy(data_path, get_config_opt(luaState, "path_to_save_icmp_data"), sizeof(data_path));
        data_path[sizeof(data_path)-1] = 0;
        fprintf(stderr, "\tpath_to_save_icmp_data: %s\n", data_path);

        //check if mandatory string parameters are present, bufsize is NOT mandatory, the rest are numbers and are handled otherwise
        if(strlen(hostaddr) == 0 || strlen(user.name) == 0 || strlen(data_path) == 0) {
            fprintf(stderr, "%s [PID %d] Error in config file: %s\n", log_time, getpid(), argv[1]);
            print_help_icmp(argv[0]);
            return -1;
        }

        if(get_config_opt(luaState, "bufsize") != EMPTY_STR) { //if optional parameter is given, set it.
            bufsize = atoi(get_config_opt(luaState, "bufsize")); //convert string type to integer type (bufsize)
        }
        fprintf(stderr, "\tbufsize: %d\n", bufsize);

        if(get_config_opt(luaState, "loglevel") != EMPTY_STR) { //if optional parameter is given, set it.
            loglevel = atoi(get_config_opt(luaState, "loglevel")); //convert string type to integer type (loglevel)
        }
        fprintf(stderr, "\tloglevel: %d\n", loglevel);

        fflush(stderr);
        lua_close(luaState);
    } else { //copy legacy command line arguments to variables
        strncpy(hostaddr, argv[1], sizeof(hostaddr));
        hostaddr[sizeof(hostaddr)-1] = 0; //copy hostaddress and ensure null termination of this string. Ugly, I know.

        //copy path for stream data and ensure null termination of this string. Ugly, again...
        strncpy(data_path, argv[2], sizeof(data_path));
        data_path[sizeof(data_path)-1] = 0;

        //copy user string and ensure null termination of this string. Ugly, again...
        strncpy(user.name, argv[3], sizeof(user.name));
        user.name[sizeof(user.name)-1] = 0;

        if (argc == 5) { //set bufsize if given and convert to integer type.
            bufsize = atoi(argv[4]);
        }

    }

    if(bufsize < 0) { //Range checks
        fprintf(stderr, "Bufsize %d out of range.\n", bufsize);
        return -2;
    }

    fprintf(stderr, "%s Starting with PID %d, hostaddress %s, bufsize is %d Byte...\n", log_time, getpid(), hostaddr, bufsize);

    //Variables
    struct sockaddr_in addr; //Hostaddress
    struct sockaddr_in trgaddr; //Storage for recvfrom

    socklen_t trgaddr_len = sizeof(trgaddr);
    socklen_t addr_len = sizeof(addr);
    unsigned char* buffer = 0;
    int listenfd = CHECK(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), != -1); //create socket filedescriptor
    // if process is running as root, drop privileges
    if (getuid() == 0) {
        fprintf(stderr, "%s Droping priviliges to user %s...", log_time, user.name);
        get_user_ids(&user); //Get traget user UDI + GID
        CHECK(setgid(user.gid), == 0); // Drop GID first for security reasons!
        CHECK(setuid(user.uid), == 0);
        if (getuid() == 0 || getgid() == 0) //Test if uid/gid is still 0
            fprintf(stderr, "...nothing to drop. WARNING: Running as root!\n");
        else
            fprintf(stderr,"SUCCESS. UID: %d\n", getuid());
        fflush(stderr);
    }

    //Initialize address struct (Host)
    bzero(&addr, addr_len);
    addr.sin_family=AF_INET;
    CHECK(inet_aton(hostaddr, &addr.sin_addr), != 0); //set and check listening address

    //Main loop
    saved_buffer(buffer = CHECK(malloc(bufsize + 1), != 0 )); //allocate buffer and saves his address to be freed by signal handler
    while (1) {
        memset(buffer,0, bufsize + 1);   //zeroize buffer
        int recv_len = CHECK(recvfrom(listenfd, buffer, bufsize, 0, (struct sockaddr *) &trgaddr, &trgaddr_len), != -1);  //Accept Incoming data

        //parse buffer, log, assemble JSON, parse IP/TCP/UDP headers, do stuff...
        worker_icmp(buffer, recv_len, hostaddr,data_path);
        //print JSON output for logging and further analysis, if JSON-Object is not empty (happens if e.g. UDP is seen by ICMP Raw Socket)
        char* output = dict_dumpstr(json_dict(false));
        if(strlen(output) > 2) {
            fprintf(stdout,"%s\n", output);
            fflush(stdout);
        }
        free(output);
    }
    return 0;
}

