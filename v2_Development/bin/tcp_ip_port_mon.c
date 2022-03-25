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

//Header includes, defintions and globals
#include "madcat.common.h"
#include "madcat.helper.h"
#include "tcp_ip_port_mon.h"

//Main

int main(int argc, char *argv[])
{

    //Display Mascott and Version
    if (argc == 2 && strcmp(argv[1], "version") == 0) {
        fprintf(stdout, "\n%s%s\n", MASCOTT, VERSION);
        exit(0);
    }
    fprintf(stderr, "\n%s%s\n", MASCOTT, VERSION);

    loglevel = 0; //Default Loglevel 0: Standard, 1: Debug

    //pseudo constant empty string e.g. for initialization of json_data_node_t and checks. Not used #define here, because this would lead to several instances of an empty constant string with different addresses.
    EMPTY_STR[0] = 0;
    //Start time
    char log_time[64] = ""; //Human readable start time (actual time zone)
    char log_time_unix[64] = ""; //Unix timestamp (UTC)
    struct timeval begin;
    gettimeofday(&begin, NULL);
    time_str(NULL, 0, log_time, sizeof(log_time)); //Get Human readable string only

    signal(SIGUSR1, sig_handler_parent); //register handler as callback function used by CHECK-Macro
    CHECK(signal(SIGINT, sig_handler_parent), != SIG_ERR); //register handler for SIGINT for parent process
    CHECK(signal(SIGTERM, sig_handler_parent), != SIG_ERR); //register handler for SIGTERM for parent process

    //Parse command line.
    hostaddr[INET6_ADDRSTRLEN] = 0; //Hostaddress to bind to. Globally defined to make it visible to functions for filtering.
    int port = 65535;
    char interface[64]= "";
    double timeout = 30;
    char data_path[PATH_LEN] = "";
    int max_file_size = -1;
    char connect_fifo[PATH_LEN] = CONNECT_FIFO_DEF;
    char header_fifo[PATH_LEN] = HEADER_FIFO_DEF;

    //Structure holding proxy configuration items
    pc = pctcp_init(pc);
    double proxy_wait_restart = 5; //time to wait before a crashed proxy restarts, e.g. because backend has failed, defaults to 5 seconds

    // Checking if number of arguments is one (config file) or 6 or 7 (command line).
    if (argc != 2  && (argc < 7 || argc > 8)) {
        print_help_tcp(argv[0]);
        return -1;
    }

    if (argc == 2) { //read config file
        lua_State *luaState = lua_open();
        if (luaL_dofile(luaState, argv[1]) != 0) {
            fprintf(stderr, "%s [PID %d] Error parsing config file: %s\n\tRun without command line arguments for help.\n", log_time, getpid(), lua_tostring(luaState, -1));
            exit(1);
        }

        fprintf(stderr, "%s [PID %d] Parsing config file: %s\n", log_time, getpid(), argv[1]);

        strncpy(interface, get_config_opt(luaState, "interface"), sizeof(interface));
        interface[sizeof(interface)-1] = 0;  //copy interface and ensure null termination of this string. Ugly.
        fprintf(stderr,"\tInterface: %s\n", interface);

        strncpy(hostaddr, get_config_opt(luaState, "hostaddress"), sizeof(hostaddr));
        hostaddr[sizeof(hostaddr)-1] = 0;
        fprintf(stderr, "\tHostaddress: %s\n", hostaddr);

        port = atoi(get_config_opt(luaState, "tcp_listening_port")); //convert string type to integer type (port)
        fprintf(stderr, "\tlistening Port: %d\n", port);

        timeout = (double) atof(get_config_opt(luaState, "tcp_connection_timeout")); //set timeout and convert to integer type.
        fprintf(stderr, "\ttimeout: %lf\n", timeout);

        strncpy(user.name, get_config_opt(luaState, "user"), sizeof(user.name));
        user.name[sizeof(user.name)-1] = 0;
        fprintf(stderr, "\tuser: %s\n", user.name);

        strncpy(data_path, get_config_opt(luaState, "path_to_save_tcp_streams"), sizeof(data_path));
        data_path[sizeof(data_path)-1] = 0;
        fprintf(stderr, "\tpath_to_save_tcp_streams: %s\n", data_path);

        //check if mandatory string parameters are present, bufsize is NOT mandatory, the rest are numbers and are handled otherwise
        if(strlen(interface) == 0 || strlen(hostaddr) == 0 || strlen(user.name) == 0 || strlen(data_path) == 0) {
            fprintf(stderr, "%s [PID %d] Error in config file: %s\n", log_time, getpid(), argv[1]);
            print_help_tcp(argv[0]);
            return -1;
        }

        if(get_config_opt(luaState, "max_file_size") != EMPTY_STR) { //if optional parameter is given, set it.
            max_file_size = atoi(get_config_opt(luaState, "max_file_size"));
        }
        fprintf(stderr, "\tmax_file_size: %d\n", max_file_size);

        if(get_config_opt(luaState, "loglevel") != EMPTY_STR) { //if optional parameter is given, set it.
            loglevel = atoi(get_config_opt(luaState, "loglevel")); //convert string type to integer type (loglevel)
        }
        fprintf(stderr, "\tloglevel: %d\n", loglevel);

        if(get_config_opt(luaState, "connection_fifo") != EMPTY_STR) { //if optional parameter is given, set it.
            strncpy(connect_fifo, get_config_opt(luaState, "connection_fifo"), sizeof(connect_fifo));
            data_path[sizeof(data_path)-1] = 0;
        }
        fprintf(stderr, "\tconnection_fifo: %s\n", connect_fifo);

        if(get_config_opt(luaState, "header_fifo") != EMPTY_STR) { //if optional parameter is given, set it.
            strncpy(header_fifo, get_config_opt(luaState, "header_fifo"), sizeof(header_fifo));
            data_path[sizeof(data_path)-1] = 0;
        }
        fprintf(stderr, "\theader_fifo: %s\n", header_fifo);

        //Read proxy configuration
        if(get_config_opt(luaState, "proxy_wait_restart") != EMPTY_STR) { //if optional parameter is given, set it.
            proxy_wait_restart = (double) atof(get_config_opt(luaState, "proxy_wait_restart")); //convert string ype to integer type (proxy_wait_restart)
        }
        fprintf(stderr, "\tFailed proxy restart time: %lf\n", proxy_wait_restart);

        get_config_table(luaState, "tcpproxy", pc);
        pctcp_print(pc);

        fflush(stderr);
        lua_close(luaState);
    } else { //copy legacy command line arguments to variables
        strncpy(interface, argv[1], sizeof(interface));
        interface[sizeof(interface)-1] = 0;  //copy hostaddress and ensure null termination of this string. Ugly.
        strncpy(hostaddr, argv[2], sizeof(hostaddr));
        hostaddr[sizeof(hostaddr)-1] = 0;
        port = atoi(argv[3]); //convert string type to integer type (port)
        timeout = (double) atof(argv[4]); //set timeout and convert to integer type.
        strncpy(user.name, argv[5], sizeof(user.name));
        user.name[sizeof(user.name)-1] = 0;
        strncpy(data_path, argv[6], sizeof(data_path));
        data_path[sizeof(data_path)-1] = 0;

        if (argc == 8) { //get max. file-size.
            max_file_size = atoi(argv[7]);
        }

    }

    if(port < 1 || port > 65535) { //Range checks
        fprintf(stderr, "%s [PID %d] Port %d out of range.\n", log_time, getpid(), port);
        return -2;
    }

    fprintf(stderr, "%s [PID %d] Starting on interface %s with hostaddress %s on port %d, timeout is %lfs, data path is %s\n", \
            log_time, getpid(), interface, hostaddr, port, timeout, data_path);


    //Unlink possibly existing old semaphores
    sem_unlink ("hdrsem");
    sem_unlink ("consem");

    //Semaphores for output globally defined for easy access inside functions
    hdrsem = CHECK(sem_open ("hdrsem", O_CREAT | O_EXCL, 0644, 1), !=  SEM_FAILED);  //open semaphore for named pipe containing TCP/IP data
    //Semaphore for named pipe containing connection data
    consem = CHECK(sem_open ("consem", O_CREAT | O_EXCL, 0644, 1), !=  SEM_FAILED);

    //Variabels for PCAP sniffing

    struct pcap_pkthdr header; // The pcap header it gives back
    const unsigned char* packet; //The Packet from pcap
    bpf_u_int32 caplen = 0; //size of pcap packet
    pcap_pid = 0; //PID of the Child doing the PCAP-Sniffing. Globally defined, cause it's used in CHECK-Makro callback function.
    listner_pid = 0; //PID of the Child doing the TCP Connection handling. Globally defined, cause it's used in CHECK-Makro callback function.

    //Make FIFO for connection discribing JSON Output
    unlink(connect_fifo);
    CHECK(mkfifo(connect_fifo, 0660), == 0);
    confifo = fopen(connect_fifo, "w+"); //FILE* confifo is globally defined to be reachabel for both proxy-childs and accept-childs
    fprintf(stderr, "%s [PID %d] FIFO for connection json: %s\n", log_time, getpid(), connect_fifo);

    //Start proxys.
    for (int listenport = 1; listenport<65536; listenport++) { //More Clever solution thus this is brute force?
        if(pc->portmap[listenport]) {
            if ( !(pctcp_get_lport(pc, listenport)->pid = fork()) ) { //Create Reverse Proxy child process(es) and save PID for parent watchdog.
                pctcp_get_lport(pc, listenport)->pid = getpid(); //update copy of listelemnt in this (forked) copy with own PID, to be able to find own config.
                //fprintf(stderr, "%s [PID %d] Starting Proxy on Port %d...\n", log_time, getpid(), listenport);
                prctl(PR_SET_PDEATHSIG, SIGTERM); //request SIGTERM if parent dies.
                CHECK(signal(SIGTERM, sig_handler_proxychild), != SIG_ERR); //re-register handler for SIGTERM for child process
                CHECK(signal(SIGINT, sig_handler_proxychild), != SIG_ERR); //re-register handler for SIGINT for child process
                CHECK(signal(SIGCHLD, sig_handler_sigchld), != SIG_ERR); //register handler for parents to prevent childs becoming Zombies
                CHECK(rsp(pctcp_get_lport(pc, listenport), hostaddr), != 0); //start proxy
            }
            usleep(10000); //sleep 10ms, so output is not mangled between forks
        }
    }

    //Fork in child, init pcap , drop priviliges, sniff for SYN-Packets and log them
    if( !(pcap_pid=fork()) ) {
        prctl(PR_SET_PDEATHSIG, SIGKILL); //request SIGKILL if parent dies.
        CHECK(signal(SIGTERM, sig_handler_pcapchild), != SIG_ERR); //re-register handler for SIGTERM for child process
        CHECK(signal(SIGINT, sig_handler_pcapchild), != SIG_ERR); //re-register handler for SIGINT for child process
        CHECK(signal(SIGABRT, sig_handler_pcapchild), != SIG_ERR); //register handler for SIGABRT for child process
        CHECK(signal(SIGCHLD, sig_handler_sigchld), != SIG_ERR); //register handler for parents to prevent childs becoming Zombies
#if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] Initialize PCAP\n", getpid());
#endif
        CHECK(init_pcap(interface, hostaddr, &handle), == 0); //Init libpcap

        //Make FIFO for header discribing JSON Output
        unlink(header_fifo);
        CHECK(mkfifo(header_fifo, 0660), == 0);
        hdrfifo = fopen(header_fifo, "r+");
        fprintf(stderr, "%s [PID %d] FIFO for header JSON: %s\n", log_time, getpid(), header_fifo);

        fprintf(stderr, "%s [PID %d] ", log_time, getpid());
        drop_root_privs(user, "Sniffer:", false); //drop priviliges

        int data_bytes = 0; //eventually exisiting data bytes in SYN (yes, this would be akward)
        long int syn_count = 0;
        int ip_hdr_id;
        while (1) {
            packet = 0;
            packet = pcap_next(handle, &header); //Wait for and grab TCP-SYN (see PCAP_FILTER) (Maybe of maybe not BLOCKING!)
            if (packet == NULL) {
                continue;
            }
            caplen = header.caplen;
            //Preserve actuall start time of Connection attempt.
            time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time));
            //print hexdump of packet
            if(loglevel > 1)
                print_hex(stderr, packet, caplen);
            //Begin new global JSON output and open JSON object
            json_do(true, "{\"timestamp\":\"%s\"", log_time);
            //Analyze Headers and discard malformed packets
            ip_hdr_id = analyze_ip_header(packet, caplen);
            if( ip_hdr_id < 0) {
                continue;
            }
            data_bytes = analyze_tcp_header(packet, caplen);
            if(data_bytes < 0) {
                continue;
            }
            //JSON Ouput and close JSON object
            json_do(false, "}, \"data_bytes\": %d, \"unixtime\": %s}", data_bytes, log_time_unix);
            struct timespec sem_timeout; //time to wait in sem_timedwait() call
            clock_gettime(CLOCK_REALTIME, &sem_timeout);
            sem_timeout.tv_sec += 1;
            sem_timedwait(hdrsem, &sem_timeout); //Acquire lock for output
            fprintf(hdrfifo,"%s\n", json_do(false, "")); //print json output for further analysis
            sem_post(hdrsem); //release lock
            fprintf(stdout,"{\"HEADER\": %s}\n", json_do(false, "")); //print json output for logging
            fflush(hdrfifo);
            fflush(stdout);
            fprintf(stderr, "%s [PID %d] Sniffer: TCP-SYN No. %ld with id 0x%x received\n", log_time, getpid(), ++syn_count, ip_hdr_id);
        }
    }

    usleep(10000); //sleep 10ms, so output is not mangled between forks
    if ( !(listner_pid=fork()) ) { //Create listening child process
        //Variables for listning socket
        struct sockaddr_in addr; //Hostaddress
        struct sockaddr_in trgaddr; //Storage for original destination port
        struct sockaddr_in claddr; //Clientaddress
        char clientaddr[INET_ADDRSTRLEN] = "";

        prctl(PR_SET_PDEATHSIG, SIGTERM); //request SIGTERM if parent dies.
        CHECK(signal(SIGTERM, sig_handler_listnerchild), != SIG_ERR); //re-register handler for SIGTERM for child process
        CHECK(signal(SIGINT, sig_handler_listnerchild), != SIG_ERR); //re-register handler for SIGINT for child process
        CHECK(signal(SIGCHLD, sig_handler_sigchld), != SIG_ERR); //register handler for parents to prevent childs becoming Zombies

        listner_pid = getpid();

        socklen_t trgaddr_len = sizeof(trgaddr);
        socklen_t claddr_len = sizeof(claddr);
        socklen_t addr_len = sizeof(addr);
        int listenfd = CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), != -1); //create socket filedescriptor

        //Initialize address struct (Host)
        bzero(&addr, addr_len);
        addr.sin_family=AF_INET;
        CHECK(inet_aton(hostaddr, &addr.sin_addr), != 0); //set and check listening address
        addr.sin_port = htons(port); //set listening port

        struct linger sl = { 1, 0 };
        int on = 1;

        CHECK(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on)), != -1);
        CHECK(setsockopt(listenfd, SOL_SOCKET, SO_LINGER, &sl, (socklen_t)sizeof(sl)), != -1);

        //Bind socket and begin listening
        CHECK(bind(listenfd, (struct sockaddr*)&addr, sizeof(addr)), != -1);
        CHECK(listen(listenfd, 5), != -1);

        //drop root priviliges
        fprintf(stderr, "%s [PID %d] ", log_time, getpid());
        drop_root_privs(user, "Listner:", false);

        //Main listening loop
        long int flow_count = 0;
        while (1) {
#if DEBUG >= 2
            fprintf(stderr, "*** DEBUG [PID %d] Listner Loop\n", getpid());
#endif
            claddr_len = sizeof(claddr); //reinitialize claddr_len, because in the call to accept(...) it is a value-result argument!
            openfd = CHECK(accept(listenfd, (struct sockaddr*)&claddr, &claddr_len), != -1);  //Accept incoming connection
            if (!fork()) { //Create stream accepting child process
#if DEBUG >= 2
                fprintf(stderr, "*** DEBUG [PID %d] Accept-Child forked\n", getpid());
#endif
                prctl(PR_SET_PDEATHSIG, SIGTERM); //request SIGTERM if parent dies.
                CHECK(signal(SIGTERM, sig_handler_listnerchild), != SIG_ERR); //register handler for SIGTERM for child process
                CHECK(signal(SIGINT, sig_handler_listnerchild), != SIG_ERR); //re-register handler for SIGINT for child process
                CHECK(signal(SIGUSR2, sig_handler_listnerchild), != SIG_ERR); //Register handler for SIGUSR2 for child process for gracefull shutdown
                //Preserve actual start time of connection attempt.
                if (loglevel > 1) {
                    time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time));
                    fprintf(stderr, "%s [PID %d] Connection incoming, trying to resolve original destination port on socket fd: %d...\n", log_time, getpid(), openfd);
                }

                CHECK(getsockopt(openfd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr*)&trgaddr, &trgaddr_len), != -1); //Read original dst. port from NAT-table, abort if it fails (may collide with TCP Postprcessor lookup)
                //retrieve client target IPv4 (important when listening on ANY_ADDR)
                inet_ntop(AF_INET, &(claddr.sin_addr), clientaddr, sizeof clientaddr);
                //worker_tcp: Log, save stream, hold connection, timeout and JSON output
#if DEBUG >= 2
                fprintf(stderr, "*** DEBUG [PID %d] Accept-Child %s:%d\n", getpid(), inet_ntoa(trgaddr.sin_addr), ntohs(trgaddr.sin_port));
                fprintf(stderr, "*** DEBUG [PID %d] Accept-Child entering Worker\n", getpid());
#endif
                worker_tcp(inet_ntoa(trgaddr.sin_addr), ntohs(trgaddr.sin_port), clientaddr, ntohs(claddr.sin_port),\
                           timeout, data_path, max_file_size, openfd, confifo);
#if DEBUG >= 2
                fprintf(stderr, "*** DEBUG [PID %d] Accept-Child left Worker\n", getpid());
#endif
                //Shutdown child process
                close(openfd); //Close connection
#if DEBUG >= 2
                fprintf(stderr, "*** DEBUG [PID %d] Accept-Child openfd closed, returning.\n", getpid());
#endif
                fflush(confifo);
                kill(getpid(), SIGKILL); //kill child process //exit may hang when used in forged child processes, thus using SIGKILL instead.; //exit(signo); //hangs sometimes under  high load>
                _exit(0);
            }
            fprintf(stderr, "%s [PID %d] Connection No. %ld accepted\n", log_time, getpid(), ++flow_count);
            close(openfd); //Close connection
        }

    } else {
        sleep(2); //Wait before starting Watchdog
        //Log start of Watchdog
        gettimeofday(&begin, NULL);
        time_str(NULL, 0, log_time, sizeof(log_time)); //Get Human readable string only
        //priviliges for watchdog can not be dropped anymore, because it may need to restart proxys with root priviliges
        //drop_root_privs(user, "Parent Watchdog");
        fprintf(stderr, "%s [PID %d] Parent Watchdog active. PIDs of childs at startup time:\n", log_time, getpid());

        // Parent Watchdog Loop.
        int stat_pcap = 0;
        int stat_accept = 0;
        int sem_sval_1 = 0;
        int sem_sval_2 = 0;
        bool firstrun = true;
        while (1) {
            gettimeofday(&begin, NULL);
            time_str(NULL, 0, log_time, sizeof(log_time)); //Get Human readable string only for this watchdog cycle
            if (firstrun) fprintf(stderr, "\tSniffer\t\t\t: %d\n\tListner\t\t\t: %d\n", pcap_pid, listner_pid);

            if ( waitpid(pcap_pid, &stat_pcap, WNOHANG) ) {
                fprintf(stderr, "%s [PID %d] Sniffer (PID %d) crashed. ARE YOU ROOT?", log_time, getpid(), pcap_pid);
                sig_handler_parent(SIGTERM);
                break;
            }
            if ( waitpid(listner_pid, &stat_accept, WNOHANG) ) {
                fprintf(stderr, "%s [PID %d] Listner (PID %d) crashed. ARE YOU ROOT?", log_time, getpid(), listner_pid);
                sig_handler_parent(SIGTERM);
                break;
            }
            for (int listenport = 1; listenport <65536; listenport++) {
                if (firstrun && pc->portmap[listenport]) fprintf(stderr, "\tProxy at Port %d\t: %d\n", listenport, pctcp_get_lport(pc, listenport)->pid);

                if ( pc->portmap[listenport] && waitpid(pctcp_get_lport(pc, listenport)->pid, &stat_accept, WNOHANG) ) {
                    pid_t old_pid = pctcp_get_lport(pc, listenport)->pid;
                    if ( !(pctcp_get_lport(pc, listenport)->pid=fork()) ) { //Re-create Reverse Proxy child process and save PID.
                        sleep(proxy_wait_restart);
                        pctcp_get_lport(pc, listenport)->pid = getpid(); //update copy of listelemnt in this (forked) copy with own PID, to be able to find own config.
#if DEBUG >= 2
                        fprintf(stderr, "%s [PID %d] Starting Proxy on Port %d...\n", log_time, getpid(), listenport);
#endif
                        prctl(PR_SET_PDEATHSIG, SIGTERM); //request SIGTERM if parent dies.
                        CHECK(signal(SIGTERM, sig_handler_proxychild), != SIG_ERR); //re-register handler for SIGTERM for child process
                        CHECK(signal(SIGINT, sig_handler_proxychild), != SIG_ERR); //re-register handler for SIGINT for child process
                        CHECK(signal(SIGCHLD, sig_handler_sigchld), != SIG_ERR); //register handler for parents to prevent childs becoming Zombies
                        CHECK(rsp(pctcp_get_lport(pc, listenport), hostaddr), != 0); //start proxy
                    }

                    fprintf(stderr, "%s [PID %d] Proxy with PID %d, local port: %d -> Backend socket: %s:%d, exited, restarting in %f seconds with PID %d...\n",\
                            log_time,\
                            getpid(),\
                            old_pid,\
                            pctcp_get_lport(pc, listenport)->listenport,\
                            pctcp_get_lport(pc, listenport)->backendaddr,\
                            pctcp_get_lport(pc, listenport)->backendport,\
                            proxy_wait_restart,\
                            pctcp_get_lport(pc, listenport)->pid\
                           );

                    usleep(10000); //sleep 10ms, so output is not mangled between forks
                }
            }


            /*
            If one or more processes or threads are blocked waiting to lock the semaphore with sem_wait(3),
            POSIX.1-2001 permits two possibilities for the value returned in sval:
            either 0 is returned; or a negative number whose absolute value is the count of the number of processes and threads
            currently blocked in sem_wait(3).
            Linux adopts the former behavior.
            */
            //For connection semaphore:
            sem_getvalue(consem, &sem_sval_1); //Look up number of processes waiting
            if(sem_sval_1 < 0) { //Test if processe(s) are waiting
                sleep(0.02);
                sem_getvalue(consem, &sem_sval_2); //Look up again after 0.02 sec.
                if (sem_sval_2 <= sem_sval_1) //Test if Number of processes stayed the same or growed
                    sem_post(consem); //If so, assume a deadlock situation happend and release one lock
            }
            //For header semaphore:
            sem_getvalue(hdrsem, &sem_sval_1); //Look up number of processes waiting
            if(sem_sval_1 < 0) { //Test if processe(s) are waiting
                sleep(0.02);
                sem_getvalue(hdrsem, &sem_sval_2); //Look up again after 0.02 sec.
                if (sem_sval_2 <= sem_sval_1) //Test if Number of processes stayed the same or growed
                    sem_post(hdrsem); //If so, assume a deadlock situation happend and release one lock
            }

            firstrun = false;
            sleep(2); //Watch for childs every 2 seconds.
        }
    }

    return 0;
}