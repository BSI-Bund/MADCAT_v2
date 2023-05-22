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
 *
 * BSI 2018-2023
*/

#include "tcp_ip_port_mon.helper.h"
#include "epollinterface.h" //struct free list and epoll_server_hdl for proxy signal handler

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

struct proxy_conf_tcp_t *pc; //globally defined to be easly accesible by functions

struct json_data_t *jd; //..defined globally as "jd" for easy access in all functions

//Helper functions

#include "madcat.helper.h"

void print_help_tcp(char* progname) //print help message
{
    fprintf(stderr, "SYNTAX:\n    %s path_to_config_file\n\
        Sample content of a config file:\n\n\
            \tinterface = \"enp0s8\"\n\
            \thostaddress = \"10.1.2.3\"\n\
            \tlistening_port = \"65535\"\n\
            \tconnection_timeout = \"10\"\n\
            \tuser = \"madcat\"\n\
            \tloglevel = 0 --optional: loglevel (0: Standard, 1: Debug)\n\
            \tpath_to_save_tcp_streams = \"./tpm/\" --Must end with trailing \"/\", will be handled as prefix otherwise\n\
            \t--max_file_size = \"1024\" --optional\n\
            \t--TCP Proxy configuration\n\
            \ttcpproxy = {\n\
            \t-- [<listen port>] = { \"<backend IP>\", <backend Port> },\n\
            \t\t[22]  = { \"192.168.10.222\", 22 },\n\
            \t\t[80]  = { \"192.168.20.80\", 8080 },\n\
            \t}\n\
        ", progname);

    fprintf(stderr, "\nLEGACY SYNTAX (pre v1.1.5):\n    %s interface hostaddress listening_port connection_timeout user path_to_save_tcp-streams [max_file_size]\n\
        Path to directory MUST end with a trailing slash, e.g.  \"/path/to/my/dir/\"\n\
        The last paramteter, max_file_size, is the maximum size of saved streams,\n\
        but the last TCP Datagramm exceeding this size will be saved anyway.\n", progname);

    fprintf(stderr,"\nExample Netfilter Rule to work properly:\n\
        iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 1:65534 -j DNAT --to 10.1.2.3:65535\n\
        Listening Port is 65535 and hostaddress is 10.1.2.3 in this example.\n\n\
    Must be run as root, but the priviliges will be droped to \"user\".\n\n\
    Opens two named pipes (FiFo) containing live JSON output:\n\
        \"%s\" for stream connection data, \"%s\" for header data.\n", CONNECT_FIFO, HEADER_FIFO);
    return;
}

int init_pcap(char* dev, char* dev_addr, pcap_t **handle, char* pcap_filter_str)
{
    char errbuf[PCAP_ERRBUF_SIZE];// Error string
    struct bpf_program fp;    // The compiled ct_filter, global to get freed. Free here?
    char filter_exp[ strlen(pcap_filter_str) + strlen(dev_addr) + 1 ]; //The ct_filter expression
    bpf_u_int32 mask;    // Our netmask
    bpf_u_int32 net;    // Our IP

    //Capture only TCP-SYN's...
    strncpy(filter_exp, pcap_filter_str, sizeof(filter_exp));
    //...for some systems (Linux Kernel >= 5 ???) own host IP has to be appended, so that the final ct_filter string looks like "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0 & dst host 1.2.3.4"
    strncat(filter_exp, dev_addr, sizeof(filter_exp) - sizeof(pcap_filter_str));

#if DEBUG >= 2
    fprintf(stderr, "*** DEBUG [PID %d] PCAP Filter Expression: \"%s\"\n", getpid(), filter_exp);
#endif

    // Find the properties for the device
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        return -1;
    // Open the session in non-promiscuous mode
    *handle = pcap_open_live(dev, BUFSIZ, 0, 100, errbuf);
    if (handle == NULL)
        return -2;
    // Compile and apply the ct_filter
    if (pcap_compile(*handle, &fp, filter_exp, 0, net) == -1)
        return -3;
    if (pcap_setfilter(*handle, &fp) == -1)
        return -4;

    free(fp.bf_insns);

    return 0;
}

void drop_root_privs(struct user_t user, const char* entity, bool silent) // if process is running as root, drop privileges
{
    if (getuid() == 0) {
        if (!silent) fprintf(stderr, "%s droping priviliges to user %s...", entity, user.name);
        get_user_ids(&user); //Get traget user UDI + GID
        CHECK(setgid(user.gid), == 0); // Drop GID first for security reasons!
        CHECK(setuid(user.uid), == 0);
        if (getuid() == 0 || getgid() == 0) { //Test if uid/gid is still 0
            if (!silent) fprintf(stderr, "...nothing to drop. WARNING: Running as root!\n");
        } else {
            if (!silent) fprintf(stderr,"SUCCESS. UID: %d\n", getuid());
        }
    }
    return;
}

//Handler

//Signal handler helper functioin with common frees, etc. for parents and childs
void sig_handler_common()
{
    static bool firstrun = true;
    if (firstrun) {
        //Free copies of proxy conf list
        pctcp_free_list(pc->portlist);
        free(pc);
        //free JSON output
        dict_free(json_dict(false));
        //release locks
        sem_post(hdrsem);
        sem_post(consem);
    }
    firstrun = false;
    return;
}

//Signal Handler for parent watchdog
void sig_handler_parent(int signo)
{
    static bool firstrun = true;
    if (firstrun) {
        char stop_time[64] = ""; //Human readable stop time (actual time zone)
        time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
        fprintf(stderr, "\n%s [PID %d] Parent Watchdog received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));

        int stat_accept = 0;

        for (int listenport = 1; listenport <65536; listenport++) {
            if ( pc->portmap[listenport] && !waitpid(pctcp_get_lport(pc, listenport)->pid, &stat_accept, WNOHANG) )
                kill(pctcp_get_lport(pc, listenport)->pid, SIGTERM);
        }

        //Check if forked childs are still alive
        //Give childs a chance to exit gracefull by sending SIGTERM
        if ( !waitpid(listner_pid, &stat_accept, WNOHANG) )
            kill(listner_pid, SIGTERM);

        if ( !waitpid(pcap_pid, &stat_accept, WNOHANG) )
            kill(pcap_pid, SIGTERM);

        sleep(1); //Childs sometimes hanging while exit() or _exit() call, thus send SIGKILL
        if ( !waitpid(listner_pid, &stat_accept, WNOHANG) )
            kill(listner_pid, SIGKILL);
        if ( !waitpid(pcap_pid, &stat_accept, WNOHANG) )
            kill(pcap_pid, SIGKILL);

        sig_handler_common();
    }
    firstrun = true;
    //exit parent process
    exit(signo);
    return;
}

//Signal Handler for Listner Parent to prevent childs becoming Zombies
void sig_handler_sigchld(int signo)
{
    pid_t pid;
    int status;

#if DEBUG >= 2
    fprintf(stderr, "*** DEBUG [PID %d] Entering  sig_handler_sigchld(%d).\n", getpid(), signo);
#endif

    do { //Search for other Childs
        pid = waitpid(-1, &status, WNOHANG);
#if DEBUG >= 2
        if (pid > 0 ) fprintf(stderr, "*** DEBUG [PID %d] Zombie child with PID %d exited with status %d.\n", getpid(), pid, status);
#endif
    } while ( pid > 0 );
    return;
}

//Signal Handler for childs
void sig_handler_pcapchild(int signo)
{
    static bool firstrun = true;
    if (firstrun) {
        if (signo == 6) //SIGABRT
            kill(getpid(), SIGKILL); //avoid calling exit() in forked childs, use kill instead!
        char stop_time[64] = ""; //Human readable stop time (actual time zone)
        time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
        fprintf(stderr, "\n%s [PID %d] Sniffer received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));

        sig_handler_common();
    }
    firstrun = false;
    kill(getpid(), SIGKILL); //avoid calling exit() in forked childs, use kill instead!
    return;
}

void sig_handler_listnerchild(int signo)
{
    static bool firstrun = true;
    pid_t kidpid = 0;
    int status = 0;
    if (firstrun) {
        char stop_time[64] = ""; //Human readable stop time (actual time zone)
        time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
        sig_handler_common();
        if (signo == SIGUSR2) { //Gracefull shutdown of Listern Accept childs
            if (loglevel > 0)
                fprintf(stderr, "%s [PID %d] Listner: Accept-Child is done. Bye.\n", stop_time, getpid());
            kill(getpid(), SIGKILL); //kill child process //exit may hang when used in forged child processes, thus using SIGKILL instead.; //exit(signo); //hangs sometimes under  high load>
        } else {
            fprintf(stderr, "\n%s [PID %d] Listner-Child received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));
#if DEBUG >= 2
            fprintf(stderr, "*** DEBUG [PID %d] Parent died, aborting.\n", getpid());
#endif
            return; //exit(signo); //hangs sometimes under high load
        }
    }
    firstrun = false;
    do
    {
        kidpid = waitpid(-1, &status, WNOHANG); //Check if childs have returned
    }
    while (kidpid > 0);
    kill(getpid(), SIGKILL); //kill child process //exit may hang when used in forged child processes, thus using SIGKILL instead.; //exit(signo); //hangs sometimes under  high load
    return;
}

void sig_handler_proxychild(int signo)
{
    static bool firstrun = true;
    if (firstrun) {
        char stop_time[64] = ""; //Human readable stop time (actual time zone)
        time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
        fprintf(stderr, "\n%s [PID %d] Proxy received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));
        jd_free_list(jd->list);
        free(jd);

        //free connections left in free list
        struct free_list_entry* temp;
        while (free_list != NULL) {
            free(free_list->block);
            temp = free_list->next;
            free(free_list);
            free_list = temp;
        }
        //free global epoll server socket handler
        free(epoll_server_hdl->closure);
        free(epoll_server_hdl);

#if DEBUG >= 2
        fprintf(stderr, "*** DEBUG [PID %d] Parent died, aborting.\n", getpid());
#endif
        sig_handler_common();
    }
    firstrun = false;
    kill(getpid(), SIGKILL); //kill child process //exit may hang when used in forged child processes, thus using SIGKILL instead.; //exit(signo); //hangs sometimes under  high load
    return;
}

//Signal Handler for SIGUSR1 to initiate gracefull shutdown, e.g. by CHECK-Macro
void sig_handler_shutdown(int signo)
{
#if DEBUG >= 2
    char stop_time[64] = ""; //Human readable stop time (actual time zone)
    time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
    fprintf(stderr, "\n%s [PID %d] Received Signal %s, shutting down...\n", stop_time, getpid(), strsignal(signo));
#endif
    if ( pcap_pid != 0 ) kill(pcap_pid, SIGINT);
    if ( listner_pid != 0 ) kill(listner_pid, SIGINT);
    _exit(-1); //exit() somtimes hangs, see man _exit and man exit
    return;
}

//Helper functions for proxy configuration

int get_config_table(lua_State* L, char* name, struct proxy_conf_tcp_t* pc) //read proxy configuration from parsed LUA-File by luaL_dofile(...). Returns number of read elements.
{
    char* backendaddr = 0;
    int backendport = 0;

    int num_elements = 0;

    lua_getglobal(L, name); //push objekt "name" to stack and...

    if ( !lua_istable(L, -1) ) { //...check if this objekt is a table
        fprintf(stderr, "\tNo proxy config found. Variable \"%s\" must be a LUA table.\n", name);
        return num_elements;
    }

    //Iterate over all possible portnumbers.
    //Think about a more clever solution?
    for (int listenport = 0; listenport<65536; listenport++) {

        lua_pushnumber(L, listenport); //push actuall portnumber on stack and...
        lua_gettable(L, -2);  //...call lua_gettable with this portnumber as key
        if( !lua_isnil(L,-1) ) { //if corresponding value is not NIL...
            lua_pushnumber(L, 1); //push "1" on the stack for the first elemnt in sub-table and...
            lua_gettable(L, -2);  //...fetch this entry
            backendaddr = (char*) lua_tostring(L, -1);
            lua_pop(L, 1); //remove result from stack

            lua_pushnumber(L, 2); //push "2" on the stack for the second elemnt in sub-table and...
            lua_gettable(L, -2); //...fetch this entry
            backendport = lua_tonumber(L, -1);
            lua_pop(L, 1);  //remove result from stack

            pctcp_push(pc, listenport, backendaddr, backendport);
            pc->portmap[listenport] = true;
            num_elements++;
        }
        lua_pop(L, 1); //remove sub-table from stack
    }
    return num_elements;
}

struct proxy_conf_tcp_t* pctcp_init() //initialize proxy configuration
{
    struct proxy_conf_tcp_t* pc = malloc (sizeof(struct proxy_conf_tcp_t));
    pc->portlist = 0; //set headpointer to 0
    for (int listenport = 0; listenport<65536; listenport++) pc->portmap[listenport] = false; //initilze map of ports used to proxy network traffic
    return pc;
}

void pctcp_push(struct proxy_conf_tcp_t* pc, int listenport, char* backendaddr, int backendport) //push new proxy configuration item to linked list
{
    struct proxy_conf_tcp_node_t* pctcp_node = malloc (sizeof(struct proxy_conf_tcp_node_t));

    pctcp_node->listenport = listenport;
    snprintf(pctcp_node->listenport_str, PCN_STRLEN, "%d", listenport);
    pctcp_node->backendaddr = malloc(strlen(backendaddr)+1);
    strncpy(pctcp_node->backendaddr, backendaddr, strlen(backendaddr)+1);
    pctcp_node->backendport = backendport;
    snprintf(pctcp_node->backendport_str, PCN_STRLEN, "%d", backendport);

    pctcp_node->pid = 0; //Set pid for proxy for this configuration to 0, because it is not running yet.

    pctcp_node->next = pc->portlist;
    pc->portlist = pctcp_node;
    pc->num_elements++;
    return;
}

struct proxy_conf_tcp_node_t* pctcp_get_lport(struct proxy_conf_tcp_t* pc, int listenport) //get proxy configuration for listenport
{
    struct proxy_conf_tcp_node_t* result = pc->portlist;
    while ( result != 0) {
        if(result->listenport == listenport) return result;
        result = result->next;
    }
    return 0;
}

struct proxy_conf_tcp_node_t* pctcp_get_pid(struct proxy_conf_tcp_t* pc, pid_t pid) //get proxy configuration for proxy with Process ID "pid"
{
    struct proxy_conf_tcp_node_t* result = pc->portlist;
    while ( result != 0) {
        if(result->pid == pid) return result;
        result = result->next;
    }
    return 0;
}

void pctcp_free_list(struct proxy_conf_tcp_node_t* pctcp_node)
{
    if (pctcp_node != NULL) {
        pctcp_free_list(pctcp_node->next);
        free(pctcp_node->backendaddr);
        free(pctcp_node);
    }
    return;
}

void pctcp_print(struct proxy_conf_tcp_t* pc) //print proxy configuration
{
    struct proxy_conf_tcp_node_t* pctcp_node = pc->portlist;
    while ( pctcp_node != NULL) {
        fprintf(stderr, "\tProxy local port: %d -> Backend socket: %s:%d\n", pctcp_node->listenport, pctcp_node->backendaddr, pctcp_node->backendport);
        pctcp_node = pctcp_node->next;
    }
    return;
}

//Helper functions for json data structure and double linked list

struct json_data_t* jd_init()  //initialize json data structure
{
    struct json_data_t* jd = malloc (sizeof(struct json_data_t));
    jd->list = 0;
    return jd;
}

void jd_push(struct json_data_t* jd, long long unsigned int id) //push new json data list node wit id "id" to list
{
    struct json_data_node_t* jd_node = malloc (sizeof(struct json_data_node_t)); //new node

    //initialize inside variables
    jd_node->id = id;
    jd_node->src_ip =  EMPTY_STR;
    jd_node->src_port = 0;
    jd_node->dest_ip =  EMPTY_STR;
    jd_node->dest_port =  EMPTY_STR;
    jd_node->timestamp =  EMPTY_STR;
    jd_node->unixtime =  EMPTY_STR;
    jd_node->start =  EMPTY_STR;
    jd_node->end =  EMPTY_STR;
    jd_node->duration = 0;
    jd_node->min_rtt = 0;
    jd_node->last_recv = 0;
    jd_node->firstpacket = true;
    jd_node->bytes_toserver =  0;
    jd_node->bytes_toclient =  0;
    jd_node->proxy_ip =  EMPTY_STR;
    jd_node->proxy_port =  0;
    jd_node->backend_ip =  EMPTY_STR;
    jd_node->backend_port =  EMPTY_STR;

    //push element to beginning of list
    //More efficient, when appendig to end?
    if(jd->list != 0) jd->list->prev=jd_node;
    jd_node->next = jd->list;
    jd->list = jd_node;
    jd_node->prev = 0;

    return;
}

struct json_data_node_t* jd_get(struct json_data_t* jd, uintptr_t id) //get json data node by id
{
    struct json_data_node_t* result = jd->list;
    while ( result != 0) {
        if(result->id == id) return result;
        result = result->next;
    }
    return 0;
}

bool jd_del(struct json_data_t* jd, uintptr_t id)  //remove json data node by id
{
    struct json_data_node_t* jd_node = jd_get(jd, id);
    if (jd_node == 0) return false;

    //free all strings if not identical to initial constant string of "EMPTY_STR"
    if (jd_node->src_ip != EMPTY_STR) free(jd_node->src_ip);
    if (jd_node->dest_ip !=  EMPTY_STR) free(jd_node->dest_ip);
    if (jd_node->dest_port !=  EMPTY_STR) free(jd_node->dest_port);
    if (jd_node->timestamp !=  EMPTY_STR) free(jd_node->timestamp);
    if (jd_node->unixtime !=  EMPTY_STR) free(jd_node->unixtime);
    if (jd_node->start !=  EMPTY_STR) free(jd_node->start);
    if (jd_node->end !=  EMPTY_STR) free(jd_node->end);
    if (jd_node->proxy_ip !=  EMPTY_STR) free(jd_node->proxy_ip);
    if (jd_node->backend_ip !=  EMPTY_STR) free(jd_node->backend_ip);
    if (jd_node->backend_port !=  EMPTY_STR) free(jd_node->backend_port);

    //reorganize list pointers
    if (jd_node == jd->list) jd->list = jd_node->next; //Is it the head node?
    if (jd_node->prev != 0) jd_node->prev->next = jd_node->next;
    if (jd_node->next != 0) jd_node->next->prev = jd_node->prev;

    free(jd_node); //free the node element itself

    return true;
}

void jd_free_list(struct json_data_node_t* jd_node) //free list with json data
{
    if (jd_node != NULL) {
        jd_free_list(jd_node->next);
        jd_del(jd, jd_node->id);
    }
    return;
}

void jd_print_list(struct json_data_t* jd) //print complete json data list
{
    struct json_data_node_t* jd_node = jd->list;

    fprintf(stderr, "\n<START>\n");

    while ( jd_node != 0 ) {
        fprintf(stderr, "\n\
long long unsigned int id: %lx\n\
void* jd_node: %lx\n\
struct json_data_node_t *next: %lx\n\
struct json_data_node_t *prev: %lx\n\
char* src_ip: %s\n\
int   src_port: %d\n\
char* dest_ip: %s\n\
char* dest_port: %s\n\
char* timestamp: %s\n\
char* unixtime: %s\n\
char* start: %s\n\
char* end: %s\n\
long long unsigned int bytes_toserver: %lld\n\
long long unsigned int bytes_toclient: %lld\n\
char* proxy_ip: %s\n\
int   proxy_port: %d\n\
char* backend_ip: %s\n\
char* backend_port: %s\n\
\n",\
                (long unsigned int) jd_node->id,\
                (long unsigned int) jd_node,
                (long unsigned int) jd_node->next,\
                (long unsigned int) jd_node->prev,\
                jd_node->src_ip,\
                jd_node->src_port,\
                jd_node->dest_ip,\
                jd_node->dest_port,\
                jd_node->timestamp,\
                jd_node->unixtime,\
                jd_node->start,\
                jd_node->end,\
                jd_node->bytes_toserver,\
                jd_node->bytes_toclient,\
                jd_node->proxy_ip,\
                jd_node->proxy_port,\
                jd_node->backend_ip,\
                jd_node->backend_port\
               );

        jd_node = jd_node->next;
    }

    fprintf(stderr, "<END>\n\n");
    return;
}

/********* Conntrack *********/
#ifdef CT_ENABLED
/*
* Usage of conntrack is experimental,
* thus using conntrack in heavy load scenarios may have a severe perfomance impact
* and may lead to errors!
* Using of conntrack lookup in TCP Postprocessing instead is adviced!
*/
int conntrack_init()
{
    int ret = 0;

    ct_handle = nfct_open(CONNTRACK, 0);
    if (!ct_handle) {
        return -1;
    }

    ct_filter = nfct_new();
    if (!ct_filter) {
        return -1;
    }

    nfct_callback_register(ct_handle, NFCT_T_ALL, conntrack_callback, ct_filter);

    return 0;
}

int conntrack_query(in_addr_t ipv4_dst, in_port_t dest_port, in_addr_t ipv4_src, in_port_t src_port)
{
    int ret = 0;
    uint8_t family = AF_INET;

    nfct_set_attr_u8(ct_filter, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ct_filter, ATTR_IPV4_SRC, ipv4_src);
    nfct_set_attr_u32(ct_filter, ATTR_IPV4_DST, ipv4_dst);

    nfct_set_attr_u8(ct_filter, ATTR_L4PROTO, IPPROTO_TCP);
    nfct_set_attr_u16(ct_filter, ATTR_PORT_SRC, src_port);
    nfct_set_attr_u16(ct_filter, ATTR_PORT_DST, dest_port);

    ret = nfct_query(ct_handle, NFCT_Q_DUMP, &family);

    return ret;
}

void conntrack_close()
{
    nfct_destroy(ct_filter);
    nfct_close(ct_handle);
    return;
}


int conntrack_callback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    char buf[1024];

    if (!nfct_cmp(data, ct, NFCT_CMP_ALL | NFCT_CMP_MASK))
        return NFCT_CB_CONTINUE;

    nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_ALL, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3);
    //Example buf content:
    //ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.2.178 dst=192.168.2.99 sport=51298 dport=45000 src=192.168.2.99 dst=192.168.2.178 sport=65535 dport=51298 [ASSURED] mark=0 use=1

    char delimiter[] = " =";
    char *ptr;
    //initialze strtok
    ptr = strtok(buf, delimiter);

    while(ptr != NULL) {
        //get next
        ptr = strtok(NULL, delimiter);
        if(strcmp(ptr, "sport") == 0) { //next one is the port we are searching for
            ptr = strtok(NULL, delimiter);
            ct_org_srcport = atoi(ptr);
            return NFCT_CB_STOP;
        }
    }

    return NFCT_CB_CONTINUE;
}
#endif