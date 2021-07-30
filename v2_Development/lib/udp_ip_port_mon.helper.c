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
/* MADCAT -Mass Attack Detecion Connection Acceptance Tool
 * UDP port monitor.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2021
*/

//Helper Functions
#include "madcat.helper.h"
#include "udp_ip_port_mon.icmp_mon.helper.h"
#include "udp_ip_port_mon.helper.h"
#include "udp_ip_port_mon.parser.h"

void print_help_udp(char* progname) //print help message
{
    fprintf(stderr, "SYNTAX:\n    %s path_to_config_file\n\
        Sample content of a config file:\n\n\
            \thostaddress = \"127.1.1.1\"\n\
            \tuser = \"hf\"\n\
            \tloglevel = 0 --optional: loglevel (0: Standard, 1: Debug)\n\
            \tpath_to_save_udp_data = \"./upm/\" --Must end with trailing \"/\", will be handled as prefix otherwise\n\
            \t--bufsize = \"1024\" --optional\n\
            \t--UDP Proxy configuration\n\
            \tudpproxy_tobackend_addr = \"192.168.2.199\" --Local address to communicate to backends with. Mandatory, if \"udpproxy\" is configured.\n\
            \tudpproxy_connection_timeout = \"3\" --Timeout for UDP \"Connections\". Optional, but only usefull if \"udpproxy\" is configured.\n\
            \tudpproxy = { -- [<listen port>] = { \"<backend IP>\", <backend Port> },\n\
            \t            [64000] = { \"192.168.2.50\", 64000 },\n\
            \t            [533]   = { \"8.8.8.8\", 53},\n\
            \t            [534]   = { \"8.8.8.8\", 53},\n\
            \t            }\n\
        ", progname);

    fprintf(stderr, "\nLEGACY SYNTAX (pre v1.1.5)t: %s hostaddress path_to_save_udp-data user [buffer_size]\n\tBuffer Size defaults to %d Bytes.\n \
\tPath to directory MUST end with a trailing slash, e.g.  \"/path/to/my/dir/\"\n\n \
Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.\n \
\tiptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP\n\n \
\tMust be run as root, but the priviliges will be droped to user after the socket has been opened.\n", progname, DEFAULT_BUFSIZE);

    return;
}

//Signal Handler for gracefull shutdown
void sig_handler_udp(int signo)
{
    char stop_time[64] = ""; //Human readable stop time (actual time zone)
    time_str(NULL, 0, stop_time, sizeof(stop_time)); //Get Human readable string only
    fprintf(stderr, "\n%s Received Signal %s, shutting down...\n", stop_time, strsignal(signo));
    //close sempahore
    CHECK(sem_close(conlistsem), == 0);
    // Free buffers
    free(saved_buffer(0));
    free(json_do(true,""));
    //Chancel Threads
    pthread_cancel(cleanup_t_id);
    pthread_join(cleanup_t_id, NULL);
    //free linked lists
    uc_free_list(uc->list);
    free(uc);
    pcudp_free_list(pc->portlist);
    free(pc);
    //exit parent process
    exit(signo);
    return;
}

//Helper functions for proxy configuration

int get_config_table(lua_State* L, char* name, struct proxy_conf_udp_t* pc) //read proxy configuration from parsed LUA-File by luaL_dofile(...). Returns number of read elements.
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

            pcudp_push(pc, listenport, backendaddr, backendport);
            pc->portmap[listenport] = true;
            num_elements++;
        }
        lua_pop(L, 1); //remove sub-table from stack
    }
    return num_elements;
}

struct proxy_conf_udp_t* pcudp_init() //initialize proxy configuration
{
    struct proxy_conf_udp_t* pc = malloc (sizeof(struct proxy_conf_udp_t));
    pc->portlist = 0; //set headpointer to 0
    for (int listenport = 0; listenport<65536; listenport++) pc->portmap[listenport] = false; //initilze map of ports used to proxy network traffic
    return pc;
}

void pcudp_push(struct proxy_conf_udp_t* pc, int listenport, char* backendaddr, int backendport) //push new proxy configuration item to linked list
{
    struct proxy_conf_udp_node_t* pcudp_node = malloc (sizeof(struct proxy_conf_udp_node_t));

    pcudp_node->listenport = listenport;
    snprintf(pcudp_node->listenport_str, PCN_STRLEN, "%d", listenport);
    //Make copy to gain full control over data and circumvent data corruption by e.g. free(backendaddr) in calling function.
    pcudp_node->backendaddr = malloc(strlen(backendaddr)+1);
    strncpy(pcudp_node->backendaddr, backendaddr, strlen(backendaddr)+1);
    pcudp_node->backendport = backendport;
    snprintf(pcudp_node->backendport_str, PCN_STRLEN, "%d", backendport);

    pcudp_node->next = pc->portlist;
    pc->portlist = pcudp_node;
    pc->num_elements++;
    return;
}

struct proxy_conf_udp_node_t* pcudp_get_lport(struct proxy_conf_udp_t* pc, int listenport) //get proxy configuration for listenport
{
    struct proxy_conf_udp_node_t* result = pc->portlist;
    while ( result != 0) {
        if(result->listenport == listenport) return result;
        result = result->next;
    }
    return 0;
}

void pcudp_free_list(struct proxy_conf_udp_node_t* pcudp_node)
{
    if (pcudp_node != NULL) {
        pcudp_free_list(pcudp_node->next);
        free(pcudp_node->backendaddr);
        free(pcudp_node);
    }
    return;
}

void pcudp_print(struct proxy_conf_udp_t* pc) //print proxy configuration
{
    struct proxy_conf_udp_node_t* pcudp_node = pc->portlist;
    while ( pcudp_node != 0) {
        fprintf(stderr, "\tProxy local port: %d -> Backend socket: %s:%d\n", pcudp_node->listenport, pcudp_node->backendaddr, pcudp_node->backendport);
        pcudp_node = pcudp_node->next;
    }
    return;
}

//udp connection structures and double linked list

struct udpcon_data_t* uc_init()
{
    struct udpcon_data_t* uc = malloc (sizeof(struct udpcon_data_t));
    uc->list = 0;
    return uc;
}

void uc_free_list(struct udpcon_data_node_t* uc_node)
{
    if (uc_node != NULL) {
        uc_free_list(uc_node->next);
        uc_del(uc, uc_node->id_fromclient);
    }
    return;
}

udpcon_id_t* uc_genlid(char* src_ip, uint64_t src_port, char* dest_ip, uint64_t dest_port, udpcon_id_t* output)
{
    udpcon_id_t* id = 0;
    uint64_t id_src = 0;
    uint64_t id_dest = 0;
    struct sockaddr_in src_sa;
    struct sockaddr_in dest_sa;

    if(output == NULL) id = malloc(sizeof(udpcon_id_t));
    else id = output;

    inet_pton(AF_INET, src_ip, &(src_sa.sin_addr));
    inet_pton(AF_INET, dest_ip, &(dest_sa.sin_addr));
    //Concatinate IPs and Ports.
    /*Shifting portnumbers to higher bits makes IDs most times (client src_port > backend dest_port) easier to distinguish,
        thus better human readable, if multiple connections from one IP occur*/
    id_src = (uint64_t) src_port << 32 | src_sa.sin_addr.s_addr;
    id_dest = (uint64_t) dest_port << 32 | dest_sa.sin_addr.s_addr;
    if(id_src > id_dest) { //Make Comparable
        id->high = id_src;
        id->low = id_dest;
    } else {
        id->low = id_src;
        id->high = id_dest;
    }

    if(output == NULL) {
        id->str = uc_strlid(id, NULL);
        id->malloced = true;
    } else {
        uc_strlid(id, id->__str);
        id->str = id->__str;
        id->malloced = false;
    }

    id->masked_id = id->high ^ id->low ^ sessionkey;

    return id;
}

bool uc_eqlid(udpcon_id_t* id_1, udpcon_id_t* id_2)
{
    if(id_1->high == id_2->high && id_1->low == id_2->low) return true;
    else return false;
}

char* uc_strlid(udpcon_id_t* id, char* out_25B)
{
    int len = 2*12+1;
    char* output = 0;

    if(out_25B == NULL) output = malloc(len);
    else output = out_25B;

    snprintf(output, len, "%012jx%012jx", id->high, id->low);
    return output;
}


struct udpcon_data_node_t* uc_push(struct udpcon_data_t* uc, udpcon_id_t id)
{
    struct udpcon_data_node_t* uc_node = malloc(sizeof(struct udpcon_data_node_t));

    //IDs
    memcpy(&(uc_node->id_fromclient), &id, sizeof(uc_node->id_fromclient));
    if(!uc_node->id_fromclient.malloced) uc_node->id_fromclient.str = uc_node->id_fromclient.__str;

    uc_node->id_tobackend.high = 0;
    uc_node->id_tobackend.low = 0;
    uc_node->id_tobackend.malloced = false;
    uc_node->id_tobackend.str = EMPTY_STR;
    uc_node->id_tobackend.__str[0] = 0;

    //Sockets
    uc_node->backend_socket = NULL;
    uc_node->backend_socket_fd = 0;
    uc_node->client_socket = NULL;
    uc_node->client_socket_fd = 0;

    //Proxy + timeout
    uc_node->last_seen = 0;
    uc_node->min_rtt = 0;
    uc_node->proxied = false;

    //DATA
    uc_node->src_ip =  EMPTY_STR;
    uc_node->src_port = 0;
    uc_node->dest_ip =  EMPTY_STR;
    uc_node->dest_port =  0;
    uc_node->timestamp =  EMPTY_STR;
    uc_node->unixtime =  0;
    uc_node->timeasdouble = 0;
    uc_node->start =  EMPTY_STR;
    uc_node->end =  EMPTY_STR;
    uc_node->bytes_toserver =  0;
    uc_node->bytes_toclient =  0;
    uc_node->proxy_ip = EMPTY_STR;
    uc_node->proxy_port =  0;
    uc_node->backend_ip =  EMPTY_STR;
    uc_node->backend_port =  0;

    uc_node->payload = NULL;
    uc_node->payload_len = 0;
    uc_node->first_dgram = NULL;
    uc_node->first_dgram_len = 0;

    if(uc->list != NULL) uc->list->prev=uc_node;
    uc_node->next = uc->list;
    uc->list = uc_node;
    uc_node->prev = NULL;

    return uc_node;
}

struct udpcon_data_node_t* uc_get(struct udpcon_data_t* uc, udpcon_id_t id)
{
    struct udpcon_data_node_t* result = uc->list;
    while ( result != 0) {
        if(uc_eqlid(&(result->id_fromclient), &id) || uc_eqlid(&(result->id_tobackend),&id)) return result;
        result = result->next;
    }
    return result;
}

bool uc_del(struct udpcon_data_t* uc, udpcon_id_t id)
{
    //re-implentation of uc_get to archive thread safeness (may not be needed in every case, but saves a function call anyway)
    struct udpcon_data_node_t* uc_node = uc->list;
    while ( uc_node != 0) {
        if(uc_node = uc_get(uc, id)) break;
        uc_node = uc_node->next;
    }
    if (uc_node == 0) return false;

    //Close sockets
    if(uc_node->client_socket_fd != 0) close(uc_node->client_socket_fd);
    if(uc_node->backend_socket_fd != 0) close(uc_node->backend_socket_fd);

    //Free
    if (uc_node->backend_socket != NULL) free(uc_node->backend_socket);
    if (uc_node->client_socket != NULL) free(uc_node->client_socket);
    if (uc_node->src_ip != EMPTY_STR) free(uc_node->src_ip);
    if (uc_node->dest_ip !=  EMPTY_STR) free(uc_node->dest_ip);
    if (uc_node->timestamp !=  EMPTY_STR) free(uc_node->timestamp);
    if (uc_node->start !=  EMPTY_STR) free(uc_node->start);
    if (uc_node->end !=  EMPTY_STR) free(uc_node->end);
    if (uc_node->proxy_ip !=  EMPTY_STR) free(uc_node->proxy_ip);
    if (uc_node->backend_ip !=  EMPTY_STR) free(uc_node->backend_ip);
    if (uc_node->payload != NULL) free(uc_node->payload);
    if (uc_node->first_dgram != NULL) free(uc_node->first_dgram);
    if(uc_node->id_fromclient.malloced) free(uc_node->id_fromclient.str);
    if(uc_node->id_tobackend.malloced) free(uc_node->id_tobackend.str);

    //Rearange pointers
    if (uc_node == uc->list) uc->list = uc_node->next;
    if (uc_node->prev != NULL) uc_node->prev->next = uc_node->next;
    if (uc_node->next != NULL) uc_node->next->prev = uc_node->prev;

    //Free the list element itself
    free(uc_node);
    return true;
}

int uc_cleanup(struct udpcon_data_t* uc, long long int timeout)
{
    struct timespec sem_timeout; //time to wait in sem_timedwait() call
    clock_gettime(CLOCK_REALTIME, &sem_timeout);
    sem_timeout.tv_sec += 1;
    sem_timedwait(conlistsem, &sem_timeout);
    struct udpcon_data_node_t* uc_node = uc->list;
    char unix_time_str[64] = "";
    time_str(unix_time_str, sizeof(unix_time_str), NULL, 0); ///Get current time and generate string with current time
    long long int unix_time = atoll(unix_time_str);
    int num_removed = 0;
    struct udpcon_data_node_t* next = NULL;

    while ( uc_node != NULL ) {
        next = uc_node->next; //save next pointer, because the element might be deleted.
        if(uc_node->last_seen + timeout < unix_time) {
            sem_post(conlistsem); //spare out the call to json_out, calculation of SHA1 over payloads may take quite some time.
            json_out(uc_node);
            clock_gettime(CLOCK_REALTIME, &sem_timeout);
            sem_timeout.tv_sec += 1;
            sem_timedwait(conlistsem, &sem_timeout);
            if(uc_del(uc, uc_node->id_fromclient)) {
                num_removed++;
            } else {
                sem_post(conlistsem);
                return -1;
            }
        }
        uc_node = next; //Next pointer always contains an element, regardless of main thread, because only here in this function uc_del is called
    }
    sem_post(conlistsem);
    return num_removed;
}

void uc_print_list(struct udpcon_data_t* uc)
{
    struct udpcon_data_node_t* uc_node = uc->list;

    fprintf(stderr, "\n<START>\n");

    while ( uc_node != 0 ) {
        fprintf(stderr, "\n\
udpcon_id_t id_fromclient: %s\n\
udpcon_id_t id_tobackend: %s\n\
void* uc_node: %lx\n\
struct udpcon_data_node_t *next: %lx\n\
struct udpcon_data_node_t *prev: %lx\n\
bool proxied: %s\n\
long long int last_seen: %llu\n\
char* src_ip: %s\n\
int   src_port: %d\n\
char* dest_ip: %s\n\
char* dest_port: %d\n\
char* timestamp: %s\n\
char* unixtime: %llu\n\
long double timeasdouble: %Lf\n\
char* start: %s\n\
char* end: %s\n\
long long unsigned int bytes_toserver: %lld\n\
long long unsigned int bytes_toclient: %lld\n\
char* proxy_ip: %s\n\
int   proxy_port: %d\n\
char* backend_ip: %s\n\
char* backend_port: %d\n\
\n",\
                uc_node->id_fromclient.str,\
                uc_node->id_tobackend.str,\
                (long unsigned int) uc_node,
                (long unsigned int) uc_node->next,\
                (long unsigned int) uc_node->prev,\
                uc_node->proxied ? "true" : "false",\
                uc_node->last_seen,\
                uc_node->src_ip,\
                uc_node->src_port,\
                uc_node->dest_ip,\
                uc_node->dest_port,\
                uc_node->timestamp,\
                uc_node->unixtime,\
                uc_node->timeasdouble,\
                uc_node->start,\
                uc_node->end,\
                uc_node->bytes_toserver,\
                uc_node->bytes_toclient,\
                uc_node->proxy_ip,\
                uc_node->proxy_port,\
                uc_node->backend_ip,\
                uc_node->backend_port\
               );

        uc_node = uc_node->next;
    }

    fprintf(stderr, "<END>\n\n");
    return;
}

void json_out(struct udpcon_data_node_t* uc_node)
{
    char* payload_hd_str = "NONE"; //Payload as string in HexDump Format
    char* payload_str = "NONE"; //Payload as string
    char * payload_sha1_str = "NONE"; //Paylod SHA1 hash
    unsigned char payload_sha1[SHA_DIGEST_LENGTH]; //SHA1 of payload

    //Begin JSON output and open new JSON
    //Log connection to STDOUT in json-format (Suricata-like)
    json_do(true, "{\"origin\":\"MADCAT\", \
\"src_ip\":\"%s\", \
\"dest_port\": %d, \
\"timestamp\":\"%s\", \
\"unixtime\": %lld, \
\"dest_ip\":\"%s\", \
\"src_port\": %d, \
\"proto\":\"%s\", \
\"event_type\":\"%s\", \
\"FLOW\": { \
\"start\":\"%s\", \
\"end\":\"%s\", \
\"duration\":%Lf,  \
\"min_rtt\":%Lf,  \
\"bytes_toserver\": %lld, \
\"bytes_toclient\": %lld\
",\
            uc_node->src_ip,\
            uc_node->dest_port,\
            uc_node->timestamp,\
            uc_node->unixtime,\
            uc_node->dest_ip,\
            uc_node->src_port,\
            "UDP",\
            uc_node->proxied ? "proxy_flow" : "flow",\
            uc_node->start,\
            uc_node->end,\
            uc_node->duration,\
            uc_node->min_rtt,\
            uc_node->bytes_toserver,\
            uc_node->bytes_toclient\
           );

    if( uc_node->proxied ) { //Proxy specific JSON output
        json_do(false, ",\
\"proxy_ip\":\"%s\", \
\"proxy_port\": %d, \
\"backend_ip\":\"%s\",\
\"backend_port\": %d\
",\
                uc_node->proxy_ip,\
                uc_node->proxy_port,\
                uc_node->backend_ip,\
                uc_node->backend_port\
               );
    }
    //Do only include payload and compute sha1, if this was not a connection handled by proxy.
    //Overhead might easily become too large and it is intended to be logged and processed by backend, anyway.
    else {
        //Compute SHA1 of payload
        SHA1(uc_node->payload, uc_node->payload_len, payload_sha1);
        payload_sha1_str = print_hex_string(payload_sha1, SHA_DIGEST_LENGTH);
        //Make HexDump output out of binary payload
        payload_hd_str = hex_dump(uc_node->payload, uc_node->payload_len, true); //must be freed
        payload_str = print_hex_string(uc_node->payload, uc_node->payload_len); //must be freed

        json_do(false, ",\
\"payload_hd\":\"%s\", \
\"payload_str\":\"%s\", \
\"payload_sha1\":\"%s\"\
",\
                payload_hd_str,\
                payload_str,\
                payload_sha1_str\
               );
        //free
        free(payload_sha1_str);
        free(payload_str);
        free(payload_hd_str);
    }

    json_do(false, "} "); //close this JSON part
    //Analyse IP & TCP Headers and concat to global JSON (done inside functions with json_do(...))
    analyze_ip_header(uc_node->first_dgram, uc_node->first_dgram_len);
    analyze_udp_header(uc_node->first_dgram, uc_node->first_dgram_len);
    //close JSON object and print it to stdout for logging
    fprintf(stdout,"%s\n", json_do(false, "}")); //print json output for logging and further analysis
    fflush(stdout);

    return;
}

uint64_t rand64() //Generates a random uint_64, using /dev/random or rand() as backup
{
    //This function is intended to be called once during startup to generate, so performance impact is not really important.
    uint64_t r64 = 0;
    FILE* fp = fopen("/dev/random", "rb");
    size_t read_elem = 0;

    if(fp != 0) {
        read_elem = fread(&r64, sizeof(uint64_t), 1, fp);
        fclose(fp);
    }

    if(fp == 0 || read_elem != 1) { //Generate random from time seed as backup
        time_t t;
        srand((unsigned) time(&t)); //init random number generator with time in seconds

        //RAND_MAX is guaranteed to be at least 32767 = 2^15, providing at least 15 random bits when rand() is called.
        for(int i = 0; i<64; i+=15) {
            r64 = r64 << 15 | rand();
        }
        fprintf(stderr, "WARNING: Possible weak random value generated by rand64()!\n");
    }

    return r64;
}