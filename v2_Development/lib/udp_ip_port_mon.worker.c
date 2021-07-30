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
 * UDP port monitor.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2021
*/

#include "udp_ip_port_mon.worker.h"
#include "udp_ip_port_mon.helper.h"


int worker_udp(unsigned char* buffer, int recv_len, char* hostaddress, char* data_path)
{
    struct ipv4udp_t ipv4udp; //struct to save IP-Header contents of intrest
    char* payload_hd_str = 0; //Payload as string in HexDump Format
    char* payload_str = 0; //Payload as string
    unsigned char payload_sha1[SHA_DIGEST_LENGTH]; //SHA1 of payload
    char * payload_sha1_str = 0;
    FILE *file = 0;
    char file_name[2*PATH_LEN] = ""; //double path length for concatination purposes. PATH_LEN *MUST* be enforced when combinating path and filename!
    struct timeval begin;
    char log_time[64] = "";
    char log_time_unix[64] ="";
    char stop_time[64] = "";
    char stop_time_unix[64] = "";
    //beginning time
    long double unix_timeasdouble = time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time)); //...generate string with current time
    //Proxy connection ID
    udpcon_id_t id;
    struct udpcon_data_node_t* uc_con = 0; //Active proxy connection matching this ID, will be 0 if none matches

    if (recv_len < 28) { //Minimum 20 Byte IP Header + 8 Byte UDP Header. Should never happen.
        fprintf(stderr, "%s ALERT: Paket to short for UDP over IPv4, dumping %d Bytes of data:\n", log_time, recv_len);
        print_hex(stderr, buffer, recv_len); //Dump malformed paket for analysis
        return -1;
    }
    //Check IPv4 Header
    ipv4udp.type = (uint8_t) (buffer[0] & 0b11110000) >> 4; //IPv4 should have set it's version field to, well, "4".
    ipv4udp.ihl = (uint8_t) ((buffer[0] & 0b00001111) * 32) / 8; //IP Header length is given in multipels of 32 bit or 4 Byte, respectively
    ipv4udp.proto = (uint8_t) buffer[9]; //Proto should be 17 (UDP), because it's a RAW IP/UDP Socket.
    //Fetch IPs and convert them to strings.
    ipv4udp.src_ip = *(uint32_t*) (buffer+12);
    ipv4udp.src_ip_str = inttoa(ipv4udp.src_ip);
    ipv4udp.dest_ip = *(uint32_t*) (buffer+16);
    ipv4udp.dest_ip_str = inttoa(ipv4udp.dest_ip);

    //Things that should never ever happen.
    if( ipv4udp.type != 4 || ipv4udp.ihl < 20 || ipv4udp.ihl > 60 || (ipv4udp.ihl + UDP_HEADER_LEN) > recv_len  || ipv4udp.proto != 17 ) {
        fprintf(stderr, "%s ALERT: Malformed Paket. Dumping %d Bytes of data:\n", log_time, recv_len);
        print_hex(stderr, buffer, recv_len);
        free(ipv4udp.src_ip_str);
        free(ipv4udp.dest_ip_str);
        return -1;
    }
    //Fetch ports by using the value from IP Header Length-Field, which has been check by the if statement above, so it should be save to use for addressing
    ipv4udp.src_port = ntohs(*(uint16_t*) (buffer + ipv4udp.ihl));
    ipv4udp.dest_port = ntohs(*(uint16_t*) (buffer + ipv4udp.ihl + sizeof(uint16_t)));
    ipv4udp.data_len = recv_len - (ipv4udp.ihl + UDP_HEADER_LEN);
    ipv4udp.data = buffer + ipv4udp.ihl + UDP_HEADER_LEN;

    uc_genlid(ipv4udp.src_ip_str, ipv4udp.src_port, ipv4udp.dest_ip_str, ipv4udp.dest_port, &id); //Proxy connection ID
    uc_con = uc_get(uc, id); //Active connection matching this ID, will be 0 if none matches

    //Ignore Pakets, that have not been addressed to an IP given by config (host or proxy backend)
    if(strcmp(ipv4udp.dest_ip_str, hostaddress) != 0 && strcmp("0.0.0.0", hostaddress) !=0 && uc_con == 0) {
        free(ipv4udp.src_ip_str);
        free(ipv4udp.dest_ip_str);
        return -1;
    }

    //Log connection
    if(loglevel>0) {
        fprintf(stderr, "%s Received packet from %s:%u to %s:%u with %d Bytes of DATA (Connection-ID: %s).\n", log_time, \
                ipv4udp.src_ip_str, ipv4udp.src_port, ipv4udp.dest_ip_str, ipv4udp.dest_port, ipv4udp.data_len, uc_con ? uc_con->id_fromclient.str : id.str);
    } else {
        fprintf(stderr, "%s Received packet from %s:%u to %s:%u with %d Bytes of DATA (Masked Connection-ID: %012jx).\n", log_time, \
                "<Masked by default loglevel>", ipv4udp.src_port, ipv4udp.dest_ip_str, ipv4udp.dest_port, ipv4udp.data_len, uc_con ? uc_con->id_fromclient.masked_id : id.masked_id);
    }

    if(pc->portmap[ipv4udp.dest_port] || (uc_con != 0 && uc_con->proxied) ) { //If proxy is active for this port and/*or* active proxy connection to backend exists...
        struct proxy_conf_udp_node_t* pc_con = pcudp_get_lport(pc, ipv4udp.dest_port); //...get proxy configuration for this connection
        if(uc_con == 0 ) { //If active connection does not exist, make new connection
            uc_con = uc_push(uc, id);
            uc_con->proxied = true;

            //Fill udpcon node structure with data
            uc_con->src_ip = strncpy(malloc(strlen(ipv4udp.src_ip_str ) +2 ), ipv4udp.src_ip_str, strlen(ipv4udp.src_ip_str) +1 );
            uc_con->src_port = ipv4udp.src_port;
            uc_con->dest_ip =  strncpy(malloc(strlen(ipv4udp.dest_ip_str ) +2 ), ipv4udp.dest_ip_str, strlen(ipv4udp.dest_ip_str) +1 );
            uc_con->dest_port =  ipv4udp.dest_port;
            uc_con->timestamp =  strncpy(malloc(strlen(log_time ) +2 ), log_time, strlen(log_time) +1 );
            uc_con->unixtime =  atoll(log_time_unix);
            uc_con->start =  strncpy(malloc(strlen(log_time) +2 ), log_time_unix, strlen(log_time) +1 );
            uc_con->end =  strncpy(malloc(strlen(log_time) +2 ), log_time_unix, strlen(log_time) +1 );
            uc_con->timeasdouble = unix_timeasdouble;
            uc_con->duration = 0;
            uc_con->last_seen =  atoll(log_time_unix);
            uc_con->min_rtt = 0;
            uc_con->bytes_toserver =  ipv4udp.data_len;
            uc_con->bytes_toclient =  0;
            uc_con->first_dgram = malloc(recv_len);
            memcpy(uc_con->first_dgram, buffer, recv_len);
            uc_con->first_dgram_len = ipv4udp.data_len;

            uc_con->backend_ip =  strncpy(malloc(strlen(pc_con->backendaddr) +2 ), pc_con->backendaddr, strlen(pc_con->backendaddr) +1 );
            uc_con->backend_port =  pc_con->backendport;

#if DEBUG >= 2
            fprintf(stderr, "****DEBUG: Proxy connection does not exists: %s\n", uc_con->src_ip);
#endif

            //Make socket towards backend
            uc_con->backend_socket = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
            if ( (uc_con->backend_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
#if DEBUG >= 2
                fprintf(stderr, "****DEBUG: Proxy backend socket creation failed");
#endif
                exit(1);
            }
            memset(uc_con->backend_socket, 0, sizeof(uc_con->backend_socket));

            // Filling backend server information
            uc_con->backend_socket->sin_family = AF_INET;
            uc_con->backend_socket->sin_port = htons(uc_con->backend_port);
            inet_pton(AF_INET, uc_con->backend_ip, &(uc_con->backend_socket->sin_addr));

            //Send received data to backend via backend-socket:
            sendto(uc_con->backend_socket_fd, ipv4udp.data, ipv4udp.data_len,
                   MSG_CONFIRM,
                   (const struct sockaddr *) uc_con->backend_socket,
                   sizeof( *uc_con->backend_socket ));

            //Get local proxy-client port for backend ID
            struct sockaddr local_address;
            int addr_size = sizeof(local_address);
            getsockname(uc_con->backend_socket_fd, &local_address, &addr_size);
            char* port_ptr = local_address.sa_data;

            uc_con->proxy_ip =  strncpy(malloc(strlen(pc->proxy_ip) + 2 ), pc->proxy_ip, strlen(pc->proxy_ip) +1 );
            uc_con->proxy_port = (uint16_t) (uint16_t) ((uint8_t) (*port_ptr)) * 256 + ((uint8_t) (*(port_ptr+1)));

#if DEBUG >= 2
            fprintf(stderr, "\n****DEBUG: PROXY: IP %s, PORT %d\n", uc_con->proxy_ip, uc_con->proxy_port);
            fprintf(stderr, "****DEBUG: Proxy connection does not exists: %s\n", uc_con->src_ip);
#endif

            // Get backend ID
            uc_genlid(uc_con->backend_ip, uc_con->backend_port, uc_con->proxy_ip, uc_con->proxy_port, &(uc_con->id_tobackend));
            //fprintf(stderr, "****DEBUG: BACKEND ID GENERATION: src: %s:%d dest:%s:%d id: %s\n",\
            uc_con->proxy_ip, uc_con->proxy_port, uc_con->backend_ip, uc_con->backend_port, uc_con->id_tobackend.str);

            //Make socket towards client
            uc_con->client_socket = (struct sockaddr_in*) malloc(sizeof(struct sockaddr_in));
            if ( (uc_con->client_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
#if DEBUG >= 2
                fprintf(stderr, "****DEBUG: Proxy client socket creation failed\n");
#endif
                exit(1);
            }
            memset(uc_con->client_socket, 0, sizeof(uc_con->client_socket));

            //Filling proxy-to-client information
            uc_con->client_socket->sin_family = AF_INET;
            uc_con->client_socket->sin_addr.s_addr = inet_addr(uc_con->src_ip); //destination IP for incoming packets
            uc_con->client_socket->sin_port = htons(uc_con->src_port); //destination port for incoming packets

            uc_con->client_localport.sin_family = AF_INET;
            uc_con->client_localport.sin_addr.s_addr= htonl(INADDR_ANY);
            uc_con->client_localport.sin_port=htons(uc_con->dest_port); //source port for outgoing packets

            int optval = 1;
            setsockopt(uc_con->client_socket_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

            CHECK(bind(uc_con->client_socket_fd,(struct sockaddr *)&uc_con->client_localport,sizeof(uc_con->client_localport)), == 0);

            uc_con->duration = time_str(NULL, 0, NULL, 0) - uc_con->unixtime;
        } else { //if proxied and connection exists...
            //fprintf(stderr, "Proxy connection exists\n");
            if (uc_eqlid(&(uc_con->id_fromclient), &id)) { //...and connections comes from client, forward it to backend
#if DEBUG >= 2
                fprintf(stderr, "***DEBUG: Connection from client\n");
#endif
                //Send received data to backend via backend-socket:
                sendto(uc_con->backend_socket_fd, ipv4udp.data, ipv4udp.data_len,
                       MSG_CONFIRM,
                       (const struct sockaddr *) uc_con->backend_socket,
                       sizeof( *uc_con->backend_socket ));
                uc_con->bytes_toserver +=  ipv4udp.data_len;

                if (uc_con->min_rtt == 0 || unix_timeasdouble - uc_con->last_seen < uc_con->min_rtt) {
                    uc_con->min_rtt = unix_timeasdouble - uc_con->last_seen;
#if DEBUG >= 2
                    fprintf(stderr, "****DEBUG: min_rtt: %Lf\n", uc_con->min_rtt);
#endif
                }
            } else if (uc_eqlid(&(uc_con->id_tobackend), &id)) { //...and connections comes from backend, forward it to client
                //fprintf(stderr, "Connection from backend\n");
                //Send received data to client via client-socket:
                sendto(uc_con->client_socket_fd, ipv4udp.data, ipv4udp.data_len,
                       MSG_CONFIRM,
                       (const struct sockaddr *) uc_con->client_socket,
                       sizeof( *uc_con->client_socket ));
                uc_con->bytes_toclient +=  ipv4udp.data_len;
            } else {
#if DEBUG >= 2
                fprintf(stderr, "****DEBUG: ID failure, proxied connection should exists.\n");
#endif
            }


            if(uc_con->end != NULL) free(uc_con->end);
            unix_timeasdouble = time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time)); //...generate string with current time
            uc_con->end =  strncpy(malloc(strlen(log_time ) +2 ), log_time_unix, strlen(log_time) +1 );
            uc_con->last_seen =  atoll(log_time_unix);
            uc_con->duration =  unix_timeasdouble - uc_con->timeasdouble;
        }

    } else { //if destination port is not configured for proxy, save the content of the datagram in a file
#if DEBUG >= 2
        fprintf(stderr, "****DEBUG: No proxy configured\n");
#endif
        bool new_con = false;
        if(uc_con == 0) { //if connection does not exists, make a new one
            new_con = true;
#if DEBUG >= 2
            fprintf(stderr, "****DEBUG: Connection does not exists\n");
#endif

            uc_con = uc_push(uc, id);
            uc_con->proxied = false;

            //Fill udpcon node structure with data
            uc_con->src_ip = strncpy(malloc(strlen(ipv4udp.src_ip_str ) +2 ), ipv4udp.src_ip_str, strlen(ipv4udp.src_ip_str) +1 );
            uc_con->src_port = ipv4udp.src_port;
            uc_con->dest_ip =  strncpy(malloc(strlen(ipv4udp.dest_ip_str ) +2 ), ipv4udp.dest_ip_str, strlen(ipv4udp.dest_ip_str) +1 );
            uc_con->dest_port =  ipv4udp.dest_port;
            uc_con->timestamp =  strncpy(malloc(strlen(log_time) +2 ), log_time, strlen(log_time) +1 );
            uc_con->unixtime =  atoll(log_time_unix);
            uc_con->start =  strncpy(malloc(strlen(log_time ) +2 ), log_time, strlen(log_time) +1 );
            uc_con->end =  strncpy(malloc(strlen(log_time) +2 ), log_time, strlen(log_time) +1 );
            uc_con->last_seen =  atoll(log_time_unix);
            uc_con->duration = 0;
            uc_con->min_rtt = 0;
            uc_con->timeasdouble = unix_timeasdouble;

            //first_dgram contains whole packet for header anaylization
            uc_con->first_dgram = malloc(recv_len);
            memcpy(uc_con->first_dgram, buffer, recv_len);
            uc_con->first_dgram_len = recv_len;
        }
        //Realloc (or use realloc like malloc) payload and append.
#if DEBUG >= 2
        fprintf(stderr,"\n*****DEBUG: Append %lld -> %lld\n\n", uc_con->payload_len, uc_con->payload_len + ipv4udp.data_len);
#endif
        uc_con->payload = realloc(uc_con->payload, uc_con->payload_len + ipv4udp.data_len);
        memcpy(uc_con->payload + uc_con->payload_len, ipv4udp.data, ipv4udp.data_len);
        uc_con->payload_len += ipv4udp.data_len;
        uc_con->bytes_toserver +=  ipv4udp.data_len;

        if(uc_con->end != NULL) free(uc_con->end);
        unix_timeasdouble = time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time)); //...generate string with current time
        uc_con->end =  strncpy(malloc(strlen(log_time) +2 ), log_time, strlen(log_time) +1 );
        if (!new_con && (uc_con->min_rtt == 0 || unix_timeasdouble - uc_con->last_seen < uc_con->min_rtt) ) {
            uc_con->min_rtt = unix_timeasdouble - uc_con->last_seen;
#if DEBUG >= 2
            fprintf(stderr, "****DEBUG: min_rtt: %Lf\n", uc_con->min_rtt);
#endif
        }
        uc_con->last_seen =  atoll(log_time_unix);
        uc_con->duration =  unix_timeasdouble - uc_con->timeasdouble;

        //Generate filename LinuxTimeStamp-milisecends_destinationAddress-destinationPort_sourceAddress-sourcePort.tpm
        sprintf(file_name, "%s%s_%s-%u_%s-%u.upm", data_path, uc_con->start, ipv4udp.dest_ip_str, ipv4udp.dest_port, ipv4udp.src_ip_str, ipv4udp.src_port);
        file_name[PATH_LEN-1] = 0; //Enforcing PATH_LEN
        file = fopen(file_name,"ab"); //Open File, append if it exists
        //Write when -and only WHEN - nothing went wrong data to file
        if (file != 0) {
            if(loglevel>0) {
                fprintf(stderr, "%s FILENAME: %s\n", log_time, file_name);
            } else {
                fprintf(stderr, "%s FILENAME: %s%s_%s-%u_%s-%u.upm\n", log_time, \
                        data_path, uc_con->start, ipv4udp.dest_ip_str, ipv4udp.dest_port, "<Masked by default loglevel>", ipv4udp.src_port);
            }
            fwrite(ipv4udp.data, ipv4udp.data_len, 1, file);
            CHECK(fflush(file), == 0);
            fclose(file);
        } else {
            //if somthing went wrong, log it.
            if(loglevel>0) {
                fprintf(stderr, "%s ERROR: Could not write to file %s\n", log_time, file_name);
            } else {
                fprintf(stderr, "%s ERROR: Could not write to file %s%s_%s-%u_%s-%u.upm\n", log_time, \
                        data_path, uc_con->start, ipv4udp.dest_ip_str, ipv4udp.dest_port, "<Masked by default loglevel>", ipv4udp.src_port);
            }
        }
    }

    free(ipv4udp.src_ip_str);
    free(ipv4udp.dest_ip_str);

    return 0;
}