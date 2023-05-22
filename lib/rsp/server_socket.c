/*******************************************************************************
RSP - A Really Simple Proxy
GitHub: https://github.com/gpjt/rsp
Documentation: http://www.gilesthomas.com/2013/08/writing-a-reverse-proxyloadbalancer-from-the-ground-up-in-c-part-0/
Gratefully adopted and modified for MADCAT by BSI 2019-2020 with special thanks to Giles Thomas:

Copyright (c) 2013 Giles Thomas

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*******************************************************************************/
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

#include "rsp.h"
#include <sys/epoll.h>

#define MAX_LISTEN_BACKLOG 4096


struct server_socket_event_data {
    char* backend_addr;
    char* backend_port_str;
};

/*//MADCAT: modified and moved to rsp.h
struct proxy_data {
    struct epoll_event_handler* client;
    struct epoll_event_handler* backend;
};
*/


void on_client_read(void* closure, char* buffer, int len)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->backend == NULL) {
        return;
    }
    connection_write(data->backend, buffer, len);
    //MADCAT
    //log, using data->client as id, which also contains the struct epoll_event_handler*
    long double unix_timeasdouble = time_str(NULL, 0, NULL, 0);
    struct json_data_node_t* jd_node = jd_get(jd, (uintptr_t ) data->client);
    jd_node->bytes_toserver += len;

    if( !jd_node->firstpacket && (unix_timeasdouble - jd_node->last_recv < jd_node->min_rtt || jd_node->min_rtt == 0 ) ) {
        jd_node->min_rtt = unix_timeasdouble - jd_node->last_recv;
        //fprintf(stderr, "\n*****DEBUG: min_rtt: %Lf\n", jd_node->min_rtt);
    }

    jd_node->last_recv = unix_timeasdouble;
    jd_node->firstpacket = false;
}


void on_client_close(void* closure)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->backend == NULL) {
        return;
    }

    json_out(jd, (uintptr_t ) data->client); //MADCAT

    connection_close(data->backend);
    data->client = NULL;
    data->backend = NULL;
    epoll_add_to_free_list(closure);
}


void on_backend_read(void* closure, char* buffer, int len)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->client == NULL) {
        return;
    }
    connection_write(data->client, buffer, len);

    //MADCAT
    //log, using data->client as id, which also contains the struct epoll_event_handler*
    jd_get(jd, (uintptr_t ) data->client)->bytes_toclient += len;
    //data->bytes_toclient += len;
}


void on_backend_close(void* closure)
{
    struct proxy_data* data = (struct proxy_data*) closure;
    if (data->client == NULL) {
        return;
    }

    //MADCAT
    json_out(jd, (uintptr_t ) data->client); //MADCAT

    connection_close(data->client);
    data->client = NULL;
    data->backend = NULL;
    epoll_add_to_free_list(closure);
}


struct proxy_data*  handle_client_connection(int client_socket_fd,
        char* backend_host,
        char* backend_port_str)
{
    struct epoll_event_handler* client_connection;
    rsp_log("Creating connection object for incoming connection...");
    client_connection = create_connection(client_socket_fd);

    int backend_socket_fd = connect_to_backend(backend_host, backend_port_str);
    struct epoll_event_handler* backend_connection;
    rsp_log("Creating connection object for backend connection...");
    backend_connection = create_connection(backend_socket_fd);

    struct proxy_data* proxy = malloc(sizeof(struct proxy_data));
    proxy->client = client_connection;
    proxy->backend = backend_connection;


    //MADCAT start
    if ( !jd_get(jd, (uintptr_t ) proxy->client)) jd_push(jd, (uintptr_t ) proxy->client);
    struct json_data_node_t* jd_node = jd_get(jd, (uintptr_t ) proxy->client);

    jd_node->bytes_toclient = 0;
    jd_node->bytes_toserver = 0;

    //proxy->bytes_toclient = 0; //MADCAT
    //proxy->bytes_toserver = 0; //MADCAT


    //Get local client address and port
    struct sockaddr local_address;
    socklen_t addr_size = sizeof(local_address);
    getsockname(backend_socket_fd, &local_address, &addr_size);

    char* port_ptr = local_address.sa_data;
    char* ip_ptr = (char*) &(local_address.sa_data) + 2;
    proxy_sock.client_port = (uint16_t) ((uint8_t) (*port_ptr)) * 256 + ((uint8_t) (*(port_ptr+1)));
    //proxy_sock.client_addr = inttoa(*(uint32_t*)ip_ptr); //Commented out, what was my thought?

    jd_node->proxy_ip = inttoa(*(uint32_t*)ip_ptr);
    jd_node->proxy_port = proxy_sock.client_port;
    jd_node->backend_ip = strncpy(malloc(strlen(proxy_sock.backend_addr) +1 ), proxy_sock.backend_addr, strlen(proxy_sock.backend_addr) +1 );
    jd_node->backend_port = strncpy(malloc(strlen(proxy_sock.backend_port_str) +1 ), proxy_sock.backend_port_str, strlen(proxy_sock.backend_port_str) +1 );

    //MADCAT end

    struct connection_closure* client_closure = (struct connection_closure*) client_connection->closure;
    client_closure->on_read = on_client_read;
    client_closure->on_read_closure = proxy;
    client_closure->on_close = on_client_close;
    client_closure->on_close_closure = proxy;

    struct connection_closure* backend_closure = (struct connection_closure*) backend_connection->closure;
    backend_closure->on_read = on_backend_read;
    backend_closure->on_read_closure = proxy;
    backend_closure->on_close = on_backend_close;
    backend_closure->on_close_closure = proxy;

    return proxy; //MADCAT
}



void handle_server_socket_event(struct epoll_event_handler* self, uint32_t events)
{
    struct server_socket_event_data* closure = (struct server_socket_event_data*) self->closure;

    //MADCAT start
    struct sockaddr_in claddr; //Clientaddress
    socklen_t claddr_len = sizeof(claddr);

    char start_time[64] = ""; //Human readable start time (actual time zone)
    char start_time_unix[64] = ""; //Unix timestamp (UTC)
    long double unix_timeasdouble = time_str(start_time_unix, sizeof(start_time_unix), start_time, sizeof(start_time));

    struct proxy_data* proxy;
    //MADCAT end

    int client_socket_fd;
    while (1) {
        client_socket_fd = accept(self->fd, (struct sockaddr*)&claddr, &claddr_len); //MADCAT
        //client_socket_fd = accept(self->fd, NULL, NULL);
        if (client_socket_fd == -1) {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                break;
            } else {
                rsp_log_error("Could not accept");
                exit(1);
            }
        }

        //MADCAT
        proxy = handle_client_connection(client_socket_fd,
                                         closure->backend_addr,
                                         closure->backend_port_str);
    }

    //MADCAT start
    //Log first part of connection in json data list, using struct epoll_event_handler* client as id.
    if ( !jd_get(jd, (uintptr_t ) proxy->client)) jd_push(jd, (uintptr_t ) proxy->client);
    struct json_data_node_t* jd_node = jd_get(jd, (uintptr_t ) proxy->client);

    jd_node->src_ip = strncpy(malloc(strlen(inet_ntoa(claddr.sin_addr)) +1 ), inet_ntoa(claddr.sin_addr), strlen(inet_ntoa(claddr.sin_addr)) +1 );
    jd_node->dest_port = strncpy(malloc(strlen(proxy_sock.server_port_str) +1 ), proxy_sock.server_port_str, strlen(proxy_sock.server_port_str) +1 );
    jd_node->timestamp = strncpy(malloc(strlen(start_time) +1 ), start_time, strlen(start_time) +1 );
    jd_node->start = strncpy(malloc(strlen(start_time) +1 ), start_time, strlen(start_time) +1 );
    jd_node->dest_ip = strncpy(malloc(strlen(proxy_sock.server_addr) +1 ), proxy_sock.server_addr, strlen(proxy_sock.server_addr) +1 );
    jd_node->src_port = ntohs(claddr.sin_port);
    jd_node->unixtime = strncpy(malloc(strlen(start_time_unix) +1 ), start_time_unix, strlen(start_time_unix) +1 );
    jd_node->timeasdouble = unix_timeasdouble;
    jd_node->last_recv = unix_timeasdouble;

    //MADCAT end

    return;
}


//MADCAT
int create_and_bind(char* hostaddr, char* server_port_str)
{
    //Variables for listning socket
    struct sockaddr_in addr; //Hostaddress

    int server_port = atoi(server_port_str);

    socklen_t addr_len = sizeof(addr);
    int server_socket_fd = CHECK(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP), != -1); //create socket filedescriptor

    //Initialize address struct (Host)
    bzero(&addr, addr_len);
    addr.sin_family=AF_INET;
    CHECK(inet_aton(hostaddr, &addr.sin_addr), != 0); //set and check listening address
    addr.sin_port = htons(server_port); //set listening port

    struct linger sl = { 1, 5 };
    int on = 1;

    CHECK(setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &on, (socklen_t)sizeof(on)), != -1);
    CHECK(setsockopt(server_socket_fd, SOL_SOCKET, SO_LINGER, &sl, (socklen_t)sizeof(sl)), != -1);

    //Bind socket and begin listening
    CHECK(bind(server_socket_fd, (struct sockaddr*)&addr, sizeof(addr)), != -1);

    //MADCAT start
    char log_time[64] = ""; //Human readable log time (actual time zone)
    time_str(NULL, 0, log_time, sizeof(log_time)); //Get Human readable string only

    //Drop Priviliges
    fprintf(stderr, "%s [PID %d] ", log_time, getpid());
    drop_root_privs(user, "Proxy", false);
    //MADCAT end */

    return server_socket_fd;
}

/* //Original
int create_and_bind(char* server_port_str)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* addrs;
    int getaddrinfo_error;
    getaddrinfo_error = getaddrinfo(NULL, server_port_str, &hints, &addrs);
    if (getaddrinfo_error != 0) {
        rsp_log("Couldn't find local host details: %s", gai_strerror(getaddrinfo_error));
        exit(1);
    }

    int server_socket_fd;
    struct addrinfo* addr_iter;
    for (addr_iter = addrs; addr_iter != NULL; addr_iter = addr_iter->ai_next) {
        server_socket_fd = socket(addr_iter->ai_family,
                                  addr_iter->ai_socktype,
                                  addr_iter->ai_protocol);
        if (server_socket_fd == -1) {
            continue;
        }

        int so_reuseaddr = 1;
        if (setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &so_reuseaddr, sizeof(so_reuseaddr)) != 0) {
            continue;
        }

        if (bind(server_socket_fd,
                 addr_iter->ai_addr,
                 addr_iter->ai_addrlen) == 0)
        {
            break;
        }

        close(server_socket_fd);
    }

    if (addr_iter == NULL) {
        rsp_log("Couldn't bind");
        exit(1);
    }

    freeaddrinfo(addrs);

    return server_socket_fd;
}
*/

struct epoll_event_handler* create_server_socket_handler(char* server_addr,
        char* server_port_str,
        char* backend_addr,
        char* backend_port_str)
{

    int server_socket_fd;
    server_socket_fd = create_and_bind(server_addr, server_port_str);
    make_socket_non_blocking(server_socket_fd);

    listen(server_socket_fd, MAX_LISTEN_BACKLOG);

    struct server_socket_event_data* closure = malloc(sizeof(struct server_socket_event_data));
    closure->backend_addr = backend_addr;
    closure->backend_port_str = backend_port_str;

    struct epoll_event_handler* result = malloc(sizeof(struct epoll_event_handler));
    result->fd = server_socket_fd;
    result->handle = handle_server_socket_event;
    result->closure = closure;

    epoll_add_handler(result, EPOLLIN | EPOLLET);

    return result;
}


