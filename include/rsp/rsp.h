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

#ifndef RSP_H
#define RSP_H

#include "epollinterface.h"
#include "logging.h"
#include "server_socket.h"
#include "netutils.h"
#include "connection.h"

struct proxy_data {
    struct epoll_event_handler* client;
    struct epoll_event_handler* backend;
    long long int bytes_toclient; //MADCAT
    long long int bytes_toserver; //MADCAT
};

//MADCAT
struct proxy_socket_t { //Adresses and ports globally defined for easy access for configuration and logging purposes.
    //remote socket
    char* backend_addr;
    char* backend_port_str;
    //lokal socket for incoming connections
    char* server_addr;
    char* server_port_str;
    //lokal socket for outgoint connections for logging purposes only, values are assigned in "int connect_to_backend(char* backend_host, char* backend_port_str)
    char* client_addr;
    u_int16_t client_port;
};
extern struct proxy_socket_t proxy_sock;

/**
 * \brief Starts an instance of RSP-Proxy
 *
 *     Starts an instance of RSP-Proxy. Takes a proxy configuration list element and the
 *     local proxy-server address ("hostaddr") as parameters.
 *     Does only return in case of an error.
 *     For detailed information about RSP-Proxy see the Documentation:
 *     http://www.gilesthomas.com/2013/08/writing-a-reverse-proxyloadbalancer-from-the-ground-up-in-c-part-0/
 *
 * \param pcn proxy configuration list element, discribing the desired connection
 * \param server_addr local proxy-server address ("hostaddr")
 * \return 0 on succesfull exit.
 *
 */
int rsp(struct proxy_conf_tcp_node_t* pcn, char* server_addr);

#endif