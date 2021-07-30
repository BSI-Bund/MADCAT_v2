/*******************************************************************************
RSP - A Really Simple Proxy
GitHub: https://github.com/gpjt/rsp
Documentation: http://www.gilesthomas.com/2013/08/writing-a-reverse-proxyloadbalancer-from-the-ground-up-in-c-part-0/
Gratefully adopted and modified for MADCAT with special thanks to Giles Thomas:

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

#include "logging.h"

void rsp_log(char* format, ...)
{
    char log_time[64];
    time_str(NULL, 0, log_time, 64);

    fprintf(stderr, "%s [PID %d] Proxy: ", log_time, getpid());

    va_list argptr;
    va_start(argptr, format);
    vfprintf(stderr, format, argptr);
    va_end(argptr);

    fprintf(stderr, "\n");

    fflush(stderr);
}


void rsp_log_error(char* message)
{
    char* error = strerror(errno);
    rsp_log("%s (%s)", message, error);
}

void json_out(struct json_data_t* jd, uintptr_t id)
{
    char end_time[64] = ""; //Human readable start time (actual time zone)
    jd_get(jd, id)->duration = time_str(NULL, 0, end_time, sizeof(end_time)) - jd_get(jd,id)->timeasdouble; //Get end time and duration

    //Log second part of connection in json data list, using struct epoll_event_handler* client as id.
    //Not realy necassary at this point, but now I've build the struct, so I decided to use it. May be usefull in further development.
    if ( !jd_get(jd, id) ) return;

    jd_get(jd, id)->end = strncpy(malloc(strlen(end_time) +1 ), end_time, strlen(end_time) +1 );

#if DEBUG >= 2
    jd_print_list(jd);
#endif

    //using json_do for composing of the json output

    //initialize and fill
    json_do(true, "{\
\"src_ip\":\"%s\", \
\"dest_port\": %s, \
\"timestamp\":\"%s\", \
\"dest_ip\":\"%s\", \
\"src_port\": %d, \
\"proto\":\"%s\", \
\"event_type\":\"%s\", \
\"unixtime\": %s, \
\"FLOW\": { \
\"start\":\"%s\",\
\"end\":\"%s\", \
\"duration\":%Lf, \
\"min_rtt\":%Lf, \
\"state\":\"%s\", \
\"reason\":\"%s\", \
\"bytes_toserver\": %lld, \
\"bytes_toclient\": %lld, \
\"proxy_ip\":\"%s\", \
\"proxy_port\": %u, \
\"backend_ip\":\"%s\", \
\"backend_port\": %s\
}}",\
            jd_get(jd, id)->src_ip, \
            jd_get(jd, id)->dest_port, \
            jd_get(jd, id)->start, \
            jd_get(jd, id)->dest_ip, \
            jd_get(jd, id)->src_port, \
            "TCP",\
            "proxy_flow",\
            jd_get(jd, id)->unixtime, \
            jd_get(jd, id)->start,\
            jd_get(jd, id)->end,\
            jd_get(jd, id)->duration,\
            jd_get(jd, id)->min_rtt,\
            "closed",\
            "closed",\
            jd_get(jd, id)->bytes_toserver,\
            jd_get(jd, id)->bytes_toclient,\
            jd_get(jd, id)->proxy_ip,\
            jd_get(jd, id)->proxy_port,\
            jd_get(jd, id)->backend_ip,\
            jd_get(jd, id)->backend_port\
           );

#if DEBUG >= 2
    int consem_val = -127;
    CHECK(sem_getvalue(consem, &consem_val), != -1); //Ceck
    fprintf(stderr, "*** DEBUG [PID %d] Acquire lock for output.\n", getpid());
    rsp_log("Value of connection semaphore: %d.\n", consem_val);
#endif
    struct timespec sem_timeout; //time to wait in sem_timedwait() call
    clock_gettime(CLOCK_REALTIME, &sem_timeout);
    sem_timeout.tv_sec += 1;
    sem_timedwait(consem, &sem_timeout); //Acquire lock for output
    fprintf(confifo,"%s\n", json_do(false, "")); //print json output for further analysis
    fflush(confifo);
#if DEBUG >= 2
    fprintf(stderr, "*** DEBUG [PID %d] Release lock for output\n", getpid());
#endif
    sem_post(consem); //release lock
    fprintf(stdout,"{\"CONNECTION\": %s}\n", json_do(false, "")); //print json output for logging
    fflush(confifo);
    fflush(stdout);
    //Remove and thereby free list element with id "id"
    jd_del(jd, id);
    return;
}
