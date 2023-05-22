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

#include "tcp_ip_port_mon.worker.h"
#include "tcp_ip_port_mon.helper.h"

//Listner thread

long int worker_tcp(const char* dst_addr, const int dest_port, const char* src_addr, const int src_port, const long double timeout, \
                    const char* data_path, const int max_file_size, const int s, FILE* confifo, char* proto_str)
{
    //on some systems, e.g. VMs, binding to a specific address does not work as expected.
    if(strcmp(dst_addr, hostaddr) != 0 && strcmp("0.0.0.0", hostaddr) !=0) //char hostaddr[INET6_ADDRSTRLEN] globally defined.
        return -1; //Filter packtes not matching hostaddress by returning from child

    int size_recv;
    char chunk[CHUNK_SIZE];
    unsigned char* payload = malloc(CHUNK_SIZE); //Paylaod (Binary)
    char* payload_hd_str = 0; //Payload as string in HexDump Format
    char* payload_str = 0; //Payload as string
    unsigned char payload_sha1[SHA_DIGEST_LENGTH]; //SHA1 of payload
    char * payload_sha1_str = 0;
    long double timediff;
    struct con_status_t con_status;
    bool size_exceeded = false;
    char log_time[64] = "";
    char log_time_unix[64] = "";
    long double unix_timeasdouble = time_str(log_time_unix, sizeof(log_time_unix), log_time, sizeof(log_time));
    long double duration = 0;
    long double min_rtt = 0;

    FILE *file = 0;
    char file_name[2*PATH_LEN] = ""; //double path length for concatination purposes. PATH_LEN *MUST* be enforced when combinating path and filename!
    char now_time[64] = "";
    char lastrecv_time[64] = "";

    //structures for timeout measurment
    struct timeval begin, now;

    //Log connection to STDERR in readeable format
    if(loglevel>0) {
        fprintf(stderr, "%s [PID %d] CONNECTION from %s:%d to %s:%d\n", log_time, getpid(), src_addr, src_port, dst_addr, dest_port);
    } else {
        fprintf(stderr, "%s [PID %d] CONNECTION from %s:%d to %s:%d\n", log_time, getpid(), "<Masked by default loglevel>", src_port, dst_addr, dest_port);
    }


    //Open new JSON and log connection to STDOUT in json-format (Suricata-alike)
    json_value.string = "MADCAT";
    dict_update(json_dict(true), JSON_STR, json_value, 1, "origin");
    json_value.string = (char*) src_addr;
    dict_update(json_dict(false), JSON_STR, json_value, 1, "src_ip");
    json_value.integer = dest_port;
    dict_update(json_dict(false), JSON_INT, json_value, 1, "dest_port");
    json_value.string = log_time;
    dict_update(json_dict(false), JSON_STR, json_value, 1, "timestamp");
    json_value.string = (char*) dst_addr;
    dict_update(json_dict(false), JSON_STR, json_value, 1, "dest_ip");
    json_value.integer = src_port;
    dict_update(json_dict(false), JSON_INT, json_value, 1, "src_port");
    json_value.string = proto_str;
    dict_update(json_dict(false), JSON_STR, json_value, 1, "proto");
    json_value.string = "flow";
    dict_update(json_dict(false), JSON_STR, json_value, 1, "event_type");
    json_value.floating = atof(log_time_unix);
    dict_update(json_dict(false), JSON_FLOAT, json_value, 1, "unixtime");

    //Generate connection tag to identify connection. Maximum is 28 Bytes, e.g. "123.456.789.012_43210_98765\0"
    snprintf(con_status.tag, 28, "%s_%d_%d", src_addr, dest_port, src_port);
    //initialize connection state for connection con_status by postprocessor
    snprintf(con_status.state, 16, "%s", "open");
    snprintf(con_status.reason, 16, "%s", "n/a");
    snprintf(con_status.start, 64, "%s", log_time);
    snprintf(con_status.end, 64, "%s", log_time);
    con_status.timeasdouble = unix_timeasdouble;
    con_status.data_bytes = 0;

    //make socket non blocking
    fcntl(s, F_SETFL, O_NONBLOCK);

    //initialize beginning time and time now for first run
    gettimeofday(&begin, NULL);
    bool firstpacket = true;
    while(1) { //receiving loop
        //get current time
        gettimeofday(&now, NULL);  //now is the receiving time
        time_str(NULL, 0, now_time, sizeof(now_time)); //Get Human readable string only
        timediff = (now.tv_sec - begin.tv_sec) + 1e-6 * (now.tv_usec - begin.tv_usec); //time elapsed in seconds
        //break after timeout
        if(timediff > timeout) {
            if (!size_exceeded) { //test if size has been exceeded (con_status.data_bytes >= max_file_size) to not overwritte con_status.reason.
                snprintf(con_status.reason, 16, "%s", "timeout");
            }
            break;
        }
        //test if max_file_size is exceeded
        if((con_status.data_bytes >= max_file_size) && max_file_size >= 0) {
            snprintf(con_status.reason, 16, "%s", "size exceeded");
            size_exceeded = true;
        }

        memset(chunk,0, CHUNK_SIZE);    //clear the variable
        size_recv =  recv(s, chunk, CHUNK_SIZE, 0);
        if(size_recv <= 0) {
            //if nothing was received then we want to wait a little before trying again, 0.1 seconds
            usleep(50000);
        } else {
            //reset beginning time
            gettimeofday(&begin, NULL);
            con_status.data_bytes += size_recv; //calculate totale size received
            if (con_status.data_bytes > 0 && !size_exceeded) { //proceed for writing payload in file / JSON only if max_file_size has not been exceeded.

                if (file == 0) { //if somthing had been received and no file is open yet...
                    //...generate filename LinuxTimeStamp-milisecends_destinationAddress-destinationPort_sourceAddress-sourcePort.tpm
                    sprintf(file_name, "%s%s_%s-%d_%s-%d.tpm", data_path, log_time, dst_addr, dest_port, src_addr, src_port);
                    file_name[PATH_LEN-1] = 0; //Enforcing PATH_LEN
                    if(loglevel>0) {
                        fprintf(stderr, "%s [PID %d] FILENAME: %s\n",log_time, getpid(), file_name);
                    } else {
                        fprintf(stderr, "%s [PID %d] FILENAME: %s%s_%s-%d_%s-%d.tpm\n",log_time, getpid(), \
                                data_path, log_time, dst_addr, dest_port, "<Masked by default loglevel>", src_port);
                    }
                    file = fopen(file_name,"wb"); //Open File
                }
                //Write when -and only WHEN nothing went wrong- data in chunk to file
                if (file != 0) {
                    fwrite(chunk, size_recv, 1, file);
                    CHECK(fflush(file), == 0);
                    //Save Payload for JSON-Output
                    payload = realloc(payload, con_status.data_bytes); //get memory for all received bytes so far
                    memcpy(payload + con_status.data_bytes - size_recv, chunk, size_recv); //copy chunk to payload
                } else { //if somthing went wrong, abort.
                    fprintf(stderr, "%s [PID %d] ERROR: Could not write to file %s\n",now_time, getpid(), file_name);
                    free(payload);
                    abort();
                }
            }
            long double duration_saved = duration;
            duration = time_str(NULL, 0, lastrecv_time, sizeof(lastrecv_time)) - con_status.timeasdouble;
            if(!firstpacket && ( duration - duration_saved < min_rtt || min_rtt == 0) ) {
                min_rtt = duration - duration_saved;
            }
            snprintf(con_status.end, sizeof(con_status.end), "%s", lastrecv_time); //save current time as end time candidate
            firstpacket = false;
        }
    } //end of receiving loop
    //if a file has been opened, because a stream had been received, close its filepointer to prevent data loss.
    if (file != 0) {
        fclose(file);
        if(loglevel>0) {
            fprintf(stderr, "%s [PID %d] FILE %s closed\n", now_time, getpid(), file_name);
        } else {
            fprintf(stderr, "%s [PID %d] FILE %s%s_%s-%d_%s-%d.tpm closed\n",log_time, getpid(), \
                    data_path, log_time, dst_addr, dest_port, "<Masked by default loglevel>", src_port);
        }
    }
    snprintf(con_status.state, 16, "%s", "closed");

    //Compute SHA1 of payload
    SHA1(payload, (size_exceeded ? max_file_size : con_status.data_bytes), payload_sha1);
    payload_sha1_str = print_hex_string(payload_sha1, SHA_DIGEST_LENGTH); //must be freed
    //Make HexDump output out of binary payload
    payload_hd_str = hex_dump(payload, (size_exceeded ? max_file_size : con_status.data_bytes), true); //must be freed
    payload_str = print_hex_string(payload, (size_exceeded ? max_file_size : con_status.data_bytes)); //must be freed

    //Log flow information in json-format (Suricata-like)
    json_value.string = con_status.start;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "start");
    json_value.string = con_status.end;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "end");
    json_value.floating = duration;
    dict_update(json_dict(false), JSON_FLOAT, json_value, 2, "FLOW", "duration");
    json_value.floating = min_rtt;
    dict_update(json_dict(false), JSON_FLOAT, json_value, 2, "FLOW", "min_rtt");
    json_value.string = con_status.state;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "state");
    json_value.string = con_status.reason;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "reason");
    json_value.integer = con_status.data_bytes;
    dict_update(json_dict(false), JSON_INT, json_value, 2, "FLOW", "bytes_toserver");
    
    json_value.string = payload_hd_str;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "payload_hd");
    json_value.string = payload_str;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "payload_str");
    json_value.string = payload_sha1_str;
    dict_update(json_dict(false), JSON_STR, json_value, 2, "FLOW", "payload_sha1");

#if DEBUG >= 2
    int consem_val = -127;
    CHECK(sem_getvalue(consem, &consem_val), != -1); //Ceck
    fprintf(stderr, "*** DEBUG [PID %d] Acquire lock for output.\n", getpid());
    fprintf(stderr, "%s [PID %d] : Value of connection semaphore: %d.\n", log_time, getpid(), consem_val);
#endif
    struct timespec sem_timeout; //time to wait in sem_timedwait() call
    clock_gettime(CLOCK_REALTIME, &sem_timeout);
    sem_timeout.tv_sec += 1;
    char* output = dict_dumpstr(json_dict(false));
    if(strlen(output) > 2) { //do not print empty JSON-Objects
        sem_timedwait(consem, &sem_timeout); //Acquire lock for output
        fprintf(confifo, "%s\n", output); //print json output for further analysis
        fflush(confifo);
        sem_post(consem); //release lock
        fprintf(stdout,"{\"CONNECTION\": %s}\n", output); //print json output for logging
        fflush(stdout);
    }
    free(output);

    if(loglevel>0) {
        fprintf(stderr, "%s [PID %d] END of connection from %s:%d started %s\n",now_time, getpid(), src_addr, src_port, log_time);
    } else {
        fprintf(stderr, "%s [PID %d] END of connection from %s:%d started %s\n",now_time, getpid(), "<Masked by default loglevel>", src_port, log_time);
    }

    free(payload_sha1_str);
    free(payload_str);
    free(payload_hd_str);
    free(payload);
    
    return con_status.data_bytes;
}
