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


#ifndef MADCAT_HELPER_H
#define MADCAT_HELPER_H

#include "madcat.common.h"

//MADCAT HELPER

/**
 * \brief Returns current time
 *
 *     Returns current time in readable format and unix time format as String and Double.
 *     If unix_buf is set to NULL, only readable format is returned as String (and vice versa),
 *     then the return value is 0.
 *     Both can be returned at the same time, if both are not NULL.
 *     (Or nothing, if both are NULL, of course, but that would be pointless, maybe even silly)
 *
 * \param unix_buf String-Buffer, which is used to return Unix-Time as String
 * \param unix_size Size of unix_buf
 * \param readable_buf String-Buffer, which is used to return Time in Readable Format
 * * \param readable_size Size of readable_buf
 * \return Unix Time as double, 0 if unix_buf is set to NULL
 *
 */
long double time_str(char* unix_buf, int unix_size, char* readable_buf, int readable_size);

/**
  * \brief Fetches user IDs
  *
  *     Fetches user IDs for username, saved in user and writes them to the same struct.
  *
  * \param user pointer to struct user_t, containing user name
  * \return void, GID and PID of user are returned in struct user_t user, given as parameter
  *
  */
void get_user_ids(struct user_t* user);

/**
  * \brief Prints binary data as hex with offset
  *
  *     Prints binary data as hex with offset in hexdump-style w/o ASCII to output.
  *     Intended for debugging.
  *
  * \param output File-Pointer to output, e.g. STDERR
  * \param buffer Buffer containing the binary data to be printed
  * \param buffersize Size of buffer
  * \return void
  *
  */
void print_hex(FILE* output, const unsigned char* buffer, int buffsize);

/**
  * \brief Prints binary data as hex string
  *
  *     Prints binary data as hex string w/o whitspaces or linebreaks to a String
  *     Intended for searchable binary JSON Data fields.
  *
  * \param buffer Buffer containing the binary data to be printed
  * \param buffersize Size of buffer
  * \return Pointer to the string, containing the dump. Must be freed afterwards.
  *
  */
char *print_hex_string(const unsigned char* buffer, unsigned int buffsize);

/**
  * \brief Prints binary data as hexdump
  *
  *     Prints binary data hexdump-style, with ASCII-Part.
  *     Intended for human readable (JSON) Data fields.
  *     The parameter json toggles escaping of line breaks.
  *
  * \param addr Buffer containing the binary data to be printed
  * \param len Size of the buffer
  * \param json Toggles escaping of line breaks for use in JSON output
  * \return Pointer to the string, containing the dump. Must be freed afterwards.
  *
  */
unsigned char* hex_dump(const void *addr, int len, const bool json);

/**
  * \brief Converts IP(v4)-Addresses from network byte order to string
  *
  *     Converts IP(v4)-Addresses from network byte order to string.
  *     The function inet_ntoa e.g. converts 127.1.1.1 to 127.0.0.1. This is bad e.g. for testing.
  *
  * \param addr Buffer containing the IP in network byte order.
  * \return Pointer to the string containing the converted IP.
  *
  */
char *inttoa(uint32_t i_addr);

/**
  * \brief Reset or initialize new JSON output
  *
  *     Resets or initializes new JSON output.
  *     If reset is set to false, the format string format is concatenated
  *     to the static buffer of this function.
  *     The function does *not* add JSON spezifics (e.g. Brackets) or checks syntax.
  *     It just appends the format string.
  *     The static buffer is freed and reset, if reset is true, thus becoming format the
  *     first part of a new JSON-Output.
  *     Returns a pointer to the static buffer, conataing all previously concatenated strings.
  *     Be carefull, when calling free on this pointer. You *may* under the right circumstances without
  *     causing harm by using free(json_do(true, ""));, if the function is guranteed to be not called again.
  *
  * \param reset Reset static buffer
  * \param format Format string
  * \return Pointer to the string in the static buffer.
  *
  */
char* json_do(bool reset, const char* format, ...); //Reset or initialize new JSON if first argument is true and append formated string.

/**
  * \brief Reads configuration Items from parsed LUA-File
  *
  *     Reads configuration item name
  *     from parsed LUA-File (by luaL_dofile(...) )and
  *     saves returns its value as String
  *
  * \param L Lua State structure from luaL_dofile(...)
  * \param name String containing the name of the configuration Item
  * \return Value of config item
  *
  */
const char* get_config_opt(lua_State* L, char* name); //Returns configuration items from LUA config file

#endif
