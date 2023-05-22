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
 * BSI 2018-2023
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
char* hex_dump(const void *addr, int len, const bool json);

/**
  * \brief Prints data as bits in a string
  *
  *     Prints data as bits as string with a delimiter in Blocks, e.g:
  *     "0101 0001 1100" or
  *     "0101:0001:1100"
  *
  * \param data Buffer containing the data to be print as bits
  * \param len Length of data in Buffer
  * \param delimter Delimiter
  * \param block_len Length of a block
  * \return Pointer to the string containing the bit representation of data.
  *
  */
char* bitdump_ntoh(unsigned char* data, uint64_t len, char delimter, int block_len);

/**
  * \brief Interprets a null terminated string containing bits as number
  *     
  *     E.g. a pointer pointing to a string containing "0101"
  *     will return 5.
  *     Every character, which is not '0' or '1' is intepreted as delimiter.
  *
  * \param bitstr String containing a presentation of bits
  * \return Pointer to the string containing the bit representation of data.
  *
  */
uint64_t bitstrton(char* bitstr);

/**
  * \brief Exponential function for uint64_t data type
  *
  *     Exponential function for uint64_t data type.
  *     Positive values only!
  *
  * \param base Base
  * \param exp Exponent
  * \return base^exp
  *
  */
uint64_t pow64(uint64_t base, uint64_t exp);

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

/** DEPRECATED
  *
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
  *\/
char* json_do(bool reset, const char* format, ...); //Reset or initialize new JSON if first argument is true and append formated string.
*/

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

/**
 * \brief Returns a descriptive string, given a protocol number
 *
 *    See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 *    The parameter proto_no is inepreted as uint8, so for instance a value of 65536
 *    will result in the same return value as a value of 0 would be.
 *    The suffix will be appended to descriptve String, e.g. "v6", so the output for proto_no
 *    beeing 6 would be "TCPv6"
 *    The char* returned must be freed in calling function.
 *
 * \param proto_no protocol number
 * \param suffix suffix to append to return value
 * \return string char*
 *
 */
char* itoprotostr(uint8_t proto_no, const char* suffix);

#endif
