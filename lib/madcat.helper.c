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
 * UDP/TCP port- and ICMP monitor.
 *
 * Netfilter should be configured to block outgoing ICMP Destination unreachable (Port unreachable) packets, e.g.:
 *      iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
 *
 * BSI 2018-2023
*/

#include "madcat.helper.h"

//pseudo constant empty string e.g. for initialization of json_data_node_t and checks. Not used #define here, because this would lead to several instances of an empty constant string with different addresses.
char EMPTY_STR[1];
int loglevel; //Default Loglevel 0 logging no IPs to stderr, 1: Full logging
uint64_t sessionkey; //Sessionkey is used e.g. in UDP Module to mask IDs GDPR conformant if loglevel == 0.
union json_type json_value; //union to fill dictionaries with appropriate values


//struct holding user UID and PID to drop priviliges to.
struct user_t user; //globally defined, used to drop priviliges in arbitrarry functions. May become local, if not needed.

long double time_str(char* unix_buf, int unix_size, char* readable_buf, int readable_size)
{
    struct timeval tv;
    char tmzone[6]; //e.g. "+0100\0" is max. 6 chars

    gettimeofday(&tv, NULL); //fetch struct timeval with actuall time and convert it to string...

    if (unix_buf != NULL && unix_size > 0) {
        snprintf(unix_buf, unix_size, "%lu.%lu", tv.tv_sec, tv.tv_usec);
        unix_buf[unix_size-1] = 0; //Unix time incl. usec
    }

    if (readable_buf != NULL && readable_size > 0) {
        char tmbuf[readable_size];
        strftime(tmbuf, readable_size, "%Y-%m-%dT%H:%M:%S", localtime(&tv.tv_sec)); //Target format: "2018-08-17T05:51:53.835934", therefore...
        strftime(tmzone, 6, "%z", localtime(&tv.tv_sec)); //...get timezone...
        //...and finally print time and ms to string, append timezone and ensure it is null terminated.
        snprintf(readable_buf, readable_size, "%s.%06ld%s", tmbuf, tv.tv_usec, tmzone);
        readable_buf[readable_size-1] = 0; //Human readable string
    }

    return (long double) tv.tv_sec + (long double) tv.tv_usec * 1e-6; //Return unixtime as double value in any case, even if no pointer given
}

void get_user_ids(struct user_t* user) //adapted example code from manpage getpwnam(3)
{
    if(user == NULL) {
        return;
    }

    struct passwd pwd;
    struct passwd *result;
    char *buf;
    size_t bufsize;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1)          // Value was indeterminate
        bufsize = 16384;        // Should be more than enough

    buf = CHECK(malloc(bufsize), != 0);
    if (buf == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    CHECK(getpwnam_r(user->name, &pwd, buf, bufsize, &result), == 0);

    user->uid = pwd.pw_uid;
    user->gid = pwd.pw_gid;
    free(buf);
    return;
}

void print_hex(FILE* output, const unsigned char* buffer, int buffsize)
{
    int i, offset = 16; //The offset of the offset is 16. X-D
    fprintf(output, "00000000 "); //first offset
    for(i=0; i<buffsize; i++) {
        fprintf(output, "%02x ", (unsigned char) buffer[i]);
        offset++;
        if (offset % 16 == 0) {
            fprintf(output, "\n%08x ", offset);
        } else if (offset % 8 == 0) {
            fprintf(output, "\t");
        }
    }
    fprintf(output, "\n\n");
    return;
}

char *print_hex_string(const unsigned char* buffer, unsigned int buffsize) //must be freed
{
    char* output = malloc(2*buffsize+1); //output has to be min. 2*buffsize + 1 for 2 characters per byte and null-termination.
    if(buffsize<=0) {
        output[0] = 0;
        return output;
    }; //return proper empty string
    int i = 0;
    for(i=0; i<buffsize; i++)
        sprintf(output+2*i, "%02x", (unsigned char) buffer[i]);
    output[2*i] = 0; //Terminate string with \0
    return output;
}
// is it nessesary?
//Put HexDump like output to string: must be freed
char* hex_dump(const void *addr, int len, const bool json)
{
    char* output = 0;
    
    if(len <= 0) { //return empty string
        output = malloc(1);
        memset(output, 0, 1);
        return output;
    }
  
    int i =0;
    unsigned char ascii_buff[17]; //size is 16 character + \0
    const unsigned char *pc = (const unsigned char*)addr;
    //Hex output is 3 characters per Byte e.g. "ff " for 16 Bytes per row plus offset, ascii and padding with spaces. Number of rows is len div 16 plus first row.
    int out_len = (16 * 3 + 32) * (len / 16 + 1);
    output = malloc(out_len); //must be freed
    char* out_ptr = output;
    memset(output, 0, out_len);

    if (len == 0) {
        return output;
    }
    if (len < 0) {
        return output;
    }
    //Cap length to prevent possible overflow in output.
    //Okay. It's at 4GB...
    if (len > 0xFFFFFFFF) {
        len = 0xFFFFFFFF;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) {
                out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"  |%s|", ascii_buff);

                if (json)
                    out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"\\n");
                else
                    out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"\n");
            }

            // Output the offset.
            out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"%08x ", i);
        } else if ((i % 8) == 0) {
            if (i != 0)
                out_ptr += snprintf(out_ptr, out_len - (out_ptr - output)," ");
        }


        // Now the hex code for the specific character.
        out_ptr += snprintf(out_ptr, out_len - (out_ptr - output)," %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            ascii_buff[i % 16] = '.';
        else if (json && pc[i] == 0x22) //Do not insert " in JSON!
            ascii_buff[i % 16] = '\'';
        else if (json && pc[i] == 0x5c) //Do not insert \ in JSON!
            ascii_buff[i % 16] = '/';
        else
            ascii_buff[i % 16] = pc[i];
        ascii_buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"   ");
        if ((i % 8) == 0)
            out_ptr += snprintf(out_ptr, out_len - (out_ptr - output)," ");

        i++;
    }

    // And print the final ASCII bit.
    out_ptr += snprintf(out_ptr, out_len - (out_ptr - output),"  |%s|", ascii_buff);
    out_ptr = 0;

    return output;
}

//print as bits
char* bitdump_ntoh(unsigned char* data, uint64_t len, char delimter, int block_len)
{
    if(len < 0) return 0;

    long int bitstr_len = len*8 + (len*8-1)/block_len + 1; //length inculdes \0 termination
    char* bitstr = malloc(bitstr_len);

    long int pos = 0;
    uint16_t mask = 0b00000001;

    for(long int n = 0; n<len; n++)
    {
        #if defined(__LITTLE_ENDIAN_BITFIELD)
            uint8_t byte = (data[n] & 0x0F) << 4 | (data[n] & 0xF0) >> 4;
                    byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;
                    byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;
        #elif defined(__BIG_ENDIAN_BITFIELD)
        #error "ERROR: Big Endian not supported yet"
        #else
        #error	"Please fix <asm/byteorder.h>"
        #endif

        for (long int i = 1; i<=8; i++)
        {
            if((pos+1) % (block_len+1) == 0)
            {
                bitstr[pos] = delimter;
                //num_delimiter++;
                pos++;
            }
                
                    
                if(byte & mask)
                {
                    bitstr[pos] = '1';
                }
                else
                    bitstr[pos] = '0';
                byte = byte >> 1;
            
            //exp -= 1;
            pos++;
        }
    }

    bitstr[pos] = 0;
    return bitstr;
}

//Make bumber out of bit string
uint64_t bitstrton(char* bitstr)
{
    long int len = strlen(bitstr);
    uint64_t res_num = 0;
    long int exp = 0;
    

    for(long int i = len; i>=0; i--)
    {
        switch(bitstr[i])
        {
            case '1':
                res_num += pow64(2, exp++);
                break;
            case '0':
                exp ++;
                break;
            default: break;
        }
    }

    return res_num;
}

//Exponential function for uint64_t data type
uint64_t pow64(uint64_t base, uint64_t exp)
{
    uint64_t res = 1;
    if(exp < 0) return 0;
    for(uint64_t n = exp; n > 0; n--)
        res *= base;
    return res;
}

//convert IP(v4)-Addresses from network byte order to string
char *inttoa(uint32_t i_addr) //inet_ntoa e.g. converts 127.1.1.1 to 127.0.0.1. This is bad e.g. for testing.
{
    char str_addr[16] = "";
    snprintf(str_addr, 16, "%u.%u.%u.%u", i_addr & 0x000000ff, (i_addr & 0x0000ff00) >> 8, (i_addr & 0x00ff0000) >> 16, (i_addr & 0xff000000) >> 24);
    return strndup(str_addr,16); //strndup ensures \0 termination. Do not forget to free()!
}

/* DEPRECATED
//initialze json objekt and concatinate to it
char* json_do(bool reset, const char* format, ...)
{
    static json_struct json; //static to hold data in json_struct after return from function
    static bool first_run = true;
    signed int numchars = 0; //number of chars to write
    va_list valst; //variable argument list
    va_start (valst, format);

    if (reset) { //should the json_struct be reseted?
        if (!first_run && json.str != NULL) free(json.str);
        first_run = false;
        CHECK(json.str = malloc(1), != 0);
        *json.str = 0;  //add trailing \0 (empty string)
    }

    //get number of chars to write
    va_start (valst, format);
    numchars = vsnprintf(NULL, 0, format, valst);
    va_end(valst);

    //if an empty string has been provided as parameter, just return the pointer to actual string
    if (numchars == 0) {
        return json.str;
    }

    //allocate new memory for chars to write
    CHECK(json.str = realloc(json.str, strlen(json.str) + numchars + 1), != 0);

    //append chars to string
    va_start(valst, format);
    CHECK(vsnprintf(json.str + strlen(json.str), numchars + 1, format, valst), != 0);
    va_end(valst);

    return json.str; //return pointer to (new) string
}
*/

const char * get_config_opt(lua_State* L, char* name) //Returns configuration items from LUA config file
{
    lua_getglobal(L, name);
    if (!lua_isstring(L, -1)) {
        return (const char*) EMPTY_STR; //return constant Empty string, if configuration item was not found.
    }
    return lua_tostring(L, -1); //must be freed
}

char* itoprotostr(uint8_t proto_no, const char* suffix)
{
    int max_len = 20 + strlen(suffix); //Max. Length is 18 in current version + length of suffix + \0, thus 20 + strlen(suffix) will do.
    char* proto_str = malloc(max_len); 
    switch(proto_no){ //Source: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        case 0 : snprintf(proto_str, max_len, "%s%s", "HOPOPT", suffix); break;
        case 1 : snprintf(proto_str, max_len, "%s%s", "ICMP", suffix); break;
        case 2 : snprintf(proto_str, max_len, "%s%s", "IGMP", suffix); break;
        case 3 : snprintf(proto_str, max_len, "%s%s", "GGP", suffix); break;
        case 4 : snprintf(proto_str, max_len, "%s%s", "IPv4", suffix); break;
        case 5 : snprintf(proto_str, max_len, "%s%s", "ST", suffix); break;
        case 6 : snprintf(proto_str, max_len, "%s%s", "TCP", suffix); break;
        case 7 : snprintf(proto_str, max_len, "%s%s", "CBT", suffix); break;
        case 8 : snprintf(proto_str, max_len, "%s%s", "EGP", suffix); break;
        case 9 : snprintf(proto_str, max_len, "%s%s", "IGP", suffix); break;
        case 10 : snprintf(proto_str, max_len, "%s%s", "BBN-RCC-MON", suffix); break;
        case 11 : snprintf(proto_str, max_len, "%s%s", "NVP-II", suffix); break;
        case 12 : snprintf(proto_str, max_len, "%s%s", "PUP", suffix); break;
        case 13 : snprintf(proto_str, max_len, "%s%s", "ARGUS (deprecated)", suffix); break;
        case 14 : snprintf(proto_str, max_len, "%s%s", "EMCON", suffix); break;
        case 15 : snprintf(proto_str, max_len, "%s%s", "XNET", suffix); break;
        case 16 : snprintf(proto_str, max_len, "%s%s", "CHAOS", suffix); break;
        case 17 : snprintf(proto_str, max_len, "%s%s", "UDP", suffix); break;
        case 18 : snprintf(proto_str, max_len, "%s%s", "MUX", suffix); break;
        case 19 : snprintf(proto_str, max_len, "%s%s", "DCN-MEAS", suffix); break;
        case 20 : snprintf(proto_str, max_len, "%s%s", "HMP", suffix); break;
        case 21 : snprintf(proto_str, max_len, "%s%s", "PRM", suffix); break;
        case 22 : snprintf(proto_str, max_len, "%s%s", "XNS-IDP", suffix); break;
        case 23 : snprintf(proto_str, max_len, "%s%s", "TRUNK-1", suffix); break;
        case 24 : snprintf(proto_str, max_len, "%s%s", "TRUNK-2", suffix); break;
        case 25 : snprintf(proto_str, max_len, "%s%s", "LEAF-1", suffix); break;
        case 26 : snprintf(proto_str, max_len, "%s%s", "LEAF-2", suffix); break;
        case 27 : snprintf(proto_str, max_len, "%s%s", "RDP", suffix); break;
        case 28 : snprintf(proto_str, max_len, "%s%s", "IRTP", suffix); break;
        case 29 : snprintf(proto_str, max_len, "%s%s", "ISO-TP4", suffix); break;
        case 30 : snprintf(proto_str, max_len, "%s%s", "NETBLT", suffix); break;
        case 31 : snprintf(proto_str, max_len, "%s%s", "MFE-NSP", suffix); break;
        case 32 : snprintf(proto_str, max_len, "%s%s", "MERIT-INP", suffix); break;
        case 33 : snprintf(proto_str, max_len, "%s%s", "DCCP", suffix); break;
        case 34 : snprintf(proto_str, max_len, "%s%s", "3PC", suffix); break;
        case 35 : snprintf(proto_str, max_len, "%s%s", "IDPR", suffix); break;
        case 36 : snprintf(proto_str, max_len, "%s%s", "XTP", suffix); break;
        case 37 : snprintf(proto_str, max_len, "%s%s", "DDP", suffix); break;
        case 38 : snprintf(proto_str, max_len, "%s%s", "IDPR-CMTP", suffix); break;
        case 39 : snprintf(proto_str, max_len, "%s%s", "TP++", suffix); break;
        case 40 : snprintf(proto_str, max_len, "%s%s", "IL", suffix); break;
        case 41 : snprintf(proto_str, max_len, "%s%s", "IPv6", suffix); break;
        case 42 : snprintf(proto_str, max_len, "%s%s", "SDRP", suffix); break;
        case 43 : snprintf(proto_str, max_len, "%s%s", "IPv6-Route", suffix); break;
        case 44 : snprintf(proto_str, max_len, "%s%s", "IPv6-Frag", suffix); break;
        case 45 : snprintf(proto_str, max_len, "%s%s", "IDRP", suffix); break;
        case 46 : snprintf(proto_str, max_len, "%s%s", "RSVP", suffix); break;
        case 47 : snprintf(proto_str, max_len, "%s%s", "GRE", suffix); break;
        case 48 : snprintf(proto_str, max_len, "%s%s", "DSR", suffix); break;
        case 49 : snprintf(proto_str, max_len, "%s%s", "BNA", suffix); break;
        case 50 : snprintf(proto_str, max_len, "%s%s", "ESP", suffix); break;
        case 51 : snprintf(proto_str, max_len, "%s%s", "AH", suffix); break;
        case 52 : snprintf(proto_str, max_len, "%s%s", "I-NLSP", suffix); break;
        case 53 : snprintf(proto_str, max_len, "%s%s", "SWIPE (deprecated)", suffix); break;
        case 54 : snprintf(proto_str, max_len, "%s%s", "NARP", suffix); break;
        case 55 : snprintf(proto_str, max_len, "%s%s", "MOBILE", suffix); break;
        case 56 : snprintf(proto_str, max_len, "%s%s", "TLSP", suffix); break;
        case 57 : snprintf(proto_str, max_len, "%s%s", "SKIP", suffix); break;
        case 58 : snprintf(proto_str, max_len, "%s%s", "IPv6-ICMP", suffix); break;
        case 59 : snprintf(proto_str, max_len, "%s%s", "IPv6-NoNxt", suffix); break;
        case 60 : snprintf(proto_str, max_len, "%s%s", "IPv6-Opts", suffix); break;
        case 61 : snprintf(proto_str, max_len, "%s%s", "ANYHOSTINT", suffix); break;
        case 62 : snprintf(proto_str, max_len, "%s%s", "CFTP", suffix); break;
        case 63 : snprintf(proto_str, max_len, "%s%s", "ANYLOCALNET", suffix); break;
        case 64 : snprintf(proto_str, max_len, "%s%s", "SAT-EXPAK", suffix); break;
        case 65 : snprintf(proto_str, max_len, "%s%s", "KRYPTOLAN", suffix); break;
        case 66 : snprintf(proto_str, max_len, "%s%s", "RVD", suffix); break;
        case 67 : snprintf(proto_str, max_len, "%s%s", "IPPC", suffix); break;
        case 68 : snprintf(proto_str, max_len, "%s%s", "ANYDFS", suffix); break;
        case 69 : snprintf(proto_str, max_len, "%s%s", "SAT-MON", suffix); break;
        case 70 : snprintf(proto_str, max_len, "%s%s", "VISA", suffix); break;
        case 71 : snprintf(proto_str, max_len, "%s%s", "IPCV", suffix); break;
        case 72 : snprintf(proto_str, max_len, "%s%s", "CPNX", suffix); break;
        case 73 : snprintf(proto_str, max_len, "%s%s", "CPHB", suffix); break;
        case 74 : snprintf(proto_str, max_len, "%s%s", "WSN", suffix); break;
        case 75 : snprintf(proto_str, max_len, "%s%s", "PVP", suffix); break;
        case 76 : snprintf(proto_str, max_len, "%s%s", "BR-SAT-MON", suffix); break;
        case 77 : snprintf(proto_str, max_len, "%s%s", "SUN-ND", suffix); break;
        case 78 : snprintf(proto_str, max_len, "%s%s", "WB-MON", suffix); break;
        case 79 : snprintf(proto_str, max_len, "%s%s", "WB-EXPAK", suffix); break;
        case 80 : snprintf(proto_str, max_len, "%s%s", "ISO-IP", suffix); break;
        case 81 : snprintf(proto_str, max_len, "%s%s", "VMTP", suffix); break;
        case 82 : snprintf(proto_str, max_len, "%s%s", "SECURE-VMTP", suffix); break;
        case 83 : snprintf(proto_str, max_len, "%s%s", "VINES", suffix); break;
        case 84 : snprintf(proto_str, max_len, "%s%s", "TTP or IPTM", suffix); break;
        case 85 : snprintf(proto_str, max_len, "%s%s", "NSFNET-IGP", suffix); break;
        case 86 : snprintf(proto_str, max_len, "%s%s", "DGP", suffix); break;
        case 87 : snprintf(proto_str, max_len, "%s%s", "TCF", suffix); break;
        case 88 : snprintf(proto_str, max_len, "%s%s", "EIGRP", suffix); break;
        case 89 : snprintf(proto_str, max_len, "%s%s", "OSPFIGP", suffix); break;
        case 90 : snprintf(proto_str, max_len, "%s%s", "Sprite-RPC", suffix); break;
        case 91 : snprintf(proto_str, max_len, "%s%s", "LARP", suffix); break;
        case 92 : snprintf(proto_str, max_len, "%s%s", "MTP", suffix); break;
        case 93 : snprintf(proto_str, max_len, "%s%s", "AX.25", suffix); break;
        case 94 : snprintf(proto_str, max_len, "%s%s", "IPIP", suffix); break;
        case 95 : snprintf(proto_str, max_len, "%s%s", "MICP (deprecated)", suffix); break;
        case 96 : snprintf(proto_str, max_len, "%s%s", "SCC-SP", suffix); break;
        case 97 : snprintf(proto_str, max_len, "%s%s", "ETHERIP", suffix); break;
        case 98 : snprintf(proto_str, max_len, "%s%s", "ENCAP", suffix); break;
        case 99 : snprintf(proto_str, max_len, "%s%s", "ANYPRIVENCSCH", suffix); break;
        case 100 : snprintf(proto_str, max_len, "%s%s", "GMTP", suffix); break;
        case 101 : snprintf(proto_str, max_len, "%s%s", "IFMP", suffix); break;
        case 102 : snprintf(proto_str, max_len, "%s%s", "PNNI", suffix); break;
        case 103 : snprintf(proto_str, max_len, "%s%s", "PIM", suffix); break;
        case 104 : snprintf(proto_str, max_len, "%s%s", "ARIS", suffix); break;
        case 105 : snprintf(proto_str, max_len, "%s%s", "SCPS", suffix); break;
        case 106 : snprintf(proto_str, max_len, "%s%s", "QNX", suffix); break;
        case 107 : snprintf(proto_str, max_len, "%s%s", "A/N", suffix); break;
        case 108 : snprintf(proto_str, max_len, "%s%s", "IPComp", suffix); break;
        case 109 : snprintf(proto_str, max_len, "%s%s", "SNP", suffix); break;
        case 110 : snprintf(proto_str, max_len, "%s%s", "Compaq-Peer", suffix); break;
        case 111 : snprintf(proto_str, max_len, "%s%s", "IPX-in-IP", suffix); break;
        case 112 : snprintf(proto_str, max_len, "%s%s", "VRRP", suffix); break;
        case 113 : snprintf(proto_str, max_len, "%s%s", "PGM", suffix); break;
        case 114 : snprintf(proto_str, max_len, "%s%s", "ANY0HOP", suffix); break;
        case 115 : snprintf(proto_str, max_len, "%s%s", "L2TP", suffix); break;
        case 116 : snprintf(proto_str, max_len, "%s%s", "DDX", suffix); break;
        case 117 : snprintf(proto_str, max_len, "%s%s", "IATP", suffix); break;
        case 118 : snprintf(proto_str, max_len, "%s%s", "STP", suffix); break;
        case 119 : snprintf(proto_str, max_len, "%s%s", "SRP", suffix); break;
        case 120 : snprintf(proto_str, max_len, "%s%s", "UTI", suffix); break;
        case 121 : snprintf(proto_str, max_len, "%s%s", "SMP", suffix); break;
        case 122 : snprintf(proto_str, max_len, "%s%s", "SM (deprecated)", suffix); break;
        case 123 : snprintf(proto_str, max_len, "%s%s", "PTP", suffix); break;
        case 124 : snprintf(proto_str, max_len, "%s%s", "ISIS over IPv4", suffix); break;
        case 125 : snprintf(proto_str, max_len, "%s%s", "FIRE", suffix); break;
        case 126 : snprintf(proto_str, max_len, "%s%s", "CRTP", suffix); break;
        case 127 : snprintf(proto_str, max_len, "%s%s", "CRUDP", suffix); break;
        case 128 : snprintf(proto_str, max_len, "%s%s", "SSCOPMCE", suffix); break;
        case 129 : snprintf(proto_str, max_len, "%s%s", "IPLT", suffix); break;
        case 130 : snprintf(proto_str, max_len, "%s%s", "SPS", suffix); break;
        case 131 : snprintf(proto_str, max_len, "%s%s", "PIPE", suffix); break;
        case 132 : snprintf(proto_str, max_len, "%s%s", "SCTP", suffix); break;
        case 133 : snprintf(proto_str, max_len, "%s%s", "FC", suffix); break;
        case 134 : snprintf(proto_str, max_len, "%s%s", "RSVP-E2E-IGNORE", suffix); break;
        case 135 : snprintf(proto_str, max_len, "%s%s", "Mobility Header", suffix); break;
        case 136 : snprintf(proto_str, max_len, "%s%s", "UDPLite", suffix); break;
        case 137 : snprintf(proto_str, max_len, "%s%s", "MPLS-in-IP", suffix); break;
        case 138 : snprintf(proto_str, max_len, "%s%s", "manet", suffix); break;
        case 139 : snprintf(proto_str, max_len, "%s%s", "HIP", suffix); break;
        case 140 : snprintf(proto_str, max_len, "%s%s", "Shim6", suffix); break;
        case 141 : snprintf(proto_str, max_len, "%s%s", "WESP", suffix); break;
        case 142 : snprintf(proto_str, max_len, "%s%s", "ROHC", suffix); break;
        case 143 : snprintf(proto_str, max_len, "%s%s", "Ethernet", suffix); break;
        //Fallback is just taking the raw protocol number as string, e.g. 144-255 which are Unassigned/Experimental/Reserved
        default: snprintf(proto_str, max_len, "%d%s", proto_no, suffix); break;
    }
    
    return proto_str;
}
