/*
 *  libdict_c, a simple implementation of python dictonaries in C
 *  Copyright (C) 2021 CFOV, github [dot] fox [at] thevoid [dot] email
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef LIBDICT_C_H
#define LIBDICT_C_H

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

//Enable or disable dynamic path update capability
#define DICT_DYN_PATH_UPDATES 1

/**
 * \brief Constants for type definition in JSON-Dictionaries and -Arrays
 *
 *      In JSON there are only the following data types allowed:
 *      - a string (here: JSON_STR)
 *      - a number (here: JSON_INT, JSON FLOAT)
 *      - an object e.g. JSON object (here: JSON_OBJ)
 *      - an array (here: JSON_ARRAY)
 *      - a boolean (here: JSON_BOOL)
 *      - null (here: JSON_NULL)
 *      
 *      In addition here are some more types definded
 *      - Number is split into JSON_INT and JSON_FLOAT, because in C they must be distinguished.
 *      - JSON_EMTPY is a none-type that is used for technical reasons to mark an allocated object as empty.
 *      - JSON_HEX is a special type, added here for convinience: It is saved as a number but has a format attached, so it is put out as JSON String in the end.
 *
 */
#define JSON_EMPTY 0 //JSON_EMTPY is 0, so memset to 0 works as if set to JSON_EMPTY.
#define JSON_NULL 10
#define JSON_BOOL 20
#define JSON_INT 30 //Numbers are distinguished by C-type for appropriate output
#define JSON_FLOAT 31 //Double type in C
#define JSON_HEX 32 //Hex is an long int put out as String with %x
#define JSON_STR 40
#define JSON_ARRAY 50
#define JSON_OBJ 60

/**
 * \brief Constants to translate type definitions
 * 
 *      For translation in human readable strings by
 *      char* json_typetostr(int json_type)
 *
 */
#define JSON_EMPTY_AS_HRSTR "Emtpy"
#define JSON_NULL_AS_HRSTR "NULL Type"
#define JSON_BOOL_AS_HRSTR "Boolean"
#define JSON_INT_AS_HRSTR "Integer" 
#define JSON_FLOAT_AS_HRSTR "Floating Point Number"
#define JSON_HEX_AS_HRSTR "Hexadecimal Number"
#define JSON_STR_AS_HRSTR "String"
#define JSON_ARRAY_AS_HRSTR "Array"
#define JSON_OBJ_AS_HRSTR "Object"


/**
 * \brief Constants for output of hexadecimal numbers as string
 *
 *     Format String lookup is done by libdict_c.c:const char* __json_hex_format[HEX_FORMAT_*]
 *     with one of the HEX_FORMAT_* constants as defined here.
 */
#define HEX_FORMAT_STD 0
#define HEX_FORMAT_02  1
#define HEX_FORMAT_04  2
#define HEX_FORMAT_05  3
#define HEX_FORMAT_08  4

/**
 * \brief Representation of JSON-Types
 *
 *     Union as representation of JSON-Types.
 *     JSON_HEX is going to be saved in an nested unnamed struct, containing its value as an integer an a format specifier for output as string representation.
 *
 */
union json_type {
    bool boolean;
    long double floating;
    long long int integer;
    struct {
        unsigned long int number;
        __uint8_t format; //Use HEX_FORMAT_* constants!
    } hex;
    char* string;
    struct array* array;
    struct dict* object;
};

/**
 * \brief Element of a dictonary as double linked list
 *
 *     -next and prev are the pointers to maintain the linked list
 *     -type stores the data-type, stored in value
 *     -value stores the data
 *     -key stores the dictonary key, which is always a string in JSON.
 *
 */
struct dict {
    struct dict* next;
    struct dict* prev;
    __uint8_t type;
    char* key;
    union json_type value;
};

/**
 * \brief Element of an array as linked list
 *
 *     -next is the pointer to maintain the linked list
 *     -type stores the data-type, stored in value
 *     -value stores the data
 *
 */
struct array {
    struct array* next;
    __uint8_t type;
    union json_type value;
};

//Function Declarations

/**
 * \brief Converts type defintions into strings
 *
 *     Outout is a human readable string
 *
 * \param json_type JSON type definition
 * \return Human readable string
 *
 */
char* json_typetostr(int json_type);

/**
 * \brief Helper function to manage a dict
 *
 *     Not necessary, but useful function to avoid the use of global vars.
 *     To free the static dict of this function and get a new dict set reset to true.
 *     To get the static dict w/o reset, set reset to false.
 *     To free the static dict of this function use:
 *     dict_free(json_dict(false));
 * 
 *     Copy this function an rename it if you want to manage more dictionaries this way at the same time.
 *
 * \param reset Reset static dict
 * \return Address of static dict
 *
 */
struct dict* json_dict(bool reset);

/**
 * \brief Print one elment of type struct dict
 *
 *     Prints only the given element and does not follow the linked list.
 *     Usefull for debugging your code (or mine).
 *
 * \param fp File pointer for output, e.g. stderr
 * \param dict address of single struct dict to print
 *
 */
void dict_printelement(FILE* fp, struct dict* dict);

/**
 * \brief Print one elment of type struct array
 *
 *     Prints only the given element and does not follow the linked list.
 *     Usefull for debugging your code (or mine).
 *
 * \param fp File pointer for output, e.g. stderr
 * \param dict address of single struct array to print
 *
 */
void array_printelement(FILE* fp, struct array* array);

/**
 * \brief Initializes a new dictionary of type struct dict
 *
 *     Fresh initialized dictionarys are set completly to 0,
 *     so the are implicit set to JSON_EMPTY and thus marked as "free to use".
 *     
 *
 * \return initialized, new dictionary
 *
 */
struct dict* dict_new();

/**
 * \brief Initializes a new array of type struct array
 *
 *     Fresh initialized arrays are set completly to 0,
 *     so the are implicit set to JSON_EMPTY and thus marked as "free to use".
 *     
 *
  * \return initialized, new array
 *
 */
struct array* array_new();

/**
 * \brief Adds an element to an array
 *
 *     Adds an element to an array with type as defined by JSON_* defines.
 *     The value is taken from a union json_type.
 *     Returns the address of the added element
 *     
 * \param array struct array to add new element to
 * \param type data type of new element
 * \param value value of the new element, given as union json_type
 * \return Address of added element
 *
 */
struct array* array_add(struct array* array, __uint8_t type, union json_type value);

/**
 * \brief Updates a dictionary with a new element
 *
 *     Updates a dictionary with a new element, using a path and ensures valid JSON.
 *     The value is taken from a union json_type.
 *     Returns the address of the added element and NULL in case of an error.
 *     If updating the dict with a string, the string is copied, so it eventually has to be freed in calling function.
 *     If updating the dict with a nested dict or array, you must not free it, but have to deal with it eventually if updating fails.
 * 
 *     If the new element does not exist in path, it will be added, example:
 *     Given the following structure stored under struct dict* dict: 
 *     {"Cougar":1, "Rabbit":null}
 *     The following code:
 *          struct dict* dict = dict_new();
 *          union json_type value;
 *          //The addition of "cougar" and "rabbit" is omitted here, but follows the same principle
 *          value.boolean = true;
 *          dict_update(dict, JSON_BOOL, value, 1, "Fox");
  *     Results in:
 *     {"Cougar":1, "Rabbit":null, "Fox":true}
 * 
 *     If a new element is on a given path, that does not exist, the path is dynamicly updated.
 *     Given:
 *     {"Cougar":1, "Rabbit":null}
 *     The following code:
 *          value.boolean = true;
 *          dict_update(dict, JSON_BOOL, value, 4, "1", "A", "iii", "Fox");
 *     Results in:
 *     {"Cougar":1, "Rabbit":null, "1":{"A":{"iii":{"Fox":true}}}}
 * 
 *     If the path is "blocked" by an none JSON_OBJ - type, the update will fail an NULL is returned.
 *     Given:
 *     {"Cougar":1, "Rabbit":null, "1":{"A":{"iii":{"Fox":true}}}}
 *     The following code is going to fail:
 *          value.boolean = true;
 *          dict_update(dict, JSON_BOOL, value, 5, "1", "A", "iii", "Fox", "Wolf");
 *     Because "Fox" is part of the path to new element "Wolf" and not a JSON_OBJ, but a JSON_BOOL - type.
 * 
 *     When adding a JSON_HEX - type value, be sure to set the format for this value for the output you desired:
 *     Given an empty dict initialized by dict_new(), the following code:
 *          value.hex.number = 10; value.hex.format = HEX_FORMAT_04;
 *          dict_update(dict, JSON_HEX, value, 1, "Hex Test");
 *     Resulst in the following output:
 *     {"Hex Test":"0x000a"}
 * 
 *     You can combine all functions to set any desired values, just be sure to descent in dict/array structures when necessary, Example:
 *     Given:
 *     {"Lamb":5, "Wolf":"Hurz", "INNER":{"Puma":false, "Rabbit":null, "Fox":true, "ARRAY":["0x000a", "asdfjklo", {}]}}
 *     The following code:     
 *          value.hex.number = 0xDEADBEEF; value.hex.format = HEX_FORMAT_STD;
 *          dict_update(array_get(dict_get(dict, 2, "INNER", "ARRAY")->value.array, 2)->value.object, JSON_HEX, value, 1, "DEADBEEF");
 *     Results in:
 *     {"Lamb":5, "Wolf":"Hurz", "INNER":{"Puma":false, "Rabbit":null, "Fox":true, "ARRAY":["0x000a", "asdfjklo", {"DEADBEEF":"0xdeadbeef"}]}}
 *     
 * \param dict struct dict to update with new element
 * \param type data type of new element
 * \param value value of the new element, given as union json_type
 * \param path_len length of variadic list, specifiying the path to add to
 * \param path variadict list specifiyng the path to add to
 * \return Address of added element, NULL in case of an error
 *
 */
struct dict* dict_update(struct dict* dict, __uint8_t type, union json_type value, unsigned int path_len, ...);

/**
 * \brief Internal function to add a value to a dictonary
 *
 *     Internal function to add a value to a dictonary without descending in nested dictionaries ("plain")
 *     
 * \param dict struct dict to add element to
 * \param type data type of new element
 * \param value value of the new element, given as union json_type
 * \param key key of the new element
 * \return initialized, new array
 *
 */
struct dict* __dict_add(struct dict* dict, __uint8_t type, union json_type value, char* key);

/**
 * \brief Prints a dictonary recursivly as JSON
 *
 *     Prints a dictonary, descending recursivly in dict/array structures as JSON
 *     
 * \param fp File pointer for output, e.g. stderr
 * \param dict address of struct dict to print recursivly
 *
 */
void dict_dump(FILE* fp, struct dict* dict);

/**
 * \brief Dumps a dictonary recursivly as JSON to a string
 *
 *     Dumps a dictonary, descending recursivly in dict/array structures as JSON, by returning a string.
 *     The string must be freed by calling function!
 *     
 * \param dict address of struct dict to print recursivly
 * \return Pointer to resulting string; has to be freed in calling function.
 *
 */
char* dict_dumpstr(struct dict* dict);

/**
 * \brief Internal function to recursivly print a dict structure
 *
 *     Prints a dictonary, descending recursivly in dict/array structures as JSON.
 *     
 * \param fp File pointer for output, e.g. stderr
 * \param dict address of struct dict to print recursivly
 *
 */
void __dict_print(FILE* fp, struct dict* dict);

/**
 * \brief Prints an array recursivly as JSON
 *
 *     Prints an array, descending recursivly in dict/array structures as JSON
 *     
 * \param fp File pointer for output, e.g. stderr
 * \param array address of struct array to print recursivly
 *
 */
void array_dump(FILE* fp, struct array* array);

/**
 * \brief Internal function to recursivly print an array structure
 *
 *     Prints an array, descending recursivly in dict/array structures as JSON.
 *     
 * \param fp File pointer for output, e.g. stderr
 * \param array address of struct array to print recursivly
 *
 */
char* array_dumpstr(struct array* array);

/**
 * \brief Internal function to recursivly dump an array structure as JSON to a string.
 *
 *     Dumps an array, descending recursivly in dict/array structures as JSON, by returning a string.
 *     The string must be freed by calling function!
 *     
 * \param fp File pointer for output, e.g. stderr
 * \param array address of struct array to print recursivly; has to be freed in calling function.
 *
 */
void __array_print(FILE* fp, struct array* array);

/**
 * \brief Function to get an element from a dictionary
 *
 *     Gets an element from a dictionary.
 *     Be aware if searching for nested dicts or arrays, you have to descend manually, example:
 *     Given a struct dict* dict with the following content:
 *     {"Wolf":"Hurz", "INNER":{"Rabbit":null, "Fox":true}, "Tiger":17}
 *     This code:
 *          ret = dict_get(dict, 1, "INNER");
 *          printf("%s\n", ret->key);
 *          printf("%s\n", ret->next->key);
 *     Will print:
 *          INNER
 *          Tiger
 *     In contrast this code:
 *          ret = dict_get(dict, 1, "INNER")->value.object;
 *          printf("%s\n", ret->key);
 *          printf("%s\n", ret->next->key);
 *     Will print:
 *          Rabbit
 *          Fox
 *     
 * \param dict struct dict to get element from
 * \param path_len length of variadic list, specifiying the path get element from
 * \param path variadict list specifiyng the path to get element from
 * \return address of struct dict if found, NULL if not found
 *
 */
struct dict* dict_get(struct dict* dict, int path_len, ...);

/**
 * \brief Internal Function to get an element without descending
 *
 *     Internal Function to get an element without descending in nested dict/array structures ("plain search")
 *     Be aware if searching for nested dicts or arrays, you have to descend manually, example:
 *     
 * \param dict struct dict to get element from
 * \param key key to search for
 * \param prev_dict the address of the element bevor the searched one is stored here (e.g. for deletion)
 * \return address of struct dict if found, NULL if not found
 *
 */
struct dict* __dict_plainsearch(struct dict* dict, char* key, struct dict** prev_dict);

/**
 * \brief Emptys a dictionary, but does not free it
 *
 *     Emptys a dictionary, but does not free it. Nested dicts/arrays are freed.
 *     The dict passed to dict_empty is marked as JSON_EMPTY.
 *     
 * \param dict struct dict to empty
 * \return address of struct dict, that has been emptied
 *
 */
struct dict* dict_empty(struct dict* dict);

/**
 * \brief Emptys a dictionary and frees it
 *
 *     Emptys a dictionary, and frees it. Nested dicts/arrays are also freed.
 *     
 * \param dict struct dict to free
 *
 */
void dict_free(struct dict* dict);

/**
 * \brief Emptys a dictionary, but does not free it
 *
 *     Emptys a dictionary, but does not free it. Nested dicts/arrays are freed.
 *     The dict passed to dict_empty is marked as JSON_EMPTY.
 *     
 * \param dict struct dict to empty
 * \return address of struct dict, that has been emptied
 *
 */
struct dict* dict_empty(struct dict* dict);

/**
 * \brief Emptys an array, but does not free it
 *
 *     Emptys an array, but does not free it. Nested dicts/arrays are freed.
 *     The array passed to dict_empty is marked as JSON_EMPTY.
 *     
 * \param array struct array to empty
 * \return address of struct array, that has been emptied
 *
 */
struct array* array_empty(struct array* array);

/**
 * \brief Emptys an array and frees it
 *
 *     Emptys an array, and frees it. Nested dicts/arrays are also freed.
 *     
 * \param array struct array to free
 *
 */
void array_free(struct array* array);

/**
 * \brief Deletes an element in a struct dict
 *
 *     Deletes an element in a struct dict, given a path to the element.
 *     The pointer to the dictionary may be altered, if the first element is the one deleted.
 *     
 * \param dict_ptr struct dict to delete element from
 * \param path_len length of variadic list, specifiying the path to the element beeing deleted
 * \param path variadict list specifiyng the path to the element beeing deleted
 * \return True if deletion was succesfull, False if not found
 *
 */
bool dict_del(struct dict** dict_ptr, int path_len, ...);

/**
 * \brief Internal Function to delete an element in a struct dict
 *
 *     Deletes an element in a struct dict, given a path to the element.
  *     
 * \param dict struct dict to delete element from
 * \param path_len length of variadic list, specifiying the path to the element beeing deleted
 * \param next_key next key on path
 * \param keys list of keys as va_list, specifying the rest of the path to the element beeing deleted
 * \return Address of deleted element, if deletion was succesfull, NULL if not found
 *
 */
struct dict* __dict_delrec(struct dict* dict, int path_len, char* next_key, va_list keys);

/**
 * \brief Returns the length of an array
 *
 *     Returns the length of an array. Elements with type JSON_EMPTY are ignored.
 *     
 * \param array struct array to get length from
 * \return length of array
 *
 */
long unsigned int array_len(struct array* array);

/**
 * \brief Gets an element from an array
 *
 *     Gets an element of an array given its postition starting with 0.
 *     
 * \param array struct array to get element from
 * \param pos postition of the element
 * \return address of the element found, NULL if not found
 *
 */
struct array* array_get(struct array* array, long int pos);

/**
 * \brief Deletes an element from an array
 *
 *     Deletes an element from an array given its postition starting with 0.
 *     Nested dicts/arrays are freed.
 *     
 * \param array struct array to delete element from
 * \param pos postition of the element
 * \return True if deletion was succesfull, False if not found
 *
 */
bool array_del(struct array* array, long int pos);

/**
 * \brief Appends two struct dict
 *
 *     Appends two struct dict, but does *not* ensure valid JSON, e.g. duplicate key usage.
 *     source_dict is not copied to dest_dict, so do not free, if appending was succesfull.
 *     On the other hand, you have to deal with it, if appending was not succesull.
 *     
 * \param source_dict dictionary to append
 * \param dest_dict dictonary to append source_dict to
 * \return True if appending was succesfull, False in case of an error
 *
 */
bool dict_append(struct dict* source_dict, struct dict* dest_dict);

#endif
