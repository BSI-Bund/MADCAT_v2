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
// Gratefully adopted and modified for MADCAT by BSI 2020-2021

#include "libdict_c.h"

//Constant globals

/**
 * \brief Format strings for output of hexadecimal numbers as string
 *
 *     Defines the format strings for use with the defined constants HEX_FORMAT_*
 *
 */
const char* const __json_hex_format[] = {
    "\"0x%lx\"",   //HEX_FORMAT_STD
    "\"0x%02lx\"", //HEX_FORMAT_02
    "\"0x%04lx\"", //HEX_FORMAT_04
    "\"0x%05lx\"", //HEX_FORMAT_05
    "\"0x%08lx\"" //HEX_FORMAT_08
};

//Function Definitions

char* json_typetostr(int json_type) {
    switch(json_type) {
        case JSON_EMPTY: return JSON_EMPTY_AS_HRSTR; break;
        case JSON_NULL: return JSON_NULL_AS_HRSTR; break;
        case JSON_BOOL: return JSON_BOOL_AS_HRSTR; break;
        case JSON_HEX: return JSON_HEX_AS_HRSTR; break;
        case JSON_INT: return JSON_INT_AS_HRSTR; break;
        case JSON_FLOAT: return JSON_FLOAT_AS_HRSTR; break;
        case JSON_STR: return JSON_STR_AS_HRSTR; break;
        case JSON_ARRAY: return JSON_ARRAY_AS_HRSTR; break;
        case JSON_OBJ: return  JSON_OBJ_AS_HRSTR; break;
        default: break;
    }
    return "JSON_UNKNOWN";
}

struct dict* json_dict(bool reset) {
    static struct dict* dict = NULL;
    if(dict == NULL) return dict = dict_new();
    if(reset) {
        dict_free(dict);
        return dict = dict_new();
    } 
    return dict;
}

void dict_printelement(FILE* fp, struct dict* dict) {
    fprintf(fp, "### PRINT DICT ELEMENT START ###\n");
    if(dict == 0)
        fprintf(fp, "\tNull-Pointer provided.");
    else {
        fprintf(fp, "\tSelf: %p\n", dict);
        fprintf(fp, "\tKey: %s\n", dict->key ? dict->key : "(key nil)");
        fprintf(fp, "\tNext: %p (%s)\n", dict->next, dict->next ? dict->next->key ? dict->next->key : "(key nil)" : "(next nil)");
        fprintf(fp, "\tprev: %p (%s)\n", dict->prev, dict->prev ? dict->prev->key ? dict->prev->key : "(key nil)" : "(prev nil)");
        fprintf(fp, "\ttype: %d (%s)\n\tvalue: ", dict->type, json_typetostr(dict->type));
        switch(dict->type) {
            case JSON_NULL: fprintf(fp, "null"); break;
            case JSON_BOOL: fprintf(fp, "%s", dict->value.boolean ? "true" : "false"); break;
            case JSON_HEX: 
                switch (dict->value.hex.format)
                {
                case HEX_FORMAT_STD:
                case HEX_FORMAT_02:
                case HEX_FORMAT_04:
                case HEX_FORMAT_05:
                case HEX_FORMAT_08:
                    fprintf(fp, __json_hex_format[dict->value.hex.format], dict->value.hex.number); break;
                    break;
                default:
                    fprintf(fp, __json_hex_format[HEX_FORMAT_STD], dict->value.hex); break;
                    break;
                }
                break;
            case JSON_INT: fprintf(fp, "%lld", dict->value.integer); break;
            case JSON_FLOAT: fprintf(fp, "%Lf", dict->value.floating); break;
            case JSON_STR: fprintf(fp, "%s", dict->value.string); break;
            case JSON_ARRAY: fprintf(fp, "%p", dict->value.array ? dict->value.array : 0); break;
            case JSON_OBJ: fprintf(fp, "%p (%s)", dict->value.object, dict->value.object ? dict->value.object->key ? dict->value.object->key : "(key nil)" : "(object nil)"); break;
            default: break;
        }
    }
    fprintf(fp, "\n### PRINT DICT ELEMENT END ###\n");
    return;
}

void array_printelement(FILE* fp, struct array* array) {
    fprintf(fp, "### PRINT ARRAY ELEMENT START ###\n");
    if(array == 0)
        fprintf(fp, "\tNull-Pointer provided.");
    else {
        fprintf(fp, "\tSelf: %p\n", array);
        fprintf(fp, "\tNext: %p\n", array->next);
        fprintf(fp, "\ttype: %d (%s)\n\tvalue: ", array->type, json_typetostr(array->type));
        switch(array->type) {
            case JSON_NULL: fprintf(fp, "null"); break;
            case JSON_BOOL: fprintf(fp, "%s", array->value.boolean ? "true" : "false"); break;
            case JSON_HEX: 
                switch (array->value.hex.format)
                {
                case HEX_FORMAT_STD:
                case HEX_FORMAT_02:
                case HEX_FORMAT_04:
                case HEX_FORMAT_05:
                case HEX_FORMAT_08:
                    fprintf(fp, __json_hex_format[array->value.hex.format], array->value.hex.number); break;
                    break;
                default:
                    fprintf(fp, __json_hex_format[HEX_FORMAT_STD], array->value.hex); break;
                    break;
                }
                break;
            case JSON_INT: fprintf(fp, "%lld", array->value.integer); break;
            case JSON_FLOAT: fprintf(fp, "%Lf", array->value.floating); break;
            case JSON_STR: fprintf(fp, "%s", array->value.string); break;
            case JSON_ARRAY: fprintf(fp, "%p", array->value.array ? array->value.array : 0); break;
            case JSON_OBJ: fprintf(fp, "%p (%s)", array->value.object, array->value.object ? array->value.object->key ? array->value.object->key : "(key nil)" : "(object nil)"); break;
            default: break;
        }
    }
    fprintf(fp, "\n### PRINT ARRAY ELEMENT END ###\n");
    return;
}

struct dict* dict_new(){
    return (struct dict*)calloc(1, sizeof(struct dict)); //sets dict->type = JSON_EMPTY and all other vars to 0;
}

struct array* array_new(){
    return (struct array *)calloc(1,sizeof(struct array)); //sets array->type = JSON_EMPTY and all other vars to 0;
}

struct array* array_add(struct array* array, __uint8_t type, union json_type value) {
    struct array* new = array;
    if(array->next == 0) {
        if(new->type != JSON_EMPTY) new = array_new();
        array->next = new;
        new->next = 0;
        new->type = type;
        switch(type) {
            case JSON_NULL: break;
            case JSON_BOOL: new->value.boolean = value.boolean; break;
            case JSON_HEX: 
                new->value.hex.number = value.hex.number;
                new->value.hex.format = value.hex.format;
                break;
            case JSON_INT: new->value.integer = value.integer; break;
            case JSON_FLOAT: new->value.floating = value.floating; break;
            case JSON_STR:
                new->value.string = malloc(strlen(value.string)+1);
                memset(new->value.string, 0, strlen(value.string)+1);
                strncpy(new->value.string, value.string, strlen(value.string));
                break;
            case JSON_ARRAY: new->value.array = value.array; break;
            case JSON_OBJ: new->value.object = value.object; break;
            default: new->type = JSON_NULL; break;
        }
        new->next = 0;
        return new;
    } else {
        array_add(array->next, type, value);
    }
    return NULL;
}

struct dict* dict_update(struct dict* dict, __uint8_t type, union json_type value, unsigned int path_len, ...) {
    if(path_len < 1 || dict == 0) return NULL;
    va_list valist;
    char* next_key = 0;
    struct dict* next_dict = dict;
    struct dict* old_next_dict = 0;
    struct dict* last_dict = 0;
    struct dict* prev_dict = 0;

    //initialize valist
    va_start(valist, path_len);
    next_key = va_arg(valist, char *); //get first key of path

    if(path_len == 1) { //Trivial case with path_len == 1
        //fprintf(stderr, "Trivial\n");
        last_dict = __dict_plainsearch(dict, next_key, &prev_dict);
        if(last_dict == 0) { //Element not existing, add new to dict directly
            return __dict_add(dict, type, value, next_key); //adds new or updates empty
        } else { //Element existing, empty first, than update
            return __dict_add(dict_empty(last_dict), type, value, next_key); //adds new or updates empty
        }
    }

    //search given path till second last
    for(int i = 0; i<path_len-1; i++) {
        //fprintf(stderr, "i: %d\n", i);
        //fprintf(stderr, "Following Path %s\n", next_key);
        old_next_dict = next_dict;
        if(i==0) //first dict has no need to descent
            next_dict = __dict_plainsearch(next_dict, next_key, &prev_dict);
        else //decent
            next_dict = __dict_plainsearch(next_dict->value.object, next_key, &prev_dict);
        //dict_printelement(stderr, next_dict);
        if(next_dict == 0) { //Check if path is existing
            #if DICT_DYN_PATH_UPDATES > 0
                if(i==0) {
                    //next_dict = __dict_add(dict, JSON_OBJ, (union json_type) dict_new(), next_key); //if not make it existing
                    next_dict = dict_update(dict, JSON_OBJ, (union json_type) dict_new(), 1, next_key);
                } else {
                    //next_dict = __dict_add(old_next_dict->value.object, JSON_OBJ, (union json_type) dict_new(), next_key); //if not make it existing
                    next_dict = dict_update(old_next_dict->value.object, JSON_OBJ, (union json_type) dict_new(), 1, next_key);
                }

                if(old_next_dict->value.object == next_dict) //Check if parent dict is linked with last dict, if so it is the first one in a nested dict,...
                    next_dict->prev = old_next_dict; //...thus link it back to parent

                if(type == JSON_OBJ) //Link an inserted nested dict with parent dict
                    next_dict->value.object->prev = next_dict;

            #else
                va_end(valist); //destroy valist
                return NULL;
            #endif
        }
        if(next_dict->type != JSON_OBJ){ //Check if a non-JSON Object is on path
            //fprintf(stderr, "non-JSON Obj on path %s\n", next_key);
            va_end(valist); //destroy valist
            return NULL;
        }
        next_key = va_arg(valist, char *);
    }
    
    va_end(valist); //destroy valist

    //get last key of path by descending in next_dict
    last_dict = __dict_plainsearch(next_dict->value.object, next_key, &prev_dict);

    if(last_dict != 0){ //if update is exisiting in dict, make it empty first, thus possible included string(s), arrays or dicts must be freed
        dict_empty(last_dict);
    }

    //inserting *in* last nested dict in path
    last_dict = __dict_add(next_dict->value.object, type, value, next_key);

    if(next_dict->value.object == last_dict) //Check if parent dict is linked with last dict, if so it is the first one in a nested dict,...
        last_dict->prev = next_dict; //...thus link it back to parent

    if(type == JSON_OBJ) //Link an inserted nested dict with parent dict
        last_dict->value.object->prev = last_dict;

    return last_dict;
}

struct dict* __dict_add(struct dict* dict, __uint8_t type, union json_type value, char* key) {
    struct dict* new = dict;
    if(dict->next == 0 || dict->type == JSON_EMPTY) { //Last element in list or Empty Element
        //fprintf(stderr, "INSERT POINT FOUND!\n");
        if(dict->type != JSON_EMPTY) { //Implicit ... && dict->next == 0, thus end of linked list and new dict-element needed.
            new = dict_new();
            new->next = 0;
            new->prev = dict;
            dict->next = new;
        }
        new->key = malloc(strlen(key)+1); //+1 for \0
        memset(new->key, 0, strlen(key)+1);
        strncpy(new->key, key, strlen(key));
        new->type = type;
        switch(type) {
            case JSON_NULL: break;
            case JSON_BOOL: new->value.boolean = value.boolean; break;
            case JSON_HEX:
                new->value.hex.number = value.hex.number;
                new->value.hex.format = value.hex.format;
                break;
            case JSON_INT: new->value.integer = value.integer; break;
            case JSON_FLOAT: new->value.floating = value.floating; break;
            case JSON_STR:
                new->value.string = malloc(strlen(value.string)+1);
                memset(new->value.string, 0, strlen(value.string)+1);
                strncpy(new->value.string, value.string, strlen(value.string));
                break;
            case JSON_ARRAY: new->value.array = value.array; break;
            case JSON_OBJ: new->value.object = value.object; break;
            default: new->type = JSON_NULL; break;
        }
        return new;
    } else {
        new = __dict_add(dict->next, type, value, key);
        return new;
    }
    return new;
}

void dict_dump(FILE* fp, struct dict* dict) {
    fprintf(fp, "{");
    if(dict != 0) __dict_print(fp, dict);
    fprintf(fp, "}");
    return;
}

//unterschied zu dict_dump Wer kümmert sich hier um das free
char* dict_dumpstr(struct dict* dict){
    char *buf = 0;
    size_t len = 0;
    FILE* stream = open_memstream(&buf, &len);
    if (stream == NULL) {
        fprintf(stderr, "ERROR: Stream could not be opened by open_memstrem\n");
        abort();
    }
    fprintf(stream, "{");
    if(dict != 0) __dict_print(stream, dict);
    fprintf(stream, "}");
    fflush(stream);
    fclose(stream);
    return buf;
}

void __dict_print(FILE* fp, struct dict* dict) {
    if(dict == 0) return;
    //fprintf(stdout,"\n##### %s ##### dict->next %s dict->prev %s\n", dict->key, dict->next ? dict->next->key : "NONE", dict->prev ? dict->prev->key : "NONE");
    //fprintf(fp, "\"<%s>\\", dict->prev ? dict->prev->key ? dict->prev->key : "key nil" : "prev nil");
    //dict_printelement(stderr, dict);

    if(dict->next == dict || dict->prev == dict || (dict->type == JSON_OBJ && dict->value.object == dict) ) {
        fprintf(stderr, "ERROR: Loop in dict %p\n", dict);
        dict_printelement(stderr,dict);
        fprintf(stderr, "Aborting... %p\n", dict);
        abort();
    }

    if(dict->type != JSON_EMPTY) {
        switch(dict->type) {
            case JSON_NULL: fprintf(fp, "\"%s\":null", dict->key); break;
            case JSON_BOOL: fprintf(fp, "\"%s\":%s", dict->key, dict->value.boolean ? "true" : "false"); break;
            case JSON_HEX:
                fprintf(fp, "\"%s\":", dict->key);
                switch (dict->value.hex.format)
                {
                case HEX_FORMAT_STD:
                case HEX_FORMAT_02:
                case HEX_FORMAT_04:
                case HEX_FORMAT_05:
                case HEX_FORMAT_08:
                    fprintf(fp, __json_hex_format[dict->value.hex.format], dict->value.hex.number); break;
                    break;
                default:
                    fprintf(fp, __json_hex_format[HEX_FORMAT_STD], dict->value.hex); break;
                    break;
                }
                break;
            case JSON_INT: fprintf(fp, "\"%s\":%lld", dict->key, dict->value.integer); break;
            case JSON_FLOAT: fprintf(fp, "\"%s\":%Lf", dict->key, dict->value.floating); break;
            case JSON_STR: fprintf(fp, "\"%s\":\"%s\"", dict->key, dict->value.string); break;
            case JSON_ARRAY: fprintf(fp, "\"%s\":", dict->key); array_dump(fp, dict->value.array); break;
            case JSON_OBJ: fprintf(fp, "\"%s\":", dict->key); dict_dump(fp, dict->value.object); break;
            default: break;
        }
    }
    if(dict->next != 0) {
        fprintf(fp, ", ");
        __dict_print(fp, dict->next);
    }

    return;
}

void array_dump(FILE* fp, struct array* array) {
    fprintf(fp, "[");
    if(array != 0) __array_print(fp, array);
    fprintf(fp, "]");
    return;
}

//unterschied zu dict_dump Wer kümmert sich hier um das free
char* array_dumpstr(struct array* array){
    char *buf = 0;
    size_t len = 0;
    FILE* stream = open_memstream(&buf, &len);
    if (stream == NULL) {
        fprintf(stderr, "ERROR: Stream could not be opened by open_memstrem\n");
        abort();
    }
    fprintf(stream, "[");
    if(array != 0) __array_print(stream, array);
    fprintf(stream, "]");
    fflush(stream);
    fclose(stream);
    return buf;
}

void __array_print(FILE* fp, struct array* array) {
    if(array == 0) return;
    if(array->type != JSON_EMPTY)
        switch(array->type) {
            case JSON_NULL: fprintf(fp, "null "); break;
            case JSON_BOOL: fprintf(fp, "%s", array->value.boolean ? "true" : "false"); break;
            case JSON_HEX:
                switch (array->value.hex.format)
                {
                case HEX_FORMAT_STD:
                case HEX_FORMAT_02:
                case HEX_FORMAT_04:
                case HEX_FORMAT_05:
                case HEX_FORMAT_08:
                    fprintf(fp, __json_hex_format[array->value.hex.format], array->value.hex.number); break;
                    break;
                default:
                    fprintf(fp, __json_hex_format[HEX_FORMAT_STD], array->value.array); break;
                    break;
                }
                break;
            case JSON_INT: fprintf(fp, "%lld", array->value.integer); break;
            case JSON_FLOAT: fprintf(fp, "%Lf", array->value.floating); break;
            case JSON_STR: fprintf(fp, "\"%s\"", array->value.string); break;
            case JSON_ARRAY: array_dump(fp, array->value.array); break;
            case JSON_OBJ: dict_dump(fp, array->value.object); break;
            default: break;
        }
    if(array->next != 0) {
        fprintf(fp, ", ");
        __array_print(fp, array->next);
    }
    return;
}


struct dict* dict_get(struct dict* dict, int path_len, ...) {
    //fprintf(stderr,"DICT_GET with dict=%p, path_len=%d\n", dict, path_len);
    va_list valist;
    char* key = 0;
    //initialize valist
    va_start(valist, path_len);
    if(dict == NULL) {
            va_end(valist); //destroy valist
            return NULL;
    }
    key = va_arg(valist, char *);
    while(path_len > 0 && dict != NULL) {
        //fprintf(stderr, "Searching for key %s...", key);
        if(dict->key != NULL && strcmp(key, dict->key) == 0) { //found actuall part of path
            if(path_len == 1) { //Object found
                //fprintf(stderr, "Object found!\n");
                return dict;
            } else if(dict->type == JSON_OBJ) { //Point to descent found
                dict = dict->value.object;
                key = va_arg(valist, char *);
                path_len--;
            }
        } else { //Iterate through list, till key ist found
            dict = dict->next;
        }
    }
    //destroy valist
    va_end(valist);
    //if(dict == NULL) fprintf(stderr,"Object *NOT* found!\n");
    return dict;
}

struct dict* __dict_plainsearch(struct dict* dict, char* key, struct dict** prev_dict) {
    if(dict == 0 || dict->key == 0){
        return NULL; //dict is not initialized, do not touch prev_dict
    }
    if(strcmp(key, dict->key) == 0) { //found key, do not touch prev_dict
        return dict;
    }
    *prev_dict = dict;
    return __dict_plainsearch(dict->next, key, prev_dict);
}


struct dict* dict_empty(struct dict* dict) {
    if(dict == NULL) return NULL;
    if(dict->type != JSON_EMPTY) {
        switch(dict->type) {
            case JSON_STR: free(dict->value.string); dict->value.string = NULL; break;
            case JSON_ARRAY: array_free(dict->value.array); dict->value.array = NULL; break;
            case JSON_OBJ: dict_free(dict->value.object); dict->value.object = NULL; break;
            default: break;
        }
        dict->type = JSON_EMPTY;
    }
    if(dict->key) {
        free(dict->key);
        dict->key = NULL;
    }
    return dict;
}

void dict_free(struct dict* dict) {
    if(dict->next != 0) {
        dict_free(dict->next);
    }
    dict_empty(dict);
    free(dict);
    return;
}

struct array* array_empty(struct array* array){
    if(array == 0) return NULL;
    if(array->next != 0) {
        array_free(array->next);
    }
    switch(array->type) {
        case JSON_STR: free(array->value.string); break;
        case JSON_ARRAY: array_free(array->value.array); break;
        case JSON_OBJ: dict_free(array->value.object); break;
        default: break;
    }
    return array;
}

void array_free(struct array* array){
    array_empty(array);
    free(array);
    return;
}

struct dict* __dict_delrec(struct dict* dict, int path_len, char* next_key, va_list keys) {
    if(dict == 0 || dict->key == 0) return NULL;
    
    //fprintf(stderr, "__dict_delrec: path_len %d next_key: %s\n", path_len, next_key);

    //fprintf(stderr, "__dict_delrec: path_len %d type: %d key: %s next_key: \n", path_len, dict->type, dict->key);//, next_key);

    bool found = strcmp(next_key, dict->key) == 0 ? true : false;

    if(path_len == 1 && found) {
    //fprintf(stderr, "DELETE: type: %d key: %s dict->next: %p\n", dict->type, dict->key, dict->next);
        switch(dict->type) { //update exisiting in dict, handle appropriate
            case JSON_OBJ:
                dict_free(dict->value.object);
                break;
            case JSON_ARRAY:
                array_free(dict->value.array);
                break;
            case JSON_STR:
                free(dict->value.string);
                break;
            default:
                break;
        }
        //fprintf(stderr, "dict->prev: %s dict->next: %s\n", dict->prev->key, dict->next->key);
        //fprintf(stderr, "dict->prev %p\n", dict->prev);
        if(dict->prev) {
            if(dict->prev->type == JSON_OBJ && dict->prev->value.object == dict) { //check if dict is first element in a nested object
                //fprintf(stderr, "Is nested!\n");
                if(!dict->next){ //check if dict is also last element in the nested object
                    dict->prev->value.object = dict_new(); //if so, make new empty dict, so parent element is not left without (empty) content
                } else
                    dict->prev->value.object = dict->next;
            } else {
                //fprintf(stderr, "Is *NOT* nested!\n");
                dict->prev->next = dict->next;
            }
        }
        if(dict->next) {
            dict->next->prev = dict->prev;
        }
        //fprintf(stderr, "next->prev: %s prev->next: %s\n", dict->next->prev->key, dict->prev->next->key);
        free(dict->key);
        free(dict);
        return dict;
    } else {
        if(dict->type == JSON_OBJ && found) {
            next_key = va_arg(keys, char *);
            return __dict_delrec(dict->value.object, path_len - 1, next_key, keys);
        } else {
            return __dict_delrec(dict->next, path_len, next_key, keys);
        }
    }
}

bool dict_del(struct dict** dict_ptr, int path_len, ...) {
    if(dict_ptr == 0 || *dict_ptr == 0) return false;
    //fprintf(stderr, "************** dict_del %s\n", (*dict_ptr)->key ? (*dict_ptr)->key : "(nil)");
    struct dict* dict_delrec = 0;
    struct dict* next_dict = (*dict_ptr)->next;
    va_list keys;
    va_start(keys, path_len);
    char* next_key = va_arg(keys, char *);
    dict_delrec = __dict_delrec(*dict_ptr, path_len, next_key, keys);
    va_end(keys);
    
    if(dict_delrec == *dict_ptr) { //if first element in dict has been deleted...
        if(next_dict == NULL) { //...and it has been also the last element in dict...
            //fprintf(stderr, "Last element deleted!\n");
            *dict_ptr = dict_new();  //...create new dict with JSON_EMPTY-type. Contents of "old" dict were allready freed here by __dict_delrec(...)
            /*
            fprintf(stderr,"Exit now set to true, dict_del breakpoint reached\n");
            exit_now = true; //For Fuzzer
            */
            //dict_printelement(stderr, *dict_ptr);
        } else { //if not last element, just correct dict_ptr
            *dict_ptr = next_dict;
        }
    }
    
    return dict_delrec ? true : false;
}

long unsigned int array_len(struct array* array) {
    if(array->next == 0) {
        if(array->type == JSON_EMPTY)
            return 0;
        else
            return 1;
    }
    if(array->type != JSON_EMPTY)
        return array_len(array->next) + 1;
    else
        return array_len(array->next);
}

struct array* array_get(struct array* array, long int pos) {
    long unsigned int len = array_len(array);
    if(pos > len)
        return NULL;
    for(long int i = 0; i<= len; i++) {
        if(i == pos) return array;
        if(array->next == NULL)
            return NULL;
        array = array->next;
    }
    return NULL;
}

bool array_del(struct array* array, long int pos) {
    //fprintf(stderr, "START array_del %p pos: %ld\n", array, pos);
    if(array == NULL) {
        //fprintf(stderr,"NOT Deleted!\n");
        return false;
    }
    struct array* array_before = NULL;
    struct array* array_next = NULL;
    if(pos == 0) {
        switch(array->type) {
            case JSON_EMPTY: return false;
            case JSON_STR: free(array->value.string); break;
            case JSON_OBJ: dict_free(array->value.object); break;
            case JSON_ARRAY: array_free(array->value.array); break;
            default: break;
        }
        if(array->next == NULL) { //last element in array, make (or leave it) JSON_EMPTY
            memset(array, 0 , sizeof(struct array));
            //fprintf(stderr,"DELTED LAST! %s (%d)!\n", json_typetostr(array->type), array->type);
        } else {
            array_next = array->next; //Copy array to not touch given array pointer, because there may be other references to it.
            array->type = array_next->type;
            array->value = array_next->value;
            array->next = array_next->next;
            free(array_next); //do not use array free, because values like Strings must be still in place for copy in array!
            //fprintf(stderr," DELTED Middle!\n");

        }
        return true;
    } else {
        array_before = array_get(array, pos - 1); //iterate array to pos-1
        if(array_before == NULL)
            return false;
        array_next = array_before->next;
        array_before->next = array_next->next;
        array_next->next = 0;
        array_free(array_next);
        //fprintf(stderr,"DELTED Array!\n");
        return true;
    }
    //fprintf(stderr," Default: NOT Deleted!\n");
    return false;
}

bool dict_append(struct dict* source_dict, struct dict* dest_dict) {
    if(source_dict == 0  || dest_dict == 0) return false;

    if(dest_dict->next == 0) {
        dest_dict->next = source_dict;
        source_dict->prev = dest_dict;
        //TODO: Doublicate elment detection or merge?
        return true;
    }

    return dict_append(source_dict, dest_dict->next);
}
