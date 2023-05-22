#include "gtest/gtest.h"
#include <string.h>

extern "C" {
  #include "libdict_c.h"

  #include <stdlib.h>
  #include <strings.h>
  #include <time.h>
}


TEST(madcat_dict_c,test_create_dict_array) {
  struct dict* dict = dict_new();
  struct array* array = array_new();
  int ret[2] = {0,0};
  size_t n = sizeof(ret)/sizeof(ret[0]);
  
  if (dict != NULL){
    dict_empty(dict);
    dict_free(dict);
    ret[0] = 0;
  } else{
    ret[0] = 1;
  }

  if (array != NULL){
    array_empty(array);
    array_free(array);
    ret[0] = 0;
  } else{
    ret[1] = 1;
  }

  for(int i = 0; i<n; i++){
    ASSERT_EQ(ret[i], 0);  
  }   
}


TEST(madcat_dict_c,test_add_elememts) {
    struct dict* dict = dict_new();
    struct dict* search_dict = NULL;
    struct array* array = NULL;
    union json_type value;
    char* output = 0;

    //test update
    value.string = (char*)"test_1";
    dict_update(dict, JSON_STR, value, 1, "String");
    union json_type ret_j_type = dict_get(dict,1,"String")->value;
    ASSERT_EQ(strcmp(ret_j_type.string,"test_1"), 0); 

    value.hex.number = 0xDEADBEEF;
    dict_update(dict, JSON_HEX, value, 1  , "HEX"); 
    ret_j_type = dict_get(dict,1,"HEX")->value;
    ASSERT_EQ(ret_j_type.hex.number,0xDEADBEEF); 

    value.integer = 1;
    dict_update(dict, JSON_INT, value, 1  , "Int");
    ret_j_type = dict_get(dict,1,"Int")->value;
    ASSERT_EQ(ret_j_type.integer,1); 

    value.boolean = true;
    dict_update(dict, JSON_BOOL, value, 1  , "Bool");
    ret_j_type = dict_get(dict,1,"Bool")->value;
    ASSERT_EQ(ret_j_type.boolean,true); 

    value.floating = 2.5;
    dict_update(dict, JSON_FLOAT, value, 1  , "double");
    ret_j_type = dict_get(dict,1,"double")->value;
    ASSERT_EQ(ret_j_type.floating,2.5);   

    value.object = dict_new();
    dict_update(dict, JSON_OBJ, value, 1  , "Dict");
    ret_j_type = dict_get(dict,1,"Dict")->value;
    EXPECT_TRUE(ret_j_type.object != NULL); 

    value.array = array_new();
    dict_update(dict, JSON_ARRAY, value, 1  , "ARRAY");
    ret_j_type = dict_get(dict,1,"ARRAY")->value;
    EXPECT_TRUE(ret_j_type.array != NULL); 

}


TEST(madcat_dict_c,test_add_all_elememts) {
    /*
    value.object = dict_new();
    dict_update(dict, JSON_OBJ, value, 1, "INNER");
    search_dict = __dict_plainsearch(dict, "INNER", &search_dict);

    value.string = "Hurz";
    dict_update(dict, JSON_STR, value, 1, "Tiger");

    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);

    value.boolean = false;
    dict_update(dict, JSON_BOOL, value, 2, "INNER", "Cougar");

    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);

    dict_update(dict, JSON_NULL, value, 2, "INNER", "Rabbit");
    value.boolean = true;
    dict_update(dict, JSON_BOOL, value, 2, "INNER", "Fox");
  
    value.array = array_new();
    dict_update(dict, JSON_ARRAY, value, 2, "INNER", "ARRAY");

    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);
    dict_update(dict, JSON_NULL, value, 5, "0", "1", "2", "3", "No");
    dict_update(dict, JSON_NULL, value, 5, "INNER", "1", "2", "3", "five");
    
    value.hex.number = 10; value.hex.format = HEX_FORMAT_04;
    array_add(dict_get(dict, 2, "INNER", "ARRAY")->value.array, JSON_HEX, value);
    value.string = "asdfjklo";
    array_add(dict_get(dict, 2, "INNER", "ARRAY")->value.array, JSON_STR, value);
    value.object = dict_new();
    array_add(dict_get(dict, 2, "INNER", "ARRAY")->value.array, JSON_OBJ, value);

    value.hex.number = 0xDEADBEEF; value.hex.format = HEX_FORMAT_STD;
    dict_update(array_get(dict_get(dict, 2, "INNER", "ARRAY")->value.array, 2)->value.object, JSON_HEX, value, 1, "DEADBEEF");

    array_dump(stderr, array_get(dict_get(dict, 2, "INNER", "ARRAY")->value.array, 2)); fprintf(stderr, "\n");

    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);

    search_dict = dict_get(dict, 2, "INNER", "ARRAY");
    fprintf(stderr, "Type %d\n", search_dict ? search_dict->type : -1);

    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);
    fprintf(stderr, "\n");

    search_dict = dict_get(dict, 1, "Lamb");
    fprintf(stderr, "Type %d\n", search_dict ? search_dict->type : -1);

    value.boolean = false;
    dict_update(dict, JSON_BOOL, value, 2, "INNER", "Carlin");


    //Array operations
    array = dict_get(dict, 2, "INNER", "ARRAY")->value.array;
    fprintf(stderr, "%s\n", output = array_dumpstr(array)); free(output);
    array_del(array, 2);
    fprintf(stderr, "%s\n", output = array_dumpstr(array)); free(output);
    array_del(array, 1);
    fprintf(stderr, "%s\n", output = array_dumpstr(array)); free(output);
    array_del(array, 0);
    fprintf(stderr, "%s\n", output = array_dumpstr(array)); free(output);
    fprintf(stderr, "\n");


    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);

    dict_del(&dict, 2, "INNER", "Carlin");
    dict_del(&dict, 2, "INNER", "Rabbit");
    dict_del(&dict, 2, "INNER", "Fox");

    value.boolean = true;
    dict_update(dict, JSON_BOOL, value, 2, "INNER", "Bear");
    
    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);

    //delete dict contents

    fprintf(stderr, "RETURN: %d\n", dict_del(&dict, 2, "INNER", "Cougar"));
    fprintf(stderr, "RETURN: %d\n", dict_del(&dict, 1, "Wolf"));

    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);

    //dict_update existing
    value.floating = 3.14;
    dict_update(dict, JSON_FLOAT, value, 2, "INNER", "ARRAY"); 

    fprintf(stderr, "%s\n", output = dict_dumpstr(dict)); free(output);
    dict_free(dict);


    ASSERT_EQ(strcasecmp("hallo","hallo"), 0);*/

}
