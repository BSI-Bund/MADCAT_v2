/* BSI 2023 */

//#include "custom_mutators.h"
#include <cstddef>
#include <pwd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <iostream>




#ifdef __cplusplus
extern "C" {
  #include "libdict_c.h"
#endif


struct dict* dict = NULL;
struct array* array = NULL;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv){
  dict = dict_new();
  array = array_new();

  if (dict == NULL){
    abort();
  } 

  if (array == NULL){
    abort();
  } 

  return 0;
}

#ifdef __cplusplus
}
#endif

extern "C" int LLVMFuzzerTestOneInput(const char *Data, size_t Size) {
  if(Size < 2){
    return 0;
  }
  union json_type value;
  int t = 0;

  char* s = (char*) malloc(Size+1);
  memcpy(s, Data, Size);
  s[Size] = 0;

  switch (Data[1]) {
    default:
      t = JSON_STR;
      value.string = s;
  }
  
  dict_update(dict,t, value, 1, "String");
  free(s);

  
// tear down code.. 
teardown:
  
  
  return 0;
}
