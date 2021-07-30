#include "gtest/gtest.h"

extern "C" {
  #include "madcat.helper.h"
  #include "madcat.common.h"
  #include <stdlib.h>
  #include <strings.h>
  #include <time.h>
}

/* test fixture
class MadCatHelper : public ::testing::Test {
 protected:
  virtual void SetUp() {

  }
  //virtual void TearDown() {}

};*/

TEST(madcat_helper,time_str_readable_buf) {
  int size = 4096;
  char * readable_buf = (char*)malloc(size);

  struct timeval tv;
  char tmbuf[size];
  char test_time[size];
  char tmzone[6]; //e.g. "+0100\0" is max. 6 chars

  time_str(NULL,0,readable_buf,size);

  gettimeofday(&tv, NULL); //fetch struct timeval with actuall time and convert it to string...
  strftime(tmbuf, size, "%Y-%m-%dT%H:%M:%S", localtime(&tv.tv_sec)); //Target format: "2018-08-17T05:51:53.835934", therefore...
  strftime(tmzone, 6, "%z", localtime(&tv.tv_sec)); //...get timezone...>

  
  if (test_time != NULL)
  {
      snprintf(test_time, size, "%s.%06ld%s", tmbuf, tv.tv_usec, tmzone); test_time[size-1] = 0; //Human readable string
  }
  
  char * compare_buffer_1 = (char*)malloc(strlen(readable_buf));
  char * compare_buffer_2 = (char*)malloc(strlen(test_time));

  snprintf(compare_buffer_1,(strlen(readable_buf)-11),"%s",readable_buf); compare_buffer_1[strlen(readable_buf)-1] = 0;
  snprintf(compare_buffer_2,(strlen(test_time)-11),"%s",test_time); compare_buffer_2[strlen(test_time)-1] = 0;

  ASSERT_EQ(strcasecmp(compare_buffer_1,compare_buffer_2), 0);
}


TEST(madcat_helper, time_str_readable_time) {
  int size = 4096;
  char * unix_buf = (char*)malloc(size);

  struct timeval tv;
  char tmbuf[size];
  char test_time[size];
  char tmzone[6]; //e.g. "+0100\0" is max. 6 chars

  time_str(unix_buf,size,NULL,0);

  gettimeofday(&tv, NULL); //fetch struct timeval with actuall time and convert it to string...
  strftime(tmbuf, size, "%Y-%m-%dT%H:%M:%S", localtime(&tv.tv_sec)); //Target format: "2018-08-17T05:51:53.835934", therefore...
  strftime(tmzone, 6, "%z", localtime(&tv.tv_sec)); //...get timezone...>

  
  if (test_time != NULL)
  {
       snprintf(test_time, size, "%lu.%lu", tv.tv_sec, tv.tv_usec); test_time[size-1] = 0; //Unix time incl. usec
  }
  
  char * compare_buffer_1 = (char*)malloc(strlen(unix_buf));
  char * compare_buffer_2 = (char*)malloc(strlen(test_time));

  snprintf(compare_buffer_1,(strlen(unix_buf)-6),"%s",unix_buf); compare_buffer_1[strlen(unix_buf)-1] = 0;
  snprintf(compare_buffer_2,(strlen(test_time)-6),"%s",test_time); compare_buffer_2[strlen(test_time)-1] = 0;

  ASSERT_EQ(strcasecmp(compare_buffer_1,compare_buffer_2), 0);
}

TEST(madcat_helper, get_user_ids) {
  
  struct user_t compare_1;
  struct user_t compare_2;

  memset(&compare_1,0,sizeof(struct user_t));
  memset(&compare_2,0,sizeof(struct user_t));

  strncpy(compare_1.name,"root",5);
  strncpy(compare_2.name,"root",5);
  compare_1.uid = 0;
  compare_1.gid = 0;

  get_user_ids(&compare_2);

  ASSERT_EQ(compare_1.uid, compare_2.uid);
  ASSERT_EQ(compare_1.gid, compare_2.gid);
}


TEST(madcat_helper, print_hex_to_file) {
  FILE * file_1;
  FILE * file_2;

  
  
}
