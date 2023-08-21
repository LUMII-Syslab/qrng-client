#include <stdlib.h>
#include <stdio.h>

#include "qrng.h"

int main(int argc, char **argv) {

  //printf("DYLD_LIBRARY_PATH=%s\n",getenv("DYLD_LIBRARY_PATH"));
  //setenv("DYLD_LIBRARY_PATH", "/Users/sergejs/.sdkman/candidates/java/current/lib:/Users/sergejs/.sdkman/candidates/java/current/bin/lib/server:." , 1);

  //graal_isolate_t *isolate = NULL;
  graal_isolatethread_t *thread = NULL;
  fprintf(stderr, "Hello from the Test C++ program!\n");
  
  if (graal_create_isolate(NULL, NULL/* &isolate */, &thread) != 0) {
    fprintf(stderr, "graal_create_isolate error\n");
    return 1;
  }

  fprintf(stderr, "We are going to connect to the QRNG server...\n");

  char *s = qrng_connect(thread);
  printf("qrng_connect returned error [%s]\n", s);
  qrng_free_result(thread, s);
  if (s!=NULL)
    return 1;

  s = qrng_get_main_executable(thread);
  printf("qrng_get_main_executable returned [%s]\n", s);
  qrng_free_result(thread, s);

  char buf[10];
  s = qrng_get_random_bytes(thread, buf, 10);
  if (s==NULL) {
    for (int i=0; i<10; i++)
        printf("%d ",buf[i]);
    printf("all ok\n");
  }
  else {
    printf("error: [%s]\n", s);
  }
  qrng_free_result(thread, s);


  s = qrng_get_random_bytes(thread, buf, -5);
  if (s==NULL) {
    return 1; // must return non-null error description
  }
  else {
    printf("error: [%s]\n", s);
  }
  qrng_free_result(thread, s);


  if (graal_detach_thread(thread) != 0) {
    fprintf(stderr, "graal_detach_thread error\n");
    return 1;
  }
  
  return 0;
}
