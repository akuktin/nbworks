#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nodename.h"

int main(int argc, unsigned char **argv) {
  int i;
  unsigned char *coded_name;

  for (i=1; i < argc; i++) {
    coded_name = make_nbnodename_sloppy(argv[i]);

    if (! coded_name) {
      fprintf(stderr, "problem with argument #%i\n", i);
    } else {
      fprintf(stdout, "%s\n", coded_name);
    }

    free(coded_name);
  }

  return 0;
}
