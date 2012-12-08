#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nodename.h"

int main(int argc, char **argv) {
  int i, j, len;
  char *prepared_name;
  char *coded_name;

  prepared_name = malloc(NETBIOS_NAME_LEN +1);
  if (! prepared_name) {
    return 1;
  }

  for (i=1; i < argc; i++) {
    /* Don't forget the tramp stamp. */
    prepared_name[NETBIOS_NAME_LEN] = '\0';

    len = strnlen(argv[i], NETBIOS_NAME_LEN +1);
    if (len > NETBIOS_NAME_LEN) {
      fprintf(stderr, "argument #%i is too long\n", i);
    }

    strncpy(prepared_name, argv[i], NETBIOS_NAME_LEN);

    for (j = len; j < NETBIOS_NAME_LEN; j++) {
      prepared_name[j] = ' '; /* a space character */
    }

    for (j = 0; j < NETBIOS_NAME_LEN; j++) {
      prepared_name[j] = toupper(prepared_name[j]);
    }

    coded_name = encode_nbnodename(prepared_name);

    if (! coded_name) {
      fprintf(stderr, "problem with argument #%i\n", i);
    }

    fprintf(stdout, "%s\n", coded_name);

    free(coded_name);
  }

  free(prepared_name);

  return 0;
}
