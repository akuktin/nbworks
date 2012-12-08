#include <stdio.h>
#include <stdlib.h>

#include "nodename.h"

int main(int argc, char **argv) {
  int i, name_description;
  char *decoded_name;

  for (i=1; i < argc; i++) {
    decoded_name = decode_nbnodename(argv[i]);
    if (! decoded_name) {
      fprintf(stderr, "problem with node name in argument #%i\n", i);
      continue;
    }
    name_description = decoded_name[NETBIOS_NAME_LEN -1];
    decoded_name[NETBIOS_NAME_LEN -1] = '\0';

    fprintf(stdout, "%s\t0x%02x\n", decoded_name, name_description);

    free(decoded_name);
  }

  return 0;
}
