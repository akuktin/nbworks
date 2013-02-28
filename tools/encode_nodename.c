/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
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
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nodename.h"

int main(int argc, unsigned char **argv) {
  int i, j, len;
  unsigned char *prepared_name;
  unsigned char *coded_name;

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
    } else {
      fprintf(stdout, "%s\n", coded_name);
    }

    free(coded_name);
  }

  free(prepared_name);

  return 0;
}
