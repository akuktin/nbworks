/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3 of the License.
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

#include "nodename.h"

int main(int argc, unsigned char **argv) {
  int i;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1], name_description;

  for (i=1; i < argc; i++) {
    if (! decode_nbnodename(argv[i], decoded_name)) {
      fprintf(stderr, "problem with node name in argument #%i\n", i);
      continue;
    }
    name_description = decoded_name[NETBIOS_NAME_LEN -1];
    decoded_name[NETBIOS_NAME_LEN -1] = '\0';

    fprintf(stdout, "%s\t0x%02x\n", decoded_name, name_description);
  }

  return 0;
}
