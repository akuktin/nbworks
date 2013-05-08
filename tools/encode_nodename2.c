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
