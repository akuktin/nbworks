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

#include "nbworks.h"
#include "constdef.h"
#include "nodename.h"

int main(int argc, unsigned char **argv) {
  int i;
  unsigned char prepared_name[NBWORKS_NBNAME_LEN+1];
  unsigned char coded_name[(NBWORKS_NBNAME_LEN*2)+1];

  prepared_name[NBWORKS_NBNAME_LEN] = 0;
  coded_name[NBWORKS_NBNAME_LEN*2] = 0;
  for (i=1; i < argc; i++) {
    if (! nbworks_create_nbnamelabel(argv[i], 0, prepared_name)) {
     error:
      fprintf(stderr, "problem with argument #%i\n", i);
    } else {
      if (! encode_nbnodename(prepared_name, coded_name))
        goto error;
      else
        fprintf(stdout, "%s\n", coded_name);
    }
  }

  return 0;
}
