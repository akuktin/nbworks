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

#include "c_lang_extensions.h"

#include <stdlib.h>

#include "constdef.h"


void *nbw_calloc(size_t members,
		 size_t size) {
  size_t len;
  void *result;

  size_t i;
  char *target;

  if ((members < 1) ||
      (size < 1))
    return malloc(0);

  len = members * size;
  if (len < size) {
    return 0;
  }

  result = malloc(len);

  if (! result)
    return 0;

//  memset(result, 0, len);
  target = result;
  for (i=0; i<len; i++) {
    *target = 0;
    target++;
  }

  return result;
}
