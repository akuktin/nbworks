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

#include "c_lang_extensions.h"

#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "constdef.h"


uint32_t rail_flushrail(uint32_t len,
			int rail) {
  uint32_t drained;
  unsigned char bucket[0xff];

  drained = 0;

  while (len) {
    if (len > 0xff) {
      if (0xff > recv(rail, bucket, 0xff, MSG_WAITALL)) {
	return FALSE;
      } else {
	len = len - 0xff;
	drained = drained + 0xff;
      }
    } else {
      if (len > recv(rail, bucket, len, MSG_WAITALL)) {
	return FALSE;
      } else {
	drained = drained + len;
	return drained;
      }
    }
  }

  return drained;
}
