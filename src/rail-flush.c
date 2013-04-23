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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "constdef.h"
#include "rail-comm.h"
#include "pckt_routines.h"


size_t rail_flushrail(size_t len,
		      int rail) {
  size_t drained;
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


struct com_comm *read_railcommand(unsigned char *packet,
				  unsigned char *endof_pckt,
				  struct com_comm *field) {
  struct com_comm *result;
  unsigned char *walker;

  if ((! packet) ||
      ((packet + LEN_COMM_ONWIRE) > endof_pckt))
    return 0;

  if (field)
    result = field;
  else {
    result = malloc(sizeof(struct com_comm));
    if (! result)
      return 0;
  }

  walker = packet;

  result->command = *walker;
  walker++;
  walker = read_64field(walker, &(result->token));
  walker = read_16field(walker, &(result->addr.sin_port));
  walker = read_32field(walker, &(result->addr.sin_addr.s_addr));
  result->node_type = *walker;
  walker++;
  walker = read_32field(walker, &(result->nbworks_errno));
  walker = read_32field(walker, &(result->len));

  result->addr.sin_family = AF_INET;
  result->data = 0;

  return result;
}

unsigned char *fill_railcommand(struct com_comm *command,
				unsigned char *packet,
				unsigned char *endof_packet) {
  unsigned char *walker;

  if (! (command && packet))
    return packet;

  if ((packet + LEN_COMM_ONWIRE) > endof_packet) {
    /* TODO: errno signaling stuff */
    return packet;
  }

  walker = packet;

  *walker = command->command;
  walker++;
  walker = fill_64field(command->token, walker);
  walker = fill_16field(command->addr.sin_port, walker);
  walker = fill_32field(command->addr.sin_addr.s_addr, walker);
  *walker = command->node_type;
  walker++;
  walker = fill_32field(command->nbworks_errno, walker);
  walker = fill_32field(command->len, walker);

  return walker;
}


struct rail_name_data *read_rail_name_data(unsigned char *startof_buff,
					   unsigned char *endof_buff) {
  struct rail_name_data *result;
  unsigned char *walker;

  if (! startof_buff)
    return 0;

  if ((startof_buff + LEN_NAMEDT_ONWIREMIN) > endof_buff) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = startof_buff;

  result = malloc(sizeof(struct rail_name_data));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->name = malloc(NETBIOS_NAME_LEN+1);
  if (! result->name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  memcpy(result->name, walker, NETBIOS_NAME_LEN);
  walker = walker + (NETBIOS_NAME_LEN -1);
  result->name_type = *walker;
  walker++;

  result->scope = read_all_DNS_labels(&walker, walker, endof_buff, 0, 0, 0, 0);

  read_32field(walker, &(result->ttl));

  return result;
}

unsigned char *fill_rail_name_data(struct rail_name_data *data,
				   unsigned char *startof_buff,
				   unsigned char *endof_buff) {
  unsigned char *walker;
  unsigned char *foo;

  if (! (data && startof_buff))
    return startof_buff;

  if ((startof_buff + LEN_NAMEDT_ONWIREMIN) > endof_buff) {
    /* TODO: errno signaling stuff */
    return startof_buff;
  }

  walker = mempcpy(startof_buff, data->name, NETBIOS_NAME_LEN);
  walker = fill_all_DNS_labels(data->scope, walker, endof_buff, 0);
  if ((walker + 4) > endof_buff) {
    return startof_buff;
  } else {
    walker = fill_32field(data->ttl, walker);
  }

  return walker;
}
