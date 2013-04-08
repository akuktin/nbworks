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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"
#include "service_sector.h"
#include "service_sector_threads.h"


/* returns: >0=success, 0=fail */
inline uint16_t dtg_srvc_doesitmatch(struct nbnodename_list *target,
				     struct dtg_srvc_packet *shot) {
  struct nbnodename_list *gun;
  struct dtg_pckt_pyld_normal *pyld;

  switch (shot->payload_t) {
  case normal:
    pyld = shot->payload;
    gun = pyld->dst_name;
    break;

  case nbnodename:
    gun = shot->payload;
    break;

  default:
    return FALSE;
  }

  if (! cmp_nbnodename(target->next_name, gun->next_name))
    if (! memcmp(target->name, gun->name, NETBIOS_CODED_NAME_LEN))
      return TRUE;
  return FALSE;
}

inline struct nbnodename_list *dtg_srvc_extract_dstname(struct dtg_srvc_packet *pckt) {
  struct dtg_pckt_pyld_normal *pyld;

  switch (pckt->payload_t) {
  case normal:
    pyld = pckt->payload;
    return pyld->dst_name;

  case nbnodename:
    return pckt->payload;

  default:
    return 0;
  }
}

inline struct nbnodename_list *dtg_srvc_extract_srcname(struct dtg_srvc_packet *pckt) {
  struct dtg_pckt_pyld_normal *pyld;

  switch (pckt->payload_t) {
  case normal:
    pyld = pckt->payload;
    return pyld->src_name;

  case nbnodename:
    return pckt->payload;

  default:
    return 0;
  }
}

inline struct nbnodename_list *dtg_srvc_get_srcnam_recvpckt(struct dtg_srvc_recvpckt *pckt) {
  if (! pckt)
    return 0;
  else
    return pckt->dst;
}

/*
void dtg_srvc_send_NOTHERE_error(struct ss_unif_pckt_list *pckt) {
  struct dtg_srvc_packet *packet;
  struct dtg_pckt_pyld_normal *normal_pyld;
  union trans_id tid;
  struct ss_queue *trans;

  packet = pckt->packet;

  if ((packet->type == DIR_UNIQ_DTG) ||
      (packet->type == DIR_GRP_DTG)) {
    if (packet->payload_t == normal) {
      normal_pyld = packet->payload;

      destroy_nbnodename(normal_pyld->src_name);
      tid.name_scope = normal_pyld->dst_name;
      normal_pyld->dst_name = 0;
      if (normal_pyld->do_del_pyldpyld)
	free(normal_pyld->payload);
      else
	free(normal_pyld->pyldpyld_delptr);
      free(normal_pyld);
    } else {
      destroy_dtg_srvc_pckt(packet, 1, 1);
      return;
    }

    packet->for_del = TRUE;
    packet->payload = 0;
    packet->payload_t = error_code;

    packet->type = DTG_ERROR;
    packet->error_code = DTG_ERR_DSTNAM_NOTHERE;

    packet->src_port = 138; /_* >< *_/
    packet->src_address = my_ipv4_address();

    /_* This will occationally produce some weird effects. *_/
    packet->flags = (packet->flags & DTG_NODE_TYPE_MASK) | DTG_FIRST_FLAG;

    /_* This is inefficient. TODO: think of a better way. *_/
    trans = ss_register_dtg_tid(&tid);
    if (trans) {
      ss_dtg_send_pckt(packet, &(pckt->addr), trans);
      ss_deregister_tid(&tid, DTG_SRVC);
      ss__dstry_recv_queue(trans);

      free(trans);
    }
    destroy_nbnodename(tid.name_scope);
  } else {
    destroy_dtg_srvc_pckt(packet, 1, 1);
  }
  return;
}
*/
