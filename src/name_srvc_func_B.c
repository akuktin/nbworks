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
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "daemon_control.h"
#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_cnst.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_B.h"
#include "name_srvc_func_func.h"
#include "randomness.h"
#include "service_sector.h"
#include "service_sector_threads.h"


/* return: >0=success (return is ttl), 0=fail */
uint32_t name_srvc_B_add_name(unsigned char *name,
			      unsigned char name_type,
			      struct nbnodename_list *scope,
			      uint32_t my_ip_address,
			      unsigned char group_flg,
			      uint32_t ttl) {
  struct sockaddr_in addr;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outside_pckt;
  struct name_srvc_resource_lst *res;
  uint32_t result, i;
  unsigned int retry_count;
  union trans_id tid;

  if ((! name) ||
      /* The explanation for the below test:
       * 1. at least one of bits ISGROUP_YES or ISGROUP_NO must be set.
       * 2. you can not set both bits at the same time. */
      (! ((group_flg & (ISGROUP_YES | ISGROUP_NO)) &&
	  (((group_flg & ISGROUP_YES) ? 1 : 0) ^
	   ((group_flg & ISGROUP_NO) ? 1 : 0)))))
    return 0;

  result = 0;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  fill_32field(get_inaddr(), (unsigned char *)&(addr.sin_addr.s_addr));

  pckt = name_srvc_make_name_reg_big(name, name_type, scope, ttl,
				     my_ip_address,
                                     ((group_flg & ISGROUP_YES) ?
                                      CACHE_NODEGRPFLG_B :
                                      CACHE_NODEFLG_B));
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  tid.tid = make_weakrandom();

  trans = ss_register_name_tid(&tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    destroy_name_srvc_pckt(pckt, 1, 1);
    return 0;
  }

  pckt->header->transaction_id = tid.tid;
  pckt->header->opcode = OPCODE_REQUEST | OPCODE_REGISTRATION;
  pckt->header->nm_flags = FLG_B;
  /* Do not ask for recursion, because
     there are no NBNS in our scope. */

  retry_count = nbworks_namsrvc_cntrl.bcast_req_retry_count;
  for (i=0; i < retry_count; i++) {
    ss_name_send_pckt(pckt, &addr, trans);

    nanosleep(&nbworks_namsrvc_cntrl.func_sleeptime, 0);
  }

  ss_set_inputdrop_name_tid(&tid);

  while (1) {
    outside_pckt = ss__recv_pckt(trans, 0);
    if (! outside_pckt) {
      break;
    }

    if ((outside_pckt->header->opcode == (OPCODE_RESPONSE |
					  OPCODE_REGISTRATION)) &&
	(outside_pckt->header->nm_flags & FLG_AA) &&
	(outside_pckt->header->rcode != 0)) {
      res = outside_pckt->answers;
      while (res && res->res) {
	if ((0 == cmp_nbnodename(pckt->questions->qstn->name,
				 res->res->name)) &&
	    (pckt->questions->qstn->qtype ==
	     res->res->rrtype) &&
	    (pckt->questions->qstn->qclass ==
	     res->res->rrclass)) {
	  /* This is a relevant NEGATIVE NAME REGISTRATION RESPONSE. */
	  /* Failed. */
	  result = outside_pckt->header->rcode;
	  break;
	} else
	  res = res->next;
      }
      if (res) {
	destroy_name_srvc_pckt(outside_pckt, 1, 1);
	break;
      }
    }

    destroy_name_srvc_pckt(outside_pckt, 1, 1);
  }

  if (! result) {
    /* Succeded. */
    pckt->header->opcode = OPCODE_REQUEST | OPCODE_REFRESH;
    pckt->for_del = TRUE;
    ss_name_send_pckt(pckt, &addr, trans);

    result = ttl;
  } else {
    destroy_name_srvc_pckt(pckt, 1, 1);

    result = 0;
  }

  ss_deregister_name_tid(&tid);
  ss__dstry_recv_queue(trans);
  free(trans);

  return result;
}
