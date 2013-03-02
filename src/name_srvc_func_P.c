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

#include "constdef.h"
#include "nodename.h"
#include "daemon_control.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_cnst.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_B.h"
#include "name_srvc_func_func.h"
#include "randomness.h"
#include "service_sector.h"
#include "service_sector_threads.h"


#define TRY_AGAIN (TRUE+1)
#define CHALLENGE (TRY_AGAIN+1)
/* return: >0=success (return is ttl), 0=fail */
uint32_t name_srvc_P_add_name(unsigned char *name,
			      unsigned char name_type,
			      struct nbnodename_list *scope,
			      uint32_t my_ip_address,
			      unsigned char group_flg,
			      uint32_t ttl) {
  struct timespec sleeptime;
  struct sockaddr_in addr;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outpckt;
  struct ss_unif_pckt_list *outside_pckt, *last_outpckt;
  struct name_srvc_resource_lst *res;
  struct nbaddress_list *nbaddr_list, *nbaddr_alllst;
  int success, i;
  unsigned char rcode;
  union trans_id tid;

  if ((! name) ||
      /* The explanation for the below test:
       * 1. at least one of bits ISGROUP_YES or ISGROUP_NO must be set.
       * 2. you can not set both bits at the same time. */
      (! ((group_flg & (ISGROUP_YES | ISGROUP_NO)) &&
	  (((group_flg & ISGROUP_YES) ? 1 : 0) ^
	   ((group_flg & ISGROUP_NO) ? 1 : 0)))))
    return 0;

  success = TRY_AGAIN;
  rcode = 0;
  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_250MS;
  outside_pckt = last_outpckt = 0;
  nbaddr_alllst = 0;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  fill_32field(get_nbnsaddr(), (unsigned char *)&(addr.sin_addr.s_addr));

  pckt = name_srvc_make_name_reg_big(name, name_type, scope, ttl,
				     my_ip_address, group_flg, CACHE_NODEFLG_P);
  if ((! pckt) ||
      (! pckt->aditionals) ||
      (! pckt->header)) {
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
  pckt->header->nm_flags = FLG_RD;

  for (i=0; i < nbworks__functn_cntrl.retries_NBNS; i++) {
    ss_name_send_pckt(pckt, &addr, trans);

    nanosleep(&sleeptime, 0);
    ss_set_inputdrop_name_tid(&tid);

    while (101) {
      outside_pckt = ss__recv_entry(trans);
      if (! outside_pckt) {
	break;
      }

      if ((! outside_pckt->packet) ||
	  (outside_pckt->addr.sin_port != addr.sin_port) ||
	  (outside_pckt->addr.sin_addr.s_addr !=
	   addr.sin_addr.s_addr)) {
	if (outside_pckt == last_outpckt) {
	  break;
	} else {
	  if (last_outpckt) {
	    if (last_outpckt->packet) {
	      last_outpckt->dstry(last_outpckt->packet, 1, 1);
	    }
	    free(last_outpckt);
	  }
	  last_outpckt = outside_pckt;
	  continue;
	}
      }

      if (last_outpckt) {
	if (last_outpckt->packet) {
	  last_outpckt->dstry(last_outpckt->packet, 1, 1);
	}
	free(last_outpckt);
      }
      last_outpckt = outside_pckt;

      outpckt = outside_pckt->packet;
      outside_pckt->packet = 0;

      if (!(outpckt->header &&
	    (outpckt->header->nm_flags & FLG_AA))) {
	outside_pckt->dstry(outpckt, 1, 1);
	continue;
      }

      if (outpckt->header->opcode == (OPCODE_RESPONSE |
				      OPCODE_REGISTRATION)) {
	if (outpckt->header->rcode) {
	  // NEGATIVE NAME REGISTRATION RESPONSE

	  /* Also make sure NBNS does actually mean *ME* when it
	   * denies the request. */
	  for (res = outpckt->answers;
	       res != 0;
	       res = res->next) {
	    if (res->res &&
		(0 == cmp_nbnodename(pckt->aditionals->res->name,
				     res->res->name)) &&
		((res->res->rrtype == RRTYPE_NULL) ||
		 (res->res->rrtype == pckt->aditionals->res->rrtype)) &&
		(res->res->rrclass == pckt->aditionals->res->rrclass))
	      break;
	  }
	  if (res) {
	    rcode = outpckt->header->rcode;
	    success = FALSE;
	    last_outpckt->dstry(outpckt, 1, 1);
	    break;
	  }
	} else {
	  if (outpckt->header->nm_flags & FLG_RA) {
	    // POSITIVE NAME REGISTRATION RESPONSE
	    for (res = outpckt->answers;
		 res != 0;
		 res = res->next) {
	      if (res->res &&
		  (0 == cmp_nbnodename(pckt->aditionals->res->name,
				       res->res->name)) &&
		  (res->res->rrtype == pckt->aditionals->res->rrtype) &&
		  (res->res->rrclass == pckt->aditionals->res->rrclass))
		break;
	    }
	    if (res) {
	      success = TRUE;
	      ttl = res->res->ttl;
	      last_outpckt->dstry(outpckt, 1, 1);
	      break;
	    }
	  } else {
	    // END-NODE CHALLENGE REGISTRATION RESPONSE
	    for (res = outpckt->answers;
		 res != 0;
		 res = res->next) {
	      if (res->res &&
		  (0 == cmp_nbnodename(pckt->aditionals->res->name,
				       res->res->name)) &&
		  (res->res->rrtype == pckt->aditionals->res->rrtype) &&
		  (res->res->rrclass == pckt->aditionals->res->rrclass))
		break;
	    }
	    if (res) {
	      if (res->res->rdata_t == nb_address_list) {
		success = CHALLENGE;
		nbaddr_alllst = res->res->rdata;
		res->res->rdata = 0;
	      }
	      last_outpckt->dstry(outpckt, 1, 1);
	      break;
	    }
	  }
	}
      }

      if (outpckt->header->opcode == (OPCODE_RESPONSE |
				      OPCODE_WACK)) {
	for (res = outpckt->answers;
	     res != 0;
	     res = res->next) {
	  if (res->res &&
	      (0 == cmp_nbnodename(pckt->aditionals->res->name,
				   res->res->name)) &&
	      ((res->res->rrtype == RRTYPE_NULL) ||
	       (res->res->rrtype == pckt->aditionals->res->rrtype)) &&
	      (res->res->rrclass == pckt->aditionals->res->rrclass))
	    break;
	}
	if (res) {
	  sleeptime.tv_sec = res->res->ttl;
	  ss_set_normalstate_name_tid(&tid);

	  nanosleep(&sleeptime, 0);

	  ss_set_inputdrop_name_tid(&tid);
	  sleeptime.tv_sec = 0;
	}
      }

      outside_pckt->dstry(outpckt, 1, 1);
    }

    if ((success == FALSE) ||
	(success == TRUE)) {
      break;
    } else {
      if (success == CHALLENGE) {
	nbaddr_list = nbaddr_alllst;
	while (nbaddr_list) {
	  if ((nbaddr_list->there_is_an_address) &&
	      ((group_flg & ISGROUP_YES) ?
	       (nbaddr_list->flags & NBADDRLST_GROUP_MASK) :
	       (!(nbaddr_list->flags & NBADDRLST_GROUP_MASK))))
	    break;
	  else
	    nbaddr_list = nbaddr_list->next_address;
	}
	if (nbaddr_list) {
	  res = name_srvc_callout_name(pckt->aditionals->res->name->name,
				       pckt->aditionals->res->name->name[NETBIOS_NAME_LEN-1],
				       pckt->aditionals->res->name->next_name,
				       nbaddr_list->address,
				       nbaddr_list->address,
				       0, FALSE);
	  if (res) {
	    while (nbaddr_alllst) {
	      nbaddr_list = nbaddr_alllst->next_address;
	      free(nbaddr_alllst);
	      nbaddr_alllst = nbaddr_list;
	    }
	    destroy_name_srvc_res_lst(res, 1, 1);

	    success = FALSE;
	    break;
	  }
	}

	while (nbaddr_alllst) {
	  nbaddr_list = nbaddr_alllst->next_address;
	  free(nbaddr_alllst);
	  nbaddr_alllst = nbaddr_list;
	}
      } /* else
	   repeat; */
    }
  }

  destroy_name_srvc_pckt(pckt, 1, 1);

  ss_deregister_name_tid(&tid);
  ss__dstry_recv_queue(trans);
  free(trans);

  if (success == TRUE)
    return ttl;
  else
    return 0;
}