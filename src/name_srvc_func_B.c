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
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_cnst.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_B.h"
#include "name_srvc_func_func.h"
#include "randomness.h"
#include "service_sector.h"
#include "service_sector_threads.h"


/* return: 0=success, >0=fail, -1=error */
int name_srvc_B_add_name(unsigned char *name,
			 unsigned char name_type,
			 struct nbnodename_list *scope,
			 uint32_t my_ip_address,
			 unsigned char group_flg,
			 uint32_t ttl) {
  struct timespec sleeptime;
  struct sockaddr_in addr;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outside_pckt;
  struct name_srvc_resource_lst *res;
  int result, i;
  union trans_id tid;

  if ((! name) ||
      /* The explanation for the below test:
       * 1. at least one of bits ISGROUP_YES or ISGROUP_NO must be set.
       * 2. you can not set both bits at the same time. */
      (! ((group_flg & (ISGROUP_YES | ISGROUP_NO)) &&
	  (((group_flg & ISGROUP_YES) ? 1 : 0) ^
	   ((group_flg & ISGROUP_NO) ? 1 : 0)))))
    return -1;

  result = 0;
  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_250MS;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  fill_32field(get_inaddr(), (unsigned char *)&(addr.sin_addr.s_addr));

  pckt = name_srvc_make_name_reg_big(name, name_type, scope, ttl,
				     my_ip_address, group_flg, CACHE_NODEFLG_B);
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  tid.tid = make_weakrandom();

  trans = ss_register_name_tid(&tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    destroy_name_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  pckt->header->transaction_id = tid.tid;
  pckt->header->opcode = OPCODE_REQUEST | OPCODE_REGISTRATION;
  pckt->header->nm_flags = FLG_B;
  /* Do not ask for recursion, because
     there are no NBNS in our scope. */

  for (i=0; i < BCAST_REQ_RETRY_COUNT; i++) {
    ss_name_send_pckt(pckt, &addr, trans);

    nanosleep(&sleeptime, 0);
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
      while (res) {
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
    pckt->for_del = 1;
    ss_name_send_pckt(pckt, &addr, trans);
  } else {
    destroy_name_srvc_pckt(pckt, 1, 1);
  }

  ss_deregister_name_tid(&tid);
  ss__dstry_recv_queue(trans);
  free(trans);

  return result;
}

/* return: 0=success, >0=fail, <0=error */
int name_srvc_B_release_name(unsigned char *name,
			     unsigned char name_type,
			     struct nbnodename_list *scope,
			     uint32_t my_ip_address,
			     unsigned char group_flg) {
  struct timespec sleeptime;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt;
  struct sockaddr_in addr;
  int i;
  union trans_id tid;

  if ((! name) ||
      /* The explanation for the below test:
       * 1. at least one of bits ISGROUP_YES or ISGROUP_NO must be set.
       * 2. you can not set both bits at the same time. */
      (! ((group_flg & (ISGROUP_YES | ISGROUP_NO)) &&
	  (((group_flg & ISGROUP_YES) ? 1 : 0) ^
	   ((group_flg & ISGROUP_NO) ? 1 : 0)))))
    return -1;

  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_250MS;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  fill_32field(get_inaddr(), (unsigned char *)&(addr.sin_addr.s_addr));

  pckt = name_srvc_make_name_reg_big(name, name_type, scope, 0,
				     my_ip_address, group_flg, CACHE_NODEFLG_B);
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  tid.tid = make_weakrandom();

  trans = ss_register_name_tid(&tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    destroy_name_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  /* Don't listen for incoming packets. */
  ss_set_inputdrop_name_tid(&tid);
  ss__dstry_recv_queue(trans);

  pckt->header->transaction_id = tid.tid;
  pckt->header->opcode = OPCODE_REQUEST | OPCODE_RELEASE;
  pckt->header->nm_flags = FLG_B;

  ss_name_send_pckt(pckt, &addr, trans);

  for (i=0; i < (BCAST_REQ_RETRY_COUNT -2); i++) {
    nanosleep(&sleeptime, 0);
    ss_name_send_pckt(pckt, &addr, trans);
  }

  nanosleep(&sleeptime, 0);
  pckt->for_del = 1;
  ss_name_send_pckt(pckt, &addr, trans);

  ss_deregister_name_tid(&tid);
  free(trans);

  return 0;
}

struct cache_namenode *name_srvc_find_name(unsigned char *name,
					   unsigned char name_type,
					   struct nbnodename_list *scope,
					   unsigned short nodetype, /* Only one node type! */
					   unsigned char group_flg,
					   unsigned char recursion) {
  struct name_srvc_resource_lst *res, *cur_res;
  struct nbaddress_list *list;//, *cmpnd_lst;
  struct ipv4_addr_list *addrlst, *frstaddrlst;
  struct cache_namenode *new_name;
  time_t curtime;
  uint32_t ttl;
  uint16_t target_flags;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];

  if ((! name) ||
      /* The explanation for the below test:
       * 1. at least one of bits ISGROUP_YES or ISGROUP_NO must be set.
       * 2. you can not set both bits at the same time. */
      (! ((group_flg & (ISGROUP_YES | ISGROUP_NO)) &&
	  (((group_flg & ISGROUP_YES) ? 1 : 0) ^
	   ((group_flg & ISGROUP_NO) ? 1 : 0)))))
    return 0;

  decoded_name[NETBIOS_NAME_LEN] = '\0';

  if (group_flg & ISGROUP_YES)
    target_flags = NBADDRLST_GROUP_YES;
  else
    target_flags = NBADDRLST_GROUP_NO;
  switch (nodetype) {
  case CACHE_NODEFLG_H:
    target_flags = target_flags | NBADDRLST_NODET_H;
    break;
  case CACHE_NODEFLG_M:
    target_flags = target_flags | NBADDRLST_NODET_M;
    break;
  case CACHE_NODEFLG_P:
    target_flags = target_flags | NBADDRLST_NODET_P;
    break;
  case CACHE_NODEFLG_B:
    break;
  default:
    /* TODO: errno signaling stuff */
    return 0;
    break;
  }

  res = name_srvc_callout_name(name, name_type, scope,
			       get_inaddr(), 0,
			       (recursion ? FLG_RD : FLG_B),
			       recursion);
  if (! res)
    return 0;
  else {
    frstaddrlst = addrlst = 0;
    ttl = 0;
    cur_res = res;
    do {
      if (cur_res->res->rdata_t == nb_address_list) {
	list = cur_res->res->rdata;
	while (list) {
	  if (list->there_is_an_address &&
	      (list->flags == target_flags)) {
	    if (! frstaddrlst) {
	      frstaddrlst = malloc(sizeof(struct ipv4_addr_list));
	      if (! frstaddrlst) {
		/* TODO: errno signaling stuff */
		destroy_name_srvc_res_lst(res, TRUE, TRUE);
		return 0;
	      }
	      addrlst = frstaddrlst;
	    } else {
	      addrlst->next = malloc(sizeof(struct ipv4_addr_list));
	      if (! addrlst->next) {
		/* TODO: errno signaling stuff */
		while (frstaddrlst) {
		  addrlst = frstaddrlst->next;
		  free(frstaddrlst);
		  frstaddrlst = addrlst;
		}
		destroy_name_srvc_res_lst(res, TRUE, TRUE);
		return 0;
	      }
	      addrlst = addrlst->next;
	    }

	    addrlst->ip_addr = list->address;
	  }
	  list = list->next_address;
	}
	if (addrlst) {
	  addrlst->next = 0;
	  /* The below will lose quite a bit of information,
	   * but I am in no mood to make YET ANOTHER LIST. */
	  if (cur_res->res->ttl > ttl)
	    ttl = cur_res->res->ttl;
	}
      }
      cur_res = cur_res->next;
    } while (cur_res);
  }

  if (frstaddrlst) {
    new_name = alloc_namecard(decode_nbnodename(res->res->name->name,
                                                decoded_name),
			      NETBIOS_NAME_LEN,
			      nodetype, 0, group_flg,
			      res->res->rrtype, res->res->rrclass);
    if (new_name) {
      new_name->addrs.recrd[0].node_type = nodetype;
      new_name->addrs.recrd[0].addr = frstaddrlst;

      if (add_scope(scope, new_name) ||
	  add_name(new_name, scope)) {
	curtime = time(0);
	new_name->endof_conflict_chance = curtime + CONFLICT_TTL;
	/* Fun fact: the below can overflow. No,
	 * I'm not gonna make a test for that. */
	new_name->timeof_death = curtime + ttl;

	destroy_name_srvc_res_lst(res, TRUE, TRUE);
	return new_name;
      } else {
	destroy_namecard(new_name);
      }
    } else {
      while (frstaddrlst) {
	addrlst = frstaddrlst->next;
	free(frstaddrlst);
	frstaddrlst = addrlst;
      }
    }
  }

  destroy_name_srvc_res_lst(res, TRUE, TRUE);
  return 0;
}

void *name_srvc_B_handle_newtid(void *input) {
  struct timespec sleeptime;
  struct newtid_params params, *release_lock;
  struct thread_node *last_will;
  struct name_srvc_packet *outpckt;
  struct ss_unif_pckt_list *outside_pckt, *last_outpckt;
  unsigned char waited;
  time_t cur_time;


  memcpy(&params, input, sizeof(struct newtid_params));
  release_lock = input;
  release_lock->isbusy = 0;

  if (params.thread_id)
    last_will = add_thread(params.thread_id);
  else
    last_will = 0;

  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_500MS;

  last_outpckt = 0;
  waited = 0;

  while (0xceca) /* Also known as sesa. */ {

    ss_set_inputdrop_name_tid(&(params.id));

    do {
      outside_pckt = ss__recv_entry(params.trans);

      if (outside_pckt == last_outpckt) {
	/* No packet. */
	if (waited) {
	  /* Wait time passed. */
	  ss_deregister_name_tid(&(params.id));
	  ss__dstry_recv_queue(params.trans);
	  free(params.trans);
	  if (last_will)
	    last_will->dead = 9001; /* It's OVER *9000*!!! */
	  return 0;
	} else {
	  waited = 1;
	  ss_set_normalstate_name_tid(&(params.id));
	  nanosleep(&sleeptime, 0);
	  ss_set_inputdrop_name_tid(&(params.id));
	}
      } else {
	if (last_outpckt)
	  free(last_outpckt);
	last_outpckt = outside_pckt;
      }

    } while (! outside_pckt->packet);

    ss_set_normalstate_name_tid(&(params.id));

    outpckt = outside_pckt->packet;

    /* Hack to make the complex loops of
       this function work as they should. */
    outside_pckt->packet = 0;

    cur_time = time(0);



    // NAME REGISTRATION REQUEST (UNIQUE)
    // NAME REGISTRATION REQUEST (GROUP)

    if ((outpckt->header->opcode == (OPCODE_REQUEST |
				     OPCODE_REGISTRATION)) &&
	(! outpckt->header->rcode)) {
      /* NAME REGISTRATION REQUEST */

      name_srvc_do_namregreq(outpckt, &(outside_pckt->addr),
			     params.trans, params.id.tid,
			     cur_time);

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME QUERY REQUEST
    // NODE STATUS REQUEST

    if ((outpckt->header->opcode == (OPCODE_REQUEST |
				     OPCODE_QUERY)) &&
	(! outpckt->header->rcode)) {

      name_srvc_do_namqrynodestat(outpckt, &(outside_pckt->addr),
				  params.trans, params.id.tid,
				  cur_time);

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // POSITIVE NAME QUERY RESPONSE

    if ((outpckt->header->opcode == (OPCODE_RESPONSE |
				     OPCODE_QUERY)) &&
	(outpckt->header->rcode == 0) &&
	(outpckt->header->nm_flags & FLG_AA)) {

      name_srvc_do_posnamqryresp(outpckt, &(outside_pckt->addr),
				 params.trans, params.id.tid,
				 cur_time);

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME CONFLICT DEMAND

    if ((outpckt->header->opcode == (OPCODE_RESPONSE |
				     OPCODE_REGISTRATION)) &&
	(outpckt->header->rcode == RCODE_CFT_ERR) &&
	(outpckt->header->nm_flags & FLG_AA)) {

      name_srvc_do_namcftdem(outpckt);

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME RELEASE REQUEST

    if ((outpckt->header->opcode == (OPCODE_REQUEST |
				     OPCODE_RELEASE)) &&
	(outpckt->header->rcode == 0)) {

      name_srvc_do_namrelreq(outpckt, &(outside_pckt->addr));

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME UPDATE REQUEST
    /*
     * The hardest one to date, because I had to COMPLETELY redo the cache
     * records to make it work. I also had to implement linked list
     * cross-checker.
     */

    if (((outpckt->header->opcode == (OPCODE_REQUEST |
				      OPCODE_REFRESH)) ||
	 (outpckt->header->opcode == (OPCODE_REQUEST |
				      OPCODE_REFRESH2))) &&
	(outpckt->header->rcode == 0)) {

      name_srvc_do_updtreq(outpckt, &(outside_pckt->addr),
			   params.trans, params.id.tid,
			   cur_time);

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NOOP

    destroy_name_srvc_pckt(outpckt, 1, 1);
  }

  return 0;
}
