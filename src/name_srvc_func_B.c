#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 199309
#endif
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
#include "randomness.h"
#include "service_sector.h"
#include "service_sector_threads.h"


/* return: 0=success, >0=fail, -1=error */
int name_srvc_B_add_name(unsigned char *name,
			 unsigned char name_type,
			 struct nbnodename_list *scope,
			 uint32_t my_ip_address,
			 int isgroup,
			 uint32_t ttl) {
  struct timespec sleeptime;
  struct sockaddr_in addr;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outside_pckt;
  struct name_srvc_resource_lst *res;
  int result, i;
  uint16_t tid;

  result = 0;
  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_250MS;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  addr.sin_addr.s_addr = INADDR_BROADCAST;

  pckt = name_srvc_make_name_reg_big(name, name_type, scope, ttl,
				     my_ip_address, isgroup, 'B');
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  tid = make_weakrandom();

  trans = ss_register_name_tid(tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    destroy_name_srvc_pckt(pckt, 0, 1);
    return -1;
  }

  pckt->header->transaction_id = tid;
  pckt->header->opcode = OPCODE_REQUEST | OPCODE_REGISTRATION;
  pckt->header->nm_flags = FLG_B;
  /* Do not ask for recursion, because
     there are no NBNS in our scope. */

  for (i=0; i < BCAST_REQ_RETRY_COUNT; i++) {
    ss_name_send_pckt(pckt, &addr, trans);

    nanosleep(&sleeptime, 0);
  }

  ss_set_inputdrop_name_tid(tid);

  while (1) {
    outside_pckt = ss_name_recv_pckt(trans);
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
    ss_name_send_pckt(pckt, &addr, trans);
  }

  ss_deregister_name_tid(tid);
  ss_name_dstry_recv_queue(trans);
  free(trans);

  destroy_name_srvc_pckt(pckt, 0, 1);

  return result;
}

/* return: 0=success, >0=fail, -1=error */
int name_srvc_B_release_name(unsigned char *name,
			     unsigned char name_type,
			     struct nbnodename_list *scope,
			     uint32_t my_ip_address,
			     int isgroup) {
  struct timespec sleeptime;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt;
  struct sockaddr_in addr;
  int i;
  uint16_t tid;

  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_250MS;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  addr.sin_addr.s_addr = INADDR_BROADCAST;

  pckt = name_srvc_make_name_reg_big(name, name_type, scope, 0,
				     my_ip_address, isgroup, 'B');
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  tid = make_weakrandom();

  trans = ss_register_name_tid(tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    destroy_name_srvc_pckt(pckt, 0, 1);
    return -1;
  }

  /* Don't listen for incoming packets. */
  ss_set_inputdrop_name_tid(tid);
  ss_name_dstry_recv_queue(trans);

  pckt->header->transaction_id = tid;
  pckt->header->opcode = OPCODE_REQUEST | OPCODE_RELEASE;
  pckt->header->nm_flags = FLG_B;

  ss_name_send_pckt(pckt, &addr, trans);

  for (i=0; i < (BCAST_REQ_RETRY_COUNT -1); i++) {
    nanosleep(&sleeptime, 0);
    ss_name_send_pckt(pckt, &addr, trans);
  }

  ss_deregister_name_tid(tid);
  free(trans);

  destroy_name_srvc_pckt(pckt, 0, 1);

  return 0;
}

struct name_srvc_resource *name_srvc_B_callout_name(unsigned char *name,
						    unsigned char name_type,
						    struct nbnodename_list *scope) {
  struct timespec sleeptime;
  struct sockaddr_in addr;
  struct name_srvc_resource_lst *res;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outside_pckt;
  struct name_srvc_resource *result;
  int i;
  uint16_t tid;

  result = 0;
  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_250MS;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  addr.sin_addr.s_addr = INADDR_BROADCAST;

  pckt = name_srvc_make_name_qry_req(name, name_type, scope);
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  tid = make_weakrandom();

  trans = ss_register_name_tid(tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    destroy_name_srvc_pckt(pckt, 0, 1);
    return 0;
  }

  pckt->header->transaction_id = tid;
  pckt->header->opcode = OPCODE_REQUEST | OPCODE_QUERY;
  pckt->header->nm_flags = FLG_B;

  for (i=0; i < BCAST_REQ_RETRY_COUNT; i++) {
    ss_name_send_pckt(pckt, &addr, trans);

    nanosleep(&sleeptime, 0);

    ss_set_inputdrop_name_tid(tid);

    while (1) {
      outside_pckt = ss_name_recv_pckt(trans);
      if (! outside_pckt) {
	break;
      }

      if ((outside_pckt->header->opcode == (OPCODE_RESPONSE |
					    OPCODE_QUERY)) &&
	  (outside_pckt->header->nm_flags & FLG_AA) &&
	  (outside_pckt->header->rcode != 0)) {
	/* POSITIVE NAME QUERY RESPONSE */
	res = outside_pckt->answers;

	while (res) {
	  if ((0 == cmp_nbnodename(pckt->questions->qstn->name,
				   res->res->name)) &&
	      (pckt->questions->qstn->qtype ==
	       res->res->rrtype) &&
	      (pckt->questions->qstn->qclass ==
	       res->res->rrclass) &&
	      (res->res->rdata_t == nb_address_list)) {
	    /* This is what we are looking for. */

	    result = res->res;
	    res->res = 0;
	    break;

	  } else
	    res = res->next;
	}
      }

      destroy_name_srvc_pckt(outside_pckt, 1, 1);

      if (result)
	break;
    }

    if (result)
      break;

    ss_set_normalstate_name_tid(tid);
  }

  ss_deregister_name_tid(tid);
  ss_name_dstry_recv_queue(trans);
  free(trans);

  destroy_name_srvc_pckt(pckt, 0, 1);

  return result;
}

void *name_srvc_B_handle_newtid(void *input) {
  struct timespec sleeptime;
  struct newtid_params params;
  struct thread_node *last_will;

  struct name_srvc_packet *pckt;
  struct ss_name_pckt_list *outside_pckt, *last_outpckt;

  struct name_srvc_resource_lst *res;
  struct cache_namenode *cache_namecard;
  struct nbaddress_list *nbaddr_list;
  uint32_t in_addr;
  unsigned char octet, label[NETBIOS_NAME_LEN+1], label_type;
  unsigned char to_toplevel, waited;

  time_t cur_time;
  void *result;


  memcpy(&params, input, sizeof(struct newtid_params));

  if (params.thread_id)
    last_will = add_thread(params.thread_id);
  else
    last_will = 0;

  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_500MS;

  to_toplevel = 0;
  label[NETBIOS_NAME_LEN] = '\0';

  ss_set_inputdrop_name_tid(params.tid);
  last_outpckt = 0;
  waited = 0;

  while (0xceca) /* Also known as sesa. */ {

    do {
      outside_pckt = ss_name_recv_entry(params.trans);

      if (outside_pckt == last_outpckt) {
	/* No packet. */
	if (waited) {
	  /* Wait time passed. */
	  ss_deregister_name_tid(params.tid);
	  ss_name_dstry_recv_queue(params.trans);
	  if (last_will)
	    last_will->dead = 9001; /* It's OVER *9000*!!! */
	  return 0;
	} else {
	  waited = 1;
	  ss_set_normalstate_name_tid(params.tid);
	  nanosleep(&sleeptime, 0);
	  ss_set_inputdrop_name_tid(params.tid);
	}
      } else {
	if (last_outpckt)
	  free(last_outpckt);
	last_outpckt = outside_pckt;
      }

    } while (! outside_pckt->packet);

    cur_time = time(0);


    // NAME REGISTRATION REQUEST (UNIQUE)
    // NAME REGISTRATION REQUEST (GROUP)

    if ((outside_pckt->packet->header->opcode == (OPCODE_REQUEST |
						  OPCODE_REGISTRATION)) &&
	(! outside_pckt->packet->header->rcode)) {
      /* NAME REGISTRATION REQUEST */

      for (res = outside_pckt->packet->aditionals;
	   res != 0;
	   res = res->next) {
	if (res->res) {

	  if ((res->res->name) &&
	      (res->res->rdata_t == nb_address_list)) {

	    nbaddr_list = res->res->rdata;
	    while (nbaddr_list) {
	      if (nbaddr_list->flags & NBADDRLST_GROUP_MASK)
		octet = 1;
	      else
		octet = 0;

	      cache_namecard = find_nblabel(res->res->name->name,
					    res->res->name->len,
					    ANY_NODETYPE, octet,
					    res->res->rrtype,
					    res->res->rrclass,
					    res->res->name->next_name);

	      if (cache_namecard)
		if (cache_namecard->ismine &&
		    (0 == cache_namecard->isgroup)) {
		  /* Someone is trying to take my name. */

		  memcpy(&label, cache_namecard->name, NETBIOS_NAME_LEN);
		  label_type = label[NETBIOS_NAME_LEN-1];
		  label[NETBIOS_NAME_LEN-1] = '\0';
		  if (cache_namecard->addrlist)
		    in_addr = cache_namecard->addrlist->ip_addr;
		  else
		    in_addr = 0;

		  pckt = name_srvc_make_name_reg_small(label, label_type,
						       res->res->name->next_name,
						       (cache_namecard->timeof_death
							  - cur_time),
						       in_addr, 0,
						       cache_namecard->node_type);
		  pckt->header->opcode = (OPCODE_RESPONSE & OPCODE_REGISTRATION);
		  pckt->header->nm_flags = FLG_AA;
		  pckt->header->rcode = RCODE_REGISTR_ACT_ERR;
		  ss_name_send_pckt(pckt, &(outside_pckt->addr), params.trans);

		  destroy_name_srvc_pckt(pckt, 0, 1);
		  destroy_name_srvc_pckt(outside_pckt->packet, 1, 1);
		  /* Hack to make the complex loops and tests
		     of this function work as they should. */
		  outside_pckt->packet = 0;
		  last_outpckt = outside_pckt;

		  to_toplevel = 1;
		  break;
		}

	      nbaddr_list = nbaddr_list->next_address;
	    }
	  }
	}

	if (to_toplevel) {
	  to_toplevel = 0;
	  break;
	}
      }
      continue;
    }

    // NAME QUERY REQUEST

    // POSITIVE NAME QUERY RESPONSE

    // NAME CONFLICT DEMAND

    // NAME RELEASE REQUEST

    // NAME UPDATE REQUEST

    // NODE STATUS REQUEST


    destroy_name_srvc_pckt(outside_pckt->packet, 1, 1);
    free(outside_pckt);
  }

  return 0;
}
