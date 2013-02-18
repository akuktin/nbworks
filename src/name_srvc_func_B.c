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
  addr.sin_addr.s_addr = get_inaddr();

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
    outside_pckt = ss__recv_pckt(trans);
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
  addr.sin_addr.s_addr = INADDR_BROADCAST;

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

struct name_srvc_resource_lst *name_srvc_B_callout_name(unsigned char *name,
							unsigned char name_type,
							struct nbnodename_list *scope) {
  struct timespec sleeptime;
  struct sockaddr_in addr;
  struct name_srvc_resource_lst *res, **last_res;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outside_pckt;
  struct name_srvc_resource_lst *result, *walker;
  int i;
  union trans_id tid;

  walker = result = 0;
  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_250MS;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  addr.sin_addr.s_addr = 0xff01a8c0; //INADDR_BROADCAST;

  pckt = name_srvc_make_name_qry_req(name, name_type, scope);
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
  pckt->header->opcode = OPCODE_REQUEST | OPCODE_QUERY;
  pckt->header->nm_flags = FLG_B;

  for (i=0; i < BCAST_REQ_RETRY_COUNT; i++) {
    ss_name_send_pckt(pckt, &addr, trans);

    nanosleep(&sleeptime, 0);

    ss_set_inputdrop_name_tid(&tid);

    while (1) {
      outside_pckt = ss__recv_pckt(trans);
      if (! outside_pckt) {
	break;
      }

      if ((outside_pckt->header->opcode == (OPCODE_RESPONSE |
					    OPCODE_QUERY)) &&
	  (outside_pckt->header->nm_flags & FLG_AA) &&
	  (outside_pckt->header->rcode != 0)) {
	/* POSITIVE NAME QUERY RESPONSE */
	res = outside_pckt->answers;
	last_res = &(outside_pckt->answers);

	while (res) {
	  if ((0 == cmp_nbnodename(pckt->questions->qstn->name,
				   res->res->name)) &&
	      (pckt->questions->qstn->qtype ==
	       res->res->rrtype) &&
	      (pckt->questions->qstn->qclass ==
	       res->res->rrclass) &&
	      (res->res->rdata_t == nb_address_list)) {
	    /* This is what we are looking for. */

	    if (result) {
	      walker->next = res;
	      walker = walker->next;
	    } else {
	      result = res;
	      walker = result;
	    }

	    res = *last_res = res->next;
	    break;

	  } else {
	    last_res = &(res->next);
	    res = res->next;
	  }
	}
      }

      /* Temporary fix to prevent reading more that one packet,
       * which could lead us to have duplicate addresses; not
       * a problem per se, but I don't want to implement yet
       * another complicated (and somewhat brittle) list walker,
       * this one for removing the duplicates. */
      if (result) {
	walker->next = 0;
	break;
      }

      destroy_name_srvc_pckt(outside_pckt, 1, 1);
    }

    if (result) {
      walker->next = 0;
      break;
    }

    ss_set_normalstate_name_tid(&tid);
  }
  ss_deregister_name_tid(&tid);
  ss__dstry_recv_queue(trans);
  free(trans);

  destroy_name_srvc_pckt(pckt, 1, 1);

  return result;
}

struct cache_namenode *name_srvc_B_find_name(unsigned char *name,
					     unsigned char name_type,
					     struct nbnodename_list *scope,
					     unsigned short nodetype, /* Only one node type! */
					     unsigned char group_flg) {
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

  res = name_srvc_B_callout_name(name, name_type, scope);
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
    new_name = alloc_namecard(decode_nbnodename(cur_res->res->name->name,
                                                decoded_name),
			      NETBIOS_NAME_LEN,
			      nodetype, 0, group_flg,
			      cur_res->res->rrtype, cur_res->res->rrclass);
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

#define STATUS_DID_NONE   0x00
#define STATUS_DID_GROUP  0x01
#define STATUS_DID_UNIQ   0x02
void *name_srvc_B_handle_newtid(void *input) {
  struct timespec sleeptime;
  struct newtid_params params, *release_lock;
  struct thread_node *last_will;

  struct name_srvc_packet *outpckt, *pckt;
  struct ss_unif_pckt_list *outside_pckt, *last_outpckt;

  struct name_srvc_resource_lst *res, *answer_lst;
  struct name_srvc_question_lst *qstn;
  struct cache_scopenode *this_scope;
  struct cache_namenode *cache_namecard, *cache_namecard_b;
  struct nbaddress_list *nbaddr_list, *nbaddr_list_frst,
    *nbaddr_list_hldme, **nbaddr_list_last;
  struct name_srvc_statistics_rfc1002 *stats;
  struct nbnodename_list_backbone *names_list;

  struct ipv4_addr_list *ipv4_addr_list;
  struct addrlst_bigblock *addr_bigblock;

  uint32_t in_addr;
  uint16_t flags, numof_answers;
  int i, j;
  unsigned char label[NETBIOS_NAME_LEN+1], label_type;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];
  unsigned char waited, status, numof_names;

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

  label[NETBIOS_NAME_LEN] = '\0';
  decoded_name[NETBIOS_NAME_LEN] = '\0';

  ss_set_inputdrop_name_tid(&(params.id));
  last_outpckt = 0;
  waited = 0;

  while (0xceca) /* Also known as sesa. */ {

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

    outpckt = outside_pckt->packet;

    /* Hack to make the complex loops of
       this function work as they should. */
    outside_pckt->packet = 0;

    cur_time = time(0);
    this_scope = 0;
    cache_namecard = 0;
    cache_namecard_b = 0;
    answer_lst = 0;
    res = 0;
    qstn = 0;
    ipv4_addr_list = 0;
    addr_bigblock = 0;
    in_addr = 0;
    numof_answers = 0;
    numof_names = 0;
    nbaddr_list = nbaddr_list_frst =
      nbaddr_list_hldme = 0;
    nbaddr_list_last = 0;
    stats = 0;
    names_list = 0;
    status = STATUS_DID_NONE;


    // NAME REGISTRATION REQUEST (UNIQUE)
    // NAME REGISTRATION REQUEST (GROUP)

    if ((outpckt->header->opcode == (OPCODE_REQUEST |
				     OPCODE_REGISTRATION)) &&
	(! outpckt->header->rcode)) {
      /* NAME REGISTRATION REQUEST */

      for (res = outpckt->aditionals;
	   res != 0;      /* Maybe test in questions too. */
	   res = res->next) {
	if (res->res) {

	  if ((res->res->name) &&
	      (res->res->rdata_t == nb_address_list)) {
	    nbaddr_list = res->res->rdata;

	    while (nbaddr_list) {
	      if ((nbaddr_list->flags & NBADDRLST_GROUP_MASK) ||
		  (! nbaddr_list->there_is_an_address)) {
		/* Jump over group addresses and empty fields. */
		nbaddr_list = nbaddr_list->next_address;
		continue;
	      }

	      cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
                                                              decoded_name),
					    NETBIOS_NAME_LEN,
					    ANY_NODETYPE, ISGROUP_NO,
					    res->res->rrtype,
					    res->res->rrclass,
					    res->res->name->next_name);

	      /*
	       * RATIONALE: Names can be either group names or unique names. Since
	       * we jump over group names, that means we are only looking for unique
	       * names. Furthermore, we are only looking for our names. If we fail to
	       * find a record for the asked unique name, that means we have no problem.
	       * Also, if we find a record, but the name is not ours, we again have
	       * no problem.
	       */

	      if (cache_namecard) {
		if ((cache_namecard->token) &&
		    (cache_namecard->timeof_death > cur_time) &&
		    (! cache_namecard->isinconflict)) { /* Paired with the DOS_BUG in the
							 * POSITIVE NAME QUERY RESPONSE
							 * section, this can be abused to
							 * execute a hostile name takeover.
							 */
		  /* Someone is trying to take my name. */

		  memcpy(label, cache_namecard->name, NETBIOS_NAME_LEN);
		  label_type = label[NETBIOS_NAME_LEN-1];
		  label[NETBIOS_NAME_LEN-1] = '\0';
		  for (i=0; i<4; i++) {
		    if (cache_namecard->addrs.recrd[i].addr)
		      in_addr = cache_namecard->addrs.recrd[i].addr->ip_addr;
		    else
		      in_addr = 0;
		  }

		  if (i<4) {
		    pckt = name_srvc_make_name_reg_small(label, label_type,
							 res->res->name->next_name,
							 (cache_namecard->timeof_death
							  - cur_time),
							 in_addr, ISGROUP_NO,
							 cache_namecard->addrs.recrd[i].node_type);
		    pckt->header->opcode = (OPCODE_RESPONSE & OPCODE_REGISTRATION);
		    pckt->header->nm_flags = FLG_AA;
		    pckt->header->rcode = RCODE_CFT_ERR;
		    pckt->for_del = 1;
		    ss_name_send_pckt(pckt, &(outside_pckt->addr), params.trans);
		  }

		  break;
		} else
		  break;
	      } else
		break;
	    }
	  }
	}

      }

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME QUERY REQUEST
    // NODE STATUS REQUEST

    if ((outpckt->header->opcode == (OPCODE_REQUEST |
				     OPCODE_QUERY)) &&
	(! outpckt->header->rcode)) {

      qstn = outpckt->questions;
      while (qstn) {

	if (qstn->qstn) {
	  if (qstn->qstn->qtype == QTYPE_NBSTAT) {
	    if (qstn->qstn->name) {
	      cache_namecard = find_nblabel(decode_nbnodename(qstn->qstn->name->name,
                                                              decoded_name),
					    NETBIOS_NAME_LEN,
					    ANY_NODETYPE, ANY_GROUP,
					    QTYPE_NB,
					    qstn->qstn->qclass,
					    qstn->qstn->name->next_name);

	      if (cache_namecard)
		if ((cache_namecard->token) &&
		    (cache_namecard->timeof_death > cur_time) &&
		    (! cache_namecard->isinconflict)) {
		  this_scope = find_scope(qstn->qstn->name->next_name);
		  if (this_scope) {

		    numof_answers++;
		    if (res) {
		      res->next = malloc(sizeof(struct name_srvc_resource_lst));
		      /* no check */
		      res = res->next;
		    } else {
		      res = malloc(sizeof(struct name_srvc_resource_lst));
		      /* no check */
		      answer_lst = res;
		    }
		    res->res = malloc(sizeof(struct name_srvc_resource));
		    /* no check */
		    res->res->name = clone_nbnodename(qstn->qstn->name);
		    res->res->rrtype = RRTYPE_NBSTAT;
		    res->res->rrclass = cache_namecard->dns_class;
		    res->res->ttl = 0;

		    stats = calloc(1, sizeof(struct name_srvc_statistics_rfc1002));
		    /* no check */

		    cache_namecard_b = this_scope->names;
		    if (cache_namecard_b) {
		      stats->listof_names = malloc(sizeof(struct nbnodename_list_backbone));
		      names_list = stats->listof_names;

		      while (0xbab1) {
			numof_names++;
			names_list->nbnodename = malloc(sizeof(struct nbnodename_list));
			names_list->nbnodename->name = encode_nbnodename(cache_namecard_b->name, 0);
			names_list->nbnodename->len = NETBIOS_CODED_NAME_LEN;
			names_list->nbnodename->next_name = 0;

			if (cache_namecard_b->group_flg & ISGROUP_YES)
			  names_list->name_flags = NBADDRLST_GROUP_YES;
			else
			  names_list->name_flags = NBADDRLST_GROUP_NO;
			for (i=0; i<4; i++) {
			  if (cache_namecard_b->addrs.recrd[i].node_type) {
			    switch (cache_namecard_b->addrs.recrd[i].node_type) {
			    case CACHE_NODEFLG_H:
			      names_list->name_flags = names_list->name_flags | NBADDRLST_NODET_H;
			      break;
			    case CACHE_NODEFLG_M:
			      names_list->name_flags = names_list->name_flags | NBADDRLST_NODET_M;
			      break;
			    case CACHE_NODEFLG_P:
			      names_list->name_flags = names_list->name_flags | NBADDRLST_NODET_P;
			      break;
			    default: /* B */
			      names_list->name_flags = names_list->name_flags | NBADDRLST_NODET_B;
			    }

			    break;
			  }
			}

			names_list->name_flags = names_list->name_flags | NODENAMEFLG_ACT;
			if (cache_namecard_b->isinconflict)
			  names_list->name_flags = names_list->name_flags | NODENAMEFLG_CNF;

			cache_namecard_b = cache_namecard_b->next;

			if (cache_namecard_b) {
			  names_list->next_nbnodename = malloc(sizeof(struct nbnodename_list));
			  /* no check */
			  names_list = names_list->next_nbnodename;
			} else
			  break;
		      }
		      names_list->next_nbnodename = 0;
		    }
		    stats->numof_names = numof_names;

		    res->res->rdata_len = 1+20*2+6+(numof_names * (2+1+NETBIOS_CODED_NAME_LEN));
		    res->res->rdata_t = nb_statistics_rfc1002;
		    res->res->rdata = stats;

		    numof_names = 0;
		  }
		}
	    }
	  } else {
	    if (qstn->qstn->name) {
	      cache_namecard = find_nblabel(decode_nbnodename(qstn->qstn->name->name,
                                                              decoded_name),
					    NETBIOS_NAME_LEN,
					    ANY_NODETYPE, ANY_GROUP,
					    qstn->qstn->qtype,
					    qstn->qstn->qclass,
					    qstn->qstn->name->next_name);
	      if (cache_namecard)
		if ((cache_namecard->token) &&
		    (cache_namecard->timeof_death > cur_time) &&
		    (! cache_namecard->isinconflict)) {
		  numof_answers++;
		  if (res) {
		    res->next = malloc(sizeof(struct name_srvc_resource_lst));
		    /* no check */
		    res = res->next;
		  } else {
		    res = malloc(sizeof(struct name_srvc_resource_lst));
		    /* no check */
		    answer_lst = res;
		  }
		  res->res = malloc(sizeof(struct name_srvc_resource));
		  /* no check */
		  res->res->name = clone_nbnodename(qstn->qstn->name);
		  res->res->rrtype = cache_namecard->dns_type;
		  res->res->rrclass = cache_namecard->dns_class;
		  res->res->ttl = (cache_namecard->timeof_death - cur_time);

		  if (cache_namecard->group_flg & ISGROUP_YES)
		    flags = NBADDRLST_GROUP_YES;
		  else
		    flags = NBADDRLST_GROUP_NO;
		  for (i=0; i<4; i++) {
		    if (cache_namecard->addrs.recrd[i].addr) {
		      switch (cache_namecard->addrs.recrd[i].node_type) {
		      case CACHE_NODEFLG_H:
			flags = flags | NBADDRLST_NODET_H;
			break;
		      case CACHE_NODEFLG_M:
			flags = flags | NBADDRLST_NODET_M;
			break;
		      case CACHE_NODEFLG_P:
			flags = flags | NBADDRLST_NODET_P;
			break;
		      default: /* B */
			flags = flags | NBADDRLST_NODET_B;
		      }

		      ipv4_addr_list = cache_namecard->addrs.recrd[i].addr;

		      break;
		    }
		  }

		  i=0;
		  if (ipv4_addr_list) {
		    nbaddr_list_frst = nbaddr_list = malloc(sizeof(struct nbaddress_list));
		    //		  if (! nbaddr_list) {
		    //		    /* Now what?? */
		    //		  }

		    while (137) {
		      i++;
		      nbaddr_list->flags = flags;
		      nbaddr_list->there_is_an_address = TRUE;
		      nbaddr_list->address = ipv4_addr_list->ip_addr;

		      ipv4_addr_list = ipv4_addr_list->next;
		      if (ipv4_addr_list) {
			nbaddr_list->next_address = malloc(sizeof(struct nbaddress_list));
			/* No test. */
			nbaddr_list = nbaddr_list->next_address;
		      } else {
			nbaddr_list->next_address = 0;
			break;
		      }
		    }
		  } else
		    nbaddr_list_frst = 0;

		  res->res->rdata_len = i * 6;
		  res->res->rdata_t = nb_address_list;
		  res->res->rdata = nbaddr_list_frst;

		}
	    }
	  }
	}

	qstn = qstn->next;
      }

      if (answer_lst) {
	res->next = 0; /* terminate the list */
	pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
	/* no check */
	pckt->answers = answer_lst;

	pckt->header->opcode = (OPCODE_RESPONSE | OPCODE_QUERY);
	pckt->header->nm_flags = FLG_AA;
	pckt->header->rcode = 0;
	pckt->header->numof_answers = numof_answers;
	pckt->for_del = 1;

	ss_name_send_pckt(pckt, &(outside_pckt->addr), params.trans);
      }

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // POSITIVE NAME QUERY RESPONSE

    if ((outpckt->header->opcode == (OPCODE_RESPONSE |
				     OPCODE_QUERY)) &&
	(outpckt->header->rcode == 0) &&
	(outpckt->header->nm_flags & FLG_AA)) {

      res = outpckt->answers;
      while (res) {
	status = STATUS_DID_NONE;
	if (res->res) {
	  if ((res->res->name) &&
	      (res->res->rdata_t == nb_address_list) &&
	      (res->res->rdata)) {
	    /* Make sure noone spoofs the response. */
	    /* VAXism below. */
	    read_32field((unsigned char *)&(outside_pckt->addr.sin_addr), &in_addr);

	    nbaddr_list_frst = nbaddr_list = res->res->rdata;
	    nbaddr_list_last = &nbaddr_list_frst;

	    /* Rearange the address list so that group names come first,
	       unique names second and naked flags fields get deleted. */
            while (nbaddr_list) {
              if (! nbaddr_list->there_is_an_address) {
		nbaddr_list_hldme = nbaddr_list;
                nbaddr_list = nbaddr_list->next_address;
		*nbaddr_list_last = nbaddr_list;
		free(nbaddr_list_hldme);
              } else {
		if (nbaddr_list->flags & NBADDRLST_GROUP_MASK) {
		  nbaddr_list_hldme = nbaddr_list;
                  *nbaddr_list_last = nbaddr_list = nbaddr_list->next_address;
		  nbaddr_list_hldme->next_address = nbaddr_list_frst;
		  nbaddr_list_frst = nbaddr_list_hldme;
                } else {
		  nbaddr_list_last = &(nbaddr_list->next_address);
                  nbaddr_list = nbaddr_list->next_address;
                }
              }
	    }
	    nbaddr_list = res->res->rdata = nbaddr_list_frst;

	    if (nbaddr_list) {
	      while (nbaddr_list->flags & NBADDRLST_GROUP_MASK) {
		if (! (status & STATUS_DID_GROUP)) {
		  status = status | STATUS_DID_GROUP;
		  cache_namecard_b = find_nblabel(decode_nbnodename(res->res->name->name,
                                                                    decoded_name),
						  NETBIOS_NAME_LEN,
						  ANY_NODETYPE, ISGROUP_YES,
						  res->res->rrtype,
						  res->res->rrclass,
						  res->res->name->next_name);

		  if (cache_namecard_b)
		    if (cache_namecard_b->endof_conflict_chance < cur_time)
		      cache_namecard_b = 0;
		}

		nbaddr_list = nbaddr_list->next_address;
		if (! nbaddr_list)
		  break;
	      }

	      if (nbaddr_list) {
		cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
                                                                decoded_name),
					      NETBIOS_NAME_LEN,
					      ANY_NODETYPE, ISGROUP_NO,
					      res->res->rrtype,
					      res->res->rrclass,
					      res->res->name->next_name);

		if (cache_namecard)
		  if (cache_namecard->endof_conflict_chance < cur_time)
		    cache_namecard = 0;

	      }
	      nbaddr_list = res->res->rdata;

	      /*
	       * DOS_BUG: It is interesting.
	       * RFC 1002 requires me to delete the entry from the
	       * cache if I receive a POSITIVE NAME QUERY RESPONSE.
	       * That would imply it is possible for an attacker to
	       * just send me a response, forcing the cache expulsion
	       * and effectivelly preventing me from ever obtaining
	       * any handles to other nodes.
	       *
	       * Attempt at mitigation: verify the following matches:
	       * 1. sender IP
	       * 2. sender IP listed in the rdata of the res
	       * 3. sender IP is listed in my cache
	       *          (Therefore, I will only ever delete or mark as
	       *           conflicting a group name if a member of the
	       *           group is the one doing the talking. Conversely,
	       *           only the owner of the unique name will be
	       *           listened to.) (In this, node types are not
	       *           taken into account.)
	       */
	      if (cache_namecard || cache_namecard_b) {
		memcpy(label, cache_namecard->name, NETBIOS_NAME_LEN);
		label_type = label[NETBIOS_NAME_LEN-1];
		label[NETBIOS_NAME_LEN-1] = '\0';

		if ((cache_namecard_b) &&
		    (cache_namecard_b->timeof_death > cur_time) &&
		    (! cache_namecard_b->isinconflict)) {
		  /* Verify the sender lists themselves as a member of the
		     group being updated. */
		  while (nbaddr_list) {
		    if (!(nbaddr_list->flags & NBADDRLST_GROUP_MASK))
		      break;
		    if (nbaddr_list->address == in_addr)
		      break;
		    else
		      nbaddr_list = nbaddr_list->next_address;
		  }

		  /* Note to self: this is here because RFC 1002 requires that
		   * this be sent regardless of whether the name is group name
		   * or unique name. */
		  /* Problem: generally, if I ask for a group name, all members of
		   * the group will respond. It may also take them some time to do
		   * so. Thus, this code may get triggered in such an innocent case.
		   * If the sending node has its conflict timer running, said node
		   * could experience various problems. */
		  pckt = name_srvc_make_name_reg_small(label, label_type,
						       res->res->name->next_name,
						       0, 0, ISGROUP_YES,
						       cache_namecard->addrs.recrd[0].node_type);
		  pckt->header->opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
		  pckt->header->nm_flags = FLG_AA;
		  pckt->header->rcode = RCODE_CFT_ERR;
		  pckt->for_del = 1;

		  ss_name_send_pckt(pckt, &(outside_pckt->addr), params.trans);

		  /* Verify that the name in question previously had
		   * the IP address in question listed as it's member. */
		  if ((nbaddr_list) &&
		      (nbaddr_list->flags & NBADDRLST_GROUP_MASK)) {
		    for (i=0; i<4; i++) {
		      ipv4_addr_list = cache_namecard->addrs.recrd[i].addr;
		      while (ipv4_addr_list) {
			if (ipv4_addr_list->ip_addr == in_addr)
			  break;
			else
			  ipv4_addr_list = ipv4_addr_list->next;
		      }
		      if (ipv4_addr_list)
			break;
		    }
		  } else
		    ipv4_addr_list = 0;

		  if (ipv4_addr_list) {
		    if (! cache_namecard->token)
		      cache_namecard->timeof_death = 0;
		    else
		      cache_namecard->isinconflict = 1;  /* WRONG!!! */
		  }
		}
		if ((cache_namecard) &&
		    (cache_namecard->timeof_death > cur_time) &&
		    (! cache_namecard->isinconflict)) {
		  /* Skip a bit, till we get to the unique names. */
		  while (nbaddr_list)
		    if (!(nbaddr_list->flags & NBADDRLST_GROUP_MASK))
		      break;
		    else
		      nbaddr_list = nbaddr_list->next_address;
		  /* Verify the sender lists himself as the owner. */
		  while (nbaddr_list)
		    if (nbaddr_list->address == in_addr)
		      break;
		    else
		      nbaddr_list = nbaddr_list->next_address;

		  pckt = name_srvc_make_name_reg_small(label, label_type,
						       res->res->name->next_name,
						       0, 0, ISGROUP_NO,
						       cache_namecard->addrs.recrd[0].node_type);
		  pckt->header->opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
		  pckt->header->nm_flags = FLG_AA;
		  pckt->header->rcode = RCODE_CFT_ERR;
		  pckt->for_del = 1;

		  ss_name_send_pckt(pckt, &(outside_pckt->addr), params.trans);

		  /* Verify that the name in question previously had
		   * the IP address in question listed as it's owner. */
		  if (nbaddr_list)
		    for (i=0; i<4; i++) {
		      ipv4_addr_list = cache_namecard->addrs.recrd[i].addr;
		      while (ipv4_addr_list) {
			if (ipv4_addr_list->ip_addr == in_addr)
			  break;
			else
			  ipv4_addr_list = ipv4_addr_list->next;
		      }
		      if (ipv4_addr_list)
			break;
		    }
		  else
		    ipv4_addr_list = 0;

		  if (ipv4_addr_list) {
		    if (! cache_namecard->token)
		      cache_namecard->timeof_death = 0;
		    else {
		      /* Impossible. */
		      cache_namecard->isinconflict = 1;
		    }
		  }
		}
	      }
	      /* TODO: THIS ISN'T OVER YET, DOS_BUG!!! */
	      /* TODO: make the function cross-reference the addr lists,
		       looking for inconsistencies, like the
		       NAME RELEASE REQUEST section does. */

	    }
	  }
	}

	res = res->next;
      }

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME CONFLICT DEMAND

    if ((outpckt->header->opcode == (OPCODE_RESPONSE |
				     OPCODE_REGISTRATION)) &&
	(outpckt->header->rcode == RCODE_CFT_ERR) &&
	(outpckt->header->nm_flags & FLG_AA)) {

      res = outpckt->answers;
      while (res) {
	status = STATUS_DID_NONE;

	if ((res->res) &&
	    (res->res->rdata_t == nb_address_list)) {

	  nbaddr_list = res->res->rdata;
	  while (nbaddr_list) {
	    if (nbaddr_list->flags & NBADDRLST_GROUP_MASK)
	      status = status | STATUS_DID_GROUP;
	    else
	      status = status | STATUS_DID_UNIQ;

	    if (status & (STATUS_DID_UNIQ | STATUS_DID_GROUP))
	      break;
	    else
	      nbaddr_list = nbaddr_list->next_address;
	  }

	  if (status & STATUS_DID_GROUP) {
	    cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
                                                            decoded_name),
					  NETBIOS_NAME_LEN,
					  ANY_NODETYPE, ISGROUP_YES,
					  res->res->rrtype,
					  res->res->rrclass,
					  res->res->name->next_name);
	    if (cache_namecard)
	      if (cache_namecard->token)
		cache_namecard->isinconflict = TRUE; /* WRONG ? */
	  }
	  if (status & STATUS_DID_UNIQ) {
	    cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
                                                            decoded_name),
					  NETBIOS_NAME_LEN,
					  ANY_NODETYPE, ISGROUP_NO,
					  res->res->rrtype,
					  res->res->rrclass,
					  res->res->name->next_name);
	    if (cache_namecard)
	      if (cache_namecard->token)
		cache_namecard->isinconflict = TRUE;
	  }
	}

	res = res->next;
      }

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME RELEASE REQUEST

    if ((outpckt->header->opcode == (OPCODE_RESPONSE |
				     OPCODE_RELEASE)) &&
	(outpckt->header->rcode == 0)) {

      /* Make sure noone spoofs the release request. */
      /* VAXism below. */
      read_32field((unsigned char *)&(outside_pckt->addr.sin_addr), &in_addr);

      res = outpckt->aditionals;
      while (res) {
	status = STATUS_DID_NONE;

	if (res->res) {
	  if (res->res->rdata_t == nb_address_list) {
	    nbaddr_list = res->res->rdata;
	    while (nbaddr_list) {
	      if ((nbaddr_list->there_is_an_address) &&
		  (nbaddr_list->address == in_addr)) {
		  if (nbaddr_list->flags & NBADDRLST_GROUP_MASK)
		    status = status | STATUS_DID_GROUP;
		  else
		    status = status | STATUS_DID_UNIQ;
	      }

	      nbaddr_list = nbaddr_list->next_address;
	      if (status == (STATUS_DID_GROUP | STATUS_DID_UNIQ))
		break;
	    }

	    if (status & STATUS_DID_GROUP) {
	      cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
                                                              decoded_name),
					    NETBIOS_NAME_LEN,
					    ANY_NODETYPE, ISGROUP_YES,
					    res->res->rrtype,
					    res->res->rrclass,
					    res->res->name->next_name);
	      if (cache_namecard)

		  cache_namecard->timeof_death = 0; /* WRONG!!!!! */
	      /* The below (commented out) function must make an
	       * exception for my IP address, lest someone make me
	       * think I am not a member of my own group. */
	      /* int remove_membrs_frmlst(nbaddr_list, cache_namecard, my_ipv4_address); */
	    }
	    if (status & STATUS_DID_UNIQ) {
	      cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
                                                              decoded_name),
					    NETBIOS_NAME_LEN,
					    ANY_NODETYPE, ISGROUP_NO,
					    res->res->rrtype,
					    res->res->rrclass,
					    res->res->name->next_name);
	      if (cache_namecard)
		if (! cache_namecard->token)
		  cache_namecard->timeof_death = 0;
	      /* else: Did I just get a name release for my own name? */
	    }
	  }
	}

	res = res->next;
      }

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

      //      /* Make sure noone spoofs the update request. */
      //      read_32field(outside_pckt->addr.sinaddr, &in_addr);

      res = outpckt->aditionals;
      while (res) {
	if (res->res) {
	  if (res->res->rdata_t == nb_address_list) {
	    addr_bigblock = sort_nbaddrs(res->res->rdata, 0);

	    if (addr_bigblock) {
	      if (addr_bigblock->node_types & CACHE_ADDRBLCK_GRP_MASK) {
		cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
                                                                decoded_name),
					      NETBIOS_NAME_LEN,
					      ANY_NODETYPE, ISGROUP_YES,
					      res->res->rrtype,
					      res->res->rrclass,
					      res->res->name->next_name);

		if (! cache_namecard) {
		  cache_namecard = add_nblabel(decode_nbnodename(res->res->name->name,
                                                                 decoded_name),
					       NETBIOS_NAME_LEN,
					       ((addr_bigblock->node_types & CACHE_ADDRBLCK_GRP_MASK)
						>> 4),
					       FALSE, ISGROUP_YES,
					       res->res->rrtype,
					       res->res->rrclass,
					       &(addr_bigblock->ysgrp),
					       res->res->name->next_name);
		  if (cache_namecard) { /* Race conditions, race conditions... */
		    if (res->res->ttl)
		      cache_namecard->timeof_death = cur_time + res->res->ttl;
		    else
		      cache_namecard->timeof_death = ZEROONES; /* infinity */
		    cache_namecard->endof_conflict_chance = cur_time + CONFLICT_TTL;

		    /* Delete the reference to the the address
		     * lists so they do not get freed.*/
		    for (i=0; i<4; i++) {
		      addr_bigblock->ysgrp.recrd[i].addr = 0;
		    }
		  }
		} else {
		  /* BUG: The number of problems a rogue node can create is mind boggling. */
		  if (res->res->ttl)
		    cache_namecard->timeof_death = cur_time + res->res->ttl;
		  else
		    cache_namecard->timeof_death = ZEROONES; /* infinity */
		  cache_namecard->endof_conflict_chance = cur_time + CONFLICT_TTL;

		  for (i=0; i<4; i++) {
		    if (addr_bigblock->ysgrp.recrd[i].addr) {
		      for (j=0; j<4; j++) {
			if (cache_namecard->addrs.recrd[j].node_type ==
			    addr_bigblock->ysgrp.recrd[i].node_type) {
			  cache_namecard->addrs.recrd[j].addr =
			    merge_addrlists(cache_namecard->addrs.recrd[j].addr,
					    addr_bigblock->ysgrp.recrd[i].addr);
			} else {
			  if (cache_namecard->addrs.recrd[j].node_type == 0) {
			    cache_namecard->addrs.recrd[j].node_type =
			      addr_bigblock->ysgrp.recrd[i].node_type;
			    cache_namecard->addrs.recrd[j].addr =
			      addr_bigblock->ysgrp.recrd[i].addr;
			    /* Delete the reference to the address
			     * list so it does not get freed.*/
			    addr_bigblock->ysgrp.recrd[i].addr = 0;

			    cache_namecard->node_types = cache_namecard->node_types |
			      addr_bigblock->ysgrp.recrd[i].node_type;

			    break;
			  }
			}
		      }
		    } else
		      break;
		  }
		}
	      }
	      if (addr_bigblock->node_types & CACHE_ADDRBLCK_UNIQ_MASK) {
		cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
                                                                decoded_name),
					      NETBIOS_NAME_LEN,
					      ANY_NODETYPE, ISGROUP_YES,
					      res->res->rrtype,
					      res->res->rrclass,
					      res->res->name->next_name);

		if (! cache_namecard) {
		  cache_namecard = add_nblabel(decode_nbnodename(res->res->name->name,
                                                                 decoded_name),
					       NETBIOS_NAME_LEN,
					       (addr_bigblock->node_types &
						CACHE_ADDRBLCK_UNIQ_MASK),
					       FALSE, ISGROUP_NO,
					       res->res->rrtype,
					       res->res->rrclass,
					       &(addr_bigblock->nogrp),
					       res->res->name->next_name);

		  if (cache_namecard) { /* Race conditions, race conditions... */
		    if (res->res->ttl)
		      cache_namecard->timeof_death = cur_time + res->res->ttl;
		    else
		      cache_namecard->timeof_death = ZEROONES; /* infinity */
		    cache_namecard->endof_conflict_chance = cur_time + CONFLICT_TTL;

		    /* Delete the reference to the the address
		     * lists so they do not get freed.*/
		    for (i=0; i<4; i++) {
		      addr_bigblock->nogrp.recrd[i].addr = 0;
		    }
		  }
		} else {
		  if (! cache_namecard->token) {
		    if (res->res->ttl)
		      cache_namecard->timeof_death = cur_time + res->res->ttl;
		    else
		      cache_namecard->timeof_death = ZEROONES; /* infinity */
		    cache_namecard->endof_conflict_chance = cur_time + CONFLICT_TTL;

		    for (i=0; i<4; i++) {
		      if (addr_bigblock->nogrp.recrd[i].addr) {
			for (j=0; j<4; j++) {
			  if (cache_namecard->addrs.recrd[j].node_type ==
			      addr_bigblock->nogrp.recrd[i].node_type) {
			    cache_namecard->addrs.recrd[j].addr =
			      merge_addrlists(cache_namecard->addrs.recrd[j].addr,
					      addr_bigblock->nogrp.recrd[i].addr);
			  } else {
			    if (cache_namecard->addrs.recrd[j].node_type == 0) {
			      cache_namecard->addrs.recrd[j].node_type =
				addr_bigblock->nogrp.recrd[i].node_type;
			      cache_namecard->addrs.recrd[j].addr =
				addr_bigblock->nogrp.recrd[i].addr;
			      /* Delete the reference to the address
			       * list so it does not get freed.*/
			      addr_bigblock->nogrp.recrd[i].addr = 0;

			      cache_namecard->node_types = cache_namecard->node_types |
				addr_bigblock->nogrp.recrd[i].node_type;

			      break;
			    }
			  }
			}
		      } else
			break;
		    }
		  }
		}
		/* else: Sorry honey baby, you're cute, but that just ain't gonna work.
		         MAYBE: send a NAME CONFLICT DEMAND packet. */
	      }

	      destroy_bigblock(addr_bigblock);
	    }
	  }
	}
	res = res->next;
      }

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NOOP

    destroy_name_srvc_pckt(outpckt, 1, 1);
  }

  return 0;
}
#undef STATUS_DID_NONE
#undef STATUS_DID_GROUP
#undef STATUS_DID_UNIQ
