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


void name_srvc_do_namregreq(struct name_srvc_packet *outpckt,
			    struct sockaddr_in *addr,
			    struct ss_queue *trans,
			    uint32_t tid,
			    time_t cur_time) {
  struct name_srvc_packet *pckt;
  struct name_srvc_resource_lst *res;
  struct nbaddress_list *nbaddr_list;
  struct cache_namenode *cache_namecard;
  uint32_t in_addr, i;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];

  for (res = outpckt->aditionals;
       res != 0;      /* Maybe test in questions too. */
       res = res->next) {
    if ((res->res) &&
	(res->res->name) &&
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

	if (cache_namecard &&
	    (cache_namecard->token) &&
	    (cache_namecard->timeof_death > cur_time) &&
	    (! cache_namecard->isinconflict)) { /* Paired with the DOS_BUG in the
						 * POSITIVE NAME QUERY RESPONSE
						 * section, this can be abused to
						 * execute a hostile name takeover.
						 */
	  /* Someone is trying to take my name. */

	  in_addr = 0;
	  for (i=0; i<4; i++) {
	    if (cache_namecard->addrs.recrd[i].addr) {
	      in_addr = cache_namecard->addrs.recrd[i].addr->ip_addr;
	      break;
	    }
	  }

	  if (i<4) {
	    pckt = name_srvc_make_name_reg_small(decoded_name, decoded_name[NETBIOS_NAME_LEN],
						 res->res->name->next_name,
						 (cache_namecard->timeof_death
						  - cur_time),
						 in_addr, ISGROUP_NO,
						 cache_namecard->addrs.recrd[i].node_type);
	    if (pckt) {
	      pckt->header->transaction_id = tid;
	      pckt->header->opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
	      pckt->header->nm_flags = FLG_AA;
	      pckt->header->rcode = RCODE_CFT_ERR;
	      pckt->for_del = 1;
	      ss_name_send_pckt(pckt, addr, trans);
	    }
	  }

	  break;
	} else
	  break;
      }
    }
  }

  return;
}


void name_srvc_do_namqrynodestat(struct name_srvc_packet *outpckt,
				 struct sockaddr_in *addr,
				 struct ss_queue *trans,
				 uint32_t tid,
				 time_t cur_time) {
  struct name_srvc_packet *pckt;
  struct name_srvc_resource_lst *res, *answer_lst;
  struct name_srvc_question_lst *qstn;
  struct cache_namenode *cache_namecard, *cache_namecard_b;
  struct cache_scopenode *this_scope;
  struct nbaddress_list *nbaddr_list, *nbaddr_list_frst;
  struct name_srvc_statistics_rfc1002 *stats;
  struct nbnodename_list_backbone *names_list;
  struct ipv4_addr_list *ipv4_addr_list;
  int i;
  uint16_t numof_answers, flags;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1], numof_names;

  numof_answers = 0;
  answer_lst = res = 0;
  ipv4_addr_list = 0;

  qstn = outpckt->questions;
  while (qstn) {

    if (qstn->qstn &&
	qstn->qstn->name) {
      if (qstn->qstn->qtype == QTYPE_NBSTAT) {
	cache_namecard = find_nblabel(decode_nbnodename(qstn->qstn->name->name,
							decoded_name),
				      NETBIOS_NAME_LEN,
				      ANY_NODETYPE, ANY_GROUP,
				      QTYPE_NB,
				      qstn->qstn->qclass,
				      qstn->qstn->name->next_name);

	if (cache_namecard &&
	    (cache_namecard->token) &&
	    (cache_namecard->timeof_death > cur_time) &&
	    (! cache_namecard->isinconflict) &&
	    (this_scope = find_scope(qstn->qstn->name->next_name))) {

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
      } else {
	cache_namecard = find_nblabel(decode_nbnodename(qstn->qstn->name->name,
							decoded_name),
				      NETBIOS_NAME_LEN,
				      ANY_NODETYPE, ANY_GROUP,
				      qstn->qstn->qtype,
				      qstn->qstn->qclass,
				      qstn->qstn->name->next_name);
	if (cache_namecard &&
	    (cache_namecard->token) &&
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

    qstn = qstn->next;
  }

  if (answer_lst) {
    res->next = 0; /* terminate the list */
    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    /* no check */
    pckt->answers = answer_lst;

    pckt->header->transaction_id = tid;
    pckt->header->opcode = (OPCODE_RESPONSE | OPCODE_QUERY);
    pckt->header->nm_flags = FLG_AA;
    pckt->header->rcode = 0;
    pckt->header->numof_answers = numof_answers;
    pckt->for_del = 1;

    ss_name_send_pckt(pckt, addr, trans);
  }

  return;
}
