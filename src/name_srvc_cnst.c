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

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_cnst.h"
#include "name_srvc_cache.h"


/* All of these functions return half-baked packets
   which must have their header flags filled in. */

struct name_srvc_packet *name_srvc_make_name_reg_big(unsigned char *name,
						     unsigned char name_type,
						     struct nbworks_nbnamelst *scope,
						     uint32_t ttl,
						     ipv4_addr_t in_address,
						     unsigned char node_type) {
  struct name_srvc_packet *result;
  struct nbworks_nbnamelst *complete_name;
  struct nbaddress_list *addr;

  if (! name)
    return 0;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  addr = malloc(sizeof(struct nbaddress_list));
  if (! addr) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }
  addr->next_address = 0;
  addr->there_is_an_address = TRUE;
  addr->address = in_address;
  switch (node_type) {
  case CACHE_NODEGRPFLG_H:
    addr->flags = NBADDRLST_GROUP_YES;
    addr->flags = addr->flags | NBADDRLST_NODET_H;
    break;
  case CACHE_NODEFLG_H:
    addr->flags = NBADDRLST_GROUP_NO;
    addr->flags = addr->flags | NBADDRLST_NODET_H;
    break;

  case CACHE_NODEGRPFLG_M:
    addr->flags = NBADDRLST_GROUP_YES;
    addr->flags = addr->flags | NBADDRLST_NODET_M;
    break;
  case CACHE_NODEFLG_M:
    addr->flags = NBADDRLST_GROUP_NO;
    addr->flags = addr->flags | NBADDRLST_NODET_M;
    break;

  case CACHE_NODEGRPFLG_P:
    addr->flags = NBADDRLST_GROUP_YES;
    addr->flags = addr->flags | NBADDRLST_NODET_P;
    break;
  case CACHE_NODEFLG_P:
    addr->flags = NBADDRLST_GROUP_NO;
    addr->flags = addr->flags | NBADDRLST_NODET_P;
    break;

  case CACHE_NODEGRPFLG_B:
    addr->flags = NBADDRLST_GROUP_YES;
    addr->flags = addr->flags | NBADDRLST_NODET_B;
    break;
  case CACHE_NODEFLG_B:
  default:
    addr->flags = NBADDRLST_GROUP_NO;
    addr->flags = addr->flags | NBADDRLST_NODET_B;
    break;
  }


  result = alloc_name_srvc_pckt(1, 0, 0, 1);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    free(addr);
    return 0;
  }

  result->questions->next = 0;
  result->questions->qstn = malloc(sizeof(struct name_srvc_question));
  if (! result->questions->qstn) {
    /* TODO: errno signaling stuff */
    free(addr);
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }

  result->aditionals->next = 0;
  result->aditionals->res = malloc(sizeof(struct name_srvc_resource));
  if (! result->aditionals->res) {
    /* TODO: errno signaling stuff */
    free(addr);
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }

  result->questions->qstn->name = complete_name;
  result->questions->qstn->qtype = QTYPE_NB;
  result->questions->qstn->qclass = QCLASS_IN;

  result->aditionals->res->name = nbworks_clone_nbnodename(complete_name);
  result->aditionals->res->rrtype = RRTYPE_NB;
  result->aditionals->res->rrclass = RRCLASS_IN;
  result->aditionals->res->ttl = ttl;
  result->aditionals->res->rdata_len = 6;
  result->aditionals->res->rdata_t = nb_address_list;
  result->aditionals->res->rdata = addr;

  return result;
}

struct name_srvc_packet *name_srvc_make_name_reg_small(unsigned char *name,
						       unsigned char name_type,
						       struct nbworks_nbnamelst *scope,
						       uint32_t ttl,
						       ipv4_addr_t in_address,
						       unsigned char node_type) {
  struct name_srvc_packet *result;
  struct nbworks_nbnamelst *complete_name;
  struct nbaddress_list *addr;

  if (! name)
    return 0;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  addr = malloc(sizeof(struct nbaddress_list));
  if (! addr) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }
  addr->next_address = 0;
  addr->there_is_an_address = 1;
  addr->address = in_address;

  switch (node_type) {
  case CACHE_NODEGRPFLG_H:
    addr->flags = NBADDRLST_GROUP_YES;
    addr->flags = addr->flags | NBADDRLST_NODET_H;
    break;
  case CACHE_NODEFLG_H:
    addr->flags = NBADDRLST_GROUP_NO;
    addr->flags = addr->flags | NBADDRLST_NODET_H;
    break;

  case CACHE_NODEGRPFLG_M:
    addr->flags = NBADDRLST_GROUP_YES;
    addr->flags = addr->flags | NBADDRLST_NODET_M;
    break;
  case CACHE_NODEFLG_M:
    addr->flags = NBADDRLST_GROUP_NO;
    addr->flags = addr->flags | NBADDRLST_NODET_M;
    break;

  case CACHE_NODEGRPFLG_P:
    addr->flags = NBADDRLST_GROUP_YES;
    addr->flags = addr->flags | NBADDRLST_NODET_P;
    break;
  case CACHE_NODEFLG_P:
    addr->flags = NBADDRLST_GROUP_NO;
    addr->flags = addr->flags | NBADDRLST_NODET_P;
    break;

  case CACHE_NODEGRPFLG_B:
    addr->flags = NBADDRLST_GROUP_YES;
    addr->flags = addr->flags | NBADDRLST_NODET_B;
    break;
  case CACHE_NODEFLG_B:
  default:
    addr->flags = NBADDRLST_GROUP_NO;
    addr->flags = addr->flags | NBADDRLST_NODET_B;
    break;
  }

  result = alloc_name_srvc_pckt(0, 1, 0, 0);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    free(addr);
    return 0;
  }

  result->answers->next = 0;
  result->answers->res = malloc(sizeof(struct name_srvc_resource));
  if (! result->answers->res) {
    /* TODO: errno signaling stuff */
    free(addr);
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }

  result->answers->res->name = complete_name;
  result->answers->res->rrtype = RRTYPE_NB;
  result->answers->res->rrclass = RRCLASS_IN;
  result->answers->res->ttl = ttl;
  result->answers->res->rdata_len = 6;
  result->answers->res->rdata_t = nb_address_list;
  result->answers->res->rdata = addr;

  return result;
}

struct name_srvc_packet *name_srvc_make_name_qry_req(unsigned char *name,
						     unsigned char name_type,
						     struct nbworks_nbnamelst *scope) {
  struct name_srvc_packet *result;
  struct nbworks_nbnamelst *complete_name;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  result = alloc_name_srvc_pckt(1, 0, 0, 0);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }

  result->questions->next = 0;
  result->questions->qstn = malloc(sizeof(struct name_srvc_question));
  if (! result->questions->qstn) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }

  result->questions->qstn->name = complete_name;
  result->questions->qstn->qtype = QTYPE_NB;
  result->questions->qstn->qclass = QCLASS_IN;

  return result;
}

struct name_srvc_packet *name_srvc_make_name_qry_pos(unsigned char *name,
						     unsigned char name_type,
						     struct nbworks_nbnamelst *scope,
						     struct nbaddress_list *addresses,
						     unsigned int numof_addresses,
						     uint32_t ttl) {
  struct name_srvc_packet *result;
  struct nbworks_nbnamelst *complete_name;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  result = alloc_name_srvc_pckt(0, 1, 0, 0);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }

  result->answers->res = malloc(sizeof(struct name_srvc_resource));
  if (! result->answers->res) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;

  }
  result->answers->res->name = complete_name;
  result->answers->res->rrtype = RRTYPE_NS;
  result->answers->res->rrclass = RRCLASS_IN;
  result->answers->res->ttl = ttl;
  result->answers->res->rdata_t = nb_address_list;
  result->answers->res->rdata_len = numof_addresses * 6;
  result->answers->res->rdata = addresses;

  return result;
}

struct name_srvc_packet *name_srvc_make_name_qry_neg(unsigned char *name,
						     unsigned char name_type,
						     struct nbworks_nbnamelst *scope) {
  struct name_srvc_packet *result;
  struct nbworks_nbnamelst *complete_name;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  result = alloc_name_srvc_pckt(0, 1, 0, 0);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }

  result->answers->res = malloc(sizeof(struct name_srvc_resource)); 
  if (! result->answers->res) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }
  result->answers->res->name = complete_name;
  result->answers->res->rrtype = RRTYPE_NULL;
  result->answers->res->rrclass = RRCLASS_IN;
  result->answers->res->ttl = 0;
  result->answers->res->rdata_t = nb_type_null;
  result->answers->res->rdata_len = 0;
  result->answers->res->rdata = 0;

  return result;
}

struct name_srvc_packet *name_srvc_make_name_qry_red(unsigned char *name,
						     unsigned char name_type,
						     struct nbworks_nbnamelst *scope,
						     struct nbworks_nbnamelst *namesrvr_name,
						     struct nbaddress_list *namesrvr_addr,
						     uint32_t ttl) {
  struct name_srvc_packet *result;
  struct nbworks_nbnamelst *complete_name;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  result = alloc_name_srvc_pckt(0, 0, 1, 1);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }

  result->authorities->res = malloc(sizeof(struct name_srvc_resource));
  if (! result->answers->res) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }
  result->aditionals->res = malloc(sizeof(struct name_srvc_resource));
  if (! result->aditionals->res) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }

  result->authorities->res->name = complete_name;
  result->authorities->res->rrtype = RRTYPE_NS;
  result->authorities->res->rrclass = RRCLASS_IN;
  result->authorities->res->ttl = ttl;
  result->authorities->res->rdata_len = nbworks_nbnodenamelen(namesrvr_name);
  result->authorities->res->rdata_t = nb_nodename;
  result->authorities->res->rdata = namesrvr_name;

  result->aditionals->res->name = nbworks_clone_nbnodename(namesrvr_name);
  result->aditionals->res->rrtype = RRTYPE_A;
  result->aditionals->res->rrclass = RRCLASS_IN;
  result->aditionals->res->ttl = ttl; /* NOTE: there is good reason to have
					       this ttl be different from the
					       other one. Maybe I will implement
					       that distinction some other time.
				      */
  result->aditionals->res->rdata_len = 4;
  result->aditionals->res->rdata_t = nb_NBT_node_ip_address;
  result->aditionals->res->rdata = namesrvr_addr;

  return result;
}

struct name_srvc_packet *name_srvc_make_stat_rfc1002_qry(unsigned char *name,
							 unsigned char name_type,
							 struct nbworks_nbnamelst *scope) {
  struct name_srvc_packet *result;
  struct nbworks_nbnamelst *complete_name;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  result = alloc_name_srvc_pckt(1, 0, 0, 0);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }

  result->questions->qstn = malloc(sizeof(struct name_srvc_question)); 
  if (! result->questions->qstn) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }

  result->questions->qstn->name = complete_name;
  result->questions->qstn->qtype = QTYPE_NBSTAT;
  result->questions->qstn->qclass = QCLASS_IN;

  return result;
}

struct name_srvc_packet *name_srvc_make_stat_rfc1002_rsp(unsigned char *name,
							 unsigned char name_type,
							 struct nbworks_nbnamelst *scope,
							 struct nbnodename_list_backbone *my_names_this_scope) {
  struct name_srvc_packet *result;
  struct nbworks_nbnamelst *complete_name;
  struct nbnodename_list_backbone *cur_names;
  struct name_srvc_statistics_rfc1002 *stats;
  uint32_t numof_names, lenof_names;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  result = alloc_name_srvc_pckt(0, 1, 0, 0);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }

  result->answers->res = malloc(sizeof(struct name_srvc_resource));
  if (! result->answers->res) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }

  stats = calloc(1, sizeof(struct name_srvc_statistics_rfc1002));
  if (! stats) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    free(result->answers->res);
    destroy_name_srvc_pckt(result, 1, 1);
    return 0;
  }

  lenof_names = 0;
  numof_names = 0;
  cur_names = my_names_this_scope;
  if (cur_names) {
    do {
      numof_names++;
      lenof_names = lenof_names + align_incr(0, nbworks_nbnodenamelen(cur_names->nbnodename), 4);
      if (nbworks_do_align)
        lenof_names = lenof_names +4;
      else
        lenof_names = lenof_names +2;
      cur_names = cur_names->next_nbnodename;
    } while (cur_names);
  };
  if (numof_names > 0xff) {
    stats->numof_names = 0xff;
  } else {
    stats->numof_names = numof_names;
  }
  stats->listof_names = my_names_this_scope;

  result->answers->res->name = complete_name;
  result->answers->res->rrtype = RRTYPE_NBSTAT;
  result->answers->res->rrclass = RRCLASS_IN;
  result->answers->res->ttl = 0;
  result->answers->res->rdata_len = lenof_names + 23*2;
  result->answers->res->rdata_t = nb_statistics_rfc1002;
  result->answers->res->rdata = stats;

  return result;
}

struct name_srvc_packet *name_srvc_make_wack(unsigned char *name,
					     unsigned char name_type,
					     struct nbworks_nbnamelst *scope,
					     uint32_t ttl,
					     uint16_t nm_flags) {
  struct nbworks_nbnamelst *complete_name;
  struct name_srvc_packet *result;
  struct nbaddress_list *rdata;

  rdata = malloc(sizeof(struct nbaddress_list));
  if (! rdata) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  rdata->there_is_an_address = 0;
  rdata->next_address = 0;
  rdata->flags = nm_flags;

  complete_name = malloc(sizeof(struct nbworks_nbnamelst));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    free(rdata);
    return 0;
  }
  complete_name->name = nbworks_make_nbnodename(name, name_type, 0);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(rdata);
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = nbworks_clone_nbnodename(scope);

  result = alloc_name_srvc_pckt(0, 1, 0, 0);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(rdata);
    free(complete_name->name);
    free(complete_name);
    return 0;
  }

  result->answers->res->name = complete_name;
  result->answers->res->rrtype = RRTYPE_NB;
  result->answers->res->rrclass = RRCLASS_IN;
  result->answers->res->ttl = ttl;
  result->answers->res->rdata_len = 2;
  result->answers->res->rdata_t = nb_address_list;
  result->answers->res->rdata = rdata;

  return result;
}
