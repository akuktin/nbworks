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

#ifndef NBWORKS_NAMESRVCFUNCFUNC_H
# define NBWORKS_NAMESRVCFUNCFUNC_H 1

# include "service_sector.h"

# ifdef COMPILING_NBNS
struct latereg_args {
  uint16_t pckt_flags;
  struct name_srvc_resource_lst *res;
  struct sockaddr_in *addr;
  struct ss_queue *trans;
  uint32_t tid;
  time_t cur_time;
  unsigned char not_done;
  pthread_t thread_id;
};

struct laters_link {
  /* RESOURCE part */
  struct name_srvc_resource_lst *res_lst;
  /* RDATA part */
  uint32_t ttl;
  uint32_t rdata_len;
  enum name_srvc_rdata_type rdata_t;
  void *rdata;
  /* internal part */
  struct cache_namenode *namecard;
  struct addrlst_bigblock addrblck;
  /* handle to the packet used for challenging */
  struct name_srvc_packet *probe;
  /* daisy-chain */
  struct laters_link *next;
};
# endif /* COMPILING_NBNS */

void *
  name_srvc_handle_newtid(void *input);
# ifdef COMPILING_NBNS
void *
  name_srvc_NBNS_newtid(void *threadid_ptr);
struct name_srvc_packet *
  name_srvc_NBNStid_hndlr(unsigned int master,
                          uint16_t frst_index,
                          uint16_t last_index);
# endif

/* return: >0=success (return is ttl), 0=fail */
uint32_t
  name_srvc_add_name(unsigned short node_type,
                     unsigned char *name,
                     unsigned char name_type,
                     struct nbnodename_list *scope,
                     ipv4_addr_t my_ip_address,
                     uint32_t ttl);
struct name_srvc_resource_lst *
  name_srvc_callout_name(unsigned char *name,
                         unsigned char name_type,
                         struct nbnodename_list *scope,
                         ipv4_addr_t ask_address,
                         ipv4_addr_t listen_address,
                         unsigned char name_flags,
                         unsigned char recursive);
struct cache_namenode *
  name_srvc_find_name(unsigned char *name,
                      unsigned char name_type,
                      struct nbnodename_list *scope,
                      unsigned short nodetype, /* Only one node type! */
                      unsigned char recursion);
/* return: 0=success, >0=fail, <0=error */
int
  name_srvc_release_name(unsigned char *name,
                         unsigned char name_type,
                         struct nbnodename_list *scope,
                         ipv4_addr_t my_ip_address,
                         unsigned char node_types,
                         unsigned char recursion);
void *
  refresh_scopes(void *i_ignore_this);

uint32_t
  name_srvc_find_biggestwack(struct name_srvc_packet *outside_pckt,
                             struct nbnodename_list *refname,
                             uint16_t reftype,
                             uint16_t refclass,
                             uint32_t prev_best_ttl);
void
  name_srvc_do_wack(struct name_srvc_packet *outside_pckt,
                    struct nbnodename_list *refname,
                    uint16_t reftype,
                    uint16_t refclass,
                    void *tid);
void
  name_srvc_do_namregreq(struct name_srvc_packet *outpckt,
                         struct sockaddr_in *addr,
                         struct ss_queue *trans,
                         uint32_t tid,
                         time_t cur_time);
# ifdef COMPILING_NBNS
/* returns: numof_laters */
uint32_t
  name_srvc_do_NBNSnamreg(struct name_srvc_packet *outpckt,
                          struct sockaddr_in *addr,
                          struct ss_queue *trans,
                          uint32_t tid,
                          time_t cur_time);
void
  destroy_laters_list(struct laters_link *laters);
void *
  name_srvc_NBNShndl_latereg(void *args);
# endif /* COMPILING_NBNS */

void
  name_srvc_do_namqrynodestat(struct name_srvc_packet *outpckt,
                              struct sockaddr_in *addr,
                              struct ss_queue *trans,
                              uint32_t tid,
                              time_t cur_time);
void
  name_srvc_do_posnamqryresp(struct name_srvc_packet *outpckt,
                             struct sockaddr_in *addr,
                             struct ss_queue *trans,
                             uint32_t tid,
                             time_t cur_time);
void
  name_srvc_do_namcftdem(struct name_srvc_packet *outpckt,
                         struct sockaddr_in *addr);
void
  name_srvc_do_namrelreq(struct name_srvc_packet *outpckt,
                         struct sockaddr_in *addr
#ifdef COMPILING_NBNS
                         ,struct ss_queue *trans,
                         uint32_t tid
#endif
                         );
void
  name_srvc_do_updtreq(struct name_srvc_packet *outpckt,
                       struct sockaddr_in *addr,
#ifdef COMPILING_NBNS
                       struct ss_queue *trans,
#endif
                       uint32_t tid,
                       time_t cur_time);

#endif /* NBWORKS_NAMESRVCFUNCFUNC_H */
