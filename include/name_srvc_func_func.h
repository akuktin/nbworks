/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3 of the License.
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

# include "constdef.h"
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

void
  name_srvc_daemon_newtidwrk(struct name_srvc_packet *outpckt,
                             struct sockaddr_in *addr,
                             struct newtid_params *params,
                             time_t cur_time);
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
  name_srvc_add_name(node_type_t node_type,
                     unsigned char *name,
                     unsigned char name_type,
                     struct nbworks_nbnamelst *scope,
                     ipv4_addr_t my_ip_address,
                     uint32_t ttl);
struct name_srvc_resource_lst *
  name_srvc_callout_name(unsigned char *name,
                         unsigned char name_type,
                         struct nbworks_nbnamelst *scope,
                         ipv4_addr_t ask_address,
                         ipv4_addr_t listen_address,
                         unsigned char name_flags,
                         unsigned char recursive);
struct cache_namenode *
  name_srvc_find_name(unsigned char *name,
                      unsigned char name_type,
                      struct nbworks_nbnamelst *scope,
                      node_type_t node_type, /* Only one node type! */
                      unsigned char recursion);
/* return: 0=success, >0=fail, <0=error */
int
  name_srvc_release_name(unsigned char *name,
                         unsigned char name_type,
                         struct nbworks_nbnamelst *scope,
                         ipv4_addr_t my_ip_address,
                         node_type_t node_types,
                         unsigned char recursion);
void *
  refresh_scopes(void *i_ignore_this);

uint32_t
  name_srvc_find_biggestwack(struct name_srvc_packet *outside_pckt,
                             struct nbworks_nbnamelst *refname,
                             uint16_t reftype,
                             uint16_t refclass,
                             uint32_t prev_best_ttl);
void
  name_srvc_do_wack(struct name_srvc_packet *outside_pckt,
                    struct nbworks_nbnamelst *refname,
                    uint16_t reftype,
                    uint16_t refclass,
                    void *tid);
struct name_srvc_resource *
  name_srvc_func_namregreq(struct name_srvc_resource *res,
                           time_t cur_time);
struct name_srvc_resource_lst *
  name_srvc_do_namregreq(struct name_srvc_packet *outpckt,
                         struct sockaddr_in *addr,
                         struct ss_queue *trans,
                         uint32_t tid,
                         time_t cur_time,
                         unsigned long *numof_answers,
                         struct name_srvc_resource_lst *state);
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

struct name_srvc_resource *
  name_srvc_func_nodestat(struct name_srvc_question *qstn,
                          time_t cur_time,
                          unsigned int *istruncated);
struct name_srvc_resource *
  name_srvc_func_namqry(struct name_srvc_question *qstn,
                        time_t cur_time,
                        unsigned int *istruncated);
struct name_srvc_resource_lst *
  name_srvc_do_namqrynodestat(struct name_srvc_packet *outpckt,
                              struct sockaddr_in *addr,
                              struct ss_queue *trans,
                              uint32_t tid,
                              time_t cur_time,
                              struct name_srvc_question_lst **state,
                              unsigned long *numof_founds,
                              unsigned long *numof_notfounds);
struct name_srvc_resource *
  name_srvc_func_posnamqryresp(struct name_srvc_resource *res,
                               struct sockaddr_in *addr,
                               struct ss_queue *trans,
                               uint32_t tid,
                               time_t cur_time,
                               ipv4_addr_t in_addr);
struct name_srvc_resource_lst *
  name_srvc_do_posnamqryresp(struct name_srvc_packet *outpckt,
                             struct sockaddr_in *addr,
                             struct ss_queue *trans,
                             uint32_t tid,
                             time_t cur_time,
                             struct name_srvc_resource_lst *state,
                             unsigned long *numof_responses);
void
  name_srvc_func_namcftdem(struct name_srvc_resource *res,
                           ipv4_addr_t in_addr,
                           uint32_t name_flags);
void
  name_srvc_do_namcftdem(struct name_srvc_packet *outpckt,
                         struct sockaddr_in *addr,
                         struct name_srvc_resource_lst *state);
/* returns: !0 = success, 0 = failure */
unsigned int
  name_srvc_func_namrelreq(struct name_srvc_resource *res,
                           ipv4_addr_t in_addr,
                           uint32_t name_flags);
struct name_srvc_resource_lst *
  name_srvc_do_namrelreq(struct name_srvc_packet *outpckt,
                         struct sockaddr_in *addr,
#ifdef COMPILING_NBNS
                         struct ss_queue *trans,
                         uint32_t tid,
                         unsigned long *numof_OK,
                         unsigned long *numof_notOK,
#endif
                         struct name_srvc_resource_lst **state);
/* returns: !0 = success, 0 = failure */
unsigned int
  name_srvc_func_updtreq(struct name_srvc_resource *res,
                         ipv4_addr_t in_addr,
                         uint32_t name_flags,
                         time_t cur_time);
struct name_srvc_resource_lst *
  name_srvc_do_updtreq(struct name_srvc_packet *outpckt,
                       struct sockaddr_in *addr,
#ifdef COMPILING_NBNS
                       struct ss_queue *trans,
                       uint32_t tid,
                       unsigned long *numof_OK,
                       unsigned long *numof_notOK,
#endif
                       time_t cur_time,
                       struct name_srvc_resource_lst **state);

#endif /* NBWORKS_NAMESRVCFUNCFUNC_H */
