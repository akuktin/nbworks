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

#ifndef NBWORKS_NAMESRVCCACHE_H
# define NBWORKS_NAMESRVCCACHE_H 1

# include "nodename.h"
# include "constdef.h"
# include "name_srvc_cache_data.h"
# include "name_srvc_pckt.h"


void init_name_srvc_cache(void);

unsigned int
  does_token_match(struct group_tokenlst *list,
                   token_t token);
struct group_tokenlst *
  add_token(struct group_tokenlst **anchor,
            token_t token);
void
  del_token(struct group_tokenlst **anchor,
            token_t token);
void
  destroy_tokens(struct group_tokenlst *tokens);

struct cache_scopenode *
  add_scope(struct nbworks_nbnamelst *scope,
            struct cache_namenode *first_node,
            ipv4_addr_t nbns_addr);
struct cache_scopenode *
  find_scope(struct nbworks_nbnamelst *scope);

ipv4_addr_t
  get_nbnsaddr(struct nbworks_nbnamelst *scope);
void
  prune_scopes(time_t when);
void
  update_myip4(ipv4_addr_t old_addr,
               ipv4_addr_t new_addr);

struct cache_namenode *
  add_name(struct cache_namenode *name,
           struct nbworks_nbnamelst *scope);
struct cache_namenode *
  add_nblabel(void *label,
              unsigned char labellen,
              node_type_t node_types,
              token_t token,
              uint16_t dns_type,
              uint16_t dns_class,
              struct addrlst_cardblock *addrblock,
              struct nbworks_nbnamelst *scope);

struct cache_namenode *
  find_name(struct cache_namenode *namecard,
            struct nbworks_nbnamelst *scope);
struct cache_namenode *
  find_nblabel(void *label,
               unsigned char labellen,
               node_type_t node_types,
               uint16_t dns_type,
               uint16_t dns_class,
               struct nbworks_nbnamelst *scope);
struct cache_namenode *
  find_namebytok(token_t token,
                 struct nbworks_nbnamelst **scope);
struct cache_namenode *
  find_nextcard(struct cache_namenode *prevcard,
                node_type_t node_types,
                uint16_t dns_type,
                uint16_t dns_class);

struct cache_namenode *
  alloc_namecard(void *label,
                 unsigned char labellen,
                 node_type_t node_types,
                 token_t token,
                 uint16_t dns_type,
                 uint16_t dns_class);
void
  destroy_namecard(struct cache_namenode *namecard);

/* returns: >0 = success, 0 = fail, <0 = error */
int
  name_srvc_enter_conflict(unsigned char group_flg,
                           struct cache_namenode *namecard,
                           unsigned char *name_ptr, /* len == NETBIOS_NAME_LEN */
                           struct nbworks_nbnamelst *scope);

struct ipv4_addr_list *
  merge_addrlists(struct ipv4_addr_list *master,
                  struct ipv4_addr_list *mergee);
void
  destroy_addrlist(struct ipv4_addr_list *list);

struct addrlst_bigblock *
  sort_nbaddrs(struct nbaddress_list *nbaddr_list,
               struct addrlst_bigblock **writeem_here);
void
  destroy_bigblock(struct addrlst_bigblock *block);
void
  cleanout_bigblock(struct addrlst_bigblock *block);

/* returns: >0 = success, 0 = failure, <0 = error */
int
  remove_membrs_frmlst(struct nbaddress_list *nbaddr_list,
                       struct cache_namenode *namecard,
                       ipv4_addr_t my_ipv4_address,
                       unsigned int sender_is_nbns);

#endif /* NBWORKS_NAMESRVCCACHE_H*/
