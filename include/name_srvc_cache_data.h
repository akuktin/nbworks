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

#ifndef NBWORKS_NAMESRVCCACHEDATA_H
# define NBWORKS_NAMESRVCCACHEDATA_H 1

# include "nbworks.h"
# include "constdef.h"
# include "nodename.h"

# define NUMOF_ADDRSES 8

# define GROUP_SHIFT 4

# define ANY_GROUP    ONES
# define ANY_NODETYPE ONES

# define CACHE_NODEFLG_B NBWORKS_NODE_B
# define CACHE_NODEFLG_P NBWORKS_NODE_P
# define CACHE_NODEFLG_M NBWORKS_NODE_M
# define CACHE_NODEFLG_H NBWORKS_NODE_H

# define CACHE_NODEGRPFLG_B (CACHE_NODEFLG_B << GROUP_SHIFT)
# define CACHE_NODEGRPFLG_P (CACHE_NODEFLG_P << GROUP_SHIFT)
# define CACHE_NODEGRPFLG_M (CACHE_NODEFLG_M << GROUP_SHIFT)
# define CACHE_NODEGRPFLG_H (CACHE_NODEFLG_H << GROUP_SHIFT)

# define CACHE_NODEFLG_PTYPE (CACHE_NODEFLG_P | CACHE_NODEFLG_M | \
                              CACHE_NODEFLG_H)
# define CACHE_NODEGRPFLG_PTYPE (CACHE_NODEGRPFLG_P | CACHE_NODEGRPFLG_M | \
                                 CACHE_NODEGRPFLG_H)

# define CACHE_ADDRBLCK_UNIQ_MASK 0x0f
# define CACHE_ADDRBLCK_GRP_MASK  0xf0

# define RAIL_NODET_BUNQ 'b'
# define RAIL_NODET_PUNQ 'p'
# define RAIL_NODET_MUNQ 'm'
# define RAIL_NODET_HUNQ 'h'
# define RAIL_NODET_BGRP 'B'
# define RAIL_NODET_PGRP 'P'
# define RAIL_NODET_MGRP 'M'
# define RAIL_NODET_HGRP 'H'

# define CACHE_TAKES_DTG 0x01
# define CACHE_TAKES_SES 0x02

extern struct cache_scopenode *nbworks_rootscope;

struct ipv4_addr_list {
  ipv4_addr_t ip_addr;
  struct ipv4_addr_list *next;
};

struct addrlst_block {
  node_type_t node_type; /* flag field */
  struct ipv4_addr_list *addr;
};

struct addrlst_cardblock {
  struct addrlst_block recrd[NUMOF_ADDRSES];
};

struct addrlst_bigblock {
  node_type_t node_types; /* flag field */
  struct addrlst_cardblock addrs;
};

struct cache_scopenode {
  struct nbworks_nbnamelst *scope;
  struct cache_namenode *names;
  ipv4_addr_t nbns_addr;
  struct cache_scopenode *next;
};

struct group_tokenlst {
  token_t token;
  pid_t signal_pid;
  int signal;
  struct group_tokenlst *next;
};

struct cache_namenode {
  unsigned char *name;
  unsigned char namelen;
  node_type_t node_types; /* flag field */
  unsigned char unq_isinconflict;
  unsigned char grp_isinconflict;
  token_t unq_token; /* 0 if name not mine */
  pid_t unq_signal_pid;
  int unq_signal_sig;
  struct group_tokenlst *grp_tokens; /* 0 if name not mine */
  uint16_t dns_type;
  uint16_t dns_class;
  time_t timeof_death;
  time_t endof_conflict_chance;
  uint32_t refresh_ttl;
  struct addrlst_cardblock addrs;
  struct cache_namenode *next;
};

#endif /* NBWORKS_NAMESRVCCACHEDATA_H */
