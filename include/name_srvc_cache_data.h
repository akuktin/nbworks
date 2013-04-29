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

#ifndef NBWORKS_NAMESRVCCACHEDATA_H
# define NBWORKS_NAMESRVCCACHEDATA_H 1

# include "constdef.h"
# include "nodename.h"

# define NUMOF_ADDRSES 8

# define ANY_GROUP    ONES
# define ANY_NODETYPE ONES

# define CACHE_NODEFLG_B 0x01
# define CACHE_NODEFLG_P 0x02
# define CACHE_NODEFLG_M 0x04
# define CACHE_NODEFLG_H 0x08

# define CACHE_NODEGRPFLG_B 0x10
# define CACHE_NODEGRPFLG_P 0x20
# define CACHE_NODEGRPFLG_M 0x40
# define CACHE_NODEGRPFLG_H 0x80

# define CACHE_ADDRBLCK_UNIQ_MASK 0x0f
# define CACHE_ADDRBLCK_GRP_MASK  0xf0

# define GROUP_SHIFT 4

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
  struct addrlst_block recrd[8];
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
  struct group_tokenlst *next;
};

struct cache_namenode {
  unsigned char *name;
  unsigned char namelen;
  node_type_t node_types; /* flag field */
  unsigned char unq_isinconflict;
  unsigned char grp_isinconflict;
  token_t unq_token; /* 0 if name not mine */
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
