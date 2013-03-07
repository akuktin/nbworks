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

# include <time.h>

# include "nodename.h"
# include "constdef.h"

# define CONFLICT_TTL 1

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

# define CACHE_NODET_B 'B'
# define CACHE_NODET_P 'P'
# define CACHE_NODET_M 'M'
# define CACHE_NODET_H 'H'

# define CACHE_TAKES_DTG 0x01
# define CACHE_TAKES_SES 0x02


struct ipv4_addr_list {
  uint32_t ip_addr;
  struct ipv4_addr_list *next;
};

struct addrlst_block {
  unsigned char node_type; /* flag field */
  struct ipv4_addr_list *addr;
};

struct addrlst_grpblock {
  struct addrlst_block recrd[4];
};

struct addrlst_bigblock {
  unsigned char node_types; /* flag field */
  struct addrlst_grpblock ysgrp;
  struct addrlst_grpblock nogrp;
};

struct cache_scopenode {
  struct nbnodename_list *scope;
  struct cache_namenode *names;
  struct cache_scopenode *next;
};

struct cache_namenode {
  void *name;
  unsigned char namelen;
  //  unsigned char magic_char;
  unsigned short node_types; /* flag field */
  unsigned char isinconflict;
  uint64_t token; /* 0 if name not mine, 1 if name in
                     process of being registered */
  unsigned char group_flg;
  uint16_t dns_type;
  uint16_t dns_class;
  time_t timeof_death;
  time_t endof_conflict_chance;
  uint32_t refresh_ttl;
  struct addrlst_grpblock addrs;
  struct cache_namenode *next;
};

#endif /* NBWORKS_NAMESRVCCACHEDATA_H */
