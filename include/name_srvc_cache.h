#ifndef NBWORKS_NAMESRVCCACHE_H
# define NBWORKS_NAMESRVCCACHE_H 1

# include <time.h>

# include "nodename.h"
# include "constdef.h"
# include "name_srvc_pckt.h"

# define ANY_GROUP ONES
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
  unsigned char ismine;
  int isgroup;
  uint16_t dns_type;
  uint16_t dns_class;
  time_t timeof_death;
  time_t endof_conflict_chance;
  struct addrlst_grpblock addrs;
  struct cache_namenode *next;
};

void init_name_srvc_cache();

struct cache_scopenode *
  add_scope(struct nbnodename_list *scope,
            struct cache_namenode *first_node);
struct cache_scopenode *
  find_scope(struct nbnodename_list *scope);

void *
  prune_scopes(void *);

struct cache_namenode *
  add_name(struct cache_namenode *name,
           struct nbnodename_list *scope);
struct cache_namenode *
  add_nblabel(void *label,
              unsigned char labellen,
              unsigned short node_types,
              unsigned char ismine,
              int isgroup,
              uint16_t dns_type,
              uint16_t dns_class,
              struct addrlst_grpblock *addrblock,
              struct nbnodename_list *scope);
struct cache_namenode *
  replace_namecard(struct cache_namenode *name,
                   struct nbnodename_list *scope);

struct cache_namenode *
  find_name(struct cache_namenode *namecard,
            struct nbnodename_list *scope);
struct cache_namenode *
  find_nblabel(void *label,
               unsigned char labellen,
               unsigned short node_types,
               int isgroup,
               uint16_t dns_type,
               uint16_t dns_class,
               struct nbnodename_list *scope);

struct cache_namenode *
  alloc_namecard(void *label,
                 unsigned char labellen,
                 unsigned short node_types,
                 unsigned char ismine,
                 int isgroup,
                 uint16_t dns_type,
                 uint16_t dns_class);
void
  destroy_namecard(struct cache_namenode *namecard);

struct ipv4_addr_list *
  merge_addrlists_cnsm(struct ipv4_addr_list *master,
                       struct ipv4_addr_list *mergee);

struct addrlst_bigblock *
  sort_nbaddrs(struct nbaddress_list *nbaddr_list,
               struct addrlst_bigblock **writeem_here);
void
  destroy_bigblock(struct addrlst_bigblock *block);

#endif /* NBWORKS_NAMESRVCCACHE_H*/
