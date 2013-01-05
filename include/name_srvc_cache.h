#ifndef NBWORKS_NAMESRVCCACHE_H
# define NBWORKS_NAMESRVCCACHE_H 1

# include <time.h>

# include "nodename.h"

# define ANY_GROUP ONES
# define ANY_NODETYPE ONES

struct ipv4_addr_list {
  uint32_t ip_addr;
  struct ipv4_addr_list *next;
};

struct cache_scopenode {
  struct nbnodename_list *scope;
  struct cache_namenode *names;
  struct cache_scopenode *next;
};

struct cache_namenode {
  void *name;
  unsigned char namelen;
  unsigned char node_type;
  unsigned char isinconflict;
  int isgroup;
  uint16_t dns_type;
  uint16_t dns_class;
  time_t timeof_death;
  time_t endof_conflict_chance;
  struct ipv4_addr_list *addrlist;
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
              unsigned char node_type,
              int isgroup,
              uint16_t dns_type,
              uint16_t dns_class,
              uint32_t ip_addr,
              struct nbnodename_list *scope);
struct cache_namenode *
  exchange_namecards(struct cache_namenode *name,
                     struct nbnodename_list *scope);

struct cache_namenode *
  find_name(struct cache_namenode *namecard,
            struct nbnodename_list *scope);
struct cache_namenode *
  find_nblabel(void *label,
               unsigned char labellen,
               unsigned char node_type,
               int isgroup,
               uint16_t dns_type,
               uint16_t dns_class,
               struct nbnodename_list *scope);

struct cache_namenode *
  alloc_namecard(void *label,
                 unsigned char labellen,
                 unsigned char node_type,
                 int isgroup,
                 uint16_t dns_type,
                 uint16_t dns_class);
void
  destroy_namecard(struct cache_namenode *namecard);

#endif /* NBWORKS_NAMESRVCCACHE_H*/
