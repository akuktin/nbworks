#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 199309
#endif
#include <time.h>

#include <pthread.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "randomness.h"
#include "service_sector.h"
#include "name_srvc_cache.h"


struct cache_scopenode *nbworks_rootscope;

struct {
  unsigned int all_stop;
} nbworks_cache_control;


void init_name_srvc_cache() {
  nbworks_rootscope.scope = 0;
  nbworks_rootscope.names = 0;
  nbworks_rootscope.next = 0;

  nbworks_cache_control.all_stop = 0;
}


struct cache_scopenode *add_scope(struct nbnodename_list *scope,
				  struct cache_namenode *first_node) {
  struct cache_scopenode *result, *new_scope,
    *cur_scope, **last_scope;

  result = malloc(sizeof(struct cache_scopenode));
  if (! result) {
    /* TODO: errno signaling */
    return 0;
  }

  result->scope = clone_nbnodename(scope);
  result->names = first_node;
  result->next = 0;
  new_scope = result;

  while (10) {
    last_scope = &(nbworks_rootscope);
    cur_scope = nbworks_rootscope;

    while (cur_scope) {
      if (0 == cmp_nbnodename(scope, cur_scope->scope)) {
	result = cur_scope;
	if (result != new_scope) {
	  destroy_nbnodename(new_scope->scope);
	  free(new_scope);
	}
	return result;
      }

      last_scope = &(cur_scope->next);
      cur_scope = cur_scope->next;
    }

    *last_scope = new_scope;
  }
}

struct cache_scopenode *find_scope(struct nbnodename_list *scope) {
  struct cache_scopenode *result;

  result = nbworks_rootscope;

  while (result) {
    if (0 == cmp_nbnodename(scope, result->scope))
      return result;
    else
      result = result->next;
  }

  return result;
}


void *prune_scopes(void *placeholder) {
  struct timespec waittime;
  struct cache_scopenode *cur_scope, **last_scope, for_del2;
  struct cache_namenode *cur_name, **last_name, *for_del;
  struct ipv4_addr_list *cur_addr, *addr_fordel;
  time_t curtime;

  waittime.waittime.tv_sec = 1;
  waittime.tv_nsec = 0;

  while (0xbeefcafe) {
    if (nbworks_cache_control.all_stop)
      break;

    curtime = time();

    cur_scope = nbworks_rootscope;
    last_scope = &(nbworks_rootscope);

    while (cur_scope) {
      cur_name = cur_scope->names;
      last_name = &(cur_scope->names);

      while (cur_name) {
	if (cur_name->timeof_death < curtime) {
	  *last_name = cur_name->next;
	  for_del = cur_name;
	  cur_name = cur_name->next;
	  cur_addr = for_del->addrlist;
	  while (cur_addr) {
	    addr_fordel = cur_addr->next;
	    free(cur_addr);
	    cur_addr = addr_fordel;
	  }
	  free(for_del->name);
	  free(for_del);
	} else
	  cur_name = cur_name->next;
      }

      if (! cur_scope->names) {
	*last_scope = cur_scope->next;
	destroy_nbnodename(cur_scope->scope);
	for_del2 = cur_scope
	cur_scope = cur_scope->next;
	free(for_del2);
      } else
	cur_scope = cur_scope->next;
    }

    nanosleep(&waittime, 0);
  }

  return 0;
}


/* returns: >0=succes, 0=fail (name exists), <0=error */
struct cache_namenode *add_name(struct cache_namenode *name,
				struct nbnodename_list *scope) {
  struct cache_scopenode *my_scope;
  struct cache_namenode *cur_name, **last_name;

  if (! name)
    return 0;

  my_scope = find_scope(scope);

  if (! my_scope)
    /* TODO: errno signaling stuff */
    return 0;

  while (0xbeef) {
    cur_name = my_scope->names;
    last_name = &(my_scope->names);

    while (cur_name) {
      if ((cur_name->namelen == name->namelen) &&
	  (0 == memcmp(cur_name->name, name->name,
		       name->namelen)) &&
	  (cur_name->isgroup == name->isgroup) &&
	  (cur_name->node_type == name->node_type) &&
	  (cur_name->dns_type == name->dns_type) &&
	  (cur_name->dns_class == name->dns_class)) {
	if (cur_name != name) {
	  /* Duplicate. */
	  return 0;
	} else {
	  /* Newly added one. */
	  return name;
	}
      } else {
	last_name = &(cur_name->next);
	cur_name = cur_name->next;
      }
    }

    *last_name = name;
  }
}

struct cache_namenode *add_nblabel(void *label,
				   unsigned char labellen,
				   unsigned char node_type,
				   int isgroup,
				   uint16_t dns_type,
				   uint16_t dns_class,
				   uint32_t ip_addr,
				   struct nbnodename_list *scope) {
  struct cache_namenode *result;

  if (! label)
    return 0;

  result = malloc(sizeof(struct cache_namenode));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->name = calloc(1, labellen +1);
  if (! result->name) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }

  result->addrlist = malloc(sizeof(struct ipv4_addr_list));
  if (! result->addrlist) {
    /* TODO: errno signaling stuff */
    free(result->name);
    free(result);
    return 0;
  }

  memcpy(result->name, label, labellen);

  result->addrlist->ip_addr = ip_addr;
  result->addrlist->next = 0;

  result->namelen = labellen;
  result->node_type = node_type;
  result->isgroup = isgroup;
  result->dns_type = dns_type;
  result->dns_class = dns_class;
  result->timeof_death = ZEROONES; /* AKA infinity. */
  result->endof_conflict_chance = 0;
  result->next = 0;

  /* The below code GUARANTEES insertion
     (unless a use-after-free or similar happens). */

  add_scope(scope, result);

  if (add_name(result, scope)) {
    /* Success! */
    return result;
  } else {
    /* Failure. There is a duplicate. */
    /* TODO: errno signaling stuff */
    free(result->addrlist);
    free(result->name);
    free(result);
    return 0;
  }
}

struct cache_namenode *update_name(struct cache_namenode *name,
				   struct nbnodename_list *scope) {
  struct cache_scopenode *my_scope;
  struct cache_namenode *cur_name, **last_name;
  struct ipv4_addr_list *addrlist, *nextaddrlist;

  if (! name)
    return 0;

  my_scope = find_scope(scope);

  if (! my_scope)
    /* TODO: errno signaling stuff */
    return 0;

  cur_name = my_scope->names;
  last_name = &(my_scope->names);

  while (cur_name) {
    if ((cur_name->namelen == name->namelen) &&
	(0 == memcmp(cur_name->name, name->name,
		     name->namelen)) &&
	(cur_name->isgroup == name->isgroup) &&
	(cur_name->node_type == name->node_type) &&
	(cur_name->dns_type == name->dns_type) &&
	(cur_name->dns_class == name->dns_class)) {

      name->next = cur_name->next;
      *last_name = name;

      addrlist = cur_name->addrlist;
      while (addrlist) {
	nextaddrlist = addrlist->next;
	free(addrlist);
	addrlist = nextaddrlist;
      }
      free(cur_name->name);
      free(cur_name);
      break;

    } else {
      last_name = &(cur_name->next);
      cur_name = cur_name->next;
    }
  }

  return cur_name;
}


struct cache_namenode *find_name(struct cache_namenode *namecard,
				 struct nbnodename_list *scope) {
  struct cache_scopenode *my_scope;
  struct cache_namenode *cur_name;

  if (! namecard)
    return 0;

  my_scope = find_scope(scope);

  if (! my_scope)
    /* TODO: errno signaling stuff */
    return 0;

  cur_name = my_scope->names;

  while (cur_name) {
    if ((cur_name->namelen == namecard->namelen) &&
	(0 == memcmp(cur_name->name, namecard->name,
		     namecard->namelen)) &&
	(cur_name->isgroup == namecard->isgroup) &&
	(cur_name->node_type == namecard->node_type) &&
	(cur_name->dns_type == namecard->dns_type) &&
	(cur_name->dns_class == namecard->dns_class)) {
      return cur_name;
    } else {
      cur_name = cur_name->next;
    }
  }

  return 0;
}

struct cache_namenode *find_nblabel(void *label,
				    unsigned char labellen,
				    unsigned char node_type,
				    int isgroup,
				    uint16_t dns_type,
				    uint16_t dns_class,
				    struct nbnodename_list *scope) {
  struct cache_scopenode *my_scope;
  struct cache_namenode *cur_name, *my_name;

  if (! label)
    return 0;



  my_scope = find_scope(scope);

  if (! my_scope)
    /* TODO: errno signaling stuff */
    return 0;

  cur_name = my_scope->names;

  while (cur_name) {
    if ((cur_name->namelen == labellen) &&
	(0 == memcmp(cur_name->name, label,
		     labellen)) &&
	(cur_name->isgroup == isgroup) &&
	(cur_name->node_type == node_type) &&
	(cur_name->dns_type == dns_type) &&
	(cur_name->dns_class == dns_class)) {
      return cur_name;
    } else {
      cur_name = cur_name->next;
    }
  }

  return 0;
}
