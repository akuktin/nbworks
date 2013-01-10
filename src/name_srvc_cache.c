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
  nbworks_rootscope = 0;

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
  struct cache_scopenode *cur_scope, **last_scope, *for_del2;
  struct cache_namenode *cur_name, **last_name, *for_del;
  struct ipv4_addr_list *cur_addr, *addr_fordel;
  int i;
  time_t curtime;

  waittime.tv_sec = 1;
  waittime.tv_nsec = 0;

  while (0xbeefcafe) {
    if (nbworks_cache_control.all_stop)
      break;

    curtime = time(0);

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
	  for (i=0; i<4; i++) {
	    cur_addr = for_del->addrs.recrd[i].addr;
	    while (cur_addr) {
	      addr_fordel = cur_addr->next;
	      free(cur_addr);
	      cur_addr = addr_fordel;
	    }
	  }
	  free(for_del->name);
	  free(for_del);
	} else
	  cur_name = cur_name->next;
      }

      if (! cur_scope->names) {
	*last_scope = cur_scope->next;
	destroy_nbnodename(cur_scope->scope);
	for_del2 = cur_scope;
	cur_scope = cur_scope->next;
	free(for_del2);
      } else
	cur_scope = cur_scope->next;
    }

    nanosleep(&waittime, 0);
  }

  return nbworks_rootscope;
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
	  (cur_name->isgroup & name->isgroup) &&
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
				   unsigned short node_types,
				   unsigned char ismine,
				   int isgroup,
				   uint16_t dns_type,
				   uint16_t dns_class,
				   uint32_t ip_addr,
				   struct nbnodename_list *scope) {
  struct cache_namenode *result;
  int i;

  if (! label)
    return 0;

  result = calloc(1, sizeof(struct cache_namenode));
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

  result->addrs.recrd[0].addr = malloc(sizeof(struct ipv4_addr_list));
  if (! result->addrs.recrd[0].addr) {
    /* TODO: errno signaling stuff */
    free(result->name);
    free(result);
    return 0;
  }

  memcpy(result->name, label, labellen);

  result->addrs.recrd[0].node_type = node_types;
  result->addrs.recrd[0].addr->ip_addr = ip_addr;
  result->addrs.recrd[0].addr->next = 0;

  result->namelen = labellen;
  result->node_types = node_types;
  result->isinconflict = FALSE;
  result->ismine = ismine;
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
    for (i=0; i<4; i++) {
      free(result->addrs.recrd[i].addr);
    }
    free(result->name);
    free(result);
    return 0;
  }
}

struct cache_namenode *replace_namecard(struct cache_namenode *name,
					struct nbnodename_list *scope) {
  struct cache_scopenode *my_scope;
  struct cache_namenode *cur_name, **last_name;
  struct ipv4_addr_list *addrlist, *nextaddrlist;
  int i;

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
	(cur_name->isgroup & name->isgroup) &&
	(cur_name->dns_type == name->dns_type) &&
	(cur_name->dns_class == name->dns_class)) {

      name->next = cur_name->next;
      *last_name = name;

      for (i=0; i<4; i++) {
	addrlist = cur_name->addrs.recrd[i].addr;
	while (addrlist) {
	  nextaddrlist = addrlist->next;
	  free(addrlist);
	  addrlist = nextaddrlist;
	}
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
	(cur_name->isgroup & namecard->isgroup) &&
	(cur_name->node_types & namecard->node_types) &&
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
				    unsigned short node_types,
				    int isgroup,
				    uint16_t dns_type,
				    uint16_t dns_class,
				    struct nbnodename_list *scope) {
  struct cache_scopenode *my_scope;
  struct cache_namenode *cur_name;

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
	(cur_name->isgroup & isgroup) &&
	(cur_name->node_types & node_types) &&
	(cur_name->dns_type == dns_type) &&
	(cur_name->dns_class == dns_class)) {
      return cur_name;
    } else {
      cur_name = cur_name->next;
    }
  }

  return 0;
}


struct cache_namenode *alloc_namecard(void *label,
				      unsigned char labellen,
				      unsigned short node_types,
				      unsigned char ismine,
				      int isgroup,
				      uint16_t dns_type,
				      uint16_t dns_class) {
  struct cache_namenode *result;

  if (! label)
    return 0;

  result = calloc(1, sizeof(struct cache_namenode));
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

  memcpy(result->name, label, labellen);
  result->namelen = labellen;
  result->node_types = node_types;
  result->isinconflict = FALSE;
  result->ismine = ismine;
  result->isgroup = isgroup;
  result->dns_type = dns_type;
  result->dns_class = dns_class;
  result->timeof_death = ZEROONES; /* AKA infinity. */
  result->endof_conflict_chance = 0;
  result->next = 0;

  return result;
}

void destroy_namecard(struct cache_namenode *namecard) {
  struct ipv4_addr_list *addrlist, *nextaddrlist;
  int i;

  if (! namecard)
    return;

  free(namecard->name);
  for (i=0; i<4; i++) {
    addrlist = namecard->addrs.recrd[i].addr;
    while (addrlist) {
      nextaddrlist = addrlist->next;
      free(addrlist);
      addrlist = nextaddrlist;
    }
  }
  free(namecard);

  return;
}


struct addrlst_bigblock *sort_nbaddrs(struct nbaddress_list *nbaddr_list,
				      struct addrlst_bigblock **writeem_here) {
  /*
   * Objectivelly, the reason for the existance of this ABORTION of a function
   * is the fact that I have made a switch statement the master worker. A switch
   * statemet moves the complexity away from the data and into text. And that is
   * the reason this function exists.
   *
   * TODO: NOTETOSELF: Think of a better way of doing this.
   *
   *              -> templates would be nice
   *              -> maybe a macro or two??
   *
   */

  struct addrlst_bigblock *result;
  int i;

  /* "Has the nature of Ctulhu." */
  struct ipv4_addr_list *ipv4_addr_list_grpB_frst,
    *ipv4_addr_list_grpP_frst, *ipv4_addr_list_grpM_frst,
    *ipv4_addr_list_grpH_frst;
  struct ipv4_addr_list *ipv4_addr_listB_frst,
    *ipv4_addr_listP_frst, *ipv4_addr_listM_frst,
    *ipv4_addr_listH_frst;
  struct ipv4_addr_list *ipv4_addr_list_grpB,
    *ipv4_addr_list_grpP, *ipv4_addr_list_grpM,
    *ipv4_addr_list_grpH;
  struct ipv4_addr_list *ipv4_addr_listB,
    *ipv4_addr_listP, *ipv4_addr_listM,
    *ipv4_addr_listH;

  /* This batch of variables is the UGLIEST thing I have yet seen. */
  ipv4_addr_list_grpB_frst = ipv4_addr_list_grpP_frst =
    ipv4_addr_list_grpM_frst = ipv4_addr_list_grpH_frst = 0;
  ipv4_addr_listB_frst = ipv4_addr_listP_frst  =
    ipv4_addr_listM_frst = ipv4_addr_listH_frst = 0;
  ipv4_addr_list_grpB = ipv4_addr_list_grpP =
    ipv4_addr_list_grpM = ipv4_addr_list_grpH = 0;
  ipv4_addr_listB = ipv4_addr_listP =
    ipv4_addr_listM = ipv4_addr_listH = 0;

  if (! nbaddr_list)
    return 0;

  if (writeem_here)
    result = *writeem_here;
  else
    result = malloc(sizeof(struct addrlst_bigblock));

  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  while (nbaddr_list) {
    if (! nbaddr_list->there_is_an_address) {
      nbaddr_list = nbaddr_list->next_address;
      continue;
    }

    switch (nbaddr_list->flags & NBADDRLST_NODET_MASK) {
    case NBADDRLST_NODET_B:
      if (nbaddr_list->flags & NBADDRLST_GROUP_MASK) {
	if (ipv4_addr_list_grpB) {
	  ipv4_addr_list_grpB->next = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_list_grpB = ipv4_addr_list_grpB->next;
	} else {
	  ipv4_addr_list_grpB = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_list_grpB_frst = ipv4_addr_list_grpB;
	}
	ipv4_addr_list_grpB->ip_addr = nbaddr_list->address;
	ipv4_addr_list_grpB->next = 0;
      } else {
	if (ipv4_addr_listB) {
	  ipv4_addr_listB->next = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_listB = ipv4_addr_listB->next;
	} else {
	  ipv4_addr_listB = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_listB_frst = ipv4_addr_listB;
	}
	ipv4_addr_listB->ip_addr = nbaddr_list->address;
	ipv4_addr_listB->next = 0;
      }
      break;

    case NBADDRLST_NODET_P:
      if (nbaddr_list->flags & NBADDRLST_GROUP_MASK) {
	if (ipv4_addr_list_grpP) {
	  ipv4_addr_list_grpP->next = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_list_grpP = ipv4_addr_list_grpP->next;
	} else {
	  ipv4_addr_list_grpP = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_list_grpP_frst = ipv4_addr_list_grpP;
	}
	ipv4_addr_list_grpP->ip_addr = nbaddr_list->address;
	ipv4_addr_list_grpP->next = 0;
      } else {
	if (ipv4_addr_listP) {
	  ipv4_addr_listP->next = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_listP = ipv4_addr_listP->next;
	} else {
	  ipv4_addr_listP = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_listP_frst = ipv4_addr_listP;
	}
	ipv4_addr_listP->ip_addr = nbaddr_list->address;
	ipv4_addr_listP->next = 0;
      }
      break;

    case NBADDRLST_NODET_M:
      if (nbaddr_list->flags & NBADDRLST_GROUP_MASK) {
	if (ipv4_addr_list_grpM) {
	  ipv4_addr_list_grpM->next = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_list_grpM = ipv4_addr_list_grpM->next;
	} else {
	  ipv4_addr_list_grpM = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_list_grpM_frst = ipv4_addr_list_grpM;
	}
	ipv4_addr_list_grpM->ip_addr = nbaddr_list->address;
	ipv4_addr_list_grpM->next = 0;
      } else {
	if (ipv4_addr_listM) {
	  ipv4_addr_listM->next = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_listM = ipv4_addr_listM->next;
	} else {
	  ipv4_addr_listM = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_listM_frst = ipv4_addr_listM;
	}
	ipv4_addr_listM->ip_addr = nbaddr_list->address;
	ipv4_addr_listM->next = 0;
      }
      break;

    case NBADDRLST_NODET_H:
    default:
      if (nbaddr_list->flags & NBADDRLST_GROUP_MASK) {
	if (ipv4_addr_list_grpH) {
	  ipv4_addr_list_grpH->next = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_list_grpH = ipv4_addr_list_grpH->next;
	} else {
	  ipv4_addr_list_grpH = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_list_grpH_frst = ipv4_addr_list_grpH;
	}
	ipv4_addr_list_grpH->ip_addr = nbaddr_list->address;
	ipv4_addr_list_grpH->next = 0;
      } else {
	if (ipv4_addr_listH) {
	  ipv4_addr_listH->next = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_listH = ipv4_addr_listH->next;
	} else {
	  ipv4_addr_listH = malloc(sizeof(struct ipv4_addr_list));
	  /* no test */
	  ipv4_addr_listH_frst = ipv4_addr_listH;
	}
	ipv4_addr_listH->ip_addr = nbaddr_list->address;
	ipv4_addr_listH->next = 0;
      }
      break;
    }

    nbaddr_list = nbaddr_list->next_address;
  }


  result->node_types = 0;
  for (i=0; i<4; i++) {
    result->ysgrp.recrd[i].node_type = 0;
    result->ysgrp.recrd[i].addr = 0;
    result->nogrp.recrd[i].node_type = 0;
    result->nogrp.recrd[i].addr = 0;
  }

  if (ipv4_addr_list_grpB_frst) {
    result->node_types = result->node_types & CACHE_NODEGRPFLG_B;
    for (i=0; i<4; i++) {
      if (! result->ysgrp.recrd[i].node_type) {
	result->ysgrp.recrd[i].node_type = CACHE_NODEFLG_B; /* not a typo */
	result->ysgrp.recrd[i].addr = ipv4_addr_list_grpB_frst;
	break;
      }
    }
  }
  if (ipv4_addr_list_grpP_frst) {
    result->node_types = result->node_types & CACHE_NODEGRPFLG_P;
    for (i=0; i<4; i++) {
      if (! result->ysgrp.recrd[i].node_type) {
	result->ysgrp.recrd[i].node_type = CACHE_NODEFLG_P; /* not a typo */
	result->ysgrp.recrd[i].addr = ipv4_addr_list_grpP_frst;
	break;
      }
    }
  }
  if (ipv4_addr_list_grpM_frst) {
    result->node_types = result->node_types & CACHE_NODEGRPFLG_M;
    for (i=0; i<4; i++) {
      if (! result->ysgrp.recrd[i].node_type) {
	result->ysgrp.recrd[i].node_type = CACHE_NODEFLG_M; /* not a typo */
	result->ysgrp.recrd[i].addr = ipv4_addr_list_grpM_frst;
	break;
      }
    }
  }
  if (ipv4_addr_list_grpH_frst) {
    result->node_types = result->node_types & CACHE_NODEGRPFLG_H;
    for (i=0; i<4; i++) {
      if (! result->ysgrp.recrd[i].node_type) {
	result->ysgrp.recrd[i].node_type = CACHE_NODEFLG_H; /* not a typo */
	result->ysgrp.recrd[i].addr = ipv4_addr_list_grpH_frst;
	break;
      }
    }
  }

  if (ipv4_addr_listB_frst) {
    result->node_types = result->node_types & CACHE_NODEFLG_B;
    for (i=0; i<4; i++) {
      if (! result->nogrp.recrd[i].node_type) {
	result->nogrp.recrd[i].node_type = CACHE_NODEFLG_B;
	result->nogrp.recrd[i].addr = ipv4_addr_listB_frst;
	break;
      }
    }
  }
  if (ipv4_addr_listP_frst) {
    result->node_types = result->node_types & CACHE_NODEFLG_P;
    for (i=0; i<4; i++) {
      if (! result->nogrp.recrd[i].node_type) {
	result->nogrp.recrd[i].node_type = CACHE_NODEFLG_P;
	result->nogrp.recrd[i].addr = ipv4_addr_listP_frst;
	break;
      }
    }
  }
  if (ipv4_addr_listM_frst) {
    result->node_types = result->node_types & CACHE_NODEFLG_M;
    for (i=0; i<4; i++) {
      if (! result->nogrp.recrd[i].node_type) {
	result->nogrp.recrd[i].node_type = CACHE_NODEFLG_M;
	result->nogrp.recrd[i].addr = ipv4_addr_listM_frst;
	break;
      }
    }
  }
  if (ipv4_addr_listH_frst) {
    result->node_types = result->node_types & CACHE_NODEFLG_H;
    for (i=0; i<4; i++) {
      if (! result->nogrp.recrd[i].node_type) {
	result->nogrp.recrd[i].node_type = CACHE_NODEFLG_H;
	result->nogrp.recrd[i].addr = ipv4_addr_listH_frst;
	break;
      }
    }
  }

  return result;
}
