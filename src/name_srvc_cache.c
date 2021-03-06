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

#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <pthread.h>

#include "constdef.h"
#include "daemon_control.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "randomness.h"
#include "service_sector.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_func.h"


void init_name_srvc_cache(void) {
  nbworks_rootscope = 0;
}


unsigned int does_token_match(struct group_tokenlst *list,
			      token_t token) {
  while (list) {
    if (list->token == token)
      return TRUE;
    else
      list = list->next;
  }

  return FALSE;
}

struct group_tokenlst *add_token(struct group_tokenlst **anchor,
				 token_t token) {
  struct group_tokenlst *grptkn, **lasttkn, *result;

  if (! (anchor && token))
    return 0;

  result = malloc(sizeof(struct group_tokenlst));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  result->token = token;
  result->signal_pid = 0;
  result->signal = SIGCHLD; /* This signal is ignored by default. */
  result->next = 0;

  while (5050) {
    lasttkn = anchor;
    grptkn = *lasttkn;

    while (grptkn) {
      if (grptkn == result)
	return result;

      lasttkn = &(grptkn->next);
      grptkn = *lasttkn;
    }

    *lasttkn = result;
  }
}

void del_token(struct group_tokenlst **anchor,
	       token_t token) {
  struct group_tokenlst *grptkn, **lasttkn;

  if (! anchor)
    return;

  lasttkn = anchor;
  grptkn = *lasttkn;

  while (grptkn) {
    if (grptkn->token == token) {
      *lasttkn = grptkn->next;
      free(grptkn);
    } else {
      lasttkn = &(grptkn->next);
    }

    grptkn = *lasttkn;
  }

  return;
}

void destroy_tokens(struct group_tokenlst *tokens) {
  struct group_tokenlst *next;

  while (tokens) {
    next = tokens->next;
    free(tokens);
    tokens = next;
  }

  return;
}


struct cache_scopenode *add_scope(struct nbworks_nbnamelst *scope,
				  struct cache_namenode *first_node,
				  ipv4_addr_t nbns_addr) {
  struct cache_scopenode *result, *new_scope,
    *cur_scope, **last_scope;

  result = malloc(sizeof(struct cache_scopenode));
  if (! result) {
    /* TODO: errno signaling */
    return 0;
  }

  result->scope = nbworks_clone_nbnodename(scope);
  result->names = first_node;
  result->nbns_addr = nbns_addr;
  result->next = 0;
  new_scope = result;

  while (10) {
    last_scope = &(nbworks_rootscope);
    cur_scope = nbworks_rootscope;

    while (cur_scope) {
      if (0 == nbworks_cmp_nbnodename(scope, cur_scope->scope)) {
	result = cur_scope;
	if (result != new_scope) {
	  nbworks_dstr_nbnodename(new_scope->scope);
	  free(new_scope);
	  return 0;
	} else
	  return result;
      }

      last_scope = &(cur_scope->next);
      cur_scope = cur_scope->next;
    }

    *last_scope = new_scope;
  }
}

struct cache_scopenode *find_scope(struct nbworks_nbnamelst *scope) {
  struct cache_scopenode *result;

  result = nbworks_rootscope;

  while (result) {
    if (0 == nbworks_cmp_nbnodename(scope, result->scope))
      return result;
    else
      result = result->next;
  }

  return result;
}


ipv4_addr_t get_nbnsaddr(struct nbworks_nbnamelst *scope) {
  struct cache_scopenode *cur_scope;

  cur_scope = nbworks_rootscope;

  while (cur_scope) {
    if (0 == nbworks_cmp_nbnodename(cur_scope->scope, scope))
      return cur_scope->nbns_addr;
    else
      cur_scope = cur_scope->next;
  }

  return nbworks__default_nbns;
}

void prune_scopes(time_t when) {
  struct cache_scopenode *cur_scope, **last_scope;
  struct cache_namenode *cur_name, **last_name;

  cur_scope = nbworks_rootscope;
  last_scope = &(nbworks_rootscope);

  while (cur_scope) {
    cur_name = cur_scope->names;
    last_name = &(cur_scope->names);

    while (cur_name) {
      if (cur_name->timeof_death < when) {
	*last_name = cur_name->next;
	destroy_namecard(cur_name);
      } else {
	last_name = &(cur_name->next);
      }

      cur_name = *last_name;
    }

    if (! cur_scope->names) {
      *last_scope = cur_scope->next;
      nbworks_dstr_nbnodename(cur_scope->scope);
      free(cur_scope);
    } else {
      last_scope = &(cur_scope->next);
    }

    cur_scope = *last_scope;
  }

  return;
}

void update_myip4(ipv4_addr_t old_addr,
                  ipv4_addr_t new_addr) {
  struct cache_scopenode *cur_scope;
  struct cache_namenode *cur_name;
  struct ipv4_addr_list *op_head;
  long i;

  cur_scope = nbworks_rootscope;

  while (cur_scope) {
    cur_name = cur_scope->names;

    while (cur_name) {
      for (i=0; i<NUMOF_ADDRSES; i++) {
	op_head = cur_name->addrs.recrd[i].addr;
	while (op_head) {
	  if (op_head->ip_addr == old_addr)
	    op_head->ip_addr = new_addr;

	  op_head = op_head->next;
	}
      }

      cur_name = cur_name->next;
    }

    cur_scope = cur_scope->next;
  }

  return;
}


/* MAYBE: make it discriminate between group and unique names. */
/* returns: >0=succes, 0=fail (name exists), <0=error */
struct cache_namenode *add_name(struct cache_namenode *name,
				struct nbworks_nbnamelst *scope) {
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
				   node_type_t node_types,
				   token_t token,
				   uint16_t dns_type,
				   uint16_t dns_class,
				   struct addrlst_cardblock *addrblock,
				   struct nbworks_nbnamelst *scope) {
  struct cache_namenode *result;

  if (! label)
    return 0;

  result = nbw_calloc(1, sizeof(struct cache_namenode));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->name = malloc(labellen +1);
  if (! result->name) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }

  memcpy(result->name, label, labellen);
  result->name[labellen] = 0;

  memcpy(&(result->addrs), addrblock, sizeof(struct addrlst_cardblock));

  result->namelen = labellen;
  result->node_types = node_types;
  result->unq_isinconflict = FALSE;
  result->grp_isinconflict = FALSE;
  if (node_types & CACHE_ADDRBLCK_UNIQ_MASK) {
    result->unq_token = token;
    result->unq_signal_pid = 0;
    result->unq_signal_sig = SIGCHLD; /* This signal is ignored by default. */
  } else {
    result->unq_token = 0;
  }
  if ((node_types & CACHE_ADDRBLCK_GRP_MASK) &&
      token) {
    if (! add_token(&(result->grp_tokens), token)) {
      /* TODO: errno signaling stuff */
      free(result);
      return 0;
    }
  } else {
    result->grp_tokens = 0;
  }
  result->dns_type = dns_type;
  result->dns_class = dns_class;
  result->timeof_death = INFINITY;
  result->endof_conflict_chance = 0;
  result->refresh_ttl = 0;
  result->next = 0;

  /* The below code GUARANTEES insertion
     (unless a use-after-free or similar happens). */

  if (add_scope(scope, result, nbworks__default_nbns) ||
      add_name(result, scope)) {
    /* Success! */
    return result;
  } else {
    /* Failure. There is a duplicate. */
    /* TODO: errno signaling stuff */
    destroy_namecard(result);
    return 0;
  }
}


struct cache_namenode *find_name(struct cache_namenode *namecard,
				 struct nbworks_nbnamelst *scope) {
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
				    node_type_t node_types,
				    uint16_t dns_type,
				    uint16_t dns_class,
				    struct nbworks_nbnamelst *scope) {
  struct cache_scopenode *my_scope;
  struct cache_namenode *cur_name;

  if (! label)
    return 0;

  my_scope = find_scope(scope);

  if (! my_scope)
    return 0;

  cur_name = my_scope->names;

  while (cur_name) {
    if ((cur_name->namelen == labellen) &&
	(0 == memcmp(cur_name->name, label,
		     labellen)) &&
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

struct cache_namenode *find_namebytok(token_t token,
				      struct nbworks_nbnamelst **ret_scope) {
  struct cache_scopenode *scope;
  struct cache_namenode *result;

  if (! token)
    return 0;

  scope = nbworks_rootscope;

  while (scope) {
    result = scope->names;
    while (result)
      if ((result->unq_token == token) ||
	  does_token_match(result->grp_tokens, token)) {
	if (ret_scope)
	  *ret_scope = nbworks_clone_nbnodename(scope->scope);
	return result;
      } else
	result = result->next;
    scope = scope->next;
  }

  return 0;
}

struct cache_namenode *find_nextcard(struct cache_namenode *prevcard,
				     unsigned short node_types,
				     uint16_t dns_type,
				     uint16_t dns_class) {
  struct cache_namenode *cur_name;
  unsigned char labellen;

  if (! prevcard)
    return 0;

  labellen = prevcard->namelen;
  cur_name = prevcard->next;

  while (cur_name) {
    if ((cur_name->namelen == labellen) &&
	(0 == memcmp(cur_name->name, prevcard->name,
		     labellen)) &&
	(cur_name->node_types & node_types) &&
	(cur_name->dns_type == dns_type) &&
	(cur_name->dns_class == dns_class)) {
      break;
    } else {
      cur_name = cur_name->next;
    }
  }

  return cur_name;
}


struct cache_namenode *alloc_namecard(void *label,
				      unsigned char labellen,
				      node_type_t node_types,
				      token_t token,
				      uint16_t dns_type,
				      uint16_t dns_class) {
  struct cache_namenode *result;

  if (! label)
    return 0;

  result = nbw_calloc(1, sizeof(struct cache_namenode));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->name = malloc(labellen +1);
  if (! result->name) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }

  memcpy(result->name, label, labellen);
  result->name[labellen] = 0;
  result->namelen = labellen;
  result->node_types = node_types;
  result->unq_isinconflict = FALSE;
  result->unq_signal_pid = 0;
  result->unq_signal_sig = SIGCHLD; /* This signal is ignored by default. */
  result->grp_isinconflict = FALSE;
  if (node_types & CACHE_ADDRBLCK_UNIQ_MASK) {
    result->unq_token = token;
  } else {
    result->unq_token = 0;
  }
  if ((node_types & CACHE_ADDRBLCK_GRP_MASK) &&
      token) {
    if (! add_token(&(result->grp_tokens), token)) {
      /* TODO: errno signaling stuff */
      free(result);
      return 0;
    }
  } else {
    result->grp_tokens = 0;
  }
  result->dns_type = dns_type;
  result->dns_class = dns_class;
  result->timeof_death = INFINITY;
  result->endof_conflict_chance = 0;
  result->refresh_ttl = 0;
  result->next = 0;

  return result;
}

void destroy_namecard(struct cache_namenode *namecard) {
  struct ipv4_addr_list *addrlist, *nextaddrlist;
  int i;

  if (! namecard)
    return;

  free(namecard->name);
  destroy_tokens(namecard->grp_tokens);
  for (i=0; i<NUMOF_ADDRSES; i++) {
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


/* returns: >0 = success, 0 = fail, <0 = error */
int name_srvc_enter_conflict(unsigned char group_flg,
			     struct cache_namenode *namecard,
			     unsigned char *name_ptr, /* len == NETBIOS_NAME_LEN */
			     struct nbworks_nbnamelst *scope) {
  struct group_tokenlst *cur_token;

  if (! namecard)
    return -1;

  switch (group_flg) {
  case ISGROUP_NO:
    namecard->unq_isinconflict = TRUE;
    break;

  case ISGROUP_YES:
    namecard->grp_isinconflict = TRUE;
    break;

  default:
    return -1;
  }

  if (namecard->unq_signal_pid) {
    kill(namecard->unq_signal_pid, namecard->unq_signal_sig);
  }
  cur_token = namecard->grp_tokens;
  while (cur_token) {
    if (cur_token->signal_pid) {
      kill(cur_token->signal_pid, cur_token->signal);
    }
    cur_token = cur_token->next;
  }

  ss__kill_allservrs(name_ptr, scope);

  return 1;
}


struct ipv4_addr_list *merge_addrlists(struct ipv4_addr_list *master,
				       struct ipv4_addr_list *mergee) {
  /*
   * Really, it was inevitable that
   * I would eventually step onto the
   * ONE landmine of linked lists.
   */
  struct ipv4_addr_list *iterator, **ptr;

  while (mergee) {
    iterator = master;
    ptr = &master;
    while (iterator) {
      if (iterator->ip_addr == mergee->ip_addr)
	break;
      else {
	ptr = &(iterator->next);
	iterator = iterator->next;
      }
    }

    if (! iterator) {
      *ptr = malloc(sizeof(struct ipv4_addr_list));
      /* no test */
      (*ptr)->ip_addr = mergee->ip_addr;
      (*ptr)->next = 0;
    }

    mergee = mergee->next;
  }

  return master;
}

void destroy_addrlist(struct ipv4_addr_list *list) {
  struct ipv4_addr_list *next;

  while (list) {
    next = list->next;
    free(list);
    list = next;
  }

  return;
}


struct addrlst_bigblock *sort_nbaddrs(struct nbaddress_list *nbaddr_list,
				      struct addrlst_bigblock **writeem_here) {
  /*
   * Objectivelly, the reason for the existance of this ABORTION of a function
   * is the fact that I have made a switch statement the master worker. A switch
   * statemet moves the complexity away from the data and into text. And that is
   * the reason this function exists. And sucks.
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

  memset(result, 0, sizeof(struct addrlst_bigblock));

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


  if (ipv4_addr_list_grpB_frst) {
    result->node_types |= CACHE_NODEGRPFLG_B;
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (! result->addrs.recrd[i].node_type) {
	result->addrs.recrd[i].node_type = CACHE_NODEGRPFLG_B;
	result->addrs.recrd[i].addr = ipv4_addr_list_grpB_frst;
	break;
      }
    }
  }
  if (ipv4_addr_list_grpP_frst) {
    result->node_types |= CACHE_NODEGRPFLG_P;
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (! result->addrs.recrd[i].node_type) {
	result->addrs.recrd[i].node_type = CACHE_NODEGRPFLG_P;
	result->addrs.recrd[i].addr = ipv4_addr_list_grpP_frst;
	break;
      }
    }
  }
  if (ipv4_addr_list_grpM_frst) {
    result->node_types |= CACHE_NODEGRPFLG_M;
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (! result->addrs.recrd[i].node_type) {
	result->addrs.recrd[i].node_type = CACHE_NODEGRPFLG_M;
	result->addrs.recrd[i].addr = ipv4_addr_list_grpM_frst;
	break;
      }
    }
  }
  if (ipv4_addr_list_grpH_frst) {
    result->node_types |= CACHE_NODEGRPFLG_H;
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (! result->addrs.recrd[i].node_type) {
	result->addrs.recrd[i].node_type = CACHE_NODEGRPFLG_H;
	result->addrs.recrd[i].addr = ipv4_addr_list_grpH_frst;
	break;
      }
    }
  }

  if (ipv4_addr_listB_frst) {
    result->node_types |= CACHE_NODEFLG_B;
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (! result->addrs.recrd[i].node_type) {
	result->addrs.recrd[i].node_type = CACHE_NODEFLG_B;
	result->addrs.recrd[i].addr = ipv4_addr_listB_frst;
	break;
      }
    }
  }
  if (ipv4_addr_listP_frst) {
    result->node_types |= CACHE_NODEFLG_P;
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (! result->addrs.recrd[i].node_type) {
	result->addrs.recrd[i].node_type = CACHE_NODEFLG_P;
	result->addrs.recrd[i].addr = ipv4_addr_listP_frst;
	break;
      }
    }
  }
  if (ipv4_addr_listM_frst) {
    result->node_types |= CACHE_NODEFLG_M;
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (! result->addrs.recrd[i].node_type) {
	result->addrs.recrd[i].node_type = CACHE_NODEFLG_M;
	result->addrs.recrd[i].addr = ipv4_addr_listM_frst;
	break;
      }
    }
  }
  if (ipv4_addr_listH_frst) {
    result->node_types |= CACHE_NODEFLG_H;
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (! result->addrs.recrd[i].node_type) {
	result->addrs.recrd[i].node_type = CACHE_NODEFLG_H;
	result->addrs.recrd[i].addr = ipv4_addr_listH_frst;
	break;
      }
    }
  }

  return result;
}

void destroy_bigblock(struct addrlst_bigblock *block) {
  struct ipv4_addr_list *deltree, *rm_rf;
  int i;

  if (! block)
    return;

  for (i=0; i<NUMOF_ADDRSES; i++) {
    deltree = block->addrs.recrd[i].addr;
    while (deltree) {
      rm_rf = deltree->next;
      free(deltree);
      deltree = rm_rf;
    }
  }
  free(block);

  return;
}

void cleanout_bigblock(struct addrlst_bigblock *block) {
  int i;

  if (! block)
    return;

  for (i = 0; i<NUMOF_ADDRSES; i++) {
    if (block->addrs.recrd[i].addr)
      destroy_addrlist(block->addrs.recrd[i].addr);
    block->addrs.recrd[i].addr = 0;
  }
}


#define REMOVED_OWN_PMODE    1
#define THEREIS_OWN_NONPMODE 2
/* returns: >0 = removed own address, 0 = didn't, <0 = error */
int remove_membrs_frmlst(struct nbaddress_list *nbaddr_list,
			 struct cache_namenode *namecard,
			 ipv4_addr_t my_ipv4_address,
			 unsigned int sender_is_nbns) {
  struct addrlst_bigblock addrblock, *addrof_addrblock;
  struct ipv4_addr_list *cur_addr, **last_addr,
    *card_addr, **last_card_addr;
  int i, j;
  unsigned char do_force, ret_val;

  if (! (nbaddr_list && namecard))
    return -1;

  ret_val = 0;
  addrof_addrblock = &addrblock;
  if (! sort_nbaddrs(nbaddr_list, &addrof_addrblock)) {
    return -1;
  }

  for (i=0; i<NUMOF_ADDRSES; i++) {
    for (j=0; j<NUMOF_ADDRSES; j++) {
      if (addrblock.addrs.recrd[i].node_type ==
          namecard->addrs.recrd[j].node_type) {
	if ((namecard->addrs.recrd[j].node_type &
	     (CACHE_NODEFLG_P | CACHE_NODEFLG_M | CACHE_NODEFLG_H |
	      CACHE_NODEGRPFLG_P | CACHE_NODEGRPFLG_M | CACHE_NODEGRPFLG_H)) &&
	    sender_is_nbns)
	  do_force = TRUE;
        else
	  do_force = FALSE;

        break;
      }
    }

    if (j>=NUMOF_ADDRSES)
      continue;

    last_addr = &(addrblock.addrs.recrd[i].addr);
    cur_addr = *last_addr;

    while (cur_addr) {
      /* First, detect if sender of the list wants us to delete our own IP
       * from the list. If yes, see if the removal should be forced. If it
       * should, set the signal bit and enter the other branch, thus
       * removing our IP and having an opportunity to signal upstream we
       * did so. If removal should not be forced, set a different signal bit
       * meaning that there is at least one surviving IP address to the name.
       * Enter this branch.
       * If it turns out the sender does not want us to delete our own address,
       * just enter the other branch. */
      if (((cur_addr->ip_addr == my_ipv4_address) ?
	   (do_force ? ((ret_val |= REMOVED_OWN_PMODE), FALSE) :
	               ((ret_val |= THEREIS_OWN_NONPMODE), TRUE)) :
	   FALSE)) {
	*last_addr = cur_addr->next;
      } else {
	last_addr = &(cur_addr->next);

	last_card_addr = &(namecard->addrs.recrd[j].addr);
	card_addr = *last_card_addr;

	while (card_addr) {
	  if (card_addr->ip_addr == cur_addr->ip_addr) {
	    *last_card_addr = card_addr->next;
	    free(card_addr);
	  } else {
	    last_card_addr = &(card_addr->next);
	  }

	  card_addr = *last_card_addr;
	}

	if (! namecard->addrs.recrd[j].addr) {
	  namecard->node_types = namecard->node_types &
	    (~(addrblock.addrs.recrd[i].node_type));
	  namecard->addrs.recrd[j].node_type = 0;

	  while (*last_addr) {
	    free(cur_addr);
	    cur_addr = *last_addr;
	    last_addr = &(cur_addr->next);
	  }
	  free(cur_addr);
	  break;
	}
      }

      free(cur_addr);
      cur_addr = *last_addr;
    }

    addrblock.addrs.recrd[i].addr = 0;
  }

  cleanout_bigblock(addrof_addrblock);

  if (ret_val & THEREIS_OWN_NONPMODE)
    return 0;
  else {
    if (ret_val & REMOVED_OWN_PMODE)
      return 1;
    else
      return 0;
  }
}
#undef REMOVED_OWN_PMODE
#undef THEREIS_OWN_NONPMODE
