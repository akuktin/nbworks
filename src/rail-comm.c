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
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <signal.h>
#include <alloca.h>

#include "constdef.h"
#include "daemon_control.h"
#include "rail-comm.h"
#include "nodename.h"
#include "service_sector_threads.h"
#include "service_sector.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_func.h"
#include "name_srvc_func_B.h"
#include "dtg_srvc_pckt.h"
#include "ses_srvc_pckt.h"
#include "randomness.h"
#include "rail-flush.h"
#include "portability.h"


void init_rail(void) {
  nbworks__rail_control.all_stop = 0;
  nbworks__rail_control.poll_timeout = TP_100MS;
}


int open_rail(void) {
  struct sockaddr_un address;
  int result;
  void *ptr;

  memset(&address, 0, sizeof(struct sockaddr_un));

  address.sun_family = AF_UNIX;
  ptr = address.sun_path +1;
  memcpy(ptr, nbworks_sckt_name, NBWORKS_SCKT_NAMELEN);

  result = socket(PF_UNIX, SOCK_STREAM, 0);
  if (result == -1) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  if (0 != set_sockoption(result, NONBLOCKING)) {
    /* TODO: errno signaling stuff */
    close(result);
    return -1;
  }

  if (0 != bind(result, (struct sockaddr *)&address,
		sizeof(struct sockaddr_un))) {
    /* TODO: errno signaling stuff */
    close(result);
    return -1;
  } else {
    if (0 != listen(result, SOMAXCONN)) {
      /* TODO: errno signaling stuff */
      close(result);
      return -1;
    } else
      return result;
  }
}

void *poll_rail(void *args) {
  struct rail_params params, new_params, *release_lock;
  struct pollfd pfd;
  struct sockaddr_un address;
  struct thread_node *last_will;
  socklen_t scktlen;
  int ret_val, new_sckt;

  if (! args)
    return 0;

  memcpy(&params, args, sizeof(struct rail_params));
  release_lock = args;
  release_lock->isbusy = 0;
  new_params.isbusy = 0;

  if (params.thread_id)
    last_will = add_thread(params.thread_id);
  else
    last_will = 0;

  pfd.fd = params.rail_sckt;
  pfd.events = POLLIN;

  while (0xfeed) {
    if (nbworks__rail_control.all_stop) {
      if (last_will)
	last_will->dead = TRUE;
      return 0;
    }

    ret_val = poll(&pfd, 1, nbworks__rail_control.poll_timeout);

    if (ret_val == 0) {
      continue;
    }
    if (ret_val < 0) {
      /* TODO: error handling */
      continue;
    }

    scktlen = sizeof(struct sockaddr_un);
    new_sckt = accept(params.rail_sckt, (struct sockaddr *)&address, &scktlen);
    if (new_sckt < 0) {
      if ((errno == EAGAIN) ||
	  (errno == EWOULDBLOCK)) {
      } else {
	/* TODO: error handling */
      }
    } else {
      while (new_params.isbusy) {
	/* busy-wait */
      }
      new_params.isbusy = 0xda;
      new_params.rail_sckt = new_sckt;
      if (0 != pthread_create(&(new_params.thread_id), 0,
			      handle_rail, &new_params)) {
	new_params.isbusy = 0;
      }
    }
  }
}


void *handle_rail(void *args) {
  struct pollfd pfd;
  struct rail_params params, *release_lock;
  struct com_comm command;
  struct cache_namenode *cache_namecard;
  struct thread_node *last_will;
  token_t guard_token;
  node_type_t guard_node_type;
  ipv4_addr_t ipv4;
  unsigned int rail_isreusable;
  int ret_val;
  unsigned char buff[LEN_COMM_ONWIRE];

  if (! args)
    return 0;

  memcpy(&params, args, sizeof(struct rail_params));
  release_lock = args;
  release_lock->isbusy = 0;

  if (params.thread_id)
    last_will = add_thread(params.thread_id);
  else
    last_will = 0;

  if (params.rail_sckt < 0) {
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  pfd.fd = params.rail_sckt;
  pfd.events = POLLIN;
  rail_isreusable = TRUE;
  guard_token = 0;
  guard_node_type = 0;

  while (rail_isreusable &&
	 (! nbworks__rail_control.all_stop)) {
    ret_val = poll(&pfd, 1, nbworks__rail_control.poll_timeout);
    if (ret_val == 0) {
      continue;
    }
    if ((ret_val < 0) ||
	(pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
      break;
    }

    if (LEN_COMM_ONWIRE > recv(params.rail_sckt, buff,
			       LEN_COMM_ONWIRE, MSG_WAITALL)) {
      break;
    }

    if (! read_railcommand(buff, (buff+LEN_COMM_ONWIRE), &command)){
      break;
    }

    switch (command.command) {
    case rail_regname:
      /* Rail is flushed by do_rail_regname(). */
      cache_namecard = do_rail_regname(params.rail_sckt, &command,
				       &rail_isreusable, &(command.token));
      if (! rail_isreusable) {
	close(params.rail_sckt);
	break;
      }
      if (cache_namecard) {
	/* command.token is set by do_rail_regname() */
	command.nbworks_errno = 0;
      } else {
	command.token = 0;
	command.nbworks_errno = ADD_MEANINGFULL_ERRNO;
      }

      command.len = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				 LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	close(params.rail_sckt);
	rail_isreusable = FALSE;
      }
      break;

    case rail_delname:
      /* Rail is flushed by do_rail_delname(). */
      if (0 < do_rail_delname(params.rail_sckt, &command,
			      &rail_isreusable)) {
	if (guard_token == command.token) {
	  guard_token = 0;
	  guard_node_type = 0;
	}
	command.command = rail_delname;
	command.nbworks_errno = 0;
	command.len = 0;
      } else {
	command.command = rail_delname;
	command.nbworks_errno = ADD_MEANINGFULL_ERRNO;
	command.len = 0;
      }

      if (rail_isreusable) {
	fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
	if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				   LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	  close(params.rail_sckt);
	  rail_isreusable = FALSE;
	}
      }

      break;

    case rail_send_dtg:
      if (find_namebytok(command.token, 0)) {
	ret_val = rail_senddtg(params.rail_sckt, &command);
	/* Rail is flushed by rail_senddtg(). */
	if (ret_val == 0) {
	  command.nbworks_errno = 0;
	  command.len = 0;
	  fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
	  if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				     LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	    close(params.rail_sckt);
	    rail_isreusable = FALSE;
	  }
	} else {
	  if (ret_val < 0) {
	    close(params.rail_sckt);
	    rail_isreusable = FALSE;
	  } else {
	    command.nbworks_errno = ret_val;
	    goto failed_to_send_dtg;
	  }
	}
      } else {
	if (command.len)
	  rail_flushrail(command.len, params.rail_sckt);
	command.nbworks_errno = ADD_MEANINGFULL_ERRNO;
      failed_to_send_dtg:

	command.len = 0;
	fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
	if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				   LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	  close(params.rail_sckt);
	  rail_isreusable = FALSE;
	}
      }
      break;

    case rail_dtg_sckt:
      rail_isreusable = FALSE;
      /* No flushing. */
      if (0 == rail_add_dtg_server(params.rail_sckt,
				   &command)) {
	command.nbworks_errno = 0;
	command.len = 0;
	fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
	if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				   LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	  close(params.rail_sckt);
	} else {
	  shutdown(params.rail_sckt, SHUT_RD);
	}
      } else {
	close(params.rail_sckt);
      }
      break;

    case rail_stream_sckt:
      rail_isreusable = FALSE;
      /* No flushing. */
      if (0 == rail_add_ses_server(params.rail_sckt,
				   &command)) {
	command.nbworks_errno = 0;
	command.len = 0;
	fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
	if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				   LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	  close(params.rail_sckt);
	}
      } else {
	close(params.rail_sckt);
      }
      break;

    case rail_stream_take:
      rail_isreusable = FALSE;
      /* No flushing. */
      rail_setup_session(params.rail_sckt,
			 command.token);
      break;

    case rail_addr_ofXuniq:
    case rail_addr_ofXgroup:
      /* Rail is flushed by rail_whatisaddrX(). */
      ipv4 = rail_whatisaddrX(params.rail_sckt, &command,
			      &rail_isreusable);

      if (ipv4 && rail_isreusable) {
	command.nbworks_errno = 0;
	command.len = 4;
	fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
	if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				   LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	  close(params.rail_sckt);
	  rail_isreusable = FALSE;
	  break;
	}
	fill_32field(ipv4, buff);
	if (4 > send(params.rail_sckt, buff, 4, MSG_NOSIGNAL)) {
	  close(params.rail_sckt);
	  rail_isreusable = FALSE;
	  break;
	}
      } else {
	if (! rail_isreusable) {
	  close(params.rail_sckt);
	  break;
	} else {
	  command.nbworks_errno = ENONET;
	  command.len = 0;
	  fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
	  if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				     LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	    close(params.rail_sckt);
	    rail_isreusable = FALSE;
	    break;
	  }
	}
      }
      break;

    case rail_isnotguard:
      if (guard_token == command.token) {
	guard_token = 0;
	guard_node_type = 0;
	command.nbworks_errno = 0;
      } else {
	command.nbworks_errno= ADD_MEANINGFULL_ERRNO;
      }
      goto send_guard_response;

    case rail_isguard:
      guard_token = command.token;
      guard_node_type = command.node_type;
      command.nbworks_errno = 0;
    send_guard_response:
      if (command.len)
	rail_flushrail(command.len, params.rail_sckt);
      command.len = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				 LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	close(params.rail_sckt);
	rail_isreusable = FALSE;
	break;
      }
      break;

    case rail_isinconflict:
      if (command.len)
	rail_flushrail(command.len, params.rail_sckt);
      command.nbworks_errno = rail_isnameinconflict(command.token);

      command.len = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				 LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	close(params.rail_sckt);
	rail_isreusable = FALSE;
	break;
      }
      break;

    case rail_setsignal:
      /* rail is flushed by rail_do_setsignal() */
      if (0 < rail_do_setsignal(params.rail_sckt, &command,
				&rail_isreusable)) {
	command.nbworks_errno = 0;
      } else {
	command.nbworks_errno = ADD_MEANINGFULL_ERRNO;
      }
      command.len = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				 LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	close(params.rail_sckt);
	rail_isreusable = FALSE;
	break;
      }
      break;

    case rail_rmsignal:
      /* rail is flushed by rail_do_rmsignal() */
      if (0 < rail_do_rmsignal(params.rail_sckt, &command)) {
	command.nbworks_errno = 0;
      } else {
	command.nbworks_errno = ADD_MEANINGFULL_ERRNO;
      }
      command.len = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      if (LEN_COMM_ONWIRE > send(params.rail_sckt, buff,
				 LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
	close(params.rail_sckt);
	rail_isreusable = FALSE;
	break;
      }
      break;

    default:
      /* Unknown command. */
      command.nbworks_errno = EINVAL;
      command.len = 0;

      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
      close(params.rail_sckt);
      rail_isreusable = FALSE;
      break;
    }

  }

  if (rail_isreusable)
    close(params.rail_sckt);

  if (guard_token) {
    memset(&command, 0, sizeof(command));
    command.command = rail_delname;
    command.token = guard_token;
    command.node_type = guard_node_type;
    rail_isreusable = FALSE;
    do_rail_delname(-1, &command, &rail_isreusable);
  }

  if (last_will)
    last_will->dead = TRUE;
  return 0;
}


struct cache_namenode *do_rail_regname(int rail_sckt,
				       struct com_comm *command,
				       unsigned int *rail_isreusable,
				       token_t *token_field) {
  struct cache_namenode *cache_namecard, *grp_namecard;
  struct rail_name_data *namedata;
  struct ipv4_addr_list *new_addr, *cur_addr, **last_addr;
  token_t new_token;
  ipv4_addr_t new_ipv4;
  uint32_t refresh_ttl;
  int i;
  node_type_t node_type;
  unsigned char *data_buff;

  if (! (command && rail_isreusable)) {
    return 0;
  }

  switch (command->node_type) {
  case RAIL_NODET_HUNQ:
    node_type = CACHE_NODEFLG_H;
    break;
  case RAIL_NODET_HGRP:
    node_type = CACHE_NODEGRPFLG_H;
    break;
  case RAIL_NODET_MUNQ:
    node_type = CACHE_NODEFLG_M;
    break;
  case RAIL_NODET_MGRP:
    node_type = CACHE_NODEGRPFLG_M;
    break;
  case RAIL_NODET_PUNQ:
    node_type = CACHE_NODEFLG_P;
    break;
  case RAIL_NODET_PGRP:
    node_type = CACHE_NODEGRPFLG_P;
    break;
  case RAIL_NODET_BUNQ:
    node_type = CACHE_NODEFLG_B;
    break;
  case RAIL_NODET_BGRP:
    node_type = CACHE_NODEGRPFLG_B;
    break;

  default:
    rail_flushrail(command->len, rail_sckt);
    return 0;
  }

  data_buff = malloc(command->len);
  if (! data_buff) {
    rail_flushrail(command->len, rail_sckt);
    return 0;
  }

  if (command->len > recv(rail_sckt, data_buff,
			  command->len, MSG_WAITALL)) {
    /* TODO: error handling */
    *rail_isreusable = FALSE;
    free(data_buff);
    return 0;
  }

  namedata = read_rail_name_data(data_buff, data_buff+command->len);
  free(data_buff);
  if (! namedata) {
    /* TODO: error handling */
    return 0;
  }

#define cleanup                        \
  free(namedata->name);                \
  nbworks_dstr_nbnodename(namedata->scope); \
  free(namedata);

  new_token = make_token();

  /* Call alloc_namecard() with ONES instead of name_type because
   * of the call to find_name() later on. */
  cache_namecard = alloc_namecard(namedata->name, NETBIOS_NAME_LEN,
				  ONES, 0, QTYPE_NB, QCLASS_IN);
  if (! cache_namecard) {
    /* TODO: error handling */
    cleanup;
    return 0;
  }
  grp_namecard = find_name(cache_namecard, namedata->scope);
  if (grp_namecard) {
    destroy_namecard(cache_namecard);
    node_type = node_type & CACHE_ADDRBLCK_GRP_MASK;

    if (node_type &&
	(! (grp_namecard->node_types & CACHE_ADDRBLCK_UNIQ_MASK)) &&
	/* (! grp_namecard->grp_isinconflict) && // maybe? */
	/* Tell the world (actually optional for B nodes). */
	(refresh_ttl = name_srvc_add_name(node_type, namedata->name,
					  namedata->name_type, namedata->scope,
					  nbworks__myip4addr, namedata->ttl))) {
      if (! add_token(&(grp_namecard->grp_tokens), new_token)) {
	cleanup;
	return 0;
      } else {
	if (token_field)
	  *token_field = new_token;
      }
      grp_namecard->timeof_death = time(0) + namedata->ttl;
      grp_namecard->refresh_ttl = refresh_ttl;

      for (i=0; i<NUMOF_ADDRSES; i++) {
	if ((grp_namecard->addrs.recrd[i].node_type == node_type) ||
	    (grp_namecard->addrs.recrd[i].node_type == 0))
	  break;
      }
      if (i<NUMOF_ADDRSES) {
	cleanup;

	grp_namecard->addrs.recrd[i].node_type = node_type;
	grp_namecard->node_types |= node_type;

	new_ipv4 = nbworks__myip4addr;

	/* First, check to see if the address is already in the cache. */
	cur_addr = grp_namecard->addrs.recrd[i].addr;
	while (cur_addr) {
	  if (cur_addr->ip_addr == new_ipv4)
	    return grp_namecard;
	  else
	    cur_addr = cur_addr->next;
	}

	/* If it isn't, add it. */
	new_addr = malloc(sizeof(struct ipv4_addr_list));
	if (! new_addr) {
	  return 0;
	}
	new_addr->ip_addr = new_ipv4;
	new_addr->next = 0;

	while (0xd0) {
	  last_addr = &(grp_namecard->addrs.recrd[i].addr);
	  cur_addr = *last_addr;

	  while (cur_addr) {
	    if (cur_addr == new_addr)
	      return grp_namecard;

	    last_addr = &(cur_addr->next);
	    cur_addr = *last_addr;
	  }

	  *last_addr = new_addr;
	}
      }
    }

    cleanup;
    return 0;
  } else {
    /* Revert the node_types field into what is should be. */
    cache_namecard->node_types = node_type;
    if (node_type & CACHE_ADDRBLCK_UNIQ_MASK) {
      cache_namecard->unq_token = new_token;
    } else {
      if (! add_token(&(cache_namecard->grp_tokens), new_token)) {
	destroy_namecard(cache_namecard);
	cleanup;
	return 0;
      }
    }
    if (token_field)
      *token_field = new_token;

    if ((refresh_ttl = name_srvc_add_name(node_type, namedata->name,
					  namedata->name_type, namedata->scope,
					  nbworks__myip4addr, namedata->ttl))) {
      if (! (add_scope(namedata->scope, cache_namecard, nbworks__default_nbns) ||
	     add_name(cache_namecard, namedata->scope))) {
	destroy_namecard(cache_namecard);
	cleanup;
	return 0;
      }

      cache_namecard->addrs.recrd[0].node_type = node_type;
      cache_namecard->addrs.recrd[0].addr = nbw_calloc(1, sizeof(struct ipv4_addr_list));
      if (! cache_namecard->addrs.recrd[0].addr) {
	/* TODO: error handling */
	cache_namecard->timeof_death = 0;
	cleanup;
	return 0;
      }
      cache_namecard->addrs.recrd[0].addr->ip_addr = nbworks__myip4addr;
      cache_namecard->timeof_death = time(0) + namedata->ttl;
      cache_namecard->refresh_ttl = refresh_ttl;

      cleanup;
      return cache_namecard;
    } else {
      /* TODO: error handling */
      destroy_namecard(cache_namecard);
      cleanup;
      return 0;
    }
  }

#undef cleanup
  /* Never reached. */
  return 0;
}

/* returns: >0 = success; 0 = fail; <0 = error */
int do_rail_delname(int rail_sckt,
		    struct com_comm *command,
		    unsigned int *rail_isreusable) {
  struct cache_namenode *cache_namecard;
  struct nbworks_nbnamelst *scope;
  struct ipv4_addr_list *cur_addr, **last_addr;
  ipv4_addr_t ipv4;
  int i, killitwithfire;
  node_type_t node_type, orig_node_type;
  unsigned char buff[LEN_COMM_ONWIRE], *name_ptr;

  scope = 0;

  if (! (command && rail_isreusable))
    return -1;

  if (command->len)
    rail_flushrail(command->len, rail_sckt);

  if (*rail_isreusable) {
    command->command = rail_readcom;
    command->nbworks_errno = 0;
    command->len = 0;
    fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
    if (LEN_COMM_ONWIRE > send(rail_sckt, buff,
			       LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
      close(rail_sckt);
      *rail_isreusable = FALSE;
      return -1;
    }
  }

  cache_namecard = find_namebytok(command->token, &scope);

  if (cache_namecard) {
    switch (command->node_type) {
    case RAIL_NODET_HUNQ:
      node_type = CACHE_NODEFLG_H;
      break;
    case RAIL_NODET_MUNQ:
      node_type = CACHE_NODEFLG_M;
      break;
    case RAIL_NODET_PUNQ:
      node_type = CACHE_NODEFLG_P;
      break;
    case RAIL_NODET_BUNQ:
      node_type = CACHE_NODEFLG_B;
      break;
    case RAIL_NODET_HGRP:
      node_type = CACHE_NODEGRPFLG_H;
      break;
    case RAIL_NODET_MGRP:
      node_type = CACHE_NODEGRPFLG_M;
      break;
    case RAIL_NODET_PGRP:
      node_type = CACHE_NODEGRPFLG_P;
      break;
    case RAIL_NODET_BGRP:
    default:
      node_type = CACHE_NODEGRPFLG_B;
      break;
    }
    name_ptr = cache_namecard->name;
    ipv4 = nbworks__myip4addr;

    orig_node_type = node_type;
    /* BTW, the below branches are redundant as node_type can
     * not possibly trigger both conditions. */
    if (node_type & CACHE_ADDRBLCK_UNIQ_MASK) {
      killitwithfire = TRUE;
      cache_namecard->unq_token = 0;
      cache_namecard->unq_signal_pid = 0;
      cache_namecard->unq_signal_sig = SIGCHLD; /* This signal is ignored by default. */
      cache_namecard->unq_isinconflict = FALSE;
      node_type |= CACHE_ADDRBLCK_UNIQ_MASK;
    } else
      killitwithfire = FALSE;
    if (node_type & CACHE_ADDRBLCK_GRP_MASK) {
      del_token(&(cache_namecard->grp_tokens), command->token);
      if (cache_namecard->grp_tokens) {
	node_type = node_type & CACHE_ADDRBLCK_UNIQ_MASK;
      } else {
	killitwithfire = TRUE;
	node_type |= CACHE_ADDRBLCK_GRP_MASK;
	cache_namecard->grp_isinconflict = FALSE;
      }
    }

    if (killitwithfire) {
      name_srvc_release_name(name_ptr, name_ptr[NETBIOS_NAME_LEN-1],
			     scope, ipv4, orig_node_type);

      ss__kill_allservrs(name_ptr, scope);

      for (i=0; i<NUMOF_ADDRSES; i++) {
	if (!(cache_namecard->addrs.recrd[i].node_type & node_type)) {
	  continue;
	}

	last_addr = &(cache_namecard->addrs.recrd[i].addr);
	cur_addr = *last_addr;

	while (cur_addr) {
	  if (cur_addr->ip_addr == ipv4) {
	    *last_addr = cur_addr->next;
	    free(cur_addr);
	  } else {
	    last_addr = &(cur_addr->next);
	  }

	  cur_addr = *last_addr;
	}

	if (! cache_namecard->addrs.recrd[i].addr) {
	  cache_namecard->node_types = cache_namecard->node_types &
	    (~(cache_namecard->addrs.recrd[i].node_type));
	  cache_namecard->addrs.recrd[i].node_type = 0;
	}

	if (! cache_namecard->node_types) {
	  cache_namecard->timeof_death = 0;
	  break;
	}
      }
    }
  }

  if (scope)
    nbworks_dstr_nbnodename(scope);
  return 1; /* return 1 in all cases becase, if the name was not here
	     * to begin with, then it *certainly* isn't here now. */
}

/* returns: 0 = success, >0 = fail, <0 = error */
int rail_senddtg(int rail_sckt,
		 struct com_comm *command) {
  struct sockaddr_in dst_addr;
  struct dtg_srvc_packet *pckt;
  struct dtg_srvc_recvpckt *sendpckt;
  struct dtg_pckt_pyld_normal *normal_pyld;
  struct cache_namenode *namecard;
  struct ss_queue_storage *trans;
  struct ipv4_addr_list *group_addrs;
  struct ss_queue *queue;
  union trans_id tid;
  int i;
  node_type_t node_type;
  unsigned short sent;
  unsigned char *buff, decoded_name[NETBIOS_NAME_LEN+1];

  if (! command)
    return -1;

  sendpckt = 0;
  sent = FALSE;
  decoded_name[NETBIOS_NAME_LEN] = 0;
  dst_addr.sin_family = AF_INET;
  /* VAXism below */
  fill_16field(138, (unsigned char *)&(dst_addr.sin_port));

  buff = malloc(command->len);
  if (! buff) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  if (command->len > recv(rail_sckt, buff, command->len, MSG_WAITALL)) {
    /* TODO: errno signaling stuff */
    free(buff);
    return -1;
  }

  pckt = partial_dtg_srvc_pckt_reader(buff, command->len, 0);
  if (! pckt) {
    /* TODO: errno signaling stuff */
    free(buff);
    return 0x7fff;
  }

  if (pckt->type == DIR_GRP_DTG) {
    switch (command->node_type) {
    case RAIL_NODET_HGRP:
    case RAIL_NODET_HUNQ:
      node_type = CACHE_NODEGRPFLG_H;
      break;
    case RAIL_NODET_MGRP:
    case RAIL_NODET_MUNQ:
      node_type = CACHE_NODEGRPFLG_M;
      break;
    case RAIL_NODET_PGRP:
    case RAIL_NODET_PUNQ:
      node_type = CACHE_NODEGRPFLG_P;
      break;
    case RAIL_NODET_BGRP:
    case RAIL_NODET_BUNQ:
    default:
      node_type = CACHE_NODEGRPFLG_B;
      break;
    }
  } else {
    switch (command->node_type) {
    case RAIL_NODET_HGRP:
    case RAIL_NODET_HUNQ:
      node_type = CACHE_NODEFLG_H;
      break;
    case RAIL_NODET_MGRP:
    case RAIL_NODET_MUNQ:
      node_type = CACHE_NODEFLG_M;
      break;
    case RAIL_NODET_PGRP:
    case RAIL_NODET_PUNQ:
      node_type = CACHE_NODEFLG_P;
      break;
    case RAIL_NODET_BGRP:
    case RAIL_NODET_BUNQ:
    default:
      node_type = CACHE_NODEFLG_B;
      break;
    }
  }

  switch (pckt->payload_t) {
  case normal:
    normal_pyld = pckt->payload;

    if ((normal_pyld->dst_name->len != NETBIOS_CODED_NAME_LEN) ||
	(normal_pyld->src_name->len != NETBIOS_CODED_NAME_LEN)) {
      break;
    }

    sendpckt = malloc(sizeof(struct dtg_srvc_recvpckt));
    if (! sendpckt) {
      break;
    }
    sendpckt->for_del = 0;
    sendpckt->dst = 0;
    sendpckt->packetbuff = buff;
    sendpckt->len = command->len;
    buff = 0;

    tid.name_scope = normal_pyld->src_name;

    trans = ss_find_queuestorage(&tid, DTG_SRVC);
    if (! trans) {
      queue = ss_register_dtg_tid(&tid);
      if (! queue) {
	break;
      }
      trans = ss_add_queuestorage(queue, &tid, DTG_SRVC);

      free(queue);
      if (! trans) {
	ss_deregister_dtg_tid(&tid);
	break;
      }
    }
    if (trans->last_active < INFINITY)
      trans->last_active = time(0);


    if ((pckt->type == BRDCST_DTG) ||
	(0 == memcmp(JOKER_NAME_CODED, normal_pyld->dst_name->name,
		     NETBIOS_CODED_NAME_LEN))) {
      /* FIXME: different operation in P-type modes.
       * However, this should produce the same final results as sending to NBDD. */
      /* VAXism below. */
      fill_32field(brdcst_addr, (unsigned char *)&(dst_addr.sin_addr.s_addr));

      sendpckt->for_del = TRUE;
      ss_dtg_send_pckt(sendpckt, &dst_addr, &(trans->queue));
      sendpckt = 0;
      sent = TRUE;

      break;
    }

    namecard = find_nblabel(decode_nbnodename(normal_pyld->dst_name->name,
					      decoded_name),
			    NETBIOS_NAME_LEN, node_type,
			    QTYPE_NB, QCLASS_IN, normal_pyld->dst_name->next_name);
    if (! namecard)
      namecard = name_srvc_find_name(decoded_name,
				     decoded_name[NETBIOS_NAME_LEN-1],
				     normal_pyld->dst_name->next_name,
				     node_type);
    if (namecard) {
      for (i=0; i<NUMOF_ADDRSES; i++) {
	if ((namecard->addrs.recrd[i].node_type == node_type) &&
	    (namecard->addrs.recrd[i].addr))
	  break;
      }
      if (i<NUMOF_ADDRSES) {
	if (namecard->addrs.recrd[i].node_type & CACHE_ADDRBLCK_GRP_MASK) {
	  /* FIXME: this should also be fixed for P-type modes.
	   * However, this should produce the same final results as sending to NBDD. */
	  group_addrs = namecard->addrs.recrd[i].addr;
	  while (group_addrs->next) {
            /* VAXism below */
	    fill_32field(group_addrs->ip_addr,
			 (unsigned char *)&(dst_addr.sin_addr.s_addr));

	    ss_dtg_send_pckt(sendpckt, &dst_addr, &(trans->queue));

	    group_addrs = group_addrs->next;
	  }

	  /* VAXism below */
	  fill_32field(group_addrs->ip_addr,
		       (unsigned char *)&(dst_addr.sin_addr.s_addr));
	} else {
	  /* VAXism below */
	  fill_32field(namecard->addrs.recrd[i].addr->ip_addr,
		       (unsigned char *)&(dst_addr.sin_addr.s_addr));
	}

	sendpckt->for_del = TRUE;
	ss_dtg_send_pckt(sendpckt, &dst_addr, &(trans->queue));
	sendpckt = 0;
	sent = TRUE;
      }
    } /* else
	 FU(); */
    break;

  default:
    break;
  }

  if (pckt)
    destroy_dtg_srvc_pckt(pckt, 1, 1);
  if (buff)
    free(buff);
  if (sendpckt) {
    free(sendpckt->packetbuff);
    free(sendpckt);
  }
  if (sent)
    return 0;
  else
    return 0x7fff;
}

/* returns: 0=success, >0=fail, <0=error */
int rail_add_dtg_server(int rail_sckt,
			struct com_comm *command) {
  struct ss_queue *trans;
  struct ss_queue_storage *queue;
  struct cache_namenode *namecard;
  struct nbworks_nbnamelst *nbname;
  struct rail_list *new_rail, *cur_rail, **last_rail;
  struct dtg_srv_params params;
  union trans_id tid;
  token_t token;
  time_t cur_time;
  unsigned char buff[LEN_COMM_ONWIRE];

  if (! command)
    return -1;

  new_rail = malloc(sizeof(struct rail_list));
  if (! new_rail) {
    return -1;
  }
  new_rail->rail_sckt = rail_sckt;
  new_rail->next = 0;

  nbname = malloc(sizeof(struct nbworks_nbnamelst) +
		  NETBIOS_CODED_NAME_LEN +1);
  if (! nbname) {
    free(new_rail);
    return -1;
  }

  cur_time = time(0);
  token = command->token;

  namecard = find_namebytok(token, &(nbname->next_name));
  if ((! namecard) ||
      (namecard->timeof_death <= cur_time) ||
      (((namecard->unq_token == token) && namecard->unq_isinconflict) ||
       (does_token_match(namecard->grp_tokens, token) &&
	namecard->grp_isinconflict))) {

    if (namecard &&
	(((namecard->unq_token == token) && namecard->unq_isinconflict) ||
	 (does_token_match(namecard->grp_tokens, token) &&
	  namecard->grp_isinconflict))) {

      command->len = 0;
      command->nbworks_errno = EADDRINUSE;
      fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
      send(rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
    }

    free(new_rail);
    free(nbname);
    return 1;
  }

  encode_nbnodename(namecard->name, nbname->name);
  nbname->len = NETBIOS_CODED_NAME_LEN;

  if (command->len)
    rail_flushrail(command->len, rail_sckt);
  tid.name_scope = nbname;

  trans = ss_register_dtg_tid(&tid);
  if (! trans) {
    /* This can only mean there is already
       a registered queue with this name. */
    queue = ss_find_queuestorage(&tid, DTG_SRVC);
  } else {
    queue = ss_add_queuestorage(trans, &tid, DTG_SRVC);
  }

  if (! queue) {
    /* Dafuq!?! */
    if (trans) {
      ss_deregister_dtg_tid(&tid);
      ss__dstry_recv_queue(trans);
      free(trans);
    }
    nbworks_dstr_nbnodename(nbname);
    free(new_rail);
    return 1;
  } else {
    /* Make the queue unperishable. */
    queue->last_active = INFINITY;
  }

  while (0x101) { /* Not really 101. */
    last_rail = &(queue->rail);
    cur_rail = *last_rail;

    while (cur_rail) {
      if (cur_rail == new_rail) {
	last_rail = 0;
	break;
      } else {
	last_rail = &(cur_rail->next);
	cur_rail = *last_rail;
      }
    }

    if (last_rail)
      *last_rail = new_rail;
    else
      break;
  }

  if (trans) {
    free(trans);

    params.isbusy = 0xda;
    params.nbname = nbname;
    params.queue = queue;

    if (0 != pthread_create(&(params.thread_id), 0,
			    dtg_server, &params)) {
      ss_del_queuestorage(&tid, DTG_SRVC);
      nbworks_dstr_nbnodename(nbname);

      return -1;
    }

    while (params.isbusy) {
      /* busy-wait */
    }
  } else {
    nbworks_dstr_nbnodename(nbname);
  }

  return 0;
}


void *dtg_server(void *arg) {
  struct dtg_srv_params *params;
  struct thread_node *last_will;
  struct nbworks_nbnamelst *nbname;
  struct ss_queue *trans;
  struct ss_queue_storage *queue;
  struct dtg_srvc_recvpckt *pckt;
  struct rail_list *cur_rail, **last_rail;
  struct pollfd pollfd;
  union trans_id tid;
  unsigned char buff[4];

  if (! arg)
    return 0;
  else
    params = arg;
  if (params->thread_id)
    last_will = add_thread(params->thread_id);
  else
    last_will = 0;
  nbname = params->nbname;
  queue = params->queue;
  /* Release the caller. */
  params->isbusy = 0;

  trans = &(queue->queue);
  pollfd.events = POLLOUT;

#define do_close_rail          \
  *last_rail = cur_rail->next; \
  close(cur_rail->rail_sckt);  \
  free(cur_rail);              \
  cur_rail = *last_rail;

  while (! nbworks_dtg_srv_cntrl.all_stop) {
    while (438) {
      pckt = ss__recv_pckt(trans, 0, 0);
      if (pckt) {
	if (queue->last_active < INFINITY)
	  queue->last_active = INFINITY;

	/* VAXism below */
	fill_32field(pckt->len, buff);

	cur_rail = queue->rail;
	last_rail = &(queue->rail);
	while (cur_rail) {
	  pollfd.fd = cur_rail->rail_sckt;
	  poll(&pollfd, 1, 0);

	  if (pollfd.revents & POLLOUT) {
	    if (4 == send(cur_rail->rail_sckt, buff, 4,
			  (MSG_DONTWAIT | MSG_NOSIGNAL))) {

	      if (pckt->len > send(cur_rail->rail_sckt,
				   pckt->packetbuff, pckt->len,
				   (MSG_DONTWAIT | MSG_NOSIGNAL))) {

		do_close_rail;
		continue;
	      }

	    } else {
	      do_close_rail;
	      continue;
	    }
	  } else {
	    if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
	      do_close_rail;
	      continue;
	    }
	  }

	  last_rail = &(cur_rail->next);
	  cur_rail = *last_rail;
	}

	destroy_dtg_srvc_recvpckt(pckt, 1, 1);

	if (! queue->rail)
	  break;
      } else {
	break;
      }
    }

    cur_rail = queue->rail;
    last_rail = &(queue->rail);
    while (cur_rail) {
      pollfd.fd = cur_rail->rail_sckt;
      poll(&pollfd, 1, 0);
      if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
	do_close_rail;
      } else {
	last_rail = &(cur_rail->next);
	cur_rail = *last_rail;
      }
    }

    if (! queue->rail)
      break;

    nanosleep(&(nbworks_dtg_srv_cntrl.dtg_srv_sleeptime), 0);
  }
#undef do_close_rail

  tid.name_scope = nbname;

  ss_del_queuestorage(&tid, DTG_SRVC);
  nbworks_dstr_nbnodename(nbname);

  if (last_will)
    last_will->dead = 0xb00; /* said the ghost */
  return 0;
}


/* returns: 0=success, >0=fail, <0=error */
int rail_add_ses_server(int rail_sckt,
			struct com_comm *command) {
  struct cache_namenode *namecard;
  struct nbworks_nbnamelst *nbname;
  token_t token;
  time_t cur_time;
  unsigned char buff[LEN_COMM_ONWIRE];

  if (! command)
    return -1;

  cur_time = time(0);
  token = command->token;

  /* Portable? */
  nbname = alloca(sizeof(struct nbworks_nbnamelst) +
		  NETBIOS_CODED_NAME_LEN +1);

  namecard = find_namebytok(token, &(nbname->next_name));
  if ((! namecard) ||
      (namecard->timeof_death <= cur_time) ||
      (((namecard->unq_token == token) && namecard->unq_isinconflict) ||
       (does_token_match(namecard->grp_tokens, token) &&
	namecard->grp_isinconflict))) {

    if (namecard &&
	(((namecard->unq_token == token) && namecard->unq_isinconflict) ||
	 (does_token_match(namecard->grp_tokens, token) &&
	  namecard->grp_isinconflict))) {

      command->len = 0;
      command->nbworks_errno = EADDRINUSE;
      fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
      send(rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
    }

    return 1;
  }

  encode_nbnodename(namecard->name, nbname->name);
  nbname->len = NETBIOS_CODED_NAME_LEN;
  /* nbname->next_name is already set */

  if (command->len)
    rail_flushrail(command->len, rail_sckt);

  if (ss__add_sessrv(nbname, rail_sckt)) {
    return 0;
  } else {
    return 1;
  }
}

/* returns: >0 = success, 0 = failed, <0 = error */
int rail__send_ses_pending(int rail,
			   token_t token) {
  struct com_comm command;
  struct pollfd pfd;
  unsigned char wire_com[LEN_COMM_ONWIRE];

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_stream_pending;
  command.token = token;

  fill_railcommand(&command, wire_com, wire_com + LEN_COMM_ONWIRE);

  pfd.fd = rail;
  pfd.events = POLLOUT;
  if ((0 < poll(&pfd, 1, 0)) &&
      (pfd.revents & POLLOUT) &&
      (! (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)))) {
    if (LEN_COMM_ONWIRE == send(rail, wire_com, LEN_COMM_ONWIRE,
				MSG_NOSIGNAL))
      return 1;
  }

  return 0;
}

/* returns: >0 = success, 0 = failed, <0 = error */
int rail_setup_session(int rail,
		       token_t token) {
  struct ses_srv_sessions *session;
  struct ses_srvc_packet pckt;
  struct com_comm answer;
  struct stream_connector_args new_session;
  int out_sckt;
  unsigned char rail_buff[LEN_COMM_ONWIRE];
  unsigned char err[] = { NEG_SESSION_RESPONSE, 0, 0, 1, SES_ERR_UNSPEC };
  unsigned char *walker;

  session = ss__take_session(token);
  if (! session) {
    close(rail);
    return 0;
  }

  memset(&pckt, 0, sizeof(struct ses_srvc_packet));

  walker = session->first_buff;
  if (! read_ses_srvc_pckt_header(&walker, walker+SES_HEADER_LEN, &pckt)) {
    send(session->out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(session->out_sckt);
    free(session->first_buff);
    free(session);
    return -1;
  }

  if ((pckt.len+SES_HEADER_LEN) > send(rail, session->first_buff,
				       (pckt.len+SES_HEADER_LEN),
				       (MSG_NOSIGNAL | MSG_DONTWAIT))) {
    send(session->out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(session->out_sckt);
    free(session->first_buff);
    free(session);
    return -1;
  } else {
    out_sckt = session->out_sckt;
    free(session->first_buff);
    free(session);
  }

  if (LEN_COMM_ONWIRE > recv(rail, rail_buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
    send(out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    return 0;
  }

  if (! read_railcommand(rail_buff, (rail_buff+LEN_COMM_ONWIRE), &answer)) {
    send(out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    return -1;
  }

  if ((answer.command != rail_stream_accept) ||
      (answer.token != token)) {
    if (answer.command == rail_stream_error) {
      err[4] = answer.node_type;
    }
    send(out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    return -1;
  } else {
    if (answer.len)
      rail_flushrail(answer.len, rail);
  }

  if (0 != set_sockoption(rail, NONBLOCKING)) {
    send(out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    return -1;
  }
  /* The rail socket is now ready for operation. Establish a tunnel. */

  new_session.isbusy = 0xda;
  new_session.sckt_lcl = rail;
  new_session.sckt_rmt = out_sckt;

  if (0 != pthread_create(&(new_session.thread_id), 0,
			  tunnel_stream_sockets, &new_session)) {
    send(out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    return -1;
  }

  while (new_session.isbusy) {
    /* busy-wait */
  }


  return TRUE;
}

void *tunnel_stream_sockets(void *arg) {
  struct stream_connector_args *params;
  struct thread_node *last_will;
  struct pollfd fds[2];
  ssize_t trans_len, sent_len, lastbuf_len;
  int sckt_lcl, sckt_rmt, read_sckt, write_sckt, l;
  int ret_val, i;
  unsigned char buf[DEFAULT_TUNNEL_LEN];

  if (! arg)
    return 0;

  params = arg;
  sckt_lcl = params->sckt_lcl;
  sckt_rmt = params->sckt_rmt;
  if (params->thread_id)
    last_will = add_thread(params->thread_id);
  else
    last_will = 0;
  params->isbusy = 0;

  trans_len = sent_len = 0;
  read_sckt = sckt_lcl;
  write_sckt = sckt_rmt;

  memset(buf, 0, DEFAULT_TUNNEL_LEN);
  lastbuf_len = 0;

  fds[0].fd = sckt_rmt;
  fds[0].events = (POLLIN | POLLPRI);
  fds[1].fd = sckt_lcl;
  fds[1].events = (POLLIN | POLLPRI);

  while (! nbworks_ses_srv_cntrl.all_stop) {
    ret_val = poll(fds, 2, nbworks_ses_srv_cntrl.poll_timeout);
    if (ret_val == 0) {
      continue;
    } else {
      if (ret_val < 0) {
	/* TODO: error handling */
	close(sckt_lcl);
	close(sckt_rmt);
	if (last_will)
	  last_will->dead = TRUE;
	return 0;
      }
    }

    /* A weird loop.
     * Coming in, write_sckt equals sckt_rmt. At the start of the loop,
     * write_sckt gets swaped out and is now equal to sckt_lcl. The test
     * at the end passes, loop reenters and write_sckt again gets swaped,
     * this time to sckt_rmt which causes the end test to fail and the
     * loop exits.
     * This was done because it's fun. */
    /* It was also done because I forgot that there is a deeper meaning to
     * the relationship between the socket on whose pollfd I operate and the
     * socket from which data is being read. Stupid. */
    i = 0;
    do {
      /* Swap the sockets. */
      l = write_sckt;
      write_sckt = read_sckt;
      read_sckt = l;

      if (fds[i].revents & (POLLIN | POLLPRI)) {
	if (fds[i].revents & POLLIN) {
	  trans_len = recv(read_sckt, buf, DEFAULT_TUNNEL_LEN,
			   MSG_DONTWAIT);
	  if ((trans_len <= 0) &&
	      ((errno != EAGAIN) &&
	       (errno != EWOULDBLOCK))) {
	    if (trans_len == 0) {
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    } else {
	      /* TODO: error handling */
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    }
	  }

	  if (trans_len < lastbuf_len) {
	    memset(buf+trans_len, 0, (lastbuf_len - trans_len));
	  }
	  lastbuf_len = trans_len;

	  sent_len = 0;
	  while (sent_len < trans_len) {
	    errno = 0;
	    sent_len = sent_len + send(write_sckt, (buf + sent_len),
				       (trans_len - sent_len),
				       MSG_NOSIGNAL);
	    if ((errno != 0) &&
		((errno != EAGAIN) &&
		 (errno != EWOULDBLOCK))) {
	      /* TODO: error handling */
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    }
	  }
	}
	if (fds[i].revents & POLLPRI) {
	  trans_len = recv(read_sckt, buf, DEFAULT_TUNNEL_LEN,
			   (MSG_DONTWAIT | MSG_OOB));

	  if ((trans_len <= 0) &&
	      ((errno != EAGAIN) &&
	       (errno != EWOULDBLOCK))) {
	    if (trans_len == 0) {
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    } else {
	      /* TODO: error handling */
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    }
	  }

	  if (trans_len < lastbuf_len) {
	    memset(buf+trans_len, 0, (lastbuf_len - trans_len));
	  }
	  lastbuf_len = trans_len;

	  sent_len = 0;
	  while (sent_len < trans_len) {
	    errno = 0;
	    sent_len = sent_len + send(write_sckt, (buf + sent_len),
				       (trans_len - sent_len),
				       (MSG_NOSIGNAL | MSG_OOB));

	    if ((errno != 0) &&
		((errno != EAGAIN) &&
		 (errno != EWOULDBLOCK))) {
	      /* TODO: error handling */
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    }
	  }
	}
      }

      if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
	if (fds[i].revents & POLLHUP) {
	  close(sckt_lcl);
	  close(sckt_rmt);
	  if (last_will)
	    last_will->dead = TRUE;
	  return 0;
	} else {
	  /* TODO: error handling */
	  close(sckt_lcl);
	  close(sckt_rmt);
	  if (last_will)
	    last_will->dead = TRUE;
	  return 0;
	}
      }

      i++;
    } while (write_sckt == sckt_lcl);
  }

  close(sckt_lcl);
  close(sckt_rmt);
  if (last_will)
    last_will->dead = TRUE;
  return 0;
}


/* WRONG FOR GROUPS! */
ipv4_addr_t rail_whatisaddrX(int rail_sckt,
			     struct com_comm *command,
			     unsigned int *rail_isreusable) {
  struct cache_namenode *namecard;
  struct nbworks_nbnamelst *name;
  int i;
  node_type_t node_type;
  unsigned char *buff, *walker;

  if (! (command && rail_isreusable))
    return 0;

  if (command->command == rail_addr_ofXgroup) {
    switch (command->node_type) {
    case RAIL_NODET_HGRP:
    case RAIL_NODET_HUNQ:
      node_type = CACHE_NODEGRPFLG_H;
      break;
    case RAIL_NODET_MGRP:
    case RAIL_NODET_MUNQ:
      node_type = CACHE_NODEGRPFLG_M;
      break;
    case RAIL_NODET_PGRP:
    case RAIL_NODET_PUNQ:
      node_type = CACHE_NODEGRPFLG_P;
      break;
    case RAIL_NODET_BGRP:
    case RAIL_NODET_BUNQ:
    default:
      node_type = CACHE_NODEGRPFLG_B;
      break;
    }
  } else {
    switch (command->node_type) {
    case RAIL_NODET_HGRP:
    case RAIL_NODET_HUNQ:
      node_type = CACHE_NODEFLG_H;
      break;
    case RAIL_NODET_MGRP:
    case RAIL_NODET_MUNQ:
      node_type = CACHE_NODEFLG_M;
      break;
    case RAIL_NODET_PGRP:
    case RAIL_NODET_PUNQ:
      node_type = CACHE_NODEFLG_P;
      break;
    case RAIL_NODET_BGRP:
    case RAIL_NODET_BUNQ:
    default:
      node_type = CACHE_NODEFLG_B;
      break;
    }
  }

  buff = malloc(command->len);
  if (! buff) {
    rail_flushrail(command->len, rail_sckt);
    return 0;
  }

  if (command->len > recv(rail_sckt, buff, command->len, MSG_WAITALL)) {
    *rail_isreusable = FALSE;
    return 0;
  }

  walker = buff;
  name = read_all_DNS_labels(&walker, buff, buff + command->len, 0, 0, 0, 0);
  free(buff);
  if ((! name) ||
      (name->len != NETBIOS_NAME_LEN)) {
    return 0;
  }

  namecard = find_nblabel(name->name, name->len,
			  node_type,
			  RRTYPE_NB, RRCLASS_IN,
			  name->next_name);

  if (! namecard) {
    namecard = name_srvc_find_name(name->name, (name->name)[name->len -1],
				   name->next_name, node_type);
  }

  nbworks_dstr_nbnodename(name);

  if (namecard) {
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if ((namecard->addrs.recrd[i].node_type == node_type) &&
	  (namecard->addrs.recrd[i].addr))
	return namecard->addrs.recrd[i].addr->ip_addr;
    }
  }

  return 0;
}

uint32_t rail_isnameinconflict(token_t token) {
  struct cache_namenode *namecard;

  namecard = find_namebytok(token, 0);
  if (namecard) {
    if (namecard->unq_token == token) {
      if (namecard->unq_isinconflict)
	return TRUE;
      else
	return FALSE;
    } else {
      if (namecard->grp_isinconflict)
	return TRUE;
      else
	return FALSE;
    }
  } else
    return FALSE;
}

/* returns: >0 = success; 0 = fail; <0 = error */
int rail_do_setsignal(int rail,
		      struct com_comm *command,
		      unsigned int *rail_isreusable) {
  struct cache_namenode *namecard;
  struct group_tokenlst *cur_token;
  int64_t transitory;
  pid_t pid;
  int signal;
  unsigned char buff[8*2];

  if ((! command) ||
      (rail < 0) ||
      (! rail_isreusable)) {
    return -1;
  }

  if ((command->len < (8*2)) ||
      (! command->token)) {
    rail_flushrail(command->len, rail);
    return 0;
  }

  if ((8*2) > recv(rail, buff, (8*2), MSG_WAITALL)) {
    *rail_isreusable = FALSE;
    return -1;
  } else {
    if ((8*2) < command->len) {
      rail_flushrail((command->len - (8*2)), rail);
    }
  }

  /* VAXism below */
  read_64field(buff, (uint64_t *)&transitory);
  pid = transitory;
  read_64field((buff +8), (uint64_t *)&transitory);
  signal = transitory;

  namecard = find_namebytok(command->token, 0);
  if (namecard) {
    if (namecard->unq_token == command->token) {
      namecard->unq_signal_pid = pid;
      namecard->unq_signal_sig = signal;
    }
    cur_token = namecard->grp_tokens;
    while (cur_token) {
      if (cur_token->token == command->token) {
	cur_token->signal_pid = pid;
	cur_token->signal = signal;
      }

      cur_token = cur_token->next;
    }
  }

  return 1;
}

/* returns: >0 = success; 0 = fail; <0 = error */
int rail_do_rmsignal(int rail,
		     struct com_comm *command) {
  struct cache_namenode *namecard;
  struct group_tokenlst *cur_token;

  if ((! command) ||
      (rail < 0)) {
    return -1;
  }

  if (command->len) {
    rail_flushrail(command->len, rail);
  }

  namecard = find_namebytok(command->token, 0);
  if (namecard) {
    if (namecard->unq_token == command->token) {
      namecard->unq_signal_pid = 0;
      namecard->unq_signal_sig = SIGCHLD; /* This signal is ignored by default. */
    }
    cur_token = namecard->grp_tokens;
    while (cur_token) {
      if (cur_token->token == command->token) {
	cur_token->signal_pid = 0;
	cur_token->signal = SIGCHLD; /* This signal is ignored by default. */
      }

      cur_token = cur_token->next;
    }
  }

  return 1;
}
