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
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <pthread.h>

#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "constdef.h"
#include "daemon_control.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_func_B.h"
#include "name_srvc_func_func.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_func.h"
#include "ses_srvc_pckt.h"
#include "randomness.h"
#include "service_sector.h"
#include "service_sector_threads.h"
#include "rail-comm.h"
#include "portability.h"


struct ss_priv_trans *nbworks_all_transactions[2];
struct ss_queue_storage *nbworks_queue_storage[2];
struct ses_srv_rails *nbworks_all_session_srvrs;
struct ses_srv_sessions *nbworks_all_sessions;


void init_service_sector_runonce(void) {
  nbworks_all_transactions[0] = 0;
  nbworks_all_transactions[1] = 0;

  nbworks_queue_storage[0] = 0;
  nbworks_queue_storage[1] = 0;

  nbworks_all_session_srvrs = 0;
  nbworks_all_sessions = 0;
}

void init_service_sector(void) {
  nbworks_all_port_cntl.all_stop = 0;
  nbworks_all_port_cntl.sleeptime.tv_sec = 0;
  nbworks_all_port_cntl.sleeptime.tv_nsec = T_12MS;
  nbworks_all_port_cntl.newtid_sleeptime.tv_sec = 0;
  nbworks_all_port_cntl.newtid_sleeptime.tv_nsec = T_500MS;
  nbworks_all_port_cntl.poll_timeout = TP_500MS;

  nbworks_dtg_srv_cntrl.all_stop = 0;
  nbworks_dtg_srv_cntrl.dtg_srv_sleeptime.tv_sec = 0;
  nbworks_dtg_srv_cntrl.dtg_srv_sleeptime.tv_nsec = T_12MS;

  nbworks_ses_srv_cntrl.all_stop = 0;
  nbworks_ses_srv_cntrl.poll_timeout = TP_500MS;
}

struct ss_queue *ss_register_tid(union trans_id *arg,
				 unsigned char branch) {
  struct ss_queue *result;
  struct ss_priv_trans *cur_trans, *my_trans;
  uint16_t tid;

  if (! arg)
    return 0;

  result = malloc(sizeof(struct ss_queue));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  my_trans = malloc(sizeof(struct ss_priv_trans));
  if (! my_trans) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }
  my_trans->in = calloc(1, sizeof(struct ss_unif_pckt_list));
  if (! my_trans->in) {
    /* TODO: errno signaling stuff */
    free(result);
    free(my_trans);
    return 0;
  }
  my_trans->in->stream.sckt = -1;
  my_trans->out = calloc(1, sizeof(struct ss_unif_pckt_list));
  if (! my_trans->out) {
    /* TODO: errno signaling stuff */
    free(result);
    free(my_trans->in);
    free(my_trans);
    return 0;
  }
  my_trans->out->stream.sckt = -1;
  if (branch == DTG_SRVC)
    my_trans->id.name_scope = nbworks_clone_nbnodename(arg->name_scope);
  else
    my_trans->id.tid = arg->tid;
  my_trans->status = nmtrst_normal;
  my_trans->next = 0;

  result->incoming = my_trans->in;
  result->outgoing = my_trans->out;

  tid = arg->tid;

  while (1) {
    if (! nbworks_all_transactions[branch]) {
      nbworks_all_transactions[branch] = my_trans;
    }

    cur_trans = nbworks_all_transactions[branch];

    while (cur_trans) {
      if ((branch == DTG_SRVC ?
	   (! nbworks_cmp_nbnodename(cur_trans->id.name_scope,
			     arg->name_scope)) :
	   cur_trans->id.tid == tid) &&
	  (cur_trans->status == nmtrst_normal ||
	   cur_trans->status == nmtrst_indrop)) {
	if (cur_trans == my_trans) {
	  /* Success! */
	  return result;
	} else {
	  /* Duplicate. */
	  free(my_trans->in);
	  free(my_trans->out);
	  if (branch == DTG_SRVC)
	    nbworks_dstr_nbnodename(my_trans->id.name_scope);
	  free(my_trans);
	  free(result);
	  return 0;
	}
      }

      if (! cur_trans->next) {
	/* BUG: there is still a (trivial) chance of
	        memory leak and tid non-registering. */
	cur_trans->next = my_trans;
	break;
      }
      cur_trans = cur_trans->next;
    }
  }
}

void ss_deregister_tid(union trans_id *arg,
		       unsigned char branch) {
  struct ss_priv_trans *cur_trans;
  uint16_t tid;

  if (! arg)
    return;

  cur_trans = nbworks_all_transactions[branch];
  if (! cur_trans)
    return;

  tid = arg->tid;

  while (cur_trans) {
    if ((branch == DTG_SRVC ?
	 (! nbworks_cmp_nbnodename(cur_trans->id.name_scope,
			   arg->name_scope)) :
	 cur_trans->id.tid == tid) &&
	(cur_trans->status == nmtrst_normal ||
	 cur_trans->status == nmtrst_indrop)) {
      cur_trans->status = nmtrst_deregister;
      return;
    }
    cur_trans = cur_trans->next;
  }

  return;
}


struct ss_queue_storage *ss_add_queuestorage(struct ss_queue *queue,
					     union trans_id *arg,
					     unsigned char branch) {
  struct ss_queue_storage *result, *cur_stor, **last_stor;
  uint16_t tid;

  if (! (queue && arg))
    return 0;

  tid = 0;

  result = malloc(sizeof(struct ss_queue_storage));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->branch = branch;
  if (branch == DTG_SRVC)
    result->id.name_scope = nbworks_clone_nbnodename(arg->name_scope);
  else {
    tid = arg->tid;
    result->id.tid = tid;
  }
  result->last_active = INFINITY -1;
  result->rail = 0;
  result->queue.incoming = queue->incoming;
  result->queue.outgoing = queue->outgoing;
  result->next = 0;

  while (0666) {
    last_stor = &(nbworks_queue_storage[branch]);
    cur_stor = *last_stor;

    while (cur_stor) {
      if ((branch == DTG_SRVC) ?
	  (! nbworks_cmp_nbnodename(cur_stor->id.name_scope,
			    arg->name_scope)) :
	  cur_stor->id.tid == tid) {
	if (cur_stor == result)
	  return result;
	else {
	  if (branch == DTG_SRVC) {
	    nbworks_dstr_nbnodename(result->id.name_scope);
	  }
	  free(result);
	  return 0;
	}
      } else {
	last_stor = &(cur_stor->next);
	cur_stor = cur_stor->next;
      }
    }

    *last_stor = result;
  }
}

void ss_del_queuestorage(union trans_id *arg,
			 unsigned char branch) {
  struct ss_queue_storage *cur_stor, **last_stor;
  struct rail_list *for_del2, *for_del2prim;
  uint16_t tid;

  if (! arg)
    return;

  last_stor = &(nbworks_queue_storage[branch]);
  cur_stor = *last_stor;

  tid = arg->tid;

  while (cur_stor) {
    if ((branch == DTG_SRVC) ?
	(! nbworks_cmp_nbnodename(cur_stor->id.name_scope,
				  arg->name_scope)) :
	cur_stor->id.tid == tid) {
      *last_stor = cur_stor->next;

      ss_deregister_tid(arg, branch);
      ss__dstry_recv_queue(&(cur_stor->queue));

      for_del2prim = cur_stor->rail;
      while (for_del2prim) {
	for_del2 = for_del2prim->next;
	close(for_del2prim->rail_sckt);
	free(for_del2prim);
	for_del2prim = for_del2;
      }

      if (branch == DTG_SRVC)
	nbworks_dstr_nbnodename(cur_stor->id.name_scope);

      free(cur_stor);
      return;
    } else {
      last_stor = &(cur_stor->next);
    }

    cur_stor = *last_stor;
  }

  return;
}

struct ss_queue_storage *ss_take_queuestorage(union trans_id *arg,
					      unsigned char branch) {
  struct ss_queue_storage *cur_stor, **last_stor;
  uint16_t tid;

  if (! arg)
    return 0;

  last_stor = &(nbworks_queue_storage[branch]);
  cur_stor = *last_stor;

  tid = arg->tid;

  while (cur_stor) {
    if ((branch == DTG_SRVC) ?
	(! nbworks_cmp_nbnodename(cur_stor->id.name_scope,
				  arg->name_scope)) :
	cur_stor->id.tid == tid) {
      *last_stor = cur_stor->next;
      return cur_stor;
    } else {
      last_stor = &(cur_stor->next);
      cur_stor = *last_stor;
    }
  }

  return 0;
}

struct ss_queue_storage *ss_find_queuestorage(union trans_id *arg,
					      unsigned char branch) {
  struct ss_queue_storage *cur_stor;
  uint16_t tid;

  if (! arg)
    return 0;

  cur_stor = nbworks_queue_storage[branch];

  tid = arg->tid;

  while (cur_stor) {
    if ((branch == DTG_SRVC) ?
	(! nbworks_cmp_nbnodename(cur_stor->id.name_scope,
				  arg->name_scope)) :
	cur_stor->id.tid == tid) {
      break;
    } else {
      cur_stor = cur_stor->next;
    }
  }

  return cur_stor;
}

void ss_prune_queuestorage(time_t killtime) {
  union trans_id tid;
  struct ss_queue_storage *cur_stor, **last_stor;
  struct rail_list *railkill, *roadkill;
  int i;

  for (i=0; i<2; i++) {
    last_stor = &(nbworks_queue_storage[i]);
    cur_stor = *last_stor;

    while (cur_stor) {
      if (cur_stor->last_active < killtime) {
	*last_stor = cur_stor->next;

	railkill = cur_stor->rail;
	while (railkill) {
	  roadkill = railkill->next;
	  close(railkill->rail_sckt);
	  free(railkill);
	  railkill = roadkill;
	}

	memcpy(&tid, &(cur_stor->id), sizeof(union trans_id));
	ss_deregister_tid(&tid, cur_stor->branch);

	if (cur_stor->branch == DTG_SRVC) {
	  nbworks_dstr_nbnodename(cur_stor->id.name_scope);
	}

	free(cur_stor);
      } else {
	last_stor = &(cur_stor->next);
      }

      cur_stor = *last_stor;
    }
  }
}


void ss_set_inputdrop_tid(union trans_id *arg,
			  unsigned char branch) {
  struct ss_priv_trans *cur_trans;
  uint16_t tid;

  if (! arg)
    return;

#ifdef COMPILING_NBNS
  if (branch == DTG_SRVC) {
#endif

  if (! nbworks_all_transactions[branch])
    return;

  cur_trans = nbworks_all_transactions[branch];

  tid = arg->tid;

  while (cur_trans) {
    if (((branch == DTG_SRVC) ?
	 (! nbworks_cmp_nbnodename(cur_trans->id.name_scope,
			   arg->name_scope)) :
	 cur_trans->id.tid == tid) &&
	cur_trans->status == nmtrst_normal) {
      cur_trans->status = nmtrst_indrop;
      return;
    }
    cur_trans = cur_trans->next;
  }
#ifdef COMPILING_NBNS
  } else {
    cur_trans = ss_alltrans[arg->tid].privtrans;
    if (cur_trans->status == nmtrst_normal) {
      cur_trans->status = nmtrst_indrop;
      return;
    }
  }
#endif

  return;
}

void ss_set_normalstate_tid(union trans_id *arg,
			    unsigned char branch) {
  struct ss_priv_trans *cur_trans;
  uint16_t tid;

  if (! arg)
    return;

#ifdef COMPILING_NBNS
  if (branch == DTG_SRVC) {
#endif

  if (! nbworks_all_transactions[branch])
    return;

  cur_trans = nbworks_all_transactions[branch];

  tid = arg->tid;

  while (cur_trans) {
    if (((branch == DTG_SRVC) ?
	 (! nbworks_cmp_nbnodename(cur_trans->id.name_scope,
			   arg->name_scope)) :
	 cur_trans->id.tid == tid) &&
	cur_trans->status != nmtrst_deregister) {
      cur_trans->status = nmtrst_normal;
      return;
    }
    cur_trans = cur_trans->next;
  }
#ifdef COMPILING_NBNS
  } else {
    cur_trans = ss_alltrans[arg->tid].privtrans;
    if (cur_trans->status != nmtrst_deregister) {
      cur_trans->status = nmtrst_indrop;
      return;
    }
  }
#endif

  return;
}


/* returns: 1=success, 0=failure, -1=error */
inline int ss_name_send_pckt(struct name_srvc_packet *pckt,
			     struct sockaddr_in *addr,
			     struct ss_queue *trans) {
  struct ss_unif_pckt_list *trans_pckt;

  if (trans)
    if (trans->outgoing && pckt && addr) {
      trans_pckt = malloc(sizeof(struct ss_unif_pckt_list));
      if (! trans_pckt) {
	/* TODO: errno signaling stuff */
	return -1;
      }

      trans_pckt->for_del = pckt->for_del;
      trans_pckt->packet = pckt;
      trans_pckt->stream.sckt = -1;
      memcpy(&(trans_pckt->addr), addr, sizeof(struct sockaddr_in));
      trans_pckt->dstry = &destroy_name_srvc_pckt;
      trans_pckt->next = 0;

      /* Add packet to queue. */
      trans->outgoing->next = trans_pckt;
      /* Move the queue pointer. */
      trans->outgoing = trans_pckt;

      pckt->stuck_in_transit = TRUE;
#ifdef COMPILING_NBNS
      ss_alltrans[pckt->header.transaction_id].ss_iosig |= SS_IOSIG_OUT;
#endif

      return 1;
    };

  return -1;
}

/* returns: 1=success, 0=failure, -1=error */
inline int ss_dtg_send_pckt(struct dtg_srvc_recvpckt *pckt,
			    struct sockaddr_in *addr,
			    struct ss_queue *trans) {
  struct ss_unif_pckt_list *trans_pckt;

  if (trans)
    if (trans->outgoing && pckt && addr) {
      trans_pckt = malloc(sizeof(struct ss_unif_pckt_list));
      if (! trans_pckt) {
	/* TODO: errno signaling stuff */
	return -1;
      }

      trans_pckt->for_del = pckt->for_del;
      trans_pckt->packet = pckt;
      trans_pckt->stream.sckt = -1;
      memcpy(&(trans_pckt->addr), addr, sizeof(struct sockaddr_in));
      trans_pckt->dstry = &destroy_dtg_srvc_recvpckt;
      trans_pckt->next = 0;

      trans->outgoing->next = trans_pckt;
      trans->outgoing = trans_pckt;

      return 1;
    };

  return -1;
}

inline void *ss__recv_pckt(struct ss_queue *trans,
			   ipv4_addr_t listen) {
  struct ss_unif_pckt_list *holdme;
  ipv4_addr_t real_listen;
  void *result;

  if (! trans)
    return 0;
  if (! trans->incoming)
    return 0;

  fill_32field(listen, (unsigned char *)&(real_listen));

  do {
    result = trans->incoming->packet;
    trans->incoming->packet = 0;
    /* TCP-INSERTION */
    if (trans->incoming->stream.sckt >= 0)
      close(trans->incoming->stream.sckt);

    if (result) {
      if (real_listen &&
	  (trans->incoming->addr.sin_addr.s_addr != real_listen)) {
	trans->incoming->dstry(result, 1, 1);
      } else {
	if (trans->incoming->next) {
	  holdme = trans->incoming;
	  trans->incoming = trans->incoming->next;
	  /* NOTETOSELF: This is safe. */
	  free(holdme);
	}
	break;
      }
    }

    if (trans->incoming->next) {
      holdme = trans->incoming;
      trans->incoming = trans->incoming->next;
      /* NOTETOSELF: This too is safe. */
      free(holdme);
    } else {
      result = 0;
      break;
    }
  } while (0101);

  return result;
}

inline struct ss_unif_pckt_list *ss__recv_entry(struct ss_queue *trans) {
  struct ss_unif_pckt_list *result;

  if (! trans)
    return 0;

  result = trans->incoming;

  if (trans->incoming)
    if (trans->incoming->next)
      trans->incoming = trans->incoming->next;

  return result;
}

inline void ss__dstry_recv_queue(struct ss_queue *trans) {
  struct ss_unif_pckt_list *for_del;

  if (! trans)
    return;

  while (trans->incoming) {
    if (trans->incoming->packet &&
	trans->incoming->dstry)
      trans->incoming->dstry(trans->incoming->packet, 1, 1);
    if (trans->incoming->stream.sckt >= 0)
      close(trans->incoming->stream.sckt);
    for_del = trans->incoming;
    trans->incoming = trans->incoming->next;
    /* NOTETOSELF: This is safe. */
    free(for_del);
  }

  return;
}


struct ses_srv_rails *ss__add_sessrv(struct nbworks_nbnamelst *name,
				     int rail) {
  struct pollfd pfd;
  struct ses_srv_rails *result, *cur_srv, **last_srv;

  if ((! name) ||
      (rail < 0))
    return 0;

  pfd.events = POLLOUT;

  result = malloc(sizeof(struct ses_srv_rails));
  if (! result)
    return 0;

  result->name = nbworks_clone_nbnodename(name);
  result->rail = rail;
  result->next = 0;

  while (218) {
    last_srv = &(nbworks_all_session_srvrs);
    cur_srv = *last_srv;

    while (cur_srv) {
      if (0 == nbworks_cmp_nbnodename(cur_srv->name, name)) {
	if (cur_srv == result)
	  return result;
	else {
	  pfd.fd = cur_srv->rail;
	  poll(&pfd, 1, 0);
	  if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) &&
	      (! (pfd.revents & POLLOUT))) {
	    *last_srv = cur_srv->next;
	    close(cur_srv->rail);
	    nbworks_dstr_nbnodename(cur_srv->name);
	    free(cur_srv);

	  } else {
	    nbworks_dstr_nbnodename(result->name);
	    free(result);
	    return 0;
	  }
	}
      } else {
	last_srv = &(cur_srv->next);
      }

      cur_srv = *last_srv;
    }

    *last_srv = result;
  }
}

struct ses_srv_rails *ss__find_sessrv(struct nbworks_nbnamelst *name) {
  struct ses_srv_rails *result;

  result = nbworks_all_session_srvrs;
  while (result) {
    if (0 == nbworks_cmp_nbnodename(result->name, name))
      break;
    else
      result = result->next;
  }

  return result;
}

void ss__del_sessrv(struct nbworks_nbnamelst *name) {
  struct ses_srv_rails *cur_srv, **last_srv;

  last_srv = &(nbworks_all_session_srvrs);
  cur_srv = *last_srv;

  while (cur_srv) {
    if (0 == nbworks_cmp_nbnodename(cur_srv->name, name)) {
      *last_srv = cur_srv->next;
      nbworks_dstr_nbnodename(cur_srv->name);
      close(cur_srv->rail);
      free(cur_srv);

      return;
    } else {
      last_srv = &(cur_srv->next);
      cur_srv = *last_srv;
    }
  }

  return;
}


void ss__kill_allservrs(unsigned char *name_ptr, /* len == NETBIOS_NAME_LEN */
			struct nbworks_nbnamelst *scope) {
  struct nbworks_nbnamelst target_name;
  union trans_id id;
  unsigned char target_label[NETBIOS_CODED_NAME_LEN];

  if (! name_ptr)
    return;

  target_name.name = target_label;
  encode_nbnodename(name_ptr, target_label);
  target_name.len = NETBIOS_CODED_NAME_LEN;
  target_name.next_name = scope;

  id.name_scope = &target_name;

  ss_del_queuestorage(&id, DTG_SRVC);
  ss__del_sessrv(&target_name);

  return;
}


struct ses_srv_sessions *ss__add_session(token_t token,
					 int out_sckt,
					 unsigned char *first_buff) {
  struct ses_srv_sessions *result, *cur_ses, **last_ses;

  result = malloc(sizeof(struct ses_srv_sessions));
  if (! result) {
    return 0;
  }

  result->token = token;
  result->out_sckt = out_sckt;
  result->first_buff = first_buff;
  result->numof_passes = 0;
  result->next = 0;

  while (0xb00b5) {
    cur_ses = nbworks_all_sessions;
    last_ses = &(nbworks_all_sessions);

    while (cur_ses) {
      if (cur_ses->token == token) {
	if (cur_ses != result) {
	  free(result);
	  return 0;
	} else
	  return result;
      } else {
	last_ses = &(cur_ses->next);
	cur_ses = cur_ses->next;
      }
    }

    *last_ses = result;
  }
}

struct ses_srv_sessions *ss__find_session(token_t token) {
  struct ses_srv_sessions *result;

  result = nbworks_all_sessions;
  while (result) {
    if (result->token == token)
      break;
    else
      result = result->next;
  }

  return result;
}

struct ses_srv_sessions *ss__take_session(token_t token) {
  struct ses_srv_sessions *cur_ses, **last_ses;

  last_ses = &(nbworks_all_sessions);
  cur_ses = *last_ses;
  while (cur_ses) {
    if (cur_ses->token == token) {
      *last_ses = cur_ses->next;
      return cur_ses;
    } else {
      last_ses = &(cur_ses->next);
      cur_ses = *last_ses;
    }
  }

  return 0;
}

void ss__del_session(token_t token,
		     unsigned char close_sckt) {
  struct ses_srv_sessions *cur_ses, **last_ses;

  last_ses = &(nbworks_all_sessions);
  cur_ses = *last_ses;
  while (cur_ses) {
    if (cur_ses->token == token) {
      *last_ses = cur_ses->next;
      if (close_sckt)
	close(cur_ses->out_sckt);
      free(cur_ses);
      return;
    } else {
      last_ses = &(cur_ses->next);
      cur_ses = *last_ses;
    }
  }

  return;
}

void ss__prune_sessions(void) {
  struct ses_srv_sessions *cur_ses, **last_ses;

  last_ses = &(nbworks_all_sessions);
  cur_ses = *last_ses;
  while (cur_ses) {
    if (cur_ses->numof_passes >
	nbworks_pruners_cntrl.passes_ses_srv_ses) {
      *last_ses = cur_ses->next;
      close(cur_ses->out_sckt);
      free(cur_ses);
    } else {
      last_ses = &(cur_ses->next);
      cur_ses->numof_passes++;
    }

    cur_ses = *last_ses;
  }

  return;
}


#ifdef COMPILING_NBNS
int fill_all_nametrans(struct ss_priv_trans **where) {
  struct ss_priv_trans *new_trans, **last_trans;
  uint32_t index;

  last_trans = &(nbworks_all_transactions[NAME_SRVC]);
  memset(ss_alltrans, 0, (MAXNUMOF_TIDS * sizeof(struct ss__NBNStrans)));

  for (index = 0; index < MAXNUMOF_TIDS; index++) {

    new_trans = malloc(sizeof(struct ss_priv_trans));
    if (! new_trans) {
      /* TODO: errno signaling stuff */
      *last_trans = 0;
      return 0;
    }
    new_trans->in = calloc(1, sizeof(struct ss_unif_pckt_list));
    if (! new_trans->in) {
      /* TODO: errno signaling stuff */
      *last_trans = 0;
      free(new_trans);
      return 0;
    }
    new_trans->in->stream.sckt = -1;
    new_trans->out = calloc(1, sizeof(struct ss_unif_pckt_list));
    if (! new_trans->out) {
      /* TODO: errno signaling stuff */
      *last_trans = 0;
      free(new_trans->in);
      free(new_trans);
      return 0;
    }
    new_trans->out->stream.sckt = -1;
    new_trans->id.tid = index;
    new_trans->status = nmtrst_normal;

    ss_alltrans[index].privtrans = new_trans;

    *last_trans = new_trans;
    last_trans = &(new_trans->next);

    ss_alltrans[index].trans.incoming = new_trans->in;
    ss_alltrans[index].trans.outgoing = new_trans->out;
  }

  *last_trans = 0;

  return 1;
}
#endif


void *ss__port137(void *placeholder) {
  struct ss_sckts sckts;
  struct sockaddr_in my_addr;
  pthread_t thread[2];
  int ret_val, i;

  my_addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(my_addr.sin_port));
  /* The use of INADDR_ANY macro in the below line has a positive effect
   * in that it will enable me to listen to any and all traffic. However,
   * it also has a bad effect on hosts with multiple interfaces (that is,
   * multiple IP addresses assigned to it). These hosts may sometimes send
   * packets which list an address different that the address listed in
   * the packet itself. My own algorithms, and presumably others too, will
   * discard and ignore the content of such packets. */
  my_addr.sin_addr.s_addr = INADDR_ANY;

  sckts.isbusy = 0xda;
  sckts.all_trans = &(nbworks_all_transactions[NAME_SRVC]);
#ifdef COMPILING_NBNS
  if (! fill_all_nametrans(sckts.all_trans)) {
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }
#endif
  sckts.newtid_handler = &name_srvc_handle_newtid;
  sckts.pckt_dstr = &destroy_name_srvc_pckt;
  sckts.master_writer = &master_name_srvc_pckt_writer;
  sckts.master_reader = &master_name_srvc_pckt_reader;
  sckts.branch = NAME_SRVC;
  sckts.tcp_sckt = socket(PF_INET, SOCK_STREAM, 0);
  sckts.udp_sckt = socket(PF_INET, SOCK_DGRAM, 0);

  if ((sckts.udp_sckt < 0) ||
      (sckts.tcp_sckt < 0)) {
    /* TODO: errno signaling stuff */
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }
/*
  if (0 != set_sockoption(sckts.udp_sckt, NONBLOCKING)) {
    /_* TODO: errno signaling stuff *_/
    close(sckts.udp_sckt);
    //XXX    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }*/
  /* XXX
  if (0 != set_sockoption(sckts.tcp_sckt, NONBLOCKING)) {
    /_* TODO: errno signaling stuff *_/
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    return 0;
  }
*/
#ifndef COMPILING_NBNS
  if (0 != set_sockoption(sckts.udp_sckt, BROADCAST)) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }
#endif

  ret_val = bind(sckts.udp_sckt, (struct sockaddr *)&my_addr,
		 sizeof(struct sockaddr_in));
  if (ret_val < 0) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }

  ret_val = bind(sckts.tcp_sckt, (struct sockaddr *)&my_addr,
		 sizeof(struct sockaddr_in));
  if (ret_val < 0) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    return 0;
  }

  ret_val = listen(sckts.tcp_sckt, MAX_NAME_TCP_QUEUE);
  if (ret_val < 0) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    return 0;
  }

  thread[0] = 0;
  thread[1] = 0;

  /* There HAS to be a very, very special place in
     hell for people as evil as I am. */
  ret_val = pthread_create(&(thread[0]), 0,
			   &ss__udp_sender, &sckts);
  if (ret_val) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }

  while (sckts.isbusy) {
    /* busy-wait */
  }
  sckts.isbusy = 0xda;

  ret_val = pthread_create(&(thread[1]), 0,
			   &ss__cmb_recver, &sckts);
  if (ret_val) {
    /* TODO: errno signaling stuff */
    pthread_cancel(thread[0]);
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }

  while (sckts.isbusy) {
    /* busy-wait */
  }
  sckts.isbusy = 0xda;

  for (i=0; i < 2; i++) {
    pthread_join(thread[i], 0);
  }

  close(sckts.udp_sckt);
  close(sckts.tcp_sckt);

  return (void *)ONES;
}

void *ss__port138(void *i_dont_actually_use_this) {
  struct ss_sckts sckts;
  struct sockaddr_in my_addr;
  pthread_t thread[2];
  int counter;

  my_addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(138, (unsigned char *)&(my_addr.sin_port));
  my_addr.sin_addr.s_addr = INADDR_ANY;

  sckts.isbusy = 0xda;
  sckts.all_trans = &(nbworks_all_transactions[DTG_SRVC]);
  sckts.newtid_handler = 0; /* Datagram service does not use newtid handlers. */
  sckts.pckt_dstr = &destroy_dtg_srvc_recvpckt;
  sckts.master_writer = &sending_dtg_srvc_pckt_writer;
  sckts.master_reader = &recving_dtg_srvc_pckt_reader;
  sckts.branch = DTG_SRVC;
  sckts.udp_sckt = socket(PF_INET, SOCK_DGRAM, 0);

  if (sckts.udp_sckt < 0) {
    /* TODO: errno signaling stuff */
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  if (0 != set_sockoption(sckts.udp_sckt, NONBLOCKING)) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  if (0 != set_sockoption(sckts.udp_sckt, BROADCAST)) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  if (0 != bind(sckts.udp_sckt, (struct sockaddr *)&my_addr,
	       sizeof(struct sockaddr_in))) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  if (pthread_create(&(thread[0]), 0,
		     &ss__cmb_recver, &sckts)) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  while (sckts.isbusy) {
    /* busy-wait */
  }
  sckts.isbusy = 0xda;

  if (pthread_create(&(thread[1]), 0,
		     &ss__udp_sender, &sckts)) {
    /* TODO: errno signaling stuff */
    pthread_cancel(thread[0]);
    close(sckts.udp_sckt);
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  for (counter = 0; counter < 2; counter++) {
    pthread_join(thread[counter], 0);
  }

  close(sckts.udp_sckt);

  return (void *)ONES;
}


struct ss_unif_pckt_list *ss__recv_tcppckt(struct ss_sckts *sckts,
					   struct pollfd *tcp_pfd,
					   uint16_t *tid) {
  struct sockaddr_in his_addr;
  struct ss_unif_pckt_list *new_pckt;
  socklen_t addr_len;

  addr_len = sizeof(struct sockaddr_in);
  if (0 >= poll(tcp_pfd, 1, 0))
    return 0;

  new_pckt = malloc(sizeof(struct ss_unif_pckt_list));
  if (! new_pckt)
    return 0;

  new_pckt->stream.sckt = accept(sckts->tcp_sckt, (struct sockaddr *)&his_addr,
				 &addr_len);
  if (new_pckt->stream.sckt < 0) {
    free(new_pckt);
    return 0;
  }

  if (2 > recv(new_pckt->stream.sckt, new_pckt->stream.buff, 2, MSG_DONTWAIT)) {
    close(new_pckt->stream.sckt);
    free(new_pckt);
    return 0;
  }

  read_16field(new_pckt->stream.buff, tid);

  new_pckt->packet = 0;
  memcpy(&(new_pckt->addr), &his_addr, sizeof(struct sockaddr_in));
  new_pckt->dstry = sckts->pckt_dstr; /* Don't play with fire. */
  new_pckt->next = 0;

  return new_pckt;
}

struct ss_unif_pckt_list *ss__recv_udppckt(struct ss_sckts *sckts,
					   struct pollfd *udp_pfd,
					   uint16_t *tid,
					   unsigned char *udp_pckt,
					   ipv4_addr_t discard_add_NETWRK,
					   struct nbworks_nbnamelst **name_as_id) {
  struct ss_unif_pckt_list *new_pckt;
  struct sockaddr_in his_addr;
  struct nbworks_nbnamelst *name_id;
  ssize_t len;
  socklen_t addr_len;

  addr_len = sizeof(struct sockaddr_in);
  if (0 >= poll(udp_pfd, 1, 0))
    return 0;

  len = recvfrom(sckts->udp_sckt, udp_pckt, MAX_UDP_PACKET_LEN,
		 /*MSG_DONTWAIT*/0, (struct sockaddr *)&his_addr, &addr_len);
  /* BUG: While testing, I have noticed that there appears to be
   *      a very strange behaviour regarding len.
   *      Sometimes, the below test passes (indicating len is either
   *      0 or positive), but if you read it after the if block,
   *      it is -1! This behaviour dissapears if the socket is blocking
   *      (the call to recvfrom() blocks). The only explanation so far
   *      is that recvfrom returns, but then retroactivelly fails and
   *      overwrites len to -1.
   *      The other explanation is that GCC fucks things up (again).
   *
   * perror() displays "Resource temporarily unavailable" */
  /* the below line used to read (len < 0) */
  if (len <= 0) {
    if (errno == EAGAIN ||
	errno == EWOULDBLOCK) {
      return 0;
    } else {
      /* TODO: error handling */
      return 0;
    }
  }

#ifndef VISIBLE_BREAKERS
  /* A *HORRIBLE* hack to enable us to receive datagrams
   * sent to other nodes on this same machine. */
  if ((his_addr.sin_addr.s_addr == discard_add_NETWRK) &&
      (sckts->branch != DTG_SRVC)) {
    return 0;
  }
#endif

  new_pckt = malloc(sizeof(struct ss_unif_pckt_list));
  if (! new_pckt)
    return 0;
  new_pckt->packet = sckts->master_reader(udp_pckt, len, tid);

  if (new_pckt->packet) {
#ifndef COMPILING_NBNS
    if ((sckts->branch == DTG_SRVC) &&
	(name_as_id)) {
      name_id = dtg_srvc_get_srcnam_recvpckt(new_pckt->packet);
      if ((! name_id) ||
	  (! name_id->name) ||
	  (name_id->len != NETBIOS_CODED_NAME_LEN)) {
	sckts->pckt_dstr(new_pckt->packet, 1, 1);
	free(new_pckt);
	return 0;
      }
      *name_as_id = name_id;
    }
#endif

    new_pckt->stream.sckt = -1;
    memcpy(&(new_pckt->addr), &his_addr, sizeof(struct sockaddr_in));
    new_pckt->dstry = sckts->pckt_dstr;
    new_pckt->next = 0;
  } else {
    // FIXME: Handle datagram service error packets.

    free(new_pckt);
    new_pckt = 0;
  }

  return new_pckt;
}

void *ss__cmb_recver(void *sckts_ptr) {
  struct ss_sckts sckts, *release_lock;
  struct ss_unif_pckt_list *new_pckt;
  struct ss_priv_trans *cur_trans;
#ifdef COMPILING_NBNS
  pthread_t threadid;
#else
  struct ss_priv_trans **last_trans, *new_trans, *hold_nwtrns;
  struct ss_queue *newtid_queue;
#endif
  struct newtid_params params;
  struct pollfd pollfds[2], *udp_pfd, *tcp_pfd;
  struct nbworks_nbnamelst *name_as_id;
  nfds_t numof_pfds;
  int ret_val;
  ipv4_addr_t discard_add, discard_add_NETWRK;
  uint16_t tid;
  unsigned char udp_pckt[MAX_UDP_PACKET_LEN];

  if (! sckts_ptr)
    return 0;

  memcpy(&sckts, sckts_ptr, sizeof(struct ss_sckts));
  release_lock = sckts_ptr;
  release_lock->isbusy = 0;

#ifdef COMPILING_NBNS
  if (sckts.branch == DTG_SRVC) {
    return 0;
  }

  if (0 != pthread_create(&threadid, 0,
			  name_srvc_NBNS_newtid, &threadid)) {
    return 0;
  }
  while (threadid) {
    /* busy-wait */
  }
#endif

  name_as_id = 0;
  discard_add = nbworks__myip4addr;

  udp_pfd = &(pollfds[0]);
  tcp_pfd = &(pollfds[1]);
  udp_pfd->fd = sckts.udp_sckt;
  udp_pfd->events = (POLLIN | POLLPRI);
  tcp_pfd->fd = sckts.tcp_sckt;
  tcp_pfd->events = (POLLIN | POLLPRI);
  params.isbusy = 0;
  if (sckts.branch == DTG_SRVC)
    numof_pfds = 1;
  else
    numof_pfds = 2;

#define make_new_queue						\
  newtid_queue = malloc(sizeof(struct ss_queue));		\
  if (! newtid_queue) {						\
    /* TODO: errno signaling stuff */				\
    return 0;							\
  }								\
								\
  new_trans = malloc(sizeof(struct ss_priv_trans));		\
  if (! new_trans) {						\
    /* TODO: errno signaling stuff */				\
    free(newtid_queue);						\
    return 0;							\
  }								\
  new_trans->in = calloc(1, sizeof(struct ss_unif_pckt_list));	\
  if (! new_trans->in) {					\
    /* TODO: errno signaling stuff */				\
    free(newtid_queue);						\
    free(new_trans);						\
    return 0;							\
  }								\
  new_trans->in->stream.sckt = -1;				\
  new_trans->out = calloc(1, sizeof(struct ss_unif_pckt_list));	\
  if (! new_trans->out) {					\
    /* TODO: errno signaling stuff */				\
    free(newtid_queue);						\
    free(new_trans->in);					\
    free(new_trans);						\
    return 0;							\
  }								\
  new_trans->out->stream.sckt = -1;				\
								\
  newtid_queue->incoming = new_trans->in;			\
  newtid_queue->outgoing = new_trans->out;                      \
								\
  new_trans->status = nmtrst_normal;				\
  new_trans->next = 0;

#ifndef COMPILING_NBNS
  if (sckts.branch == DTG_SRVC) {
    /* This is for one of the below tests. */
    new_trans = (struct ss_priv_trans *)ONES;
    newtid_queue = (struct ss_queue *)ONES;
  } else {
    make_new_queue;
  }

  hold_nwtrns = 0;
#endif

  while (! nbworks_all_port_cntl.all_stop) {
    ret_val = poll(pollfds, numof_pfds, nbworks_all_port_cntl.poll_timeout);
    if (ret_val == 0)
      continue;
    if (ret_val < 0) {
      /* TODO: error handling */
      continue;
    }


    while (0xcafe) {
      /* The below is added to enable support for changing of addresses. */
      if (discard_add != nbworks__myip4addr) {
	discard_add = nbworks__myip4addr;
	/* VAXism below */
	fill_32field(discard_add,
		     (unsigned char *)&discard_add_NETWRK);
      }

      new_pckt = ss__recv_udppckt(&sckts, udp_pfd, &tid,
				  udp_pckt, discard_add_NETWRK, &name_as_id);
      if (! new_pckt) {
	if (sckts.branch != DTG_SRVC) {
	  new_pckt = ss__recv_tcppckt(&sckts, tcp_pfd, &tid);
	  if (! new_pckt)
	    break;
	} else
	  break;
      }


#ifdef COMPILING_NBNS
      cur_trans = ss_alltrans[tid].privtrans;
      if (cur_trans->status == nmtrst_normal) {
	cur_trans->in->next = new_pckt;
	cur_trans->in = new_pckt;

	ss_alltrans[tid].ss_iosig |= SS_IOSIG_IN;
      } else {
	sckts.pckt_dstr(new_pckt->packet, 1, 1);
	if (new_pckt->stream.sckt >= 0)
	  close(new_pckt->stream.sckt);
	free(new_pckt);
      }
#else
      do {
	last_trans = sckts.all_trans;
	cur_trans = *last_trans;
	while (cur_trans) {
	  if (((sckts.branch) == DTG_SRVC) ?              /* The problem with this scheme */
	      (! nbworks_cmp_nbnodename(cur_trans->id.name_scope, /* is that it is possible for a */
				name_as_id)) :            /* torrent of datagram packets  */
	      cur_trans->id.tid == tid) {                 /* to criple the daemon.        */
	    if (cur_trans->status == nmtrst_normal) {
	      cur_trans->in->next = new_pckt;
	      cur_trans->in = new_pckt;
	      new_pckt = 0;

	      break;
	    } else {
	      /* ((cur_trans->status == nmtrst_indrop) ||
		  (cur_trans->status == nmtrst_deregister)) */
	      sckts.pckt_dstr(new_pckt->packet, 1, 1);
	      if (new_pckt->stream.sckt >= 0)
		close(new_pckt->stream.sckt);
	      free(new_pckt);
	      new_pckt = 0;

	      break;
	    }
	  } else {
	    last_trans = &(cur_trans->next);
	    cur_trans = *last_trans;
	  }
	}

	if (new_pckt) {
	  /* This means there were no previously registered transactions
	   * with this tid. If name service, register a new one and signal
	   * its existance. If datagram service, send a NOT-HERE error.
	   * MUSING: perhaps I could just drop the datagram and not send
	   *         the error. */
	  if ((sckts.branch) == DTG_SRVC) { /* There goes my terminally abstract code... */
	    //	FIXME    dtg_srvc_send_NOTHERE_error(new_pckt);
	    sckts.pckt_dstr(new_pckt->packet, 1, 1);
	    if (new_pckt->stream.sckt >= 0)
	      close(new_pckt->stream.sckt);
	    free(new_pckt);
	    new_pckt = 0;

	    break;
	  } else {
	    if (! new_trans) {
	      new_trans = hold_nwtrns;
	    }
	    new_trans->id.tid = tid;
	    *last_trans = new_trans;

	    params.id.tid = tid;
	    hold_nwtrns = new_trans;
	    new_trans = 0;

	    /* Since I _must_ implement a consistency check,
	     * the flow now goes back into the main loop. */
	  }
	}
      } while (new_pckt);
      /* Superfluous in datagram mode. */
      if (! new_trans) {
	/* Signaling the new queue. */
	while (params.isbusy) {
	  /* busy-wait */
	}
	params.isbusy = 0xda;
	params.thread_id = 0;
	params.trans = newtid_queue;
	if (0 != pthread_create(&(params.thread_id), 0,
				sckts.newtid_handler, &params)) {
	  params.isbusy = 0;
	  hold_nwtrns->status = nmtrst_deregister;
	  ss__dstry_recv_queue(newtid_queue);
	  free(newtid_queue);
	}

	make_new_queue;
      }
#endif
    }
  }

#ifndef COMPILING_NBNS
  if (sckts.branch != DTG_SRVC) {
    free(newtid_queue);
    free(new_trans->in);
    free(new_trans->out);
    free(new_trans);
  }
#endif

  return 0;
}

void *ss__udp_sender(void *sckts_ptr) {
  struct ss_sckts sckts, *release_lock;
  struct ss_unif_pckt_list *for_del;
#ifdef COMPILING_NBNS
  uint32_t index;
#else
  struct ss_priv_trans **last_trans, *for_del2;
#endif
  struct ss_priv_trans *cur_trans;
  unsigned long len, prev_len, sendlen;
  unsigned char udp_pckt[MAX_UDP_PACKET_LEN];
  void *ptr;

  if (! sckts_ptr)
    return 0;

  memcpy(&sckts, sckts_ptr, sizeof(struct ss_sckts));
  release_lock = sckts_ptr;
  release_lock->isbusy = 0;

#ifdef COMPILING_NBNS
  if (sckts.branch == DTG_SRVC) {
    return 0;
  }
#endif

  memset(udp_pckt, 0, MAX_UDP_PACKET_LEN);
  prev_len = 0;

  while (! nbworks_all_port_cntl.all_stop) {
#ifdef COMPILING_NBNS
    sendlen = nbworks_namsrvc_cntrl.name_srvc_max_udppckt_len;
    if (sendlen > MAX_UDP_PACKET_LEN)
      sendlen = MAX_UDP_PACKET_LEN;
      /* In NBNS mode of operation, it is not possible to deregister a transaction. */
    for (index = 0; index < MAXNUMOF_TIDS; index++) {
      if (ss_alltrans[index].ss_iosig & SS_IOSIG_MASK_OUT) {
	cur_trans = ss_alltrans[index].privtrans;
#else
    if (sckts.branch == DTG_SRVC)
      sendlen = MAX_UDP_PACKET_LEN;
    else {
      sendlen = nbworks_namsrvc_cntrl.name_srvc_max_udppckt_len;
      if (sendlen > MAX_UDP_PACKET_LEN)
	sendlen = MAX_UDP_PACKET_LEN;
    }
    cur_trans = *(sckts.all_trans);
    last_trans = sckts.all_trans;
    while (cur_trans) {
      /* Special treatment of deregistered transactions. */
      if (cur_trans->status == nmtrst_deregister) {
	*last_trans = cur_trans->next;

	while (cur_trans->out) {
	  if (cur_trans->out->packet) {
	    ptr = cur_trans->out->packet;
	    len = sendlen;
	    sckts.master_writer(ptr, &len, udp_pckt, TRANSIS_UDP);
	    if (prev_len > len) {
	      memset((udp_pckt + prev_len), 0, (prev_len - len));
	    }
	    prev_len = len;

	    sendto(sckts.udp_sckt, udp_pckt, len, MSG_NOSIGNAL,
		   (struct sockaddr *)&(cur_trans->out->addr),
		   sizeof(cur_trans->out->addr));

	    if (cur_trans->out->for_del)
	      sckts.pckt_dstr(cur_trans->out->packet, 1, 1);
	  }

	  for_del = cur_trans->out;
	  cur_trans->out = cur_trans->out->next;
	  if (for_del->stream.sckt >= 0)
	    close(for_del->stream.sckt);
	  free(for_del);
	}

	for_del2 = cur_trans;
	cur_trans = cur_trans->next;
	/* BUG: There is a (trivial?) chance of use-after-free. */
	free(for_del2);
      } else {
#endif
	while (cur_trans->out->next) {
	  if (cur_trans->out->packet) {
	    ptr = cur_trans->out->packet;
	    len = sendlen;
	    sckts.master_writer(ptr, &len, udp_pckt, TRANSIS_UDP);
	    if (prev_len > len) {
	      memset((udp_pckt + prev_len), 0, (prev_len - len));
	    }
	    prev_len = len;

	    sendto(sckts.udp_sckt, udp_pckt, len, MSG_NOSIGNAL,
		   (struct sockaddr *)&(cur_trans->out->addr),
		   sizeof(cur_trans->out->addr));

	    if (cur_trans->out->for_del)
	      sckts.pckt_dstr(cur_trans->out->packet, 1, 1);
	  }

	  for_del = cur_trans->out;
	  cur_trans->out = cur_trans->out->next;
	  if (for_del->stream.sckt >= 0)
	    close(for_del->stream.sckt);
	  free(for_del);
	}

	if (cur_trans->out->packet) {
	  ptr = cur_trans->out->packet;
	  len = sendlen;
	  sckts.master_writer(ptr, &len, udp_pckt, TRANSIS_UDP);
	  if (prev_len > len) {
	    memset((udp_pckt + prev_len), 0, (prev_len - len));
	  }
	  prev_len = len;

	  sendto(sckts.udp_sckt, udp_pckt, len, MSG_NOSIGNAL,
		 (struct sockaddr *)&(cur_trans->out->addr),
		 sizeof(cur_trans->out->addr));

	  if (cur_trans->out->for_del)
	    sckts.pckt_dstr(cur_trans->out->packet, 1, 1);
	  cur_trans->out->packet = 0;
	};
	if (cur_trans->out->stream.sckt >= 0)
	  close(cur_trans->out->stream.sckt);
#ifndef COMPILING_NBNS

	last_trans = &(cur_trans->next);
	cur_trans = cur_trans->next;
      }
    }
#else
      }
    }
#endif

    nanosleep(&(nbworks_all_port_cntl.sleeptime), 0);
  }

  return 0;
}


void *ss__port139(void *args) {
  struct ss_tcp_sckts params;
  struct pollfd pfd;
  struct sockaddr_in port_addr;
  ssize_t ret_val;
  int sckt139, new_sckt;

  port_addr.sin_family = AF_INET;
  /* VAXism below */
  fill_16field(139, (unsigned char *)&(port_addr.sin_port));
  fill_32field(nbworks__myip4addr,
	       (unsigned char *)&(port_addr.sin_addr.s_addr));

  sckt139 = socket(PF_INET, SOCK_STREAM, 0);
  if (sckt139 < 0) {
    return 0;
  }

  if (0 != set_sockoption(sckt139, NONBLOCKING)) {
    /* TODO: errno signaling stuff */
    close(sckt139);
    return 0;
  }

  if (0 != bind(sckt139, (struct sockaddr *)&port_addr,
		sizeof(struct sockaddr_in))) {
    close(sckt139);
    return 0;
  }

  if (0 != listen(sckt139, SOMAXCONN)) {
    close(sckt139);
    return 0;
  }

  pfd.fd = sckt139;
  pfd.events = POLLIN;

  params.isbusy = 0;
  params.servers = &(nbworks_all_session_srvrs);
  params.thread_id = 0;
  while (! nbworks_ses_srv_cntrl.all_stop) {
    ret_val = poll(&pfd, 1, nbworks_ses_srv_cntrl.poll_timeout);
    if (ret_val <= 0) {
      if (ret_val == 0) {
	continue;
      } else {
	/* TODO: error handling */
	continue;
      }
    }

    new_sckt = accept(sckt139, 0, 0);
    if (new_sckt < 0) {
      continue;
    } else {
      params.sckt139 = new_sckt;
      take_incoming_session(&params);
    }
  }

  close(sckt139);
  return nbworks_all_session_srvrs;
}

void *take_incoming_session(void *arg) {
  struct ses_srvc_packet new_pckt;
  struct ss_tcp_sckts params, *release_lock;
  struct ses_srv_rails *servers;
  struct nbworks_nbnamelst *called_name;
  struct ses_srv_sessions *session;
  struct thread_node *last_will;
  token_t token;
  unsigned char buf[SES_HEADER_LEN+1]; /* +1 is for the error code */
  //  unsigned char decoded_name[NETBIOS_CODED_NAME_LEN+1];
  unsigned char err[] = { NEG_SESSION_RESPONSE, 0, 0, 1, SES_ERR_NOCALLED };
  unsigned char *walker, *big_buff;

  memcpy(&params, arg, sizeof(struct ss_tcp_sckts));
  release_lock = arg;
  release_lock->isbusy = 0;

  if (params.thread_id)
    last_will = add_thread(params.thread_id);
  else
    last_will = 0;

  memset(&new_pckt, 0, sizeof(struct ses_srvc_packet));
  memset(buf, 0, (SES_HEADER_LEN+1));

  if (SES_HEADER_LEN > recv(params.sckt139, buf,
			    SES_HEADER_LEN, MSG_WAITALL)) {
    err[4] = SES_ERR_UNSPEC;
    send(params.sckt139, err, 5, MSG_NOSIGNAL);

    close(params.sckt139);
    if (last_will)
      last_will->dead = 0xda; /* My favourite line. */
    return 0;
  }

  if (buf[0] != SESSION_REQUEST) {
    err[4] = SES_ERR_UNSPEC;
    send(params.sckt139, err, 5, MSG_NOSIGNAL);

    close(params.sckt139);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  walker = buf;
  if (! read_ses_srvc_pckt_header(&walker, buf+SES_HEADER_LEN, &new_pckt)) {
    err[4] = SES_ERR_UNSPEC;
    send(params.sckt139, err, 5, MSG_NOSIGNAL);

    close(params.sckt139);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  if (two_names != (new_pckt.payload_t =
		    understand_ses_pckt_type(new_pckt.type))) {
    /* Sorry, wrong daemon. */
    err[4] = SES_ERR_UNSPEC;
    send(params.sckt139, err, 5, MSG_NOSIGNAL);

    close(params.sckt139);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  big_buff = malloc(new_pckt.len+SES_HEADER_LEN);
  if (! big_buff) {
    err[4] = SES_ERR_UNSPEC;
    send(params.sckt139, err, 5, MSG_NOSIGNAL);

    close(params.sckt139);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  memcpy(big_buff, buf, SES_HEADER_LEN);

  if (new_pckt.len > recv(params.sckt139, (big_buff+SES_HEADER_LEN),
			  new_pckt.len, MSG_WAITALL)) {
    err[4] = SES_ERR_UNSPEC;
    send(params.sckt139, err, 5, MSG_NOSIGNAL);

    free(big_buff);
    close(params.sckt139);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  called_name = ses_srvc_get_calledname(big_buff, (new_pckt.len+SES_HEADER_LEN));
  if ((! called_name) ||
      (called_name->len != NETBIOS_CODED_NAME_LEN)) {
    err[4] = SES_ERR_UNSPEC;
    send(params.sckt139, err, 5, MSG_NOSIGNAL);

    free(big_buff);
    close(params.sckt139);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  //  memcpy(decoded_name, called_name->name, NETBIOS_CODED_NAME_LEN);
  //  called_name->name = decode_nbnodename(decoded_name, called_name->name);
  //  called_name->len = NETBIOS_NAME_LEN;

  servers = *(params.servers);
  while (servers) {
    if (0 != nbworks_cmp_nbnodename(called_name, servers->name))
      servers = servers->next;
    else
      break;
  }

  if (servers) {
    token = make_token();
    if (0 != set_sockoption(params.sckt139, NONBLOCKING)) {
      err[4] = SES_ERR_UNSPEC;
      send(params.sckt139, err, 5, MSG_NOSIGNAL);

      free(big_buff);
      close(params.sckt139);
      if (last_will)
	last_will->dead = TRUE;
      return 0;
    }

    if (! ((session = ss__add_session(token, params.sckt139, big_buff)) &&
	   (0 < rail__send_ses_pending(servers->rail, token)))) {
      if (session)
	ss__del_session(token, FALSE);

      err[4] = SES_ERR_UNSPEC;
      send(params.sckt139, err, 5, MSG_NOSIGNAL);

      free(big_buff);
      close(params.sckt139);
      if (last_will)
	last_will->dead = TRUE;
      return 0;
    }
  } else {
    send(params.sckt139, err, 5, MSG_NOSIGNAL);

    free(big_buff);
    close(params.sckt139);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  if (last_will)
    last_will->dead = TRUE;
  return 0;
}


void ss_check_all_ses_server_rails(void) {
  struct ses_srv_rails *cur_rail, **last_rail;
  struct pollfd pfd;

  pfd.events = POLLOUT;

  last_rail = &(nbworks_all_session_srvrs);
  cur_rail = *last_rail;
  while (cur_rail) {
    pfd.fd = cur_rail->rail;
    poll(&pfd, 1, 0);

    if (pfd.revents & POLLHUP) {
      *last_rail = cur_rail->next;
      close(cur_rail->rail);
      free(cur_rail);
    } else {
      last_rail = &(cur_rail->next);
    }
    cur_rail = *last_rail;
  }

  return;
}
