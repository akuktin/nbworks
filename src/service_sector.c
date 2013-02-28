#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 199309
#endif
#include <time.h>
#include <errno.h>

#include <pthread.h>

#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "daemon_control.h"
#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_func_B.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_func.h"
#include "ses_srvc_pckt.h"
#include "randomness.h"
#include "service_sector.h"
#include "service_sector_threads.h"
#include "rail-comm.h"


struct ss_priv_trans *nbworks_all_transactions[2];
struct ss_queue_storage *nbworks_queue_storage[2];
struct ses_srv_rails *nbworks_all_session_srvrs;
struct ses_srv_sessions *nbworks_all_sessions;


void init_service_sector() {
  nbworks_all_transactions[0] = 0;
  nbworks_all_transactions[1] = 0;

  nbworks_queue_storage[0] = 0;
  nbworks_queue_storage[1] = 0;

  nbworks_all_session_srvrs = 0;
  nbworks_all_sessions = 0;

  nbworks_all_port_cntl.all_stop = 0;
  nbworks_all_port_cntl.sleeptime.tv_sec = 0;
  nbworks_all_port_cntl.sleeptime.tv_nsec = T_10MS;
  nbworks_all_port_cntl.poll_timeout = TP_10MS;

  nbworks_dtg_srv_cntrl.all_stop = 0;
  nbworks_dtg_srv_cntrl.dtg_srv_sleeptime.tv_sec = 0;
  nbworks_dtg_srv_cntrl.dtg_srv_sleeptime.tv_nsec = T_10MS;

  nbworks_ses_srv_cntrl.all_stop = 0;
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
  my_trans->out = calloc(1, sizeof(struct ss_unif_pckt_list));
  if (! my_trans->out) {
    /* TODO: errno signaling stuff */
    free(result);
    free(my_trans->in);
    free(my_trans);
    return 0;
  }
  if (branch == DTG_SRVC)
    my_trans->id.name_scope = clone_nbnodename(arg->name_scope);
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
	   (! cmp_nbnodename(cur_trans->id.name_scope,
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
	    destroy_nbnodename(my_trans->id.name_scope);
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

  if (! nbworks_all_transactions[branch])
    return;

  cur_trans = nbworks_all_transactions[branch];

  tid = arg->tid;

  while (cur_trans) {
    if ((branch == DTG_SRVC ?
	 (! cmp_nbnodename(cur_trans->id.name_scope,
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
    result->id.name_scope = clone_nbnodename(arg->name_scope);
  else {
    tid = arg->tid;
    result->id.tid = tid;
  }
  result->last_active = ZEROONES -1;
  result->rail = 0;
  result->queue.incoming = queue->incoming;
  result->queue.outgoing = queue->outgoing;
  result->next = 0;

  while (0666) {
    last_stor = &(nbworks_queue_storage[branch]);
    cur_stor = *last_stor;

    while (cur_stor) {
      if ((branch == DTG_SRVC) ?
	  (! cmp_nbnodename(cur_stor->id.name_scope,
			    arg->name_scope)) :
	  cur_stor->id.tid == tid) {
	if (cur_stor == result)
	  return result;
	else {
	  if (branch == DTG_SRVC) {
	    destroy_nbnodename(result->id.name_scope);
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
	(! cmp_nbnodename(cur_stor->id.name_scope,
			  arg->name_scope)) :
	cur_stor->id.tid == tid) {
      *last_stor = cur_stor->next;

      for_del2prim = cur_stor->rail;
      while (for_del2prim) {
	for_del2 = for_del2prim->next;
	free(for_del2prim);
	for_del2prim = for_del2;
      }

      if (branch == DTG_SRVC)
	destroy_nbnodename(cur_stor->id.name_scope);

      free(cur_stor);
      return;
    } else {
      last_stor = &(cur_stor->next);
    }

    cur_stor = *last_stor;
  }

  return;
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
	(! cmp_nbnodename(cur_stor->id.name_scope,
			  arg->name_scope)) :
	cur_stor->id.tid == tid) {
      return cur_stor;
    } else {
      cur_stor = cur_stor->next;
    }
  }

  return 0;
}

void ss_prune_queuestorage(time_t killtime) {
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

	if (cur_stor->branch == DTG_SRVC) {
	  destroy_nbnodename(cur_stor->id.name_scope);
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

  if (! nbworks_all_transactions[branch])
    return;

  cur_trans = nbworks_all_transactions[branch];

  tid = arg->tid;

  while (cur_trans) {
    if (((branch == DTG_SRVC) ?
	 (! cmp_nbnodename(cur_trans->id.name_scope,
			   arg->name_scope)) :
	 cur_trans->id.tid == tid) &&
	cur_trans->status == nmtrst_normal) {
      cur_trans->status = nmtrst_indrop;
      return;
    }
    cur_trans = cur_trans->next;
  }

  return;
}

void ss_set_normalstate_tid(union trans_id *arg,
			    unsigned char branch) {
  struct ss_priv_trans *cur_trans;
  uint16_t tid;

  if (! arg)
    return;

  if (! nbworks_all_transactions[branch])
    return;

  cur_trans = nbworks_all_transactions[branch];

  tid = arg->tid;

  while (cur_trans) {
    if (((branch == DTG_SRVC) ?
	 (! cmp_nbnodename(cur_trans->id.name_scope,
			   arg->name_scope)) :
	 cur_trans->id.tid == tid) &&
	cur_trans->status != nmtrst_deregister) {
      cur_trans->status = nmtrst_normal;
      return;
    }
    cur_trans = cur_trans->next;
  }

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
      memcpy(&(trans_pckt->addr), addr, sizeof(struct sockaddr_in));
      trans_pckt->dstry = &destroy_name_srvc_pckt;
      trans_pckt->next = 0;

      /* Add packet to queue. */
      trans->outgoing->next = trans_pckt;
      /* Move the queue pointer. */
      trans->outgoing = trans_pckt;
    };

  return 1;
}

/* returns: 1=success, 0=failure, -1=error */
inline int ss_dtg_send_pckt(struct dtg_srvc_packet *pckt,
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
      memcpy(&(trans_pckt->addr), addr, sizeof(struct sockaddr_in));
      trans_pckt->dstry = &destroy_dtg_srvc_pckt;
      trans_pckt->next = 0;

      trans->outgoing->next = trans_pckt;
      trans->outgoing = trans_pckt;

      return 1;
    };

  return -1;
}

inline void *ss__recv_pckt(struct ss_queue *trans) {
  struct ss_unif_pckt_list *holdme;
  void *result;

  if (! trans)
    return 0;
  if (! trans->incoming)
    return 0;

  result = trans->incoming->packet;
  trans->incoming->packet = 0;

  if (result) {
    if (trans->incoming->next) {
      holdme = trans->incoming;
      trans->incoming = trans->incoming->next;
      /* NOTETOSELF: This is safe. */
      free(holdme);
    }
  } else {
    if (trans->incoming->next) {
      holdme = trans->incoming;
      trans->incoming = trans->incoming->next;
      /* NOTETOSELF: This too is safe. */
      free(holdme);

      result = ss__recv_pckt(trans);
    } else {
      result = 0;
    }
  }

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
    for_del = trans->incoming;
    trans->incoming = trans->incoming->next;
    /* NOTETOSELF: This is safe. */
    free(for_del);
  }

  return;
}


struct ses_srv_rails *ss__add_sessrv(struct nbnodename_list *name,
				     int rail) {
  struct ses_srv_rails *result, *cur_srv, **last_srv;

  result = malloc(sizeof(struct ses_srv_rails));
  if (! result)
    return 0;

  result->name = clone_nbnodename(name);
  result->rail = rail;
  result->next = 0;

  while (218) {
    last_srv = &(nbworks_all_session_srvrs);
    cur_srv = *last_srv;

    while (cur_srv) {
      if (0 == cmp_nbnodename(cur_srv->name, name)) {
	if (cur_srv == result)
	  return result;
	else {
	  destroy_nbnodename(result->name);
	  free(result);
	  return 0;
	}
      } else {
	last_srv = &(cur_srv->next);
	cur_srv = *last_srv;
      }
    }

    *last_srv = result;
  }
}

struct ses_srv_rails *ss__find_sessrv(struct nbnodename_list *name) {
  struct ses_srv_rails *result;

  result = nbworks_all_session_srvrs;
  while (result) {
    if (0 == cmp_nbnodename(result->name, name))
      break;
    else
      result = result->next;
  }

  return result;
}

void ss__del_sessrv(struct nbnodename_list *name) {
  struct ses_srv_rails *cur_srv, **last_srv;

  last_srv = &(nbworks_all_session_srvrs);
  cur_srv = *last_srv;

  while (cur_srv) {
    if (0 == cmp_nbnodename(cur_srv->name, name)) {
      *last_srv = cur_srv->next;
      destroy_nbnodename(cur_srv->name);
      free(cur_srv);

      return;
    } else {
      last_srv = &(cur_srv->next);
      cur_srv = *last_srv;
    }
  }

  return;
}


struct ses_srv_sessions *ss__add_session(uint64_t token,
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

struct ses_srv_sessions *ss__find_session(uint64_t token) {
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

struct ses_srv_sessions *ss__take_session(uint64_t token) {
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

void ss__del_session(uint64_t token,
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

void ss__prune_sessions() {
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


void *ss__port137(void *placeholder) {
  struct ss_sckts sckts;
  struct sockaddr_in my_addr;
  pthread_t thread[2];/*3];*/
  unsigned int ones;
  int ret_val, i;

  ones = ONES;
  my_addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(my_addr.sin_port));
  /* The use of INADDR_ANY macro in the below line has a positive effect
   * in that it will enable me to listen to any and all traffic. However,
   * it also has a bad effect on hosts with multiple interfaces (that is,
   * multiple IP addresses assigned to it). These hosts may sometimes send
   * packets which list an address different that the address listed in
   * the packet itself. My own algorithms, and presumably other too, will
   * discard and ignore the content of such packets. */
  my_addr.sin_addr.s_addr = INADDR_ANY;

  sckts.isbusy = 0xda;
  sckts.all_trans = &(nbworks_all_transactions[NAME_SRVC]);
  sckts.newtid_handler = &name_srvc_B_handle_newtid;
  sckts.pckt_dstr = &destroy_name_srvc_pckt;
  sckts.master_writer = &master_name_srvc_pckt_writer;
  sckts.master_reader = &master_name_srvc_pckt_reader;
  sckts.branch = NAME_SRVC;
  //XXX  sckts.tcp_sckt = socket(PF_INET, SOCK_STREAM, 0);
  sckts.udp_sckt = socket(PF_INET, SOCK_DGRAM, 0);

  if (sckts.udp_sckt < 0) /* XXX ||
			     sckts.tcp_sckt < 0)*/ {
    /* TODO: errno signaling stuff */
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }
  /*
  ret_val = fcntl(sckts.udp_sckt, F_SETFL, O_NONBLOCK);
  if (ret_val < 0) {
    /...* TODO: errno signaling stuff *.../
    close(sckts.udp_sckt);
    //XXX    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }*/
  /* XXX
  ret_val = fcntl(sckts.tcp_sckt, F_SETFL, O_NONBLOCK);
  if (ret_val < 0) {
    /...* TODO: errno signaling stuff *.../
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    return 0;
  }
*/
  ret_val = setsockopt(sckts.udp_sckt, SOL_SOCKET, SO_BROADCAST,
		       &ones, sizeof(unsigned int));
  if (ret_val < 0) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }

  ret_val = bind(sckts.udp_sckt, (struct sockaddr *)&my_addr,
		 sizeof(struct sockaddr_in));
  if (ret_val < 0) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }
/* XXX
  ret_val = bind(sckts.tcp_sckt, (struct sockaddr *)&my_addr,
		 sizeof(struct sockaddr_in));
  if (ret_val < 0) {
    /...* TODO: errno signaling stuff *.../
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    return 0;
  }

  ret_val = listen(sckts.tcp_sckt, MAX_NAME_TCP_QUEUE);
  if (ret_val < 0) {
    /...* TODO: errno signaling stuff *.../
    close(sckts.udp_sckt);
    close(sckts.tcp_sckt);
    return 0;
  }
*/
  thread[0] = 0;
  thread[1] = 0;
  //XXX  thread[2] = 0;

  /* There HAS to be a very, very special place in
     hell for people as evil as I am. */
  ret_val = pthread_create(&(thread[0]), 0,
			   &ss__udp_sender, &sckts);
  if (ret_val) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    //XXX    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }

  while (sckts.isbusy) {
    /* busy-wait */
  }
  sckts.isbusy = 0xda;

  ret_val = pthread_create(&(thread[1]), 0,
			   &ss__udp_recver, &sckts);
  if (ret_val) {
    /* TODO: errno signaling stuff */
    pthread_cancel(thread[0]);
    close(sckts.udp_sckt);
    //XXX    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }

  while (sckts.isbusy) {
    /* busy-wait */
  }
  sckts.isbusy = 0xda;

  for (i=0; i < 2/*XXX3*/; i++) {
    pthread_join(thread[i], 0);
  }

  close(sckts.udp_sckt);
  //XXX  close(sckts.tcp_sckt);

  return (void *)ONES;
}

void *ss__port138(void *i_dont_actually_use_this) {
  struct ss_sckts sckts;
  struct sockaddr_in my_addr;
  pthread_t thread[2];
  unsigned int ones;

  ones = ONES;
  my_addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(138, (unsigned char *)&(my_addr.sin_port));
  my_addr.sin_addr.s_addr = INADDR_ANY;

  sckts.isbusy = 0xda;
  sckts.all_trans = &(nbworks_all_transactions[DTG_SRVC]);
  sckts.newtid_handler = 0; /* FIXME */
  sckts.pckt_dstr = &destroy_dtg_srvc_recvpckt;
  sckts.master_writer = &master_dtg_srvc_pckt_writer;
  sckts.master_reader = &recving_dtg_srvc_pckt_reader;
  sckts.branch = DTG_SRVC;
  sckts.udp_sckt = socket(PF_INET, SOCK_DGRAM, 0);

  if (sckts.udp_sckt < 0) {
    /* TODO: errno signaling stuff */
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  if (0 != fcntl(sckts.udp_sckt, F_SETFL, O_NONBLOCK)) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  if (0 != setsockopt(sckts.udp_sckt, SOL_SOCKET, SO_BROADCAST,
		     &ones, sizeof(unsigned int))) {
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
		     &ss__udp_recver, &sckts)) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  while (sckts.isbusy) {
    /* busy-wait */
  }
  sckts.isbusy = 0xda;

  sckts.pckt_dstr = &destroy_dtg_srvc_pckt;

  if (pthread_create(&(thread[1]), 0,
		     &ss__udp_sender, &sckts)) {
    /* TODO: errno signaling stuff */
    pthread_cancel(thread[0]);
    close(sckts.udp_sckt);
    nbworks_all_port_cntl.all_stop = 4;
    return 0;
  }

  for (ones = 0; ones < 2; ones++) {
    pthread_join(thread[ones], 0);
  }

  close(sckts.udp_sckt);

  return (void *)ONES;
}


void *ss__udp_recver(void *sckts_ptr) {
  struct ss_sckts sckts, *release_lock;
  struct sockaddr_in his_addr, discard_addr;
  struct ss_unif_pckt_list *new_pckt;
  struct ss_priv_trans *cur_trans;
  struct ss_queue *newtid_queue;
  struct newtid_params params;
  struct pollfd polldata;
  struct nbnodename_list *name_as_id;
  socklen_t addr_len;
  int ret_val;
  unsigned int len;
  uint16_t tid;
  unsigned char udp_pckt[MAX_UDP_PACKET_LEN], *deleter;

  if (! sckts_ptr)
    return 0;

  newtid_queue = 0;

  memcpy(&sckts, sckts_ptr, sizeof(struct ss_sckts));
  release_lock = sckts_ptr;
  release_lock->isbusy = 0;

  name_as_id = 0;

  discard_addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(discard_addr.sin_port));
  fill_32field(my_ipv4_address(),
	       (unsigned char *)&(discard_addr.sin_addr.s_addr));

  polldata.fd = sckts.udp_sckt;
  polldata.events = (POLLIN | POLLPRI);
  params.isbusy = 0;

  while (! nbworks_all_port_cntl.all_stop) {
    ret_val = poll(&polldata, 1, nbworks_all_port_cntl.poll_timeout);
    if (ret_val == 0)
      continue;
    if (ret_val < 0) {
      /* TODO: error handling */
      continue;
    }

    while (0xcafe) {
      addr_len = sizeof(struct sockaddr_in);
      /* VAXism below. */
      deleter = (unsigned char *)&his_addr;
      while (deleter < ((unsigned char *)(&his_addr) + addr_len)) {
	*deleter = '\0';
	deleter++;
      }
      if (0 >= poll(&polldata, 1, 0))
	break;

      len = recvfrom(sckts.udp_sckt, udp_pckt, MAX_UDP_PACKET_LEN,
		     /*MSG_DONTWAIT*/0, &his_addr, &addr_len);
      /* BUG: While testing, I have noticed that there appears to be
	      a very strange behaviour regarding len.
	      Sometimes, the below test passes (indicating len is either
	      0 or positive), but if you read it after the if block,
	      it is -1! This behaviour dissapears if the socket is blocking
	      (the call to recvfrom() blocks). The only explanation so far
	      is that recvfrom returns, but then retroactivelly fails and
	      overwrites len to -1.
	      The other explanation is that GCC fucks things up (again).

              perror() displays "Resource temporarily unavailable" */
      /* the below line used to read (len < 0) */
      if (len <= 0) {
	if (errno == EAGAIN ||
	    errno == EWOULDBLOCK) {
	  break;
	} else {
	  /* TODO: error handling */
	  break;
	}
      }

      if (his_addr.sin_addr.s_addr == discard_addr.sin_addr.s_addr) {
	continue;
      }

      new_pckt = malloc(sizeof(struct ss_unif_pckt_list));
      /* NOTE: No check for failure. */
      new_pckt->packet = sckts.master_reader(udp_pckt, len, &tid);

      if (new_pckt->packet) {

	if (sckts.branch == DTG_SRVC) {
	  name_as_id = dtg_srvc_get_srcnam_recvpckt(new_pckt->packet);
	  if ((! name_as_id) ||
	      (name_as_id->len != NETBIOS_CODED_NAME_LEN)) {
	    sckts.pckt_dstr(new_pckt->packet, 1, 1);
	    free(new_pckt);
	    new_pckt = 0;
	  }
	}

	memcpy(&(new_pckt->addr), &his_addr, sizeof(struct sockaddr_in));
	new_pckt->dstry = sckts.pckt_dstr;
	new_pckt->next = 0;

      } else {
	/* TODO: errno signaling stuff */
	/* BUT see third comment up! */

	// FIXME: Handle datagram service error packets.

	free(new_pckt);
	new_pckt = 0;
      }

      while (new_pckt) {
	cur_trans = *(sckts.all_trans);
	while (cur_trans) {
	  if (((sckts.branch) == DTG_SRVC) ?              /* The problem with this scheme */
	      (! cmp_nbnodename(cur_trans->id.name_scope, /* is that it is possible for a */
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
	      free(new_pckt);
	      new_pckt = 0;

	      break;
	    }
	  } else {
	    cur_trans = cur_trans->next;
	  }
	}

	if (new_pckt) {
	  /* This means there were no previously registered transactions
	     with this tid. If name service, register a new one and signal
	     its existance. If datagram service, send a NOT-HERE error.
	     MUSING: perhaps I could just drop the datagram and not send
	             the error. */
	  if ((sckts.branch) == DTG_SRVC) { /* There goes my terminally abstract code... */
	    //	FIXME    dtg_srvc_send_NOTHERE_error(new_pckt);
	    sckts.pckt_dstr(new_pckt->packet, 1, 1);
	    free(new_pckt);
	    new_pckt = 0;

	    break;
	  } else {
	    params.id.tid = tid;
	    newtid_queue = ss_register_name_tid(&(params.id));
	  }
	}
      }
      /* Superfluous in datagram mode. */
      if (newtid_queue) {
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
	}
	newtid_queue = 0;
      }
    }
  }

  return 0;
}

void *ss__udp_sender(void *sckts_ptr) {
  struct ss_sckts sckts, *release_lock;
  struct ss_unif_pckt_list *for_del;
  struct ss_priv_trans *cur_trans, **last_trans, *for_del2;
  unsigned int len, prev_len;
  unsigned char udp_pckt[MAX_UDP_PACKET_LEN];
  void *ptr;

  if (! sckts_ptr)
    return 0;

  memcpy(&sckts, sckts_ptr, sizeof(struct ss_sckts));
  release_lock = sckts_ptr;
  release_lock->isbusy = 0;

  memset(udp_pckt, 0, MAX_UDP_PACKET_LEN);
  prev_len = 0;

  while (! nbworks_all_port_cntl.all_stop) {
    cur_trans = *(sckts.all_trans);
    last_trans = sckts.all_trans;
    while (cur_trans) {
      /* Special treatment of deregistered transactions. */
      if (cur_trans->status == nmtrst_deregister) {
	*last_trans = cur_trans->next;

	while (cur_trans->out) {
	  if (cur_trans->out->packet) {
	    ptr = cur_trans->out->packet;
	    len = MAX_UDP_PACKET_LEN;
	    sckts.master_writer(ptr, &len, udp_pckt);
	    if (prev_len > len) {
	      memset((udp_pckt + prev_len), 0, (prev_len - len));
	    }
	    prev_len = len;

	    sendto(sckts.udp_sckt, udp_pckt, len, MSG_NOSIGNAL,
		   &(cur_trans->out->addr),
		   sizeof(cur_trans->out->addr));

	    if (cur_trans->out->for_del)
	      sckts.pckt_dstr(cur_trans->out->packet, 1, 1);
	  }

	  for_del = cur_trans->out;
	  cur_trans->out = cur_trans->out->next;
	  free(for_del);
	}

	for_del2 = cur_trans;
	cur_trans = cur_trans->next;
	/* BUG: There is a (trivial?) chance of use-after-free. */
	free(for_del2);
      } else {
	while (cur_trans->out->next) {
	  if (cur_trans->out->packet) {
	    ptr = cur_trans->out->packet;
	    len = MAX_UDP_PACKET_LEN;
	    sckts.master_writer(ptr, &len, udp_pckt);
	    if (prev_len > len) {
	      memset((udp_pckt + prev_len), 0, (prev_len - len));
	    }
	    prev_len = len;

	    sendto(sckts.udp_sckt, udp_pckt, len, MSG_NOSIGNAL,
		   &(cur_trans->out->addr),
		   sizeof(cur_trans->out->addr));

	    if (cur_trans->out->for_del)
	      sckts.pckt_dstr(cur_trans->out->packet, 1, 1);
	  }

	  for_del = cur_trans->out;
	  cur_trans->out = cur_trans->out->next;
	  free(for_del);
	}

	if (cur_trans->out->packet) {
	  ptr = cur_trans->out->packet;
	  len = MAX_UDP_PACKET_LEN;
	  sckts.master_writer(ptr, &len, udp_pckt);
	  if (prev_len > len) {
	    memset((udp_pckt + prev_len), 0, (prev_len - len));
	  }
	  prev_len = len;

	  sendto(sckts.udp_sckt, udp_pckt, len, MSG_NOSIGNAL,
		 &(cur_trans->out->addr),
		 sizeof(cur_trans->out->addr));

	  if (cur_trans->out->for_del)
	    sckts.pckt_dstr(cur_trans->out->packet, 1, 1);
	  cur_trans->out->packet = 0;
	};

	last_trans = &(cur_trans->next);
	cur_trans = cur_trans->next;
      }
    }

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
  unsigned int ones;

  ones = ZEROONES;

  port_addr.sin_family = AF_INET;
  /* VAXism below */
  fill_16field(139, (unsigned char *)&(port_addr.sin_port));
  fill_32field(my_ipv4_address(), (unsigned char *)&(port_addr.sin_addr.s_addr));

  params.isbusy = 0; /* This is 0 on purpose. */

  sckt139 = socket(PF_INET, SOCK_STREAM, 0);
  if (sckt139 < 0) {
    return 0;
  }

  if (0 != fcntl(sckt139, F_SETFL, O_NONBLOCK)) {
    /* TODO: errno signaling stuff */
    close(sckt139);
    return 0;
  }

  if (0 != bind(sckt139, &port_addr, sizeof(struct sockaddr_in))) {
    close(sckt139);
    return 0;
  }

  if (0 != listen(sckt139, SOMAXCONN)) {
    close(sckt139);
    return 0;
  }

  pfd.fd = sckt139;
  pfd.events = POLLIN;

  while (! nbworks_ses_srv_cntrl.all_stop) {
    ret_val = poll(&pfd, 1, TP_100MS);
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
      while (params.isbusy) {
	/* busy-wait */
      }
      params.isbusy = 0xda;
      params.sckt139 = new_sckt;
      params.servers = &(nbworks_all_session_srvrs);
      if (0 != pthread_create(&(params.thread_id), 0,
			      take_incoming_session, &params)) {
	params.isbusy = 0;
	close(new_sckt);
      }
    }
  }

  close(sckt139);
  return nbworks_all_session_srvrs;
}

void *take_incoming_session(void *arg) {
  struct ses_srvc_packet new_pckt;
  struct ss_tcp_sckts params, *release_lock;
  struct ses_srv_rails *servers;
  struct nbnodename_list *called_name;
  struct ses_srv_sessions *session;
  struct thread_node *last_will;
  uint64_t token;
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
    if (0 != cmp_nbnodename(called_name, servers->name))
      servers = servers->next;
    else
      break;
  }

  if (servers) {
    token = make_token();
    if (0 != fcntl(params.sckt139, F_SETFL, O_NONBLOCK)) {
      /*      err[4] = SES_ERR_UNSPEC;
      send(params.sckt139, err, 5, MSG_NOSIGNAL);

      free(big_buff);
      close(params.sckt139);
      if (last_will)
	last_will->dead = TRUE;
	return 0;*/
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


void ss_check_all_ses_server_rails() {
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


uint32_t get_inaddr() {
  // FIXME: stub
  //        192.168.1.255/24
  return 0xff01a8c0;
}

uint32_t my_ipv4_address() {
  // FIXME: stub
  //        192.168.1.3/24
  return 0xc0a80103;
}
