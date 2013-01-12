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
#include "randomness.h"
#include "service_sector.h"


struct ss_name_trans *nbworks_all_name_transactions;


void init_service_sector() {
  nbworks_all_name_transactions = 0;
  nbworks_all_port_cntl.all_stop = 0;
  nbworks_all_port_cntl.sleeptime.tv_sec = 0;
  nbworks_all_port_cntl.sleeptime.tv_nsec = T_10MS;
  nbworks_all_port_cntl.poll_timeout = 10; /* 10 ms */
}

struct ss_queue *ss_register_name_tid(uint16_t tid) {
  struct ss_queue *result;
  struct ss_name_trans *cur_trans, *my_trans;
  int break_me_out;

  break_me_out = 0;
  cur_trans = nbworks_all_name_transactions;

  while (cur_trans) {
    if (cur_trans->tid == tid) {
      /* ALREADY_EXISTS */
      /* TODO: errno signaling stuff */
      return 0;
    }
    cur_trans = cur_trans->next;
  }

  result = malloc(sizeof(struct ss_queue));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  my_trans = malloc(sizeof(struct ss_name_trans));
  if (! my_trans) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }
  my_trans->tid = tid;
  my_trans->incoming = calloc(1, sizeof(struct ss_name_trans));
  if (! my_trans->incoming) {
    /* TODO: errno signaling stuff */
    free(result);
    free(my_trans);
    return 0;
  }
  my_trans->outgoing = calloc(1, sizeof(struct ss_name_trans));
  if (! my_trans->outgoing) {
    /* TODO: errno signaling stuff */
    free(result);
    free(my_trans->incoming);
    free(my_trans);
    return 0;
  }
  my_trans->status = nmtrst_normal;
  my_trans->next = 0;

  result->incoming = my_trans->incoming;
  result->outgoing = my_trans->outgoing;

  while (1) {
    if (! nbworks_all_name_transactions) {
      nbworks_all_name_transactions = my_trans;
    }

    cur_trans = nbworks_all_name_transactions;

    while (cur_trans) {
      if (cur_trans->tid == tid &&
	  (cur_trans->status == nmtrst_normal ||
	   cur_trans->status == nmtrst_indrop)) {
	/* Success! */
	break_me_out = 1;
	break;
      }

      if (! cur_trans->next) {
	/* BUG: there is still a (trivial) chance of
	        memory leak and tid non-registering. */
	cur_trans->next = my_trans;
	break;
      }
      cur_trans = cur_trans->next;
    }

    if (break_me_out)
      break;
  }

  return result;
}

void ss_deregister_name_tid(uint16_t tid) {
  struct ss_name_trans *cur_trans;

  if (! nbworks_all_name_transactions)
    return;

  cur_trans = nbworks_all_name_transactions;

  while (cur_trans) {
    if (cur_trans->tid == tid &&
	(cur_trans->status == nmtrst_normal ||
	 cur_trans->status == nmtrst_indrop)) {
      cur_trans->status = nmtrst_deregister;
      return;
    }
    cur_trans = cur_trans->next;
  }

  return;
}

void ss_set_inputdrop_name_tid(uint16_t tid) {
  struct ss_name_trans *cur_trans;

  if (! nbworks_all_name_transactions)
    return;

  cur_trans = nbworks_all_name_transactions;

  while (cur_trans) {
    if (cur_trans->tid == tid &&
	cur_trans->status == nmtrst_normal) {
      cur_trans->status = nmtrst_indrop;
      return;
    }
    cur_trans = cur_trans->next;
  }

  return;
}

void ss_set_normalstate_name_tid(uint16_t tid) {
  struct ss_name_trans *cur_trans;

  if (! nbworks_all_name_transactions)
    return;

  cur_trans = nbworks_all_name_transactions;

  while (cur_trans) {
    if (cur_trans->tid == tid &&
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
  struct ss_name_pckt_list *trans_pckt;

  if (trans)
    if (trans->outgoing && pckt && addr) {
      trans_pckt = malloc(sizeof(struct name_srvc_packet));
      if (! trans_pckt) {
	/* TODO: errno signaling stuff */
	return -1;
      }

      trans_pckt->packet = pckt;
      memcpy(&(trans_pckt->addr), addr, sizeof(struct sockaddr_in));
      trans_pckt->next = 0;
      /* Add packet to queue. */
      trans->outgoing->next = trans_pckt;
      /* Move the queue pointer. */
      trans->outgoing = trans_pckt;
    };

  return 1;
}

inline struct name_srvc_packet *ss_name_recv_pckt(struct ss_queue *trans) {
  struct name_srvc_packet *result;
  struct ss_name_pckt_list *holdme;

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

      result = ss_name_recv_pckt(trans);
    } else {
      result = 0;
    }
  }

  return result;
}

inline struct ss_name_pckt_list *ss_name_recv_entry(struct ss_queue *trans) {
  struct ss_name_pckt_list *result;

  if (! trans)
    return 0;

  result = trans->incoming;

  if (trans->incoming)
    if (trans->incoming->next)
      trans->incoming = trans->incoming->next;

  return result;
}

inline void ss_name_dstry_recv_queue(struct ss_queue *trans) {
  struct ss_name_pckt_list *for_del;

  if (! trans)
    return;

  while (trans->incoming) {
    if (trans->incoming->packet)
      destroy_name_srvc_pckt(trans->incoming->packet, 1, 1);
    for_del = trans->incoming;
    trans->incoming = trans->incoming->next;
    /* NOTETOSELF: This is safe. */
    free(for_del);
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
  my_addr.sin_addr.s_addr = get_inaddr();

  sckts.all_trans = &nbworks_all_name_transactions;
  //XXX  sckts.tcp_sckt = socket(PF_INET, SOCK_STREAM, 0);
  sckts.udp_sckt = socket(PF_INET, SOCK_DGRAM, 0);

  if (sckts.udp_sckt < 0) /* XXX ||
			     sckts.tcp_sckt < 0)*/ {
    /* TODO: errno signaling stuff */
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }

  ret_val = fcntl(sckts.udp_sckt, F_SETFL, O_NONBLOCK);
  if (ret_val < 0) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    //XXX    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }
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
		       &ones, sizeof(int));
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
			   &ss_name_udp_sender, &sckts);
  if (ret_val) {
    /* TODO: errno signaling stuff */
    close(sckts.udp_sckt);
    //XXX    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }
  ret_val = pthread_create(&(thread[1]), 0,
			   &ss_name_udp_recver, &sckts);
  if (ret_val) {
    /* TODO: errno signaling stuff */
    pthread_cancel(thread[0]);
    close(sckts.udp_sckt);
    //XXX    close(sckts.tcp_sckt);
    nbworks_all_port_cntl.all_stop = 2;
    return 0;
  }

  for (i=0; i < 2/*XXX3*/; i++) {
    pthread_join(thread[i], 0);
  }

  close(sckts.udp_sckt);
  //XXX  close(sckts.tcp_sckt);

  return (void *)ONES;
}

void *ss_name_udp_recver(void *sckts_ptr) {
  struct ss_sckts *sckts;
  struct sockaddr_in his_addr;
  struct ss_name_pckt_list *new_pckt;
  struct ss_name_trans *cur_trans;
  struct ss_queue *newtid_queue;
  struct newtid_params params;
  struct pollfd polldata;
  socklen_t addr_len;
  int ret_val;
  unsigned int len;
  unsigned char udp_pckt[MAX_UDP_PACKET_LEN], *deleter;

  if (! sckts_ptr)
    return 0;

  newtid_queue = 0;
  sckts = sckts_ptr;
  polldata.fd = sckts->udp_sckt;
  polldata.events = (POLLIN | POLLPRI);

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
      len = recvfrom(sckts->udp_sckt, udp_pckt, MAX_UDP_PACKET_LEN,
		     MSG_DONTWAIT, &his_addr, &addr_len);
      if (len < 0) {
	if (errno == EAGAIN ||
	    errno == EWOULDBLOCK) {
	  break;
	} else {
	  /* TODO: error handling */
	}
      }

      new_pckt = calloc(1, sizeof(struct ss_name_pckt_list));
      /* NOTE: No check for failure. */
      new_pckt->packet = master_name_srvc_pckt_reader(udp_pckt, len);
      memcpy(&(new_pckt->addr), &his_addr, sizeof(struct sockaddr_in));
      new_pckt->next = 0;

      while (new_pckt) {
	cur_trans = *(sckts->all_trans);
	while (cur_trans) {
	  if (cur_trans->tid == new_pckt->packet->header->transaction_id) {
	    if (cur_trans->status == nmtrst_indrop) {
	      destroy_name_srvc_pckt(new_pckt->packet, 1, 1);
	      free(new_pckt);
	      new_pckt = 0;
	      break;
	    }
	    if (cur_trans->status == nmtrst_normal) {
	      cur_trans->incoming->next = new_pckt;
	      cur_trans->incoming = new_pckt;
	      new_pckt = 0;
	      break;
	    }
	  } else {
	    cur_trans = cur_trans->next;
	  }
	}

	if (new_pckt) {
	  /* This means there were no previously registered transactions
	     with this tid. Register a new one and signal its existance. */
	  newtid_queue =
	    ss_register_name_tid(new_pckt->packet->header->transaction_id);
	}
      }
      if (newtid_queue) {
	/* Signaling the new queue. */
	params.thread_id = 0;
	params.tid = new_pckt->packet->header->transaction_id;
	params.trans = newtid_queue;
	pthread_create(&(params.thread_id), 0,
		       name_srvc_B_handle_newtid, &params);
	/* No. Fucking. Comment. */
	newtid_queue = 0;
      }
    }
  }

  return 0;
}

void *ss_name_udp_sender(void *sckts_ptr) {
  struct ss_sckts *sckts;
  struct ss_name_pckt_list *for_del;
  struct ss_name_trans *cur_trans, **last_trans, *for_del2;
  unsigned int len, i;
  unsigned char *deleter, udp_pckt[MAX_UDP_PACKET_LEN];
  void *ptr;

  if (! sckts_ptr)
    return 0;

  sckts = sckts_ptr;

  deleter = udp_pckt;
  for (i=0; i < MAX_UDP_PACKET_LEN; i++) {
    *deleter = '\0';
  }

  while (! nbworks_all_port_cntl.all_stop) {
    cur_trans = *(sckts->all_trans);
    last_trans = sckts->all_trans;
    while (cur_trans) {
      /* Special treatment of deregistered transactions. */
      if (cur_trans->status == nmtrst_deregister) {
	*last_trans = cur_trans->next;

	while (cur_trans->outgoing) {
	  if (cur_trans->outgoing->packet) {
	    ptr = cur_trans->outgoing->packet;
	    len = MAX_UDP_PACKET_LEN;
	    master_name_srvc_pckt_writer(ptr, &len, udp_pckt);

	    sendto(sckts->udp_sckt, udp_pckt, len, 0,
		   &(cur_trans->outgoing->addr),
		   sizeof(cur_trans->outgoing->addr));

	    deleter = udp_pckt;
	    for (i=0; i<len; i++) {
	      *deleter = '\0';
	      deleter++;
	    }
	    if (cur_trans->outgoing->packet->for_del)
	      destroy_name_srvc_pckt(cur_trans->outgoing->packet, 1, 1);
	  }

	  for_del = cur_trans->outgoing;
	  cur_trans->outgoing = cur_trans->outgoing->next;
	  free(for_del);
	}

	for_del2 = cur_trans;
	cur_trans = cur_trans->next;
	/* BUG: There is a (trivial?) chance of use-after-free. */
	free(for_del2);
      } else {
	while (cur_trans->outgoing->next) {
	  if (cur_trans->outgoing->packet) {
	    ptr = cur_trans->outgoing->packet;
	    len = MAX_UDP_PACKET_LEN;
	    master_name_srvc_pckt_writer(ptr, &len, udp_pckt);

	    sendto(sckts->udp_sckt, udp_pckt, len, 0,
		   &(cur_trans->outgoing->addr),
		   sizeof(cur_trans->outgoing->addr));

	    deleter = udp_pckt;
	    for (i=0; i<len; i++) {
	      *deleter = '\0';
	      deleter++;
	    }
	    if (cur_trans->outgoing->packet->for_del)
	      destroy_name_srvc_pckt(cur_trans->outgoing->packet, 1, 1);
	  }

	  for_del = cur_trans->outgoing;
	  cur_trans->outgoing = cur_trans->outgoing->next;
	  free(for_del);
	}

	if (cur_trans->outgoing->packet) {
	  ptr = cur_trans->outgoing->packet;
	  len = MAX_UDP_PACKET_LEN;
	  master_name_srvc_pckt_writer(ptr, &len, udp_pckt);

	  sendto(sckts->udp_sckt, udp_pckt, len, 0,
		 &(cur_trans->outgoing->addr),
		 sizeof(cur_trans->outgoing->addr));

	  deleter = udp_pckt;
	  for (i=0; i<len; i++) {
	    *deleter = '\0';
	    deleter++;
	  }
	  if (cur_trans->outgoing->packet->for_del)
	    destroy_name_srvc_pckt(cur_trans->outgoing->packet, 1, 1);
	  cur_trans->outgoing->packet = 0;
	};

	last_trans = &(cur_trans->next);
	cur_trans = cur_trans->next;
      }
    }

    nanosleep(&(nbworks_all_port_cntl.sleeptime), 0);
  }

  return 0;
}


unsigned int get_inaddr() {
  unsigned int result;

  // FIXME: stub
  //        192.168.1.255/24
  result = 0xff01a8c0;

  return result;
}
