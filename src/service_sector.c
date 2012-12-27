#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "dtg_srvc_pckt.h"
#include "randomness.h"


struct ss_name_trans *all_transactions;


void init_service_sector() {
  all_transactions = 0;
}

struct ss_queue *ss_register_name_tid(uint16_t tid) {
  struct ss_queue *result;
  struct ss_name_trans *cur_trans, *last_trans, *my_trans;
  int break_me_out;

  break_me_out = 0;
  cur_trans = all_transactions;

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
  my_trans->next = 0;

  while (1) {
    if (! all_transactions) {
      all_transactions = my_trans;
    }

    cur_trans = all_transactions;

    while (cur_trans) {
      if (cur_trans->tid == tid) {
	/* Success! */
	break_me_out = 1;
	break;
      }

      if (! cur_trans->next) {
	cur_trans->next = my_trans;
	break;
      }
      cur_trans = cur_trans->next;
    }

    if (break_me_out)
      break;
  }

  result->tid = tid;
  result->incoming = my_trans->incoming;
  result->outgoing = my_trans->outgoing;
  result->keep_me_alive = 1;

  return result;
}

void ss_deregister_name_tid(uint16_t tid) {
  struct ss_name_trans *cur_trans, **last_trans;

  cur_trans = all_transactions;
  *last_trans = &all_transactions;

  if (! all_transactions)
    return;

  while (cur_trans) {
    if (cur_trans->tid == tid) {
      *last_trans = cur_trans->next;
      /* There is a (trivial?) chance of use-after-free. */
      free(cur_trans);
      return;
    }
    *last_trans = &(cur_trans->next);
    cur_trans = cur_trans->next;
  }

  return;
}


inline void ss_name_send_pckt(struct ss_name_pckt_list *pckt,
			      struct ss_queue *trans) {
  pckt->next = 0;
  trans->outgoing->next = pckt;
  trans->outgoing = pckt;
}

inline struct name_srvc_packet *ss_recv_name_pckt(struct ss_queue *trans) {
  struct name_srvc_packet *result;
  struct ss_name_pckt_list *holdme;

  result = trans->incoming->packet;
  trans->incoming->packet = 0;

  if (trans->incoming->next) {
    holdme = trans->incoming;
    trans->incoming = trans->incoming->next;
    free(holdme);
  }

  return result;
}
