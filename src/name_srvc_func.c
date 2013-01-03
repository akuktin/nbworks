#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifndef _POSIX_C_SOURCE
# define _POSIX_C_SOURCE 199309
#endif
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_cnst.h"
#include "name_srvc_func.h"
#include "randomness.h"
#include "service_sector.h"


/* return: 0=success, >0=fail, -1=error */
int name_srvc_B_add_name(unsigned char *name,
			 unsigned char name_type,
			 struct nbnodename_list *scope,
			 uint32_t my_ip_address,
			 int isgroup) {
  struct timespec sleeptime;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outside_pckt;
  int result;
  uint16_t tid;

  result = 0;
  /* TODO: change this to a global setting. */
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = 2 * T_250MS;

  pckt = name_srvc_make_name_reg_big(name, name_type, scope, 0,
				     my_ip_address, isgroup, 'B');
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  tid = make_weakrandom();

  trans = ss_register_name_tid(tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    return -1;
  }
    
  pckt->header->transaction_id = tid;
  pckt->header->opcode = OPCODE_REQUEST | OPCODE_REGISTRATION;
  pckt->header->nm_flags = FLG_B;
  /* Do not ask for recursion, because
     there are no NBNS in our scope. */

  ss_name_send_pckt(pckt, trans);

  nanosleep(&sleeptime, 0);

  /* TODO: put a recv stoper. */

  while (1) {
    outside_pckt = ss_name_recv_pckt(trans);
    if (! outside_pckt) {
      break;
    }

    if ((outside_pckt->header->opcode == (OPCODE_RESPONSE |
					  OPCODE_REGISTRATION)) &&
	(outside_pckt->header->nm_flags & FLG_AA) &&
	(outside_pckt->header->rcode != 0)) {
      /* This is a NEGATIVE NAME REGISTRATION RESPONSE. */
      /* Failed. */
      result = outside_pckt->header->rcode;
      destroy_name_srvc_pckt(outside_pckt, 1, 1);
      break;
    }

    destroy_name_srvc_pckt(outside_pckt, 1, 1);
  }

  if (! result) {
    /* Succeded. */
    pckt->header->opcode = OPCODE_REQUEST | OPCODE_REFRESH;
    ss_name_send_pckt(pckt, trans);
  }

  ss_deregister_name_tid(tid);
  ss_name_dstry_recv_queue(trans);
  free(trans);

  destroy_name_srvc_pckt(pckt, 0, 1);

  return result;
}
