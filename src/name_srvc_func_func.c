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

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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
#include "name_srvc_cache.h"
#include "name_srvc_func_B.h"
#include "name_srvc_func_P.h"
#include "name_srvc_func_func.h"
#include "randomness.h"
#include "service_sector.h"
#include "service_sector_threads.h"
#include "daemon_control.h"
#include "portability.h"


void name_srvc_daemon_newtidwrk(struct name_srvc_packet *outpckt,
				struct sockaddr_in *addr,
				struct newtid_params *params,
				time_t cur_time) {
  if (! (outpckt && addr && params))
    return;

  // NAME REGISTRATION REQUEST (UNIQUE)
  // NAME REGISTRATION REQUEST (GROUP)

  if ((outpckt->header.opcode == (OPCODE_REQUEST |
				   OPCODE_REGISTRATION)) &&
      (! outpckt->header.rcode)) {
    /* NAME REGISTRATION REQUEST */

    name_srvc_do_namregreq(outpckt, addr, params->trans, params->id.tid,
			   cur_time, 0, 0);

    return;
  }

  // NAME QUERY REQUEST
  // NODE STATUS REQUEST

  if ((outpckt->header.opcode == (OPCODE_REQUEST |
				   OPCODE_QUERY)) &&
      (! outpckt->header.rcode)) {

    name_srvc_do_namqrynodestat(outpckt, addr, params->trans, params->id.tid,
				cur_time, 0, 0, 0);

    return;
  }

  // POSITIVE NAME QUERY RESPONSE

  if ((outpckt->header.opcode == (OPCODE_RESPONSE |
				   OPCODE_QUERY)) &&
      (outpckt->header.rcode == 0) &&
      (outpckt->header.nm_flags & FLG_AA)) {

    name_srvc_do_posnamqryresp(outpckt, addr, params->trans, params->id.tid,
			       cur_time, 0, 0);

    return;
  }

  // NAME CONFLICT DEMAND

  if ((outpckt->header.opcode == (OPCODE_RESPONSE |
				   OPCODE_REGISTRATION)) &&
      (outpckt->header.rcode == RCODE_CFT_ERR) &&
      (outpckt->header.nm_flags & FLG_AA)) {

    name_srvc_do_namcftdem(outpckt, addr, 0);

    return;
  }

  // NAME RELEASE REQUEST

  if ((outpckt->header.opcode == (OPCODE_REQUEST |
				   OPCODE_RELEASE)) &&
      (outpckt->header.rcode == 0)) {

    name_srvc_do_namrelreq(outpckt, addr,
#ifdef COMPILING_NBNS
			   params->trans, params->id.tid, 0, 0,
#endif
			   0);

    return;
  }

  // NAME UPDATE REQUEST

  if (((outpckt->header.opcode == (OPCODE_REQUEST |
				    OPCODE_REFRESH)) ||
       (outpckt->header.opcode == (OPCODE_REQUEST |
				    OPCODE_REFRESH2))) &&
      (outpckt->header.rcode == 0)) {

    name_srvc_do_updtreq(outpckt, addr,
#ifdef COMPILING_NBNS
			 params->trans, params->id.tid, 0, 0,
#endif
			 cur_time, 0, 0);

    return;
  }

  // NOOP

  return;
}

#define BLOCK_SIZE 16
struct name_srvc_resource_lst *
  name_srvc_TCPcallout_name(struct name_srvc_packet *pckt,
			    struct sockaddr_in *address,
			    unsigned int recursive) {
  int sckt;
  struct timespec sleeptime;
  struct name_srvc_pckt_header returnheader;
  struct nbworks_nbnamelst *auth;
  struct name_srvc_question_lst *cur_qstn;
  struct name_srvc_resource_lst *res, *cur_res, **last_res, *result;
  struct nbaddress_list *nbaddr_list;
  uint32_t offsetof_start, biggest_wack, max_wack;
  unsigned int block, len_leftover, do_stuff;
  unsigned char buff[MAX_RDATALEN], startbuff[SIZEOF_STARTBUFF],
    writebuff[TCP_READWRITEBUFF_LEN], *walker, *startbuff_walker,
    *writewalker;
  time_t start_time;

#define send_resources							\
  while (cur_res) {							\
    writewalker =							\
      fill_name_srvc_resource(cur_res->res, writebuff,			\
			      (writebuff + TCP_READWRITEBUFF_LEN),	\
			      0, 0);					\
    if (writewalker > writebuff) {					\
      if ((writewalker - writebuff) >					\
	  send(sckt, writebuff,						\
	       (writewalker - writebuff),				\
	       MSG_NOSIGNAL)) {						\
	close(sckt);							\
	return 0;							\
      }									\
    }									\
    cur_res = cur_res->next;						\
  }

#define ffrwd_resource(a)						\
  do_stuff = a;								\
  while (do_stuff) {							\
    if (! ffrwd_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,		\
				   &walker, &len_leftover, &offsetof_start, \
				   startbuff, &startbuff_walker)) {	\
      close(sckt);							\
      return 0;								\
    }									\
    do_stuff--;								\
  }

#define ffrwd_question(a)						\
  do_stuff = a;								\
  while (do_stuff) {							\
    if (! ffrwd_name_srvc_qstnTCP(sckt, buff, MAX_RDATALEN,		\
				  &walker, &len_leftover, &offsetof_start, \
				  startbuff, &startbuff_walker)) {	\
      close(sckt);							\
      return 0;								\
    }									\
    do_stuff--;								\
  }

#define read_block							\
  if (do_stuff >= BLOCK_SIZE)						\
    block = BLOCK_SIZE;							\
  else									\
    block = do_stuff;							\
  do_stuff = do_stuff - block;						\
									\
  last_res = &res;							\
  while (block) {							\
    *last_res = malloc(sizeof(struct name_srvc_resource_lst));		\
    cur_res = *last_res;						\
    if (! cur_res) {							\
      close(sckt);							\
      destroy_name_srvc_res_lst(res, 1, 1);				\
      return 0;								\
    }									\
    cur_res->res = read_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,	\
					   &walker, &len_leftover, &offsetof_start, \
					   startbuff, &startbuff_walker); \
    if (! cur_res->res) {						\
      close(sckt);							\
      cur_res->next = 0;						\
      destroy_name_srvc_res_lst(res, 1, 1);				\
      return 0;								\
    }									\
    last_res = &(cur_res->next);					\
									\
    block--;								\
  }


  if (! (pckt && address))
    return 0;

  /* -- verify ---------------------- */
  if ((pckt->header.numof_questions != 1) ||
      (pckt->header.numof_answers != 0) ||
      (pckt->header.numof_authorities != 0) ||
      (pckt->header.numof_additional_recs != 0))
    return 0;
  /* -- end verify ------------------ */

 all_over_again:
  result = 0;
  walker = startbuff;
  len_leftover = 0;
  offsetof_start = 0;
  biggest_wack = 0;
  startbuff_walker = startbuff;
  auth = 0;


  sckt = socket(PF_INET, SOCK_STREAM, 0);
  if (sckt < 0)
    return 0;

  if (0 != connect(sckt, (struct sockaddr *)address,
		   sizeof(struct sockaddr_in))) {
    close(sckt);
    return 0;
  }

  if (0 != set_sockoption(sckt, NONBLOCKING)) {
    close(sckt);
    return 0;
  }

  /* -- sending --------------------- */
  fill_name_srvc_pckt_header(&(pckt->header), writebuff,
			     (writebuff + TCP_READWRITEBUFF_LEN));

  if (SIZEOF_NAMEHDR_ONWIRE > send(sckt, writebuff, SIZEOF_NAMEHDR_ONWIRE,
				   MSG_NOSIGNAL)) {
    close (sckt);
    return 0;
  }

  cur_qstn = pckt->questions;
  while (cur_qstn) {
    writewalker =
      fill_name_srvc_pckt_question(cur_qstn->qstn, writebuff,
				   (writebuff + TCP_READWRITEBUFF_LEN), 0);
    if (writewalker > writebuff) {
      if ((writewalker - writebuff) > send(sckt, writebuff,
					   (writewalker - writebuff),
					   MSG_NOSIGNAL)) {
	close(sckt);
	return 0;
      }
    }	
    cur_qstn = cur_qstn->next;
  }

  cur_res = pckt->answers;
  send_resources;

  cur_res = pckt->authorities;
  send_resources;

  cur_res = pckt->aditionals;
  send_resources;
  /* -- done sending ---------------- */

  start_time = time(0);

  /* -- receiving and parsing ------- */
 process_new_packet:
  if (SIZEOF_NAMEHDR_ONWIRE > recv(sckt, startbuff, SIZEOF_NAMEHDR_ONWIRE,
				   MSG_WAITALL)) {
    close(sckt);
    return 0;
  }

  read_name_srvc_pckt_header(&walker, (startbuff +SIZEOF_NAMEHDR_ONWIRE),
			     &returnheader);
  walker = buff;

  if ((returnheader.opcode == (OPCODE_RESPONSE |
			       OPCODE_QUERY)) &&
      (returnheader.nm_flags & FLG_AA)) {
    if (returnheader.rcode == 0) {
      /* POSITIVE NAME QUERY RESPONSE */
      ffrwd_question(returnheader.numof_questions);

      do_stuff = returnheader.numof_answers;
      while (do_stuff && (! result)) {
	read_block;

	cur_res = res;
	last_res = &(res);

	while (cur_res) {
	  if (cur_res->res &&
	      (0 == nbworks_cmp_nbnodename(pckt->questions->qstn->name,
					   cur_res->res->name)) &&
	      (pckt->questions->qstn->qtype ==
	       cur_res->res->rrtype) &&
	      (pckt->questions->qstn->qclass ==
	       cur_res->res->rrclass) &&
	      (cur_res->res->rdata_t == nb_address_list)) {
	    /* This is what we are looking for. */

	    result = cur_res;
	    cur_res = *last_res = cur_res->next;
	    result->next = 0;

	    break;
	  } else {
	    last_res = &(cur_res->next);
	    cur_res = cur_res->next;
	  }
	}

	destroy_name_srvc_res_lst(res, 1, 1);
      }

      close(sckt);
      return result;
    } else {
      /* NEGATIVE NAME QUERY RESPONSE */
      /* Just fast-forward it. */
      ffrwd_question(returnheader.numof_questions);

      do_stuff = returnheader.numof_answers;
      while (do_stuff && (! result)) {
	read_block;

	cur_res = res;
	last_res = &(res);

	while (cur_res) {
	  if (cur_res->res &&
	      (0 == nbworks_cmp_nbnodename(pckt->questions->qstn->name,
					   cur_res->res->name)) &&
	      ((cur_res->res->rrtype == RRTYPE_NULL) ||
	       (pckt->questions->qstn->qtype ==
		cur_res->res->rrtype)) &&
	      (pckt->questions->qstn->qclass ==
	       cur_res->res->rrclass)) {
	    /* This is what we are looking for. */

	    result = cur_res;
	    cur_res = *last_res = cur_res->next;
	    result->next = 0;

	    break;
	  } else {
	    last_res = &(cur_res->next);
	    cur_res = cur_res->next;
	  }
	}

	destroy_name_srvc_res_lst(res, 1, 1);
      }

      /* Early test and exit. */
      if (result) {
	destroy_name_srvc_res_lst(result, 1, 1);
	close(sckt);
	return 0;
      }

      ffrwd_resource(returnheader.numof_authorities);
      ffrwd_resource(returnheader.numof_additional_recs);

      goto process_new_packet;
    }
  }

  if (returnheader.opcode == (OPCODE_RESPONSE |
			      OPCODE_WACK)) {
    // WACK

    ffrwd_question(returnheader.numof_questions);

    do_stuff = returnheader.numof_answers;
    while (do_stuff) {
      read_block;

      biggest_wack = name_srvc_find_biggestwack(0, pckt->questions->qstn->name,
						pckt->questions->qstn->qtype,
						pckt->questions->qstn->qclass,
						biggest_wack, res);

      destroy_name_srvc_res_lst(res, 1, 1);
    }

    ffrwd_resource(returnheader.numof_authorities);
    ffrwd_resource(returnheader.numof_additional_recs);

    if (biggest_wack) {
      max_wack = nbworks_namsrvc_cntrl.max_wack_sleeptime;
      if ((start_time + max_wack) > time(0)) {
	close(sckt);
	return 0;
      }
      if (biggest_wack > max_wack)
	biggest_wack = max_wack;

      sleeptime.tv_sec = biggest_wack;
      sleeptime.tv_nsec = 0;

      nanosleep(&sleeptime, 0);
    }
    biggest_wack = 0;

    goto process_new_packet;
  }

  if ((returnheader.opcode == (OPCODE_RESPONSE |
			       OPCODE_QUERY)) &&
      (returnheader.nm_flags & FLG_RD) &&
      (returnheader.rcode == 0)) {
    // REDIRECT NAME QUERY RESPONSE, probably

    ffrwd_question(returnheader.numof_questions);
    ffrwd_resource(returnheader.numof_answers);

    do_stuff = returnheader.numof_authorities;
    while (do_stuff) {
      read_block;

      cur_res = res;

      while (cur_res) {
	if (cur_res->res &&
	    (0 == nbworks_cmp_nbnodename(pckt->questions->qstn->name,
					 cur_res->res->name)) &&
	    (pckt->questions->qstn->qtype ==
	     cur_res->res->rrtype) &&
	    (pckt->questions->qstn->qclass ==
	     cur_res->res->rrclass) &&
	    (cur_res->res->rdata_t == nb_nodename)) {
	  /* This is what we are looking for. */

	  if (auth)
	    nbworks_dstr_nbnodename(auth);
	  auth = cur_res->res->rdata;
	  cur_res->res->rdata = 0;
	  break;
	} else {
	  cur_res = cur_res->next;
	}
      }

      destroy_name_srvc_res_lst(res, 1, 1);
    }
    do_stuff = returnheader.numof_additional_recs;
    while (do_stuff) {
      read_block;

      cur_res = res;

      while (cur_res) {
	if (cur_res->res &&
	    (0 == nbworks_cmp_nbnodename(auth, cur_res->res->name)) &&
	    (cur_res->res->rrtype == RRTYPE_A) &&
	    (cur_res->res->rrclass == RRCLASS_IN) &&
	    (cur_res->res->rdata_t == nb_NBT_node_ip_address) &&
	    (cur_res->res->rdata)) {
	  /* This is what we are looking for. */
	  nbaddr_list = cur_res->res->rdata;

	  /* VAXism below. */
	  fill_32field(nbaddr_list->address,
		       (unsigned char *)&(address->sin_addr.s_addr));
	  break;
	} else {
	  cur_res = cur_res->next;
	}
      }

      destroy_name_srvc_res_lst(res, 1, 1);
      if (cur_res) {
	close(sckt);
	goto all_over_again;
      }
    }

    close(sckt);
    return 0;
  }
  
  /* -- done receiving and parsing -- */
  close(sckt);
  return result;
}
#undef BLOCK_SIZE

#define BLOCK_SIZE 16
void name_srvc_daemon_newtidtcp(int sckt,
				struct sockaddr_in *addr,
				struct newtid_params *params,
				time_t cur_time) {
  struct name_srvc_pckt_header header, returnheader;
  struct name_srvc_question_lst *qstn, *cur_qstn, **last_qstn;
  struct name_srvc_resource_lst *res, *cur_res, **last_res, *res2;
  unsigned long numof_OK, numof_notOK;
  uint32_t offsetof_start;
  unsigned int do_qstn, do_answ, do_auth, do_adit, block, len_leftover, answerhim;
  /* There was a lot of thinking going on with regards the buff below.
   * For the longest time, I was gung-ho about making it a ring buffer
   * (in a ring buffer, when a read or write head reaches the end of the
   * buffer, it automatically wraps around to the beggining). But, I was
   * ultimately persuaded against it when I began thinking about the ways
   * I would have to change read_name_srvc_resource_data(). */
  unsigned char buff[MAX_RDATALEN], startbuff[SIZEOF_STARTBUFF],
    writebuff[TCP_READWRITEBUFF_LEN], *walker, *startbuff_walker,
    *writewalker;

  if ((sckt < 0) || (! (addr && params)))
    return;

#define ffrwrdto_aditionals						\
  do_qstn = header.numof_questions;					\
  while (do_qstn) {							\
    if (! ffrwd_name_srvc_qstnTCP(sckt, buff, MAX_RDATALEN,		\
				  &walker, &len_leftover, &offsetof_start, \
				  startbuff, &startbuff_walker)) {	\
      return;								\
    }									\
									\
    do_qstn--;								\
  }									\
									\
  do_answ = header.numof_answers;					\
  while (do_answ) {							\
    if (! ffrwd_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,		\
				   &walker, &len_leftover, &offsetof_start, \
				   startbuff, &startbuff_walker)) {	\
      return;								\
    }									\
									\
    do_answ--;								\
  }									\
									\
  do_auth = header.numof_authorities;					\
  while (do_auth) {							\
    if (! ffrwd_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,		\
				   &walker, &len_leftover, &offsetof_start, \
				   startbuff, &startbuff_walker)) {	\
      return;								\
    }									\
									\
    do_auth--;								\
  }


  walker = startbuff;
  numof_OK = numof_notOK = 0;
  len_leftover = 0;
  offsetof_start = 0;
  startbuff_walker = startbuff;

  answerhim = FALSE;

  fill_16field(params->id.tid, startbuff);
  if ((SIZEOF_NAMEHDR_ONWIRE -2) > recv(sckt, (startbuff +2),
					(SIZEOF_NAMEHDR_ONWIRE -2),
					MSG_WAITALL)) {
    return;
  }

  read_name_srvc_pckt_header(&walker, (startbuff +SIZEOF_NAMEHDR_ONWIRE),
			     &header);
  walker = buff;

  /* ----------------------------------- */
  // NAME REGISTRATION REQUEST (UNIQUE)
  // NAME REGISTRATION REQUEST (GROUP)

  if ((header.opcode == (OPCODE_REQUEST |
			 OPCODE_REGISTRATION)) &&
      (! header.rcode)) {
    /* NAME REGISTRATION REQUEST */

    ffrwrdto_aditionals;

    do_adit = header.numof_additional_recs;
    while (do_adit) {
      if (do_adit >= BLOCK_SIZE)
	block = BLOCK_SIZE;
      else
	block = do_adit;
      do_adit = do_adit - block;

      last_res = &res;
      while (block) {
	*last_res = malloc(sizeof(struct name_srvc_resource_lst));
	cur_res = *last_res;
	if (! cur_res) {
	  /* Abort. */
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	cur_res->res = read_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,
					       &walker, &len_leftover, &offsetof_start,
					       startbuff, &startbuff_walker);
	if (! cur_res->res) {
	  /* Abort. */
	  cur_res->next = 0;
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	last_res = &(cur_res->next);

	block--;
      }

      res2 = name_srvc_do_namregreq(0, 0, 0, params->id.tid,
				    cur_time, &numof_OK, res);
      destroy_name_srvc_res_lst(res, 1, 1);

      if (res2 && (! answerhim)) {
	memset(&returnheader, 0, sizeof(struct name_srvc_pckt_header));
	returnheader.transaction_id = params->id.tid;
	returnheader.opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
	returnheader.nm_flags = FLG_AA;
	returnheader.rcode = RCODE_CFT_ERR;

	/* See the comment over at POSITIVE NAME QUERY RESPONSE. */
	returnheader.numof_answers = do_adit + numof_OK;

	fill_name_srvc_pckt_header(&returnheader, writebuff,
				   (writebuff + TCP_READWRITEBUFF_LEN));

	if (SIZEOF_NAMEHDR_ONWIRE > send(sckt, writebuff, SIZEOF_NAMEHDR_ONWIRE,
					 MSG_NOSIGNAL)) {
	  destroy_name_srvc_res_lst(res2, 1, 1);
	  return;
	}

	answerhim = TRUE;
      }

      cur_res = res2;
      while (cur_res) {
	writewalker = fill_name_srvc_resource(cur_res->res, writebuff,
					      (writebuff + TCP_READWRITEBUFF_LEN),
					      0, 0);
	if (writewalker > writebuff) {
	  if ((writewalker - writebuff) > send(sckt, writebuff,
					       (writewalker - writebuff),
					       MSG_NOSIGNAL)) {
	    destroy_name_srvc_res_lst(res2, 1, 1);
	    return;
	  }
	}

	cur_res = cur_res->next;
      }

      destroy_name_srvc_res_lst(res2, 1, 1);
    }


    return;
  }

  // NAME QUERY REQUEST
  // NODE STATUS REQUEST

  if ((header.opcode == (OPCODE_REQUEST |
			 OPCODE_QUERY)) &&
      (! header.rcode)) {

    do_qstn = header.numof_questions;
    while (do_qstn) {
      if (do_qstn >= BLOCK_SIZE)
	block = BLOCK_SIZE;
      else
	block = do_qstn;
      do_qstn = do_qstn - block;

      last_qstn = &qstn;
      while (block) {
	*last_qstn = malloc(sizeof(struct name_srvc_question_lst));
	cur_qstn = *last_qstn;
	if (! cur_qstn) {
	  /* Abort. */
	  destroy_name_srvc_qstn_lst(qstn, 1);
	  return;
	}
	cur_qstn->qstn = read_name_srvc_qstnTCP(sckt, buff, MAX_RDATALEN,
						&walker, &len_leftover, &offsetof_start,
						startbuff, &startbuff_walker);
	if (! cur_qstn->qstn) {
	  /* Abort. */
	  cur_qstn->next = 0;
	  destroy_name_srvc_qstn_lst(qstn, 1);
	  return;
	}
	last_qstn = &(cur_qstn->next);

	block--;
      }

      res = name_srvc_do_namqrynodestat(0, 0, 0, params->id.tid, cur_time,
					&qstn, &numof_OK, &numof_notOK);
      if (qstn) {
	destroy_name_srvc_qstn_lst(qstn, 1);
      }

      if (res && (! answerhim)) {
	memset(&returnheader, 0, sizeof(struct name_srvc_pckt_header));
	returnheader.transaction_id = params->id.tid;
	returnheader.opcode = (OPCODE_RESPONSE | OPCODE_QUERY);
#ifdef COMPILING_NBNS
	returnheader.nm_flags = FLG_AA | FLG_RA;
#else
	returnheader.nm_flags = FLG_AA;
#endif
	returnheader.rcode = 0;

	/* See the comment over at POSITIVE NAME QUERY RESPONSE. */
	returnheader.numof_answers = do_qstn + numof_OK;

	fill_name_srvc_pckt_header(&returnheader, writebuff,
				   (writebuff + TCP_READWRITEBUFF_LEN));

	if (SIZEOF_NAMEHDR_ONWIRE > send(sckt, writebuff, SIZEOF_NAMEHDR_ONWIRE,
					 MSG_NOSIGNAL)) {
	  destroy_name_srvc_res_lst(res2, 1, 1);
	  return;
	}

	answerhim = TRUE;
      }

      cur_res = res;
      while (cur_res) {
	writewalker = fill_name_srvc_resource(cur_res->res, writebuff,
					      (writebuff + TCP_READWRITEBUFF_LEN),
					      0, 0);
	if (writewalker > writebuff) {
	  if ((writewalker - writebuff) > send(sckt, writebuff,
					       (writewalker - writebuff),
					       MSG_NOSIGNAL)) {
	    destroy_name_srvc_res_lst(res, 1, 1);
	    return;
	  }
	}

	cur_res = cur_res->next;
      }

      destroy_name_srvc_res_lst(res, 1, 1);
    }

    return;
  }

  // POSITIVE NAME QUERY RESPONSE

  if ((header.opcode == (OPCODE_RESPONSE |
			 OPCODE_QUERY)) &&
      (header.rcode == 0) &&
      (header.nm_flags & FLG_AA)) {

    do_qstn = header.numof_questions;
    while (do_qstn) {
      if (! ffrwd_name_srvc_qstnTCP(sckt, buff, MAX_RDATALEN,
				    &walker, &len_leftover, &offsetof_start,
				    startbuff, &startbuff_walker)) {
	return;
      }

      do_qstn--;
    }

    do_answ = header.numof_answers;
    while (do_answ) {
      if (do_answ >= BLOCK_SIZE)
	block = BLOCK_SIZE;
      else
	block = do_answ;
      do_answ = do_answ - block;

      last_res = &res;
      while (block) {
	*last_res = malloc(sizeof(struct name_srvc_resource_lst));
	cur_res = *last_res;
	if (! cur_res) {
	  /* Abort. */
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	cur_res->res = read_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,
					       &walker, &len_leftover, &offsetof_start,
					       startbuff, &startbuff_walker);
	if (! cur_res->res) {
	  /* Abort. */
	  cur_res->next = 0;
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	last_res = &(cur_res->next);

	block--;
      }

      res2 = name_srvc_do_posnamqryresp(0, addr, 0, params->id.tid,
					cur_time, res, &numof_OK);
      destroy_name_srvc_res_lst(res, 1, 1);

      if (res2 && (! answerhim)) {
	memset(&returnheader, 0, sizeof(struct name_srvc_pckt_header));
	returnheader.transaction_id = params->id.tid;
	returnheader.opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
	returnheader.nm_flags = FLG_AA;
	returnheader.rcode = RCODE_CFT_ERR;

	/* Actually, this will greatly overstate the actuall number of resources
	 * sent, but I have no way of knowing in advance just how many things will
	 * I send down the pipe and the packet may be infinite so there is no point
	 * in keeping the resources around untill they can be counted for an accurate
	 * number. I hope the other side can handle an abrupt stop in the packet
	 * before all the claimed resources have arrived (basically, that it properly
	 * and benevolently handles a BULLSHIT_IN_PACKET error condition). */
	returnheader.numof_answers = do_answ + numof_OK;

	fill_name_srvc_pckt_header(&returnheader, writebuff,
				   (writebuff + TCP_READWRITEBUFF_LEN));

	if (SIZEOF_NAMEHDR_ONWIRE > send(sckt, writebuff, SIZEOF_NAMEHDR_ONWIRE,
					 MSG_NOSIGNAL)) {
	  destroy_name_srvc_res_lst(res2, 1, 1);
	  return;
	}

	answerhim = TRUE;
      }

      cur_res = res2;
      while (cur_res) {
	writewalker = fill_name_srvc_resource(cur_res->res, writebuff,
					      (writebuff + TCP_READWRITEBUFF_LEN),
					      0, 0);
	if (writewalker > writebuff) {
	  if ((writewalker - writebuff) > send(sckt, writebuff,
					       (writewalker - writebuff),
					       MSG_NOSIGNAL)) {
	    destroy_name_srvc_res_lst(res2, 1, 1);
	    return;
	  }
	}

	cur_res = cur_res->next;
      }

      destroy_name_srvc_res_lst(res2, 1, 1);
    }

    return;
  }

  // NAME CONFLICT DEMAND

  if ((header.opcode == (OPCODE_RESPONSE |
			 OPCODE_REGISTRATION)) &&
      (header.rcode == RCODE_CFT_ERR) &&
      (header.nm_flags & FLG_AA)) {

    do_qstn = header.numof_questions;
    while (do_qstn) {
      if (! ffrwd_name_srvc_qstnTCP(sckt, buff, MAX_RDATALEN,
				    &walker, &len_leftover, &offsetof_start,
				    startbuff, &startbuff_walker)) {
	return;
      }

      do_qstn--;
    }

    do_answ = header.numof_answers;
    while (do_answ) {
      if (do_answ >= BLOCK_SIZE)
	block = BLOCK_SIZE;
      else
	block = do_answ;
      do_answ = do_answ - block;

      last_res = &res;
      while (block) {
	*last_res = malloc(sizeof(struct name_srvc_resource_lst));
	cur_res = *last_res;
	if (! cur_res) {
	  /* Abort. */
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	cur_res->res = read_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,
					       &walker, &len_leftover, &offsetof_start,
					       startbuff, &startbuff_walker);
	if (! cur_res->res) {
	  /* Abort. */
	  cur_res->next = 0;
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	last_res = &(cur_res->next);

	block--;
      }

      name_srvc_do_namcftdem(0, addr, res);

      destroy_name_srvc_res_lst(res, 1, 1);
    }

    return;
  }

  // NAME RELEASE REQUEST

  if ((header.opcode == (OPCODE_REQUEST |
			 OPCODE_RELEASE)) &&
      (header.rcode == 0)) {

    ffrwrdto_aditionals;

    do_adit = header.numof_additional_recs;
    while (do_adit) {
      if (do_adit >= BLOCK_SIZE)
	block = BLOCK_SIZE;
      else
	block = do_adit;
      do_adit = do_adit - block;

      last_res = &res;
      while (block) {
	*last_res = malloc(sizeof(struct name_srvc_resource_lst));
	cur_res = *last_res;
	if (! cur_res) {
	  /* Abort. */
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	cur_res->res = read_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,
					       &walker, &len_leftover, &offsetof_start,
					       startbuff, &startbuff_walker);
	if (! cur_res->res) {
	  /* Abort. */
	  cur_res->next = 0;
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	last_res = &(cur_res->next);

	block--;
      }

      res2 = res;
      name_srvc_do_namrelreq(0, addr,
#ifdef COMPILING_NBNS
			     params->trans, params->id.tid,
			     &numof_OK, &numof_notOK,
#endif
			     &res2);

      destroy_name_srvc_res_lst(res, 1, 1);
    }

    return;
  }

  // NAME UPDATE REQUEST

  if (((header.opcode == (OPCODE_REQUEST |
			  OPCODE_REFRESH)) ||
       (header.opcode == (OPCODE_REQUEST |
			  OPCODE_REFRESH2))) &&
      (header.rcode == 0)) {

    ffrwrdto_aditionals;

    do_adit = header.numof_additional_recs;
    while (do_adit) {
      if (do_adit >= BLOCK_SIZE)
	block = BLOCK_SIZE;
      else
	block = do_adit;
      do_adit = do_adit - block;

      last_res = &res;
      while (block) {
	*last_res = malloc(sizeof(struct name_srvc_resource_lst));
	cur_res = *last_res;
	if (! cur_res) {
	  /* Abort. */
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	cur_res->res = read_name_srvc_resrcTCP(sckt, buff, MAX_RDATALEN,
					       &walker, &len_leftover, &offsetof_start,
					       startbuff, &startbuff_walker);
	if (! cur_res->res) {
	  /* Abort. */
	  cur_res->next = 0;
	  destroy_name_srvc_res_lst(res, 1, 1);
	  return;
	}
	last_res = &(cur_res->next);

	block--;
      }

      res2 = res;
      name_srvc_do_updtreq(0, addr,
#ifdef COMPILING_NBNS
			   params->trans, params->id.tid,
			   &numof_OK, &numof_notOK,
#endif
			   cur_time, &res2, 0);

      destroy_name_srvc_res_lst(res, 1, 1);
    }

    return;
  }

  // NOOP

  return;
}
#undef BLOCK_SIZE

void *name_srvc_handle_newtid(void *input) {
  struct newtid_params params, *release_lock;
  struct thread_node *last_will;
  struct ss_unif_pckt_list *outside_pckt, *last_outpckt;
  unsigned char waited;
  time_t cur_time;


  memcpy(&params, input, sizeof(struct newtid_params));
  release_lock = input;
  release_lock->isbusy = 0;

  if (params.thread_id)
    last_will = add_thread(params.thread_id);
  else
    last_will = 0;

  last_outpckt = 0;
  waited = 0;

  while (0xceca) /* Also known as sesa. */ {

    ss_set_inputdrop_name_tid(&(params.id));

    do {
      outside_pckt = ss__recv_entry(params.trans);

      if (outside_pckt == last_outpckt) {
	/* No packet. */
	if (waited ||
	    nbworks_all_port_cntl.all_stop) {
	  /* Wait time passed. */
	  ss_deregister_name_tid(&(params.id));
	  ss__dstry_recv_queue(params.trans);
	  free(params.trans);
	  if (last_will)
	    last_will->dead = 9001; /* It's OVER *9000*!!! */
	  return 0;
	} else {
	  waited = 1;
	  ss_set_normalstate_name_tid(&(params.id));
	  nanosleep(&(nbworks_all_port_cntl.newtid_sleeptime), 0);
	  ss_set_inputdrop_name_tid(&(params.id));
	}
      } else {
	if (last_outpckt) {
          if (last_outpckt->stream.sckt >= 0)
            close(last_outpckt->stream.sckt);
	  free(last_outpckt);
        }
	last_outpckt = outside_pckt;
      }

    } while ((! outside_pckt->packet) &&
	     (outside_pckt->stream.sckt < 0));

    ss_set_normalstate_name_tid(&(params.id));
    cur_time = time(0);


    if (outside_pckt->packet) {
      name_srvc_daemon_newtidwrk(outside_pckt->packet, &(outside_pckt->addr),
				 &params, cur_time);

      destroy_name_srvc_pckt(outside_pckt->packet, 1, 1);
      outside_pckt->packet = 0;
      continue;
    }

    if (outside_pckt->stream.sckt >= 0) {
      name_srvc_daemon_newtidtcp(outside_pckt->stream.sckt, &(outside_pckt->addr),
				 &params, cur_time);

      close(outside_pckt->stream.sckt);
      outside_pckt->stream.sckt = -1;
      continue;
    }

    /* Impossible. */
  }

  return 0;
}

#ifdef COMPILING_NBNS
void *name_srvc_NBNS_newtid(void *threadid_ptr) {
  pthread_t *tid;
  struct thread_node *last_will;

  tid = threadid_ptr;

  if (tid) {
    last_will = add_thread(*tid);
    *tid = 0; /* Release the lock. */
  } else
    last_will = 0;

  name_srvc_NBNStid_hndlr(TRUE, 0, ONES);

  if (last_will)
    last_will->dead = TRUE;
  return 0;
}


struct name_srvc_packet *name_srvc_NBNStid_hndlr(unsigned int master,
						 uint16_t frst_index,
						 uint16_t last_index) {
  union trans_id transid;
  struct name_srvc_packet *outpckt;
  struct ss_unif_pckt_list *outside_pckt, *last_outpckt;
  time_t cur_time;
  uint16_t index;

  if (master) {
    if (last_index < frst_index)
      return 0;

    /* Reserve the index range and make sure some or all of the
     * requested trans have not already been reserved. */
    for (index=frst_index; index < last_index; index++) {
      if ((ss_alltrans[index].ss_iosig & SS_IOSIG_TIDED) ||
	  (ss_alltrans[index].ss_iosig & SS_IOSIG_TIDING)) {
	for (; index > frst_index; index--) {
	  ss_alltrans[index].ss_iosig = ss_alltrans[index].ss_iosig & (~SS_IOSIG_TIDING);
	}
	ss_alltrans[index].ss_iosig = ss_alltrans[index].ss_iosig & (~SS_IOSIG_TIDING);

	return 0;
      } else {
	ss_alltrans[index].ss_iosig |= SS_IOSIG_TIDING;
      }
    }
    if ((ss_alltrans[index].ss_iosig & SS_IOSIG_TIDED) ||
	(ss_alltrans[index].ss_iosig & SS_IOSIG_TIDING)) {
      for (; index > frst_index; index--) {
	ss_alltrans[index].ss_iosig = ss_alltrans[index].ss_iosig & (~SS_IOSIG_TIDING);
      }
      ss_alltrans[index].ss_iosig = ss_alltrans[index].ss_iosig & (~SS_IOSIG_TIDING);

      return 0;
    } else {
      for (; index > frst_index; index--) {
	ss_alltrans[index].ss_iosig |= SS_IOSIG_TIDED;
	ss_alltrans[index].ss_iosig = ss_alltrans[index].ss_iosig & (~SS_IOSIG_TIDING);
      }
      ss_alltrans[index].ss_iosig |= SS_IOSIG_TIDED;
      ss_alltrans[index].ss_iosig = ss_alltrans[index].ss_iosig & (~SS_IOSIG_TIDING);
    }

    transid.tid = frst_index;
    ss_set_inputdrop_name_tid(&transid);
  }

  last_outpckt = 0;
  index = frst_index;

  while (! nbworks_all_port_cntl.all_stop) {
    do {
      outside_pckt = ss__recv_entry(&(ss_alltrans[index].trans));

      if (outside_pckt == last_outpckt) {
	/* No packet. */
	if (master) {
	  /* In all fairness, the below code is very poorly positioned. */

	  transid.tid = index;
	  ss_set_normalstate_name_tid(&transid);

	  /* Note to self: this code will not create a memory leak because
	   * it only ever gets executed during the NO_PACKET condition. */
	  last_outpckt = 0;
	  do {
	    if (nbworks_all_port_cntl.all_stop) {
	      goto endof_function;
	    }

	    index++;
	    if ((index > last_index) ||
		(index == 0)) {
	      index = frst_index;
	      nanosleep(&(nbworks_namsrvc_cntrl.NBNSnewtid_sleeptime), 0);
	    }
	    /* The below while is actually an exit guard, preventing the
	     * exit from the loop in the event there is nothing in this
	     * trans. */
	  } while ((! (ss_alltrans[index].ss_iosig & SS_IOSIG_IN)) ||
		   (ss_alltrans[index].ss_iosig & SS_IOSIG_TAKEN));

	  transid.tid = index;
	  ss_set_inputdrop_name_tid(&transid);

	  continue;
	} else {
	  return 0;
	}
      } else {
	if (last_outpckt) {
          if (last_outpckt->stream.sckt >= 0)
            close(last_outpckt->stream.sckt >= 0);
	  free(last_outpckt);
        }
	last_outpckt = outside_pckt;
      }

    } while (! outside_pckt->packet);

    /* TCP-INSERTION */
    outpckt = outside_pckt->packet;
    outside_pckt->packet = 0;

    cur_time = time(0);

    // NAME REGISTRATION REQUEST (UNIQUE)
    // NAME REGISTRATION REQUEST (GROUP)

    if ((outpckt->header.opcode == (OPCODE_REQUEST |
				     OPCODE_REGISTRATION)) &&
	(! outpckt->header.rcode)) {

      if (! (master && name_srvc_do_NBNSnamreg(outpckt, &(outside_pckt->addr),
					       &(ss_alltrans[index].trans),
					       index, cur_time))) {
	/* If there is already a registration request pending on this
	 * transaction number, then siletly ignore all new registration
	 * requests until the original one is not resolved. */
	destroy_name_srvc_pckt(outpckt, 1, 1);
      }

      continue;
    }


    // NAME QUERY REQUEST
    // NODE STATUS REQUEST

    if ((outpckt->header.opcode == (OPCODE_REQUEST |
				     OPCODE_QUERY)) &&
	(! outpckt->header.rcode)) {

      name_srvc_do_namqrynodestat(outpckt, &(outside_pckt->addr),
				  &(ss_alltrans[index].trans),
				  index, cur_time, 0, 0, 0);

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // POSITIVE NAME QUERY RESPONSE

    if ((outpckt->header.opcode == (OPCODE_RESPONSE |
				     OPCODE_QUERY)) &&
	(outpckt->header.rcode == 0) &&
	(outpckt->header.nm_flags & FLG_AA)) {

      if (! master) {
	if (last_outpckt) {
          if (last_outpckt->stream.sckt >= 0)
            close(last_outpckt->stream.sckt >= 0);
	  free(last_outpckt);
        }
	/* Make sure there are no memory leaks. */
	if (outside_pckt->next) {
          if (outside_pckt->stream.sckt >= 0)
            close(outside_pckt->stream.sckt >= 0);
	  free(outside_pckt);
        }

	return outpckt;
      } else
	destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME RELEASE REQUEST

    if ((outpckt->header.opcode == (OPCODE_REQUEST |
				     OPCODE_RELEASE)) &&
	(outpckt->header.rcode == 0)) {

      name_srvc_do_namrelreq(outpckt, &(outside_pckt->addr),
			     &(ss_alltrans[index].trans),
			     index, 0, 0, 0);

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NAME UPDATE REQUEST

    if (((outpckt->header.opcode == (OPCODE_REQUEST |
				      OPCODE_REFRESH)) ||
	 (outpckt->header.opcode == (OPCODE_REQUEST |
				      OPCODE_REFRESH2))) &&
	(outpckt->header.rcode == 0)) {

      name_srvc_do_updtreq(outpckt, &(outside_pckt->addr),
			   &(ss_alltrans[index].trans),
			   index, 0, 0, cur_time, 0, 0);

      destroy_name_srvc_pckt(outpckt, 1, 1);
      continue;
    }

    // NOOP

    destroy_name_srvc_pckt(outpckt, 1, 1);
  }

 endof_function:
  if (master) {
    for (index = frst_index; index > last_index; index++) {
      ss_alltrans[index].ss_iosig = ss_alltrans[index].ss_iosig & (~SS_IOSIG_TIDED);
    }
    ss_alltrans[index].ss_iosig = ss_alltrans[index].ss_iosig & (~SS_IOSIG_TIDED);
  }
  return 0;
}
#endif


/* return: >0=success (return is ttl), 0=fail */
uint32_t name_srvc_add_name(node_type_t node_type,
			    unsigned char *name,
			    unsigned char name_type,
			    struct nbworks_nbnamelst *scope,
			    ipv4_addr_t my_ip_address,
			    uint32_t ttl) {
  unsigned char group_flg;

  switch (node_type) {
  case CACHE_NODEFLG_B:
    group_flg = ISGROUP_NO;
    goto B_mode_jumpover;
  case CACHE_NODEGRPFLG_B:
    group_flg = ISGROUP_YES;

  B_mode_jumpover:
    return name_srvc_B_add_name(name, name_type, scope,
				my_ip_address, group_flg,
				ttl);
    /*******/

  case CACHE_NODEFLG_P:
    group_flg = ISGROUP_NO;
    goto P_mode_jumpover;
  case CACHE_NODEGRPFLG_P:
    group_flg = ISGROUP_YES;

  P_mode_jumpover:
    return name_srvc_P_add_name(name, name_type, scope,
				my_ip_address, group_flg,
				ttl);
    /*******/

  case CACHE_NODEFLG_M:
    group_flg = ISGROUP_NO;
    goto M_mode_jumpover;
  case CACHE_NODEGRPFLG_M:
    group_flg = ISGROUP_YES;

  M_mode_jumpover:
    return name_srvc_P_add_name(name, name_type, scope,
				my_ip_address, group_flg,
				name_srvc_B_add_name(name, name_type, scope,
						     my_ip_address, group_flg,
						     ttl));
    /*******/

  case CACHE_NODEFLG_H:
    group_flg = ISGROUP_NO;
    goto H_mode_jumpover;
  case CACHE_NODEGRPFLG_H:
    group_flg = ISGROUP_YES;

  H_mode_jumpover:
    return name_srvc_B_add_name(name, name_type, scope,
				my_ip_address, group_flg,
				name_srvc_P_add_name(name, name_type, scope,
						     my_ip_address, group_flg,
						     ttl));
    /*******/

  default:
    return 0;
  }
}

/* XXX */

struct name_srvc_resource_lst *name_srvc_callout_name(unsigned char *name,
						      unsigned char name_type,
						      struct nbworks_nbnamelst *scope,
						      ipv4_addr_t ask_address,
						      ipv4_addr_t listen_address,
						      unsigned int name_flags,
						      unsigned int recursive,
						      struct sockaddr_in *target_addr) {
  struct sockaddr_in addr, taddr;
  union trans_id tid;
  struct name_srvc_resource_lst *res, **last_res;
  struct nbworks_nbnamelst *authority;
  struct nbaddress_list *nbaddr_list;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outside_pckt;
  struct name_srvc_resource_lst *result, *walker;
  unsigned int retry_count, i, truncated;

  if (! (name && ask_address))
    return 0;

  if (! target_addr)
    target_addr = &taddr;
  memset(target_addr, 0, sizeof(struct sockaddr_in));

  walker = result = 0;
  truncated = FALSE;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  fill_32field(ask_address, (unsigned char *)&(addr.sin_addr.s_addr));

  pckt = name_srvc_make_name_qry_req(name, name_type, scope);
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  tid.tid = make_id();

  trans = ss_register_name_tid(&tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    destroy_name_srvc_pckt(pckt, 1, 1);
    return 0;
  }

  pckt->header.transaction_id = tid.tid;
  pckt->header.opcode = OPCODE_REQUEST | OPCODE_QUERY;
  pckt->header.nm_flags = name_flags;

  retry_count = nbworks_namsrvc_cntrl.bcast_req_retry_count;
  for (i=0; i < retry_count; i++) {
    ss_name_send_pckt(pckt, &addr, trans);

    nanosleep(&(nbworks_namsrvc_cntrl.bcast_sleeptime), 0);

    ss_set_inputdrop_name_tid(&tid);

    while (1) {
      outside_pckt = ss__recv_pckt(trans, listen_address, target_addr);
      if (! outside_pckt) {
	break;
      }

      if ((outside_pckt->header.opcode == (OPCODE_RESPONSE |
					   OPCODE_QUERY)) &&
	  (outside_pckt->header.nm_flags & FLG_AA) &&
	  (outside_pckt->header.rcode == 0)) {
	/* POSITIVE NAME QUERY RESPONSE */
	res = outside_pckt->answers;
	last_res = &(outside_pckt->answers);

	while (res) {
	  if (res->res &&
	      (0 == nbworks_cmp_nbnodename(pckt->questions->qstn->name,
				   res->res->name)) &&
	      (pckt->questions->qstn->qtype ==
	       res->res->rrtype) &&
	      (pckt->questions->qstn->qclass ==
	       res->res->rrclass) &&
	      (res->res->rdata_t == nb_address_list)) {
	    /* This is what we are looking for. */

	    if (outside_pckt->header.nm_flags & FLG_TC)
	      truncated = TRUE;

	    if (result) {
	      walker->next = res;
	      walker = walker->next;
	    } else {
	      result = res;
	      walker = result;
	    }

	    res = *last_res = res->next;
	    break;

	  } else {
	    last_res = &(res->next);
	    res = res->next;
	  }
	}
      }

      /* Temporary fix to prevent reading more that one packet,
       * which could lead us to have duplicate addresses; not
       * a problem per se, but I don't want to implement yet
       * another complicated (and somewhat brittle) list walker,
       * this one for removing the duplicates. */
      if (result) {
	walker->next = 0;
	destroy_name_srvc_pckt(outside_pckt, 1, 1);
	break;
      }

      if (recursive) {
	if (outside_pckt->header.opcode == (OPCODE_RESPONSE |
					     OPCODE_WACK)) {
	  name_srvc_do_wack(outside_pckt,
			    pckt->questions->qstn->name,
			    pckt->questions->qstn->qtype,
			    pckt->questions->qstn->qclass,
			    &tid);
	}

	if ((outside_pckt->header.opcode == (OPCODE_RESPONSE |
					      OPCODE_QUERY)) &&
	    (outside_pckt->header.nm_flags & FLG_RD) &&
	    (outside_pckt->header.rcode == 0)) {
	  // REDIRECT NAME QUERY RESPONSE, probably
	  res = outside_pckt->authorities;

	  authority = 0;
	  while (res) {
	    if (res->res &&
		(0 == nbworks_cmp_nbnodename(pckt->questions->qstn->name,
				     res->res->name)) &&
		(res->res->rrtype == RRTYPE_NS) &&
		(pckt->questions->qstn->qclass ==
		 res->res->rrclass) &&
		(res->res->rdata_t == nb_nodename)) {
	      authority = res->res->rdata;
	      break;
	    }

	    res = res->next;
	  }

	  if (authority) {
	    res = outside_pckt->aditionals;

	    while (res) {
	      if (res->res &&
		  (0 == nbworks_cmp_nbnodename(authority,
				       res->res->name)) &&
		  (res->res->rrtype == RRTYPE_A) &&
		  (pckt->questions->qstn->qclass ==
		   res->res->rrclass) &&
		  (res->res->rdata_t == nb_NBT_node_ip_address)) {
		nbaddr_list = res->res->rdata;

		/* Hey, what if I ask for several names, and the NBNS sends a
		 * separate (and different) reference NBNS for each name? In how
		 * much trouble would I be then? */
		/* VAXism below. */
		fill_32field(nbaddr_list->address,
			     (unsigned char *)&(addr.sin_addr.s_addr));
		listen_address = nbaddr_list->address;
		break;
	      }

	      res = res->next;
	    }
	  }
	}
      }

      destroy_name_srvc_pckt(outside_pckt, 1, 1);
    }

    if (result) {
      walker->next = 0;
      break;
    }

    ss_set_normalstate_name_tid(&tid);
  }
  ss_deregister_name_tid(&tid);
  ss__dstry_recv_queue(trans);
  free(trans);

  if (truncated) {
    walker = name_srvc_TCPcallout_name(pckt, target_addr, recursive);
    if (walker) {
      if (result)
	destroy_name_srvc_res_lst(result, 1, 1);
      result = walker;
    }
  }

  destroy_name_srvc_pckt(pckt, 1, 1);

  return result;
}

struct cache_namenode *name_srvc_find_name(unsigned char *name,
					   unsigned char name_type,
					   struct nbworks_nbnamelst *scope,
					   node_type_t node_type) {  /* Only one node type! */
  struct sockaddr_in addr;
  struct cache_namenode *result;
  struct name_srvc_resource_lst *res, *res2;
  ipv4_addr_t nbns_addr;
  uint16_t target_flags;

  if (! name)
    return 0;

  switch (node_type) {
  case CACHE_NODEFLG_H:
    target_flags = NBADDRLST_GROUP_NO;
    goto H_mode_jumpover;
  case CACHE_NODEGRPFLG_H:
    target_flags = NBADDRLST_GROUP_YES;
  H_mode_jumpover:
    target_flags = target_flags | NBADDRLST_NODET_H;
    nbns_addr = get_nbnsaddr(scope);
    res = name_srvc_callout_name(name, name_type, scope, nbns_addr,
				 nbns_addr, FLG_RD, TRUE, &addr);
    if (! res) {
      res = name_srvc_callout_name(name, name_type, scope, brdcst_addr,
				   0, FLG_B, FALSE, &addr);
    }
    break;

  case CACHE_NODEFLG_M:
    target_flags = NBADDRLST_GROUP_NO;
    goto M_mode_jumpover;
  case CACHE_NODEGRPFLG_M:
    target_flags = NBADDRLST_GROUP_YES;
  M_mode_jumpover:
    target_flags = target_flags | NBADDRLST_NODET_M;
    res = name_srvc_callout_name(name, name_type, scope, brdcst_addr,
				 0, FLG_B, FALSE, &addr);
    if (! res) {
      nbns_addr = get_nbnsaddr(scope);
      res = name_srvc_callout_name(name, name_type, scope, nbns_addr,
				   nbns_addr, FLG_RD, TRUE, &addr);
    }
    break;

  case CACHE_NODEFLG_P:
    target_flags = NBADDRLST_GROUP_NO;
    goto P_mode_jumpover;
  case CACHE_NODEGRPFLG_P:
    target_flags = NBADDRLST_GROUP_YES;
  P_mode_jumpover:
    target_flags = target_flags | NBADDRLST_NODET_P;
    nbns_addr = get_nbnsaddr(scope);
    res = name_srvc_callout_name(name, name_type, scope, nbns_addr,
				 nbns_addr, FLG_RD, TRUE, &addr);
    break;

  case CACHE_NODEFLG_B:
    target_flags = NBADDRLST_GROUP_NO;
    goto B_mode_jumpover;
  case CACHE_NODEGRPFLG_B:
    target_flags = NBADDRLST_GROUP_YES;
  B_mode_jumpover:
    target_flags = target_flags | NBADDRLST_NODET_B;
    res = name_srvc_callout_name(name, name_type, scope, brdcst_addr,
				 0, FLG_B, FALSE, &addr);
    break;

  default:
    /* TODO: errno signaling stuff */
    return 0;
    break;
  }

  if (! res)
    return 0;

  result = 0;
  res2 = res;
  name_srvc_do_updtreq(0, &addr,
#ifdef COMPILING_NBNS
		       0, 0, 0, 0,
#endif
		       time(0), &res2, &result);

  destroy_name_srvc_res_lst(res, 1, 1);

  return result;
}

void name_srvc_release_name(unsigned char *name,
			    unsigned char name_type,
			    struct nbworks_nbnamelst *scope,
			    ipv4_addr_t my_ip_address,
			    node_type_t node_types) {
  if (! name)
    return;

  switch (node_types) {
  case CACHE_NODEFLG_B:
  case CACHE_NODEGRPFLG_B:
    name_srvc_do_release_name(name, name_type, scope, my_ip_address,
			      node_types, FALSE);
    return;

  case CACHE_NODEFLG_P:
  case CACHE_NODEGRPFLG_P:
    name_srvc_do_release_name(name, name_type, scope, my_ip_address,
			      node_types, TRUE);
    return;

    /* The below two introduce a bit of non-pedanticness where the
     * transaction between the daemon and NBNS has a different transaction
     * ID than the transaction between the daemon and other nodes. */
  case CACHE_NODEFLG_M:
  case CACHE_NODEGRPFLG_M:
    /* This is not accoding to standard. Accoding to RFC1002, if the NBNS
     * returns a negative response to the name removal request, I am supposed
     * to retain the name. But, the daemon goes forward and straight up deletes
     * the name anyway. The local broadcast segment is not informed of anything,
     * however and, since the daemon deletes the name, it also neither defends
     * the name nor does it update neighbours (or the NBNS for that matter). */
    /* This requirement of RFC1002 regarding M-mode is inconsistent with
     * requirements regarding the P-mode name deletion protocol. */
    if (0 < name_srvc_do_release_name(name, name_type, scope, my_ip_address,
				      node_types, TRUE)) {
      name_srvc_do_release_name(name, name_type, scope, my_ip_address,
				node_types, FALSE);
    }
    return;

  case CACHE_NODEFLG_H:
  case CACHE_NODEGRPFLG_H:
    name_srvc_do_release_name(name, name_type, scope, my_ip_address,
			      node_types, FALSE);
    name_srvc_do_release_name(name, name_type, scope, my_ip_address,
			      node_types, TRUE);
    return;

  default:
    return;
  }
}

/* return: >0=success, 0=fail, <0=error */
int name_srvc_do_release_name(unsigned char *name,
			      unsigned char name_type,
			      struct nbworks_nbnamelst *scope,
			      ipv4_addr_t my_ip_address,
			      node_type_t node_types,
			      unsigned char recursion) {
  struct sockaddr_in addr;
  struct timespec *sleeptime;
  struct ss_queue *trans;
  struct name_srvc_packet *pckt, *outpckt;
  struct nbworks_nbnamelst *probe;
  ipv4_addr_t listento;
  int ret_val;
  uint16_t type, class;
  unsigned int retry_count;
  unsigned char stop_yourself;
  union trans_id tid;

  if (! name)
    return -1;

  stop_yourself = FALSE;
  ret_val = 1;

  addr.sin_family = AF_INET;
  /* VAXism below. */
  fill_16field(137, (unsigned char *)&(addr.sin_port));
  /* In case of recursion, call get_nbnsaddr(), put the result in listento
   * and use it as an argument for fill_32field(), otherwise, set listento
   * to 0, and pass brdcst_addr to fill_32field(). */
  fill_32field((recursion ? (listento = get_nbnsaddr(scope)) :
		            (listento = 0, brdcst_addr)),
	       (unsigned char *)&(addr.sin_addr.s_addr));
  if (! addr.sin_addr.s_addr)
    return -1;

  pckt = name_srvc_make_name_reg_big(name, name_type, scope, 0,
				     my_ip_address,
				     node_types);
  if (! pckt) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  tid.tid = make_id();

  trans = ss_register_name_tid(&tid);
  if (! trans) {
    /* TODO: errno signaling stuff */
    destroy_name_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  if (! recursion) {
    /* Don't listen for incoming packets in B mode. */
    ss_set_inputdrop_name_tid(&tid);
    ss__dstry_recv_queue(trans);
    probe = 0;
    type = class = 0;

    retry_count = nbworks_namsrvc_cntrl.bcast_req_retry_count;
    sleeptime = &(nbworks_namsrvc_cntrl.bcast_sleeptime);
  } else {
    probe = nbworks_clone_nbnodename(pckt->questions->qstn->name);
    type = pckt->questions->qstn->qtype;
    class = pckt->questions->qstn->qclass;

    retry_count = nbworks_namsrvc_cntrl.ucast_req_retry_count;
    sleeptime = &(nbworks_namsrvc_cntrl.ucast_sleeptime);
  }

  pckt->header.transaction_id = tid.tid;
  pckt->header.opcode = OPCODE_REQUEST | OPCODE_RELEASE;
  pckt->header.nm_flags = (recursion ? FLG_RD : FLG_B);

  if (retry_count < 1)
    retry_count = 1;
  for (; retry_count > 0; retry_count--) {
    if (retry_count == 1)
      pckt->for_del = TRUE;

    if (stop_yourself)
      break;

    ss_name_send_pckt(pckt, &addr, trans);
    nanosleep(sleeptime, 0);

    if (recursion) {
      ss_set_inputdrop_name_tid(&tid);

      while (0101) {
	if (stop_yourself)
	  break;

	outpckt = ss__recv_pckt(trans, listento, 0);
	if (! outpckt) {
	  ss_set_normalstate_name_tid(&tid);
	  break;
	}

	if (outpckt->header.opcode == (OPCODE_RESPONSE |
					OPCODE_WACK)) {
	  name_srvc_do_wack(outpckt, probe,
			    type, class, &tid);
	}

	if ((outpckt->header.opcode == (OPCODE_RESPONSE |
					 OPCODE_RELEASE)) &&
	    (outpckt->header.nm_flags & FLG_AA)) {
	  stop_yourself = TRUE;
	  if (outpckt->header.rcode == 0) {
	    // POSITIVE NAME RELEASE RESPONSE
	  } else {
	    // NEGATIVE NAME RELEASE RESPONSE
	    ret_val = 0; /* Signal failure. */
	  }
	}

	destroy_name_srvc_pckt(outpckt, 1, 1);
      }
    }
  }

  ss_deregister_name_tid(&tid);
  if (recursion) {
    nbworks_dstr_nbnodename(probe);
    ss__dstry_recv_queue(trans);
  }
  free(trans);

  return ret_val;
}

/* This function sends refresh packets for scopes. */
void *refresh_scopes(void *i_ignore_this) {
#define B_CLASS 1
#define P_CLASS 0
  struct sockaddr_in addr;
  struct timespec sleeptime;
  struct cache_scopenode *cur_scope;
  struct ss_unif_pckt_list *outside_pckt, *last_outpckt;
  struct name_srvc_packet *pckt;
  union trans_id tid;
  struct ss_queue *trans;
  time_t cur_time, start_time;
  uint32_t wack;
  unsigned int i;
  struct {
    node_type_t node_types;
    ipv4_addr_t target_address;
    unsigned int auto_update;
  } refresh_desc[2];

  tid.tid = 0;

  addr.sin_family = AF_INET;
  /* VAXism below! */
  fill_16field(137, (unsigned char *)&(addr.sin_port));

  refresh_desc[P_CLASS].node_types = (CACHE_NODEFLG_P | CACHE_NODEFLG_M |
				      CACHE_NODEFLG_H |
				      CACHE_NODEGRPFLG_P | CACHE_NODEGRPFLG_M |
				      CACHE_NODEGRPFLG_H);
  refresh_desc[P_CLASS].auto_update = FALSE;
  refresh_desc[B_CLASS].node_types = (CACHE_NODEFLG_B | CACHE_NODEFLG_M |
				      CACHE_NODEFLG_H |
				      CACHE_NODEGRPFLG_B | CACHE_NODEGRPFLG_M |
				      CACHE_NODEGRPFLG_H);
  refresh_desc[B_CLASS].auto_update = TRUE;

  while (! nbworks_all_port_cntl.all_stop) {
    /* To pick up address changes. */
    refresh_desc[B_CLASS].target_address = brdcst_addr;
    cur_scope = nbworks_rootscope;
    trans = 0;

    while (cur_scope) {
      if (cur_scope->nbns_addr) {
	refresh_desc[P_CLASS].target_address = cur_scope->nbns_addr;
	for (i=0; i<2; i++) {
	  pckt = name_srvc_timer_mkpckt(cur_scope->names, cur_scope->scope,
					0, refresh_desc[i].node_types,
					refresh_desc[i].auto_update);

	  if (pckt) {
	    if (! trans) {
	      tid.tid = make_id();
	      trans = ss_register_name_tid(&tid);
	      if (! trans) {
		destroy_name_srvc_pckt(pckt, 1, 1);
		return 0;
	      }
	    }

	    pckt->header.transaction_id = tid.tid;
	    if (i == B_CLASS) {
	      pckt->header.nm_flags = FLG_B;
	    } else {
	      /* Flags already set by name_srvc_timer_mkpckt(). */
	      /* pckt->header.nm_flags = FLG_RD; */
	    }
	    pckt->for_del = TRUE;
	    /* VAXism below! */
	    fill_32field(refresh_desc[i].target_address,
			 (unsigned char *)&(addr.sin_addr.s_addr));

	    ss_name_send_pckt(pckt, &addr, trans);
	  }
	}
      }

      cur_scope = cur_scope->next;
    }

    if (trans) {
      nanosleep(&(nbworks_all_port_cntl.newtid_sleeptime), 0);

      ss_set_inputdrop_name_tid(&tid);
      start_time = cur_time = time(0);
      last_outpckt = outside_pckt = 0;
      wack = 0;

      while (0105) {
	do {
	  outside_pckt = ss__recv_entry(trans);

	  if (outside_pckt == last_outpckt) {
	    if (wack &&
		(time(0) < (start_time +
			    nbworks_namsrvc_cntrl.max_wack_sleeptime))) {
	      ss_set_normalstate_name_tid(&tid);

	      if (wack > nbworks_namsrvc_cntrl.max_wack_sleeptime) {
		wack = nbworks_namsrvc_cntrl.max_wack_sleeptime;
	      }
	      sleeptime.tv_sec = wack;
	      sleeptime.tv_nsec = 0;
	      nanosleep(&sleeptime, 0);
	      wack = 0;

	      ss_set_inputdrop_name_tid(&tid);
	      cur_time = time(0);
	    } else {
	      ss_deregister_name_tid(&tid);
	      ss__dstry_recv_queue(trans);
	      free(trans);
	      trans = 0;

	      break;
	    }
	  } else {
	    if (last_outpckt) {
	      if (last_outpckt->stream.sckt >= 0)
                close(last_outpckt->stream.sckt >= 0);
	      free(last_outpckt);
            }
	    last_outpckt = outside_pckt;
	  }

	} while (! outside_pckt->packet);

	if (! trans)
	  break;

        /* TCP-INSERTION */
	pckt = outside_pckt->packet;
	outside_pckt->packet = 0;

	if (pckt->header.opcode == (OPCODE_RESPONSE |
				     OPCODE_WACK)) {

	  /* BUG: This should actually cross-check to see if the sender
	   *      of the WACK was:
	   *      (a) an NBNS
	   *      (b) for the scope that it sent a WACK for
	   *      (c) whose opinion on the matter we asked for
	   *      I am not doing anything of that because COME-ON!! */
          wack = name_srvc_find_biggestwack(pckt, 0, 0, 0, wack, 0);

	  destroy_name_srvc_pckt(pckt, 1, 1);
	  continue;
        }

	if ((pckt->header.opcode == (OPCODE_RESPONSE |
				     OPCODE_REFRESH)) ||
	    (pckt->header.opcode == (OPCODE_RESPONSE |
				     OPCODE_REFRESH2))) {
	  if (pckt->header.rcode == 0) {

	    name_srvc_do_updtreq(pckt, &(outside_pckt->addr),
#ifdef COMPILING_NBNS
				 trans, tid.tid, 0, 0,
#endif
				 cur_time, 0, 0);

	  } else {

	    name_srvc_do_namcftdem(pckt, &(outside_pckt->addr), 0);

	  }

	}

	destroy_name_srvc_pckt(pckt, 1, 1);
      }

    }

    nanosleep(&(nbworks_all_port_cntl.newtid_sleeptime), 0);
  }

  return 0;
#undef P_CLASS
#undef B_CLASS
}


uint32_t name_srvc_find_biggestwack(struct name_srvc_packet *outside_pckt,
				    struct nbworks_nbnamelst *refname,
				    uint16_t reftype,
				    uint16_t refclass,
				    uint32_t prev_best_ttl,
				    struct name_srvc_resource_lst *state) {
  struct name_srvc_resource_lst *res;

  for ((state ? (res = state) : (res = outside_pckt->answers));
       res != 0;
       res = res->next) {
    if (res->res) {
      if ((! reftype) ||
	  (((0 == nbworks_cmp_nbnodename(refname, res->res->name)) &&
	    ((res->res->rrtype == RRTYPE_NULL) ||
	     (res->res->rrtype == reftype)) &&
	    (res->res->rrclass == refclass) &&
	    (res->res->ttl > prev_best_ttl)))) {
	prev_best_ttl = res->res->ttl;
      }
    }
  }

  return prev_best_ttl;
}

void name_srvc_do_wack(struct name_srvc_packet *outside_pckt,
		       struct nbworks_nbnamelst *refname,
		       uint16_t reftype,
		       uint16_t refclass,
		       void *tid) {
  struct timespec sleeptime;
  struct name_srvc_resource_lst *res;
  uint32_t ttl;

  ttl = 0;

  for (res = outside_pckt->answers;
       res != 0;
       res = res->next) {
    if (res->res &&
	(0 == nbworks_cmp_nbnodename(refname, res->res->name)) &&
	((res->res->rrtype == RRTYPE_NULL) ||
	 (res->res->rrtype == reftype)) &&
	(res->res->rrclass == refclass) &&
	(res->res->ttl > ttl))
      ttl = res->res->ttl;
  }

  if (ttl > nbworks_namsrvc_cntrl.max_wack_sleeptime) {
    ttl = nbworks_namsrvc_cntrl.max_wack_sleeptime;
  }

  if (ttl) {
    sleeptime.tv_sec = ttl;
    sleeptime.tv_nsec = 0;
    ss_set_normalstate_name_tid(tid);

    nanosleep(&sleeptime, 0);

    ss_set_inputdrop_name_tid(tid);
  }

  return;
}

struct name_srvc_resource *
  name_srvc_func_namregreq(struct name_srvc_resource *res,
			   time_t cur_time) {
  struct name_srvc_resource *answer;
  struct cache_namenode *cache_namecard;
  struct nbaddress_list *nbaddr;
  ipv4_addr_t in_addr;
  uint32_t i;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];

  /* This function fully shadows the difference
   * between B mode and P mode operation. */

  answer = 0;

  if (!((res) &&
	(res->name) &&
	(res->name->name) &&
	(res->name->len == NETBIOS_CODED_NAME_LEN) &&
	(res->rdata_t == nb_address_list)))
    return 0;

  nbaddr = res->rdata;
  while (nbaddr) {
    if (((nbaddr->flags & NBADDRLST_NODET_MASK) != NBADDRLST_NODET_P) &&
	(nbaddr->there_is_an_address))
      break;
    else
      nbaddr = nbaddr->next_address;
  }
  if (! nbaddr)
    return 0;

  decode_nbnodename(res->name->name, decoded_name);

  cache_namecard = find_nblabel(decoded_name,
				NETBIOS_NAME_LEN,
				CACHE_ADDRBLCK_UNIQ_MASK,
				res->rrtype,
				res->rrclass,
				res->name->next_name);

  /*
   * RATIONALE: Names can be either group names or unique names. Since
   * we jump over group names, that means we are only looking for unique
   * names. Furthermore, we are only looking for our names. If we fail to
   * find a record for the asked unique name, that means we have no problem.
   * Also, if we find a record, but the name is not ours, we again have
   * no problem.
   */

  if (!(cache_namecard &&
	((cache_namecard->unq_token) && (! cache_namecard->unq_isinconflict)) &&
	(cache_namecard->timeof_death > cur_time)))
    return 0;

  /* Paired with the DOS_BUG in the POSITIVE NAME QUERY RESPONSE
   * section, this can be abused to execute a hostile name takeover. */
  /* Someone is trying to take my name. */

  in_addr = 0;
  for (i=0; i<NUMOF_ADDRSES; i++) {
    if (cache_namecard->addrs.recrd[i].addr &&
	(cache_namecard->addrs.recrd[i].node_type &
	 CACHE_ADDRBLCK_UNIQ_MASK)) {
      in_addr = cache_namecard->addrs.recrd[i].addr->ip_addr;
      break;
    }
  }

  if (i<NUMOF_ADDRSES) {
    answer = name_srvc_make_res_nbaddrlst(decoded_name,
					  decoded_name[NETBIOS_NAME_LEN-1],
					  res->name->next_name,
					  /* Y2K38 */
					  (cache_namecard->timeof_death
					   - cur_time),
					  in_addr,
					  cache_namecard->addrs.recrd[i].node_type);
  }

  return answer;
}

struct name_srvc_resource_lst *
  name_srvc_do_namregreq(struct name_srvc_packet *outpckt,
			 struct sockaddr_in *addr,
			 struct ss_queue *trans,
			 uint32_t tid,
			 time_t cur_time,
			 unsigned long *numof_answers,
			 struct name_srvc_resource_lst *state) {
  struct name_srvc_resource_lst *res, *answer, **last_answr, *cur_answr;
  struct name_srvc_resource *response;
  struct name_srvc_packet *pckt;
  unsigned long numof_responses;

  /* This function fully shadows the difference
   * between B mode and P-type mode operation. */

  if (! ((outpckt && addr && trans) || state))
    return 0;

  last_answr = &answer;
  numof_responses = 0;

  for ((state ? (res = state) : (res = outpckt->aditionals));
       res != 0;      /* Maybe test in questions too. */
       res = res->next) {
    response = name_srvc_func_namregreq(res->res, cur_time);

    if (response) {
      *last_answr = malloc(sizeof(struct name_srvc_resource_lst));
      cur_answr = *last_answr;
      if (! cur_answr)
	break;

      cur_answr->res = response;
      last_answr = &(cur_answr->next);

      numof_responses++;
    }
  }
  *last_answr = 0;

  if (numof_answers)
    *numof_answers = numof_responses;

  if (state)
    return answer;

  pckt = alloc_name_srvc_pckt(0, 0, 0, 0);

  if (pckt) {
    pckt->for_del = TRUE;

    pckt->header.transaction_id = tid;
    pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
    pckt->header.nm_flags = FLG_AA;
    pckt->header.rcode = RCODE_CFT_ERR;

    pckt->header.numof_answers = numof_responses;
    pckt->answers = answer;

    ss_name_send_pckt(pckt, addr, trans);
  } else {
    destroy_name_srvc_res_lst(answer, 1, 1);
  }

  return 0;
}

#ifdef COMPILING_NBNS
/* returns: numof_laters */
uint32_t name_srvc_do_NBNSnamreg(struct name_srvc_packet *outpckt,
				 struct sockaddr_in *addr,
				 struct ss_queue *trans,
				 uint32_t tid,
				 time_t cur_time) {
  struct latereg_args laterargs;
  struct addrlst_bigblock addrblck, *addrblck_ptr;
  struct name_srvc_packet *pckt;
  struct name_srvc_resource_lst *res, **last_res, *fail, **last_fail,
    *later, **last_later;
  struct cache_namenode *cache_namecard;
  struct laters_link *laters_pair;
  time_t new_deathtime;
  uint32_t i, j, succeded, failed, laters;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];

  if (! (outpckt && addr && trans))
    return 0;

# define make_it_into_failed			\
  failed++;					\
						\
  *last_fail = res;				\
  last_fail = &(res->next);			\
						\
  *last_res = res->next;			\
  res = *last_res;

# define empty_addrblck						\
  for (i=0; i<NUMOF_ADDRSES; i++) {				\
    if (addrblck.addrs.recrd[i].addr) {				\
      destroy_addrlist(addrblck.addrs.recrd[i].addr);		\
      addrblck.addrs.recrd[i].addr = 0;				\
    }								\
  }

  last_fail = &fail;
  last_later = &later;
  succeded = failed = laters = 0;

  empty_addrblck;
  addrblck_ptr = &addrblck;

  last_res = &(outpckt->aditionals);
  res = *last_res;
  while (res != 0) {
    if (res->res) {
      if (!((res->res->name) &&
	    (res->res->name->name) &&
	    (res->res->name->len == NETBIOS_CODED_NAME_LEN) &&
	    (res->res->ttl > nbworks_namsrvc_cntrl.NBNS_threshold_ttl) &&
	    (res->res->rdata_t == nb_address_list) &&
	    (res->res->rdata))) {
	make_it_into_failed;
	continue;
      }

      if (! sort_nbaddrs(res->res->rdata, &addrblck_ptr)) {
	make_it_into_failed;
	continue;
      }

      /* Do not enter B node records into the cache. */
      addrblck.node_types = addrblck.node_types & (~(CACHE_NODEGRPFLG_B |
						     CACHE_NODEFLG_B));
      if (! addrblck.node_types) {
	make_it_into_failed;
	empty_addrblck;
	continue;
      }

      if ((addrblck.node_types & CACHE_ADDRBLCK_UNIQ_MASK) &&
	  (addrblck.node_types & CACHE_ADDRBLCK_GRP_MASK)) {
	make_it_into_failed;
	empty_addrblck;
	continue;
      }

      for (i=0; i<NUMOF_ADDRSES; i++) {
	if (addrblck.addrs.recrd[i].addr &&
	    (addrblck.addrs.recrd[i].node_type & (CACHE_NODEGRPFLG_B |
						  CACHE_NODEFLG_B))) {
	  destroy_addrlist(addrblck.addrs.recrd[i].addr);
	  addrblck.addrs.recrd[i].node_type = 0;
	  addrblck.addrs.recrd[i].addr = 0;
	}
      }

      if (! decode_nbnodename(res->res->name->name, decoded_name)) {
	make_it_into_failed;
	empty_addrblck;
	continue;
      }

      cache_namecard = find_nblabel(decoded_name, NETBIOS_NAME_LEN,
				    ANY_NODETYPE,
				    res->res->rrtype, res->res->rrclass,
				    res->res->name->next_name);

      /* Now, I have to weed out any possible B-only records. */
      if (cache_namecard) {
	while (! (cache_namecard->node_types &
		  (~(CACHE_NODEFLG_B | CACHE_NODEGRPFLG_B)))) {
	  cache_namecard = find_nextcard(cache_namecard,
					 ANY_NODETYPE,
					 res->res->rrtype, res->res->rrclass);

	  if (! cache_namecard) {
	    /* One may wonder why am I wasting cycles by looking everything
	     * up from the beggining. And to them I say that, at this point
	     * in processing, it is a real possibility that we will have to
	     * callout and challenge nodes for their names. One name lookup
	     * should not (emphasis on "*should* not") add a large cost. */
	    /* That said, I should perhaps streamline this. */
	    cache_namecard = find_nblabel(decoded_name, NETBIOS_NAME_LEN,
					  ANY_NODETYPE,
					  res->res->rrtype, res->res->rrclass,
					  res->res->name->next_name);
	    if (! cache_namecard) {
	      /* Impossible. */
	      goto make_a_new_namecard;
	    } else {
	      /* BUG: The below double loop doen't check that the sender
	       *      lists itself in the requested IP addresses. */
	      for (i=0; i<NUMOF_ADDRSES; i++) {
		for (j=0; j<NUMOF_ADDRSES; j++) {
		  if (cache_namecard->addrs.recrd[j].node_type ==
		      addrblck.addrs.recrd[i].node_type) {
		    cache_namecard->addrs.recrd[j].addr =
		      merge_addrlists(cache_namecard->addrs.recrd[j].addr,
				      addrblck.addrs.recrd[i].addr);
		    break;
		  } else {
		    if (cache_namecard->addrs.recrd[j].node_type == 0) {
		      cache_namecard->addrs.recrd[j].node_type =
			addrblck.addrs.recrd[i].node_type;
		      cache_namecard->addrs.recrd[j].addr =
			merge_addrlists(0, addrblck.addrs.recrd[i].addr);

		      cache_namecard->node_types |= addrblck.addrs.recrd[i].node_type;

		      break;
		    }
		  }
		}
	      }

	      new_deathtime = cur_time + res->res->ttl;
	      if (new_deathtime > cache_namecard->timeof_death)
		cache_namecard->timeof_death = new_deathtime;
	      cache_namecard->refresh_ttl = res->res->ttl;

	      succeded++;

	      last_res = &(res->next);
	      res = *last_res;

	      empty_addrblck;

	      continue;
	    }
	  }
	}
	/* Getting here means there is at least one lease on the name in
	 * at least one of the relevant modes.
	 * Assuming this is not a node which has expired but has yet to
	 * be deleted by the name pruner, this is a match and this
	 * resource has to be handled in a different manner. */

	laters_pair = nbw_calloc(1, sizeof(struct laters_link));
	if (! laters_pair) {
	  make_it_into_failed;
	  empty_addrblck;
	  continue;
	}
	memcpy(&(laters_pair->addrblck), &addrblck,
	       sizeof(struct addrlst_bigblock));

	laters_pair->rdata = res->res->rdata;
	laters_pair->namecard = cache_namecard;
	res->res->rdata = laters_pair;

	laters++;

	*last_later = res;
	last_later = &(res->next);

	*last_res = res->next;
	res = *last_res;

	continue;

      } else {
      make_a_new_namecard:
	cache_namecard = add_nblabel(decoded_name, NETBIOS_NAME_LEN,
				     addrblck.node_types,
				     0,
				     res->res->rrtype,
				     res->res->rrclass,
				     &(addrblck.addrs),
				     res->res->name->next_name);

	if (! cache_namecard) {
	  make_it_into_failed;
	  empty_addrblck;
	  continue;
	} else {
	  memset(&(addrblck.addrs), 0, sizeof(struct addrlst_cardblock));
          /* overflows in a safe way */
          cache_namecard->timeof_death = cur_time + res->res->ttl;
	  cache_namecard->refresh_ttl = res->res->ttl;

	  succeded++;
	}
      }
    }

    last_res = &(res->next);
    res = *last_res;
  }

  if (succeded) {
    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (pckt) {

      pckt->header.transaction_id = tid;
      pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
      pckt->header.nm_flags = FLG_AA | FLG_RA;
      pckt->header.rcode = 0;
      pckt->header.numof_answers = succeded;

      pckt->answers = outpckt->aditionals;
      outpckt->aditionals = 0;

      pckt->for_del = TRUE;

      ss_name_send_pckt(pckt, addr, trans);
    }
  }

  if (laters) {
    *last_later = 0;

    laterargs.pckt_flags = outpckt->header.opcode;
    laterargs.pckt_flags = laterargs.pckt_flags << 7;
    laterargs.pckt_flags |= outpckt->header.nm_flags;
    laterargs.pckt_flags = laterargs.pckt_flags << 4;
    laterargs.pckt_flags |= outpckt->header.rcode;

    laterargs.res = later;
    laterargs.addr = addr;
    laterargs.trans = trans;
    laterargs.tid = tid;
    laterargs.cur_time = cur_time;
    laterargs.not_done = 0xda;

    if (0 != pthread_create(&(laterargs.thread_id), 0,
			    name_srvc_NBNShndl_latereg, &laterargs)) {
      *last_fail = later;
      last_fail = last_later;

      failed = failed + laters;
      laters = 0;

      while (later) {
	laters_pair = later->res->rdata;
	later->res->rdata = laters_pair->rdata;

	for (i=0; i<NUMOF_ADDRSES; i++) {
	  if (laters_pair->addrblck.addrs.recrd[i].addr) {
	    destroy_addrlist(laters_pair->addrblck.addrs.recrd[i].addr);
	    laters_pair->addrblck.addrs.recrd[i].addr = 0;
	  }
	}
	free(laters_pair);

	later = later->next;
      }

    }
  }

  if (failed) {
    *last_fail = 0;

    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (pckt) {

      pckt->header.transaction_id = tid;
      pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
      pckt->header.nm_flags = FLG_AA | FLG_RA;
      pckt->header.rcode = RCODE_SRV_ERR;
      pckt->header.numof_answers = failed;

      pckt->answers = fail;

      pckt->for_del = TRUE;

      ss_name_send_pckt(pckt, addr, trans);
    } else {
      destroy_name_srvc_res_lst(fail, 1, 1);
    }
  }

  if (laters) {
    while (laterargs.not_done) {
      /* busy-wait */
    }

    ss_alltrans[tid].ss_iosig |= SS_IOSIG_TAKEN;
  }

# undef make_it_into_failed
# undef empty_addrblck

  return laters;
}

void destroy_laters_list(struct laters_link *laters) {
  struct name_srvc_resource dummyres;
  struct laters_link *next_later;
  int i;

  memset(&dummyres, 0, sizeof(struct name_srvc_resource));

  while (laters) {
    if (laters->res_lst) {
      if (laters->res_lst->res) {
	laters->res_lst->res->rdata_t = laters->rdata_t;
	laters->res_lst->res->rdata = laters->rdata;
	laters->res_lst->next = 0;
	destroy_name_srvc_res_lst(laters->res_lst, 1, 1);

	laters->rdata = 0;
      } else {
	free(laters->res_lst);
      }
    }

    if (laters->rdata) {
      dummyres.rdata_t = laters->rdata_t;
      dummyres.rdata = laters->rdata;

      destroy_name_srvc_res_data(&dummyres, 1, 1);
    }

    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (laters->addrblck.addrs.recrd[i].addr) {
	destroy_addrlist(laters->addrblck.addrs.recrd[i].addr);
      }
    }

    if (laters->probe)
      destroy_name_srvc_pckt(laters->probe, 1, 1);

    next_later = laters->next;
    free(laters);
    laters = next_later;
  }

  return;
}

void *name_srvc_NBNShndl_latereg(void *args) {
  struct sockaddr_in addr, probeaddr;
  union trans_id transid;
  struct nbaddress_list pckt_flags; /* I will SURELY burn in hell. */
  struct latereg_args laterargs, *release_lock;
  struct cache_namenode *cache_namecard;
  struct name_srvc_packet *pckt, *sendpckt, *response_pckt;
  struct addrlst_cardblock *addrses;
  struct thread_node *last_will;
  struct name_srvc_resource_lst *res, *response_res, *failed, **last_failed,
    *succeded, **last_succeded;
  struct laters_link *laters, *cur_laters, **last_laters, *killme, **last_killme;
  time_t cur_time, new_deathtime;
  uint32_t i, j, retries, numof_laters, numof_succeded, numof_failed;
  unsigned int retry_count;
  unsigned char you_may_succed, you_may_fail;

  if (! args)
    return 0;

# define empty_addrblck							\
  for (i=0; i<NUMOF_ADDRSES; i++) {					\
    if (addrblck->addrs.recrd[i].addr) {				\
      destroy_addrlist(addrblck->addrs.recrd[i].addr);			\
      addrblck->addrs.recrd[i].addr = 0;				\
    }									\
  }

  memcpy(&laterargs, args, sizeof(struct latereg_args));
  memcpy(&addr, laterargs.addr, sizeof(struct sockaddr_in));
  release_lock = args;
  release_lock->not_done = 0;

  if (laterargs.thread_id)
    last_will = add_thread(laterargs.thread_id);
  else
    last_will = 0;

  transid.tid = laterargs.tid;

  probeaddr.sin_family = AF_INET;
  /* VAXism below */
  fill_16field(137, (unsigned char *)&(probeaddr.sin_port));

  pckt_flags.flags = laterargs.pckt_flags;
  pckt_flags.there_is_an_address = FALSE;
  pckt_flags.address = 0;
  pckt_flags.next_address = 0;

  /* The laters list contains resources whose names have at least one lease
   * in at least one relevant mode. Their rdata's have been changed to contain
   * the laters_pair which contains both the original rdata and the pointer to
   * the cache namecard. */

  /* First, translate everything. */
  numof_laters = 0;
  last_laters = &laters;
  res = laterargs.res;
  while (res) {
    numof_laters++;

    cur_laters = *last_laters = res->res->rdata;
    last_laters = &(cur_laters->next);

    cur_laters->res_lst = res;

    cur_laters->ttl = res->res->ttl;
    cur_laters->rdata_len = res->res->rdata_len;
    cur_laters->rdata_t = res->res->rdata_t;
    /* cur_laters->rdata is already filled. */

    /* Get ready for sending WACKs. */
    res->res->ttl = (3 * (nbworks_namsrvc_cntrl.ucast_sleeptime.tv_sec +1));
    res->res->rdata_len = 2;
    res->res->rdata_t = nb_address_list;
    res->res->rdata = &pckt_flags;

    res = res->next;
  }
  *last_laters = 0;

  /* Second, send out WACKs. */
  pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
  if (! pckt) {
    destroy_laters_list(laters);
    goto endof_function;
  }
  pckt->header.transaction_id = laterargs.tid;
  pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_WACK);
  pckt->header.nm_flags = FLG_RA | FLG_AA;
  pckt->header.rcode = 0;

  pckt->header.numof_answers = numof_laters;
  pckt->answers = laterargs.res;

  ss_name_send_pckt(pckt, &addr, laterargs.trans);

  /* Now that that is out of the way, lets focus on actual laters themselves. */
  /* There are two basic cases that have to be handled.
   * The FIRST case is when trying to register a group name. If an identical unique
   * name is found to exist, we first have to challenge the unique node. If it
   * succedes or if there is no unique name, we can register the group name.
   * The SECOND case is when trying to register a unique name. If there is an
   * identical unique name, challenge it, if it does not defend, register the name.
   * However, if there is an identical group name, flat-out refuse to register the name.*/
  /* Note that these case groups have been inverted in the code below. */

  numof_failed = 0;
  last_failed = &failed;
  last_killme = &killme;

  numof_succeded = 0;
  last_succeded = &succeded;

  while (pckt->stuck_in_transit) {
    /* busy-wait */
    /* Prevents the resources being manipulated before
     * the WACK packet clears the service sector. */
  }

  retry_count = nbworks_namsrvc_cntrl.NBNS_retries;
  for (retries = 0; retries < retry_count; retries++) {
    ss_set_normalstate_name_tid(&transid);

    cur_time = time(0);
    numof_succeded = 0;
    last_succeded = &succeded;
    last_laters = &laters;
    cur_laters = *last_laters;
    while (cur_laters) {
      you_may_succed = FALSE;
      you_may_fail = FALSE;

      if (cur_laters->namecard->node_types & CACHE_ADDRBLCK_GRP_MASK) {
	if (cur_laters->addrblck.node_types & CACHE_ADDRBLCK_UNIQ_MASK) {
	  you_may_fail = TRUE;
	} else {
	  you_may_succed = TRUE;
	}
      }
      if ((cur_laters->namecard->node_types & CACHE_ADDRBLCK_UNIQ_MASK) &&
	  (! you_may_fail)) {
	you_may_succed = FALSE;

	if (! cur_laters->probe) {
	  cur_laters->probe =
	    name_srvc_make_name_qry_req(cur_laters->namecard->name,
					cur_laters->namecard->name[cur_laters->namecard->namelen -1],
					cur_laters->res_lst->res->name->next_name);

	  if (cur_laters->probe) {
	    cur_laters->probe->header.transaction_id = laterargs.tid;
	    cur_laters->probe->header.opcode = OPCODE_REQUEST | OPCODE_QUERY;
	    cur_laters->probe->header.nm_flags = 0;
	    cur_laters->probe->header.rcode = 0;
	  } /* else
	     ss_name_send_pckt() will handle the cur_laters->probe == 0 situation. */
	}
	for (i=0; i<NUMOF_ADDRSES; i++) {
	  if (cur_laters->addrblck.addrs.recrd[i].node_type & (CACHE_NODEFLG_P |
							       CACHE_NODEFLG_M |
							       CACHE_NODEFLG_H)) {
	    /* VAXism below */
	    fill_32field(cur_laters->addrblck.addrs.recrd[i].addr->ip_addr,
			 (unsigned char *)&(probeaddr.sin_port));

	    /* Send one to EACH address. Hopefully we won't create a network meltdown. */
	    ss_name_send_pckt(cur_laters->probe, &probeaddr, laterargs.trans);
	  }
	}
      }

      if (you_may_succed || you_may_fail) {
	if (you_may_fail) {
	  numof_failed++;

	  *last_failed = res = cur_laters->res_lst;
	  last_failed = &(res->next);
	} else { /* Intentionately written like this, to prevent a later
		  * from both succeding and failing. */
	  numof_succeded++;

	  *last_succeded = res = cur_laters->res_lst;
	  last_succeded = &(res->next);

	  /* -------------------- */
	  cache_namecard = cur_laters->namecard;
	  addrses = &(cur_laters->addrblck.addrs);
	  /* BUG: The below double loop doesn't check that the sender
	   *      lists itself in the requested IP addresses. */
	  for (i=0; i<NUMOF_ADDRSES; i++) {
	    for (j=0; j<NUMOF_ADDRSES; j++) {
	      if (cache_namecard->addrs.recrd[j].node_type ==
		  addrses->recrd[i].node_type) {
		cache_namecard->addrs.recrd[j].addr =
		  merge_addrlists(cache_namecard->addrs.recrd[j].addr,
				  addrses->recrd[i].addr);
		break;
	      } else {
		if (cache_namecard->addrs.recrd[j].node_type == 0) {
		  cache_namecard->addrs.recrd[j].node_type =
		    addrses->recrd[i].node_type;
		  cache_namecard->addrs.recrd[j].addr =
		    merge_addrlists(0, addrses->recrd[i].addr);

		  cache_namecard->node_types |= addrses->recrd[i].node_type;

		  break;
		}
	      }
	    }
	  }

	  new_deathtime = cur_time + cur_laters->ttl;
	  if (new_deathtime > cache_namecard->timeof_death)
	    cache_namecard->timeof_death = new_deathtime;
	  cache_namecard->refresh_ttl = cur_laters->ttl;
	  /* -------------------- */
	}

	res->res->ttl = cur_laters->ttl;
	res->res->rdata_len = cur_laters->rdata_len;
	res->res->rdata_t = cur_laters->rdata_t;
	res->res->rdata = cur_laters->rdata;

	cur_laters->rdata = 0;
	cur_laters->res_lst = 0;

	*last_killme = cur_laters;
	last_killme = &(cur_laters->next);

	*last_laters = cur_laters->next;
      } else {
	last_laters = &(cur_laters->next);
      }

      cur_laters = *last_laters;
    }
    *last_succeded = 0;
    *last_failed = 0;
    *last_killme = 0;
    *last_laters = 0;
    if (numof_succeded) {
      sendpckt = alloc_name_srvc_pckt(0, 0, 0, 0);
      if (sendpckt) {
	sendpckt->header.transaction_id = laterargs.tid;
	sendpckt->header.opcode = OPCODE_RESPONSE | OPCODE_REGISTRATION;
	sendpckt->header.nm_flags = FLG_AA | FLG_RA;
	sendpckt->header.rcode = 0;
	sendpckt->header.numof_answers = numof_succeded;

	sendpckt->answers = succeded;

	sendpckt->for_del = TRUE;
	ss_name_send_pckt(sendpckt, &addr, laterargs.trans);
      } else {
	destroy_name_srvc_res_lst(succeded, TRUE, TRUE);
      }
    }
    if (numof_failed) {
      sendpckt = alloc_name_srvc_pckt(0, 0, 0, 0);
      if (sendpckt) {
	sendpckt->header.transaction_id = laterargs.tid;
	sendpckt->header.opcode = OPCODE_RESPONSE | OPCODE_REGISTRATION;
	sendpckt->header.nm_flags = FLG_AA | FLG_RA;
	sendpckt->header.rcode = RCODE_ACT_ERR;
	sendpckt->header.numof_answers = numof_failed;

	sendpckt->answers = failed;

	sendpckt->for_del = TRUE;
	ss_name_send_pckt(sendpckt, &addr, laterargs.trans);
      } else {
	destroy_name_srvc_res_lst(failed, TRUE, TRUE);
      }
    }
    if (killme) {
      destroy_laters_list(killme);
    }

    nanosleep(&(nbworks_namsrvc_cntrl.ucast_sleeptime), 0);

    ss_set_inputdrop_name_tid(&transid);

    numof_failed = 0;
    last_failed = &failed;
    last_killme = &killme;

    while ((response_pckt = name_srvc_NBNStid_hndlr(FALSE, laterargs.tid,
						    laterargs.tid))) {
      response_res = response_pckt->answers;

      while (response_res) {
	last_laters = &laters;
	cur_laters = *last_laters;
	while (cur_laters) {
	  if (0 == nbworks_cmp_nbnodename(cur_laters->res_lst->res->name,
				  response_res->res->name)) {
	    /* Some node (I am not checking the senders IP address nor
	     * that said address is properly registered) has responded
	     * to a NAME QUERY REQUEST (or just sent the response of
	     * it's own volition with the same transaction_id as the one
	     * we are listening on). Interpret this to mean that this name
	     * is active and thus off-limits. */
	    numof_failed++;

	    *last_failed = res = cur_laters->res_lst;
	    last_failed = &(res->next);

	    res->res->ttl = cur_laters->ttl;
	    res->res->rdata_len = cur_laters->rdata_len;
	    res->res->rdata_t = cur_laters->rdata_t;
	    res->res->rdata = cur_laters->rdata;

	    cur_laters->rdata = 0;
	    cur_laters->res_lst = 0;

	    *last_killme = cur_laters;
	    last_killme = &(cur_laters->next);

	    *last_laters = cur_laters->next;
	  } else {
	    last_laters = &(cur_laters->next);
	  }

	  cur_laters = *last_laters;
	}

	response_res = response_res->next;
      }
    }

    if (! laters)
      break;
  }

  cur_time = time(0);
  /* These have survived the killing fields and are to be registered. */
  last_laters = &laters;
  cur_laters = *last_laters;
  while (cur_laters) {
    numof_succeded++;

    *last_succeded = res = cur_laters->res_lst;
    last_succeded = &(res->next);

    /* -------------------- */
    cache_namecard = cur_laters->namecard;
    addrses = &(cur_laters->addrblck.addrs);
    /* BUG: The below double loop doesn't check that the sender
     *      lists itself in the requested IP addresses. */
    for (i=0; i<NUMOF_ADDRSES; i++) {
      for (j=0; j<NUMOF_ADDRSES; j++) {
	if (cache_namecard->addrs.recrd[j].node_type ==
	    addrses->recrd[i].node_type) {
	  cache_namecard->addrs.recrd[j].addr =
	    merge_addrlists(cache_namecard->addrs.recrd[j].addr,
			    addrses->recrd[i].addr);
	  break;
	} else {
	  if (cache_namecard->addrs.recrd[j].node_type == 0) {
	    cache_namecard->addrs.recrd[j].node_type =
	      addrses->recrd[i].node_type;
	    cache_namecard->addrs.recrd[j].addr =
	      merget_addrlists(0, addrses->recrd[i].addr);

	    cache_namecard->node_types |= addrses->recrd[i].node_type;

	    break;
	  }
	}
      }
    }

    new_deathtime = cur_time + cur_laters->ttl;
    if (new_deathtime > cache_namecard->timeof_death)
      cache_namecard->timeof_death = new_deathtime;
    cache_namecard->refresh_ttl = cur_laters->ttl;
    /* -------------------- */

    res->res->ttl = cur_laters->ttl;
    res->res->rdata_len = cur_laters->rdata_len;
    res->res->rdata_t = cur_laters->rdata_t;
    res->res->rdata = cur_laters->rdata;

    cur_laters->rdata = 0;
    cur_laters->res_lst = 0;

    *last_killme = cur_laters;
    last_killme = &(cur_laters->next);

    *last_laters = cur_laters->next;
    cur_laters = *last_laters;
  }

  *last_succeded = 0;
  *last_failed = 0;
  *last_killme = 0;
  *last_laters = 0;
  if (numof_succeded) {
    sendpckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (sendpckt) {
      sendpckt->header.transaction_id = laterargs.tid;
      sendpckt->header.opcode = OPCODE_RESPONSE | OPCODE_REGISTRATION;
      sendpckt->header.nm_flags = FLG_AA | FLG_RA;
      sendpckt->header.rcode = 0;
      sendpckt->header.numof_answers = numof_succeded;

      sendpckt->answers = succeded;

      sendpckt->for_del = TRUE;
      ss_name_send_pckt(sendpckt, &addr, laterargs.trans);
    } else {
      destroy_name_srvc_res_lst(succeded, TRUE, TRUE);
    }
  }
  if (numof_failed) {
    sendpckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (sendpckt) {
      sendpckt->header.transaction_id = laterargs.tid;
      sendpckt->header.opcode = OPCODE_RESPONSE | OPCODE_REGISTRATION;
      sendpckt->header.nm_flags = FLG_AA | FLG_RA;
      sendpckt->header.rcode = RCODE_ACT_ERR;
      sendpckt->header.numof_answers = numof_failed;

      sendpckt->answers = failed;

      sendpckt->for_del = TRUE;
      ss_name_send_pckt(sendpckt, &addr, laterargs.trans);
    } else {
      destroy_name_srvc_res_lst(failed, TRUE, TRUE);
    }
  }
  if (killme) {
    destroy_laters_list(killme);
  }

  /* Destroy the long since forgotten WACK packet. */
  pckt->answers = 0;
  destroy_name_srvc_pckt(pckt, 1, 1);

 endof_function:
  ss_set_normalstate_name_tid(&transid);
  ss_alltrans[laterargs.tid].ss_iosig =
    ss_alltrans[laterargs.tid].ss_iosig & (~SS_IOSIG_TAKEN);
  if (last_will)
    last_will->dead = 218;
# undef empty_addrblck
  return 0;
}

#endif /* COMPILING_NBNS */


struct name_srvc_resource *name_srvc_func_nodestat(struct name_srvc_question *qstn,
						   time_t cur_time,
						   unsigned int *istruncated) {
#ifdef COMPILING_NBNS
  return 0;
#else
  struct name_srvc_resource *res;
  struct cache_namenode *cache_namecard;
  struct cache_scopenode *this_scope;
  struct name_srvc_statistics_rfc1002 *stats;
  struct nbnodename_list_backbone *names_list, **names_list_last;
  unsigned int i, numof_names;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];

  /* This function is identical in all modes of operation. */

  if (!(qstn &&
	(qstn->qtype == QTYPE_NBSTAT) &&
	qstn->name &&
	qstn->name->name &&
	(qstn->name->len == NETBIOS_CODED_NAME_LEN)))
    return 0;

  decode_nbnodename(qstn->name->name, decoded_name);

  if (((0 == memcmp(JOKER_NAME, decoded_name, NETBIOS_NAME_LEN)) ||
       ((cache_namecard = find_nblabel(decoded_name,
				       NETBIOS_NAME_LEN,
				       ANY_NODETYPE,
				       QTYPE_NB, qstn->qclass,
				       qstn->name->next_name)) &&
	((cache_namecard->unq_token && (! cache_namecard->unq_isinconflict)) ||
	 (cache_namecard->grp_tokens && (! cache_namecard->grp_isinconflict))) &&
	(cache_namecard->timeof_death > cur_time))) &&
      (this_scope = find_scope(qstn->name->next_name))) {

    res = malloc(sizeof(struct name_srvc_resource));
    if (! res) {
      return 0;
    }

    res->name = nbworks_clone_nbnodename(qstn->name);
    res->rrtype = RRTYPE_NBSTAT;
    res->rrclass = qstn->qclass;
    res->ttl = 0;

    stats = nbw_calloc(1, sizeof(struct name_srvc_statistics_rfc1002));
    if (! stats) {
      nbworks_dstr_nbnodename(res->name);
      free(res);
      return 0;
    }

    numof_names = 0;
    cache_namecard = this_scope->names;
    names_list_last = &(stats->listof_names);
    while (cache_namecard) {
      if (! (cache_namecard->unq_token || cache_namecard->grp_tokens)) {
	cache_namecard = cache_namecard->next;
	continue;
      }

      /* It is enough to only check for this overflow, as it is not possible
       * for RDATALEN to overflow if this one does not overflow first. */
      if (numof_names >= 0xff) {
	*istruncated = TRUE;
	*names_list_last = 0;
	break;
      }

      *names_list_last = malloc(sizeof(struct nbnodename_list_backbone));
      names_list = *names_list_last;

      if (! names_list) {
	/* No need to NULL-terminate the list becase it is already terminated. */
	*istruncated = TRUE;
	break;
      }
      numof_names++;

      names_list->nbnodename = malloc(sizeof(struct nbworks_nbnamelst));
      names_list->nbnodename->name = encode_nbnodename(cache_namecard->name, 0);
      names_list->nbnodename->len = NETBIOS_CODED_NAME_LEN;
      names_list->nbnodename->next_name = 0;

      for (i=0; i<NUMOF_ADDRSES; i++) {
	if (cache_namecard->addrs.recrd[i].node_type) {
	  switch (cache_namecard->addrs.recrd[i].node_type) {
	  case CACHE_NODEFLG_H:
	    names_list->name_flags = NBADDRLST_GROUP_NO;
	    names_list->name_flags |= NBADDRLST_NODET_H;
	    break;
	  case CACHE_NODEGRPFLG_H:
	    names_list->name_flags = NBADDRLST_GROUP_YES;
	    names_list->name_flags |= NBADDRLST_NODET_H;
	    break;

	  case CACHE_NODEFLG_M:
	    names_list->name_flags = NBADDRLST_GROUP_NO;
	    names_list->name_flags |= NBADDRLST_NODET_M;
	    break;
	  case CACHE_NODEGRPFLG_M:
	    names_list->name_flags = NBADDRLST_GROUP_YES;
	    names_list->name_flags |= NBADDRLST_NODET_M;
	    break;

	  case CACHE_NODEFLG_P:
	    names_list->name_flags = NBADDRLST_GROUP_NO;
	    names_list->name_flags |= NBADDRLST_NODET_P;
	    break;
	  case CACHE_NODEGRPFLG_P:
	    names_list->name_flags = NBADDRLST_GROUP_YES;
	    names_list->name_flags |= NBADDRLST_NODET_P;
	    break;

	  case CACHE_NODEFLG_B:
	    names_list->name_flags = NBADDRLST_GROUP_NO;
	    names_list->name_flags |= NBADDRLST_NODET_B;
	    break;
	  case CACHE_NODEGRPFLG_B:
	  default:
	    names_list->name_flags = NBADDRLST_GROUP_YES;
	    names_list->name_flags |= NBADDRLST_NODET_B;
	    break;
	  }

	  break;
	}
      }

      names_list->name_flags = names_list->name_flags | NODENAMEFLG_ACT;
      if (cache_namecard->unq_isinconflict || cache_namecard->grp_isinconflict)
	names_list->name_flags = names_list->name_flags | NODENAMEFLG_CNF;

      cache_namecard = cache_namecard->next;
      names_list_last = &(names_list->next_nbnodename);
    }
    *names_list_last = 0;
    stats->numof_names = numof_names;

    res->rdata_len = 1+20*2+6+(numof_names * (2+1+NETBIOS_CODED_NAME_LEN));
    res->rdata_t = nb_statistics_rfc1002;
    res->rdata = stats;

    return res;
  } else
    return 0;
#endif /* COMPILING_NBNS */
}

struct name_srvc_resource *name_srvc_func_namqry(struct name_srvc_question *qstn,
						 time_t cur_time,
						 unsigned int *istruncated) {
  struct name_srvc_resource *res;
  struct cache_namenode *cache_namecard;
  struct nbaddress_list *nbaddr_list, *nbaddr_list_frst, **nbaddr_list_last;
  struct ipv4_addr_list *ipv4_addr_list;
  unsigned long i, lenof_addresses;
  uint32_t flags;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];
  time_t lowest_deathtime, overflow_test;

  /* This function is identical in all modes of operation. */

  if (!(qstn &&
	(qstn->qtype != QTYPE_NBSTAT) &&
	qstn->name &&
	qstn->name->name &&
	(qstn->name->len == NETBIOS_CODED_NAME_LEN)))
    return 0;

  decode_nbnodename(qstn->name->name, decoded_name);

  flags = 0;
  lowest_deathtime = INFINITY;
  lenof_addresses = 0;
  nbaddr_list_last = &nbaddr_list_frst;
  cache_namecard = 0;
  do { /* Loop finds all duplicates of the name in the cache. */
    if (cache_namecard) {
      cache_namecard = find_nextcard(cache_namecard,
				     ANY_NODETYPE,
				     qstn->qtype,
				     qstn->qclass);
    } else {
      cache_namecard = find_nblabel(decoded_name,
				    NETBIOS_NAME_LEN,
				    ANY_NODETYPE,
				    qstn->qtype,
				    qstn->qclass,
				    qstn->name->next_name);
    }

    if (cache_namecard &&
#ifndef COMPILING_NBNS
	((cache_namecard->unq_token && (! cache_namecard->unq_isinconflict)) ||
	 (cache_namecard->grp_tokens && (! cache_namecard->grp_isinconflict))) &&
#endif
	(cache_namecard->timeof_death > cur_time)) {

      if (cache_namecard->timeof_death < lowest_deathtime)
	lowest_deathtime = cache_namecard->timeof_death;

      ipv4_addr_list = 0;
      for (i=0; i<NUMOF_ADDRSES; i++) {
	if (cache_namecard->addrs.recrd[i].addr) {
	  switch (cache_namecard->addrs.recrd[i].node_type) {
	  case CACHE_NODEFLG_H:
	    flags = NBADDRLST_GROUP_NO;
	    flags = flags | NBADDRLST_NODET_H;
	    break;
	  case CACHE_NODEGRPFLG_H:
	    flags = NBADDRLST_GROUP_YES;
	    flags = flags | NBADDRLST_NODET_H;
	    break;

	  case CACHE_NODEFLG_M:
	    flags = NBADDRLST_GROUP_NO;
	    flags = flags | NBADDRLST_NODET_M;
	    break;
	  case CACHE_NODEGRPFLG_M:
	    flags = NBADDRLST_GROUP_YES;
	    flags = flags | NBADDRLST_NODET_M;
	    break;

	  case CACHE_NODEFLG_P:
	    flags = NBADDRLST_GROUP_NO;
	    flags = flags | NBADDRLST_NODET_P;
	    break;
	  case CACHE_NODEGRPFLG_P:
	    flags = NBADDRLST_GROUP_YES;
	    flags = flags | NBADDRLST_NODET_P;
	    break;

	  case CACHE_NODEFLG_B:
	    flags = NBADDRLST_GROUP_NO;
	    flags = flags | NBADDRLST_NODET_B;
	    break;
	  case CACHE_NODEGRPFLG_B:
	  default:
	    flags = NBADDRLST_GROUP_YES;
	    flags = flags | NBADDRLST_NODET_B;
	    break;
	  }

	  ipv4_addr_list = cache_namecard->addrs.recrd[i].addr;
	}

	while (ipv4_addr_list) {
	  /* Overflow check. */
	  if (lenof_addresses > (MAX_RDATALEN - 6)) {
	    *istruncated = TRUE;
	    *nbaddr_list_last = 0;
	    break;
	  }

	  *nbaddr_list_last = malloc(sizeof(struct nbaddress_list));
	  nbaddr_list = *nbaddr_list_last;
	  if (! nbaddr_list) {
	    /* The list is already terminated, no need to do it here. */
	    break;
	  }

	  lenof_addresses = lenof_addresses +6;
	  nbaddr_list->flags = flags;
	  nbaddr_list->there_is_an_address = TRUE;
	  nbaddr_list->address = ipv4_addr_list->ip_addr;

	  nbaddr_list_last = &(nbaddr_list->next_address);
	  ipv4_addr_list = ipv4_addr_list->next;
	}
      } /* end the for loop */
    } /* end the cache_namecard tests */
  } while (cache_namecard);

  if (lenof_addresses) {
    *nbaddr_list_last = 0;

    res = malloc(sizeof(struct name_srvc_resource));
    if (! res) {
      destroy_nbaddress_list(nbaddr_list_frst);
      return 0;
    }
    res->name = nbworks_clone_nbnodename(qstn->name);
    res->rrtype = qstn->qtype;
    res->rrclass = qstn->qclass;
    if (lowest_deathtime > cur_time) {
      overflow_test = lowest_deathtime - cur_time;
      /* Test if RDATA_TTL will overflow. */
      if (overflow_test < (uint32_t)ONES)
	res->ttl = overflow_test;
      else
	res->ttl = (uint32_t)ONES;
    } else {
      /* *NEVER* send infinite answers. */
      res->ttl = 1;
    }

    return res;
  } else
    return 0;
}

struct name_srvc_resource_lst *
  name_srvc_do_namqrynodestat(struct name_srvc_packet *outpckt,
			      struct sockaddr_in *addr,
			      struct ss_queue *trans,
			      uint32_t tid,
			      time_t cur_time,
			      struct name_srvc_question_lst **state,
			      unsigned long *numof_founds,
			      unsigned long *numof_notfounds) {
  struct name_srvc_packet *pckt;
  struct name_srvc_resource_lst *frst_res, *res, **answer_lst, **last_res;
  struct name_srvc_question_lst *qstn, **last_qstn, *unknown, **last_unknown;
  struct name_srvc_resource *answer;
  unsigned int istruncated;
  unsigned long numof_answers, numof_failed;

  /* This function fully shadows the difference
   * between B mode and P-type mode of operation. */

  if (! ((outpckt && addr && trans) || (state && *state)))
    return 0;

  numof_failed = numof_answers = 0;
  answer_lst = &frst_res;
  istruncated = FALSE;
  numof_answers = 0;

  if (state && *state) {
    last_qstn = state;
  } else {
    last_qstn = &(outpckt->questions);
  }
  qstn = *last_qstn;
  last_unknown = &unknown;
  while (qstn) {
    if (! qstn->qstn) {
      qstn = qstn->next;
      continue;
    }

    if (qstn->qstn->qtype == QTYPE_NBSTAT)
      answer = name_srvc_func_nodestat(qstn->qstn, cur_time,
				       &istruncated);
    else
      answer = name_srvc_func_namqry(qstn->qstn, cur_time,
				     &istruncated);

    if (answer) {
      *answer_lst = malloc(sizeof(struct name_srvc_resource_lst));
      res = *answer_lst;
      if (! res) {
	destroy_name_srvc_res(answer, 1, 1);
	break;
      }
      res->res = answer;
      answer_lst = &(res->next);

      numof_answers++;

      last_qstn = &(qstn->next);
    } else {
      *last_unknown = qstn;
      last_unknown = &(qstn->next);

      *last_qstn = qstn->next;

      numof_failed++;
    }

    qstn = qstn->next;
  }
  *answer_lst = 0;
  *last_unknown = 0;

  if (numof_notfounds)
    *numof_notfounds = numof_failed;
  if (numof_founds)
    *numof_founds = numof_answers;

  if (state && *state) {
    destroy_name_srvc_qstn_lst(*state, 1);
    *state = unknown;

    return frst_res;
  }

  if (frst_res) {
    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (pckt) {
      pckt->answers = frst_res;

      pckt->header.transaction_id = tid;
      pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_QUERY);
#ifdef COMPILING_NBNS
      pckt->header.nm_flags = FLG_AA | FLG_RA;
#else
      pckt->header.nm_flags = FLG_AA;
#endif
      if (istruncated) {
	pckt->header.nm_flags |= FLG_TC;
      }
      pckt->header.rcode = 0;
      pckt->header.numof_answers = numof_answers;
      pckt->for_del = TRUE;

      ss_name_send_pckt(pckt, addr, trans);
    } else {
      destroy_name_srvc_res_lst(frst_res, 1, 1);
    }
  }

  /* Since we (presumably) have recursion as NBNS, I should actually
   * recursivelly ask upstream servers for the names I did not find. */
  if (unknown &&
      (!(outpckt->header.nm_flags & FLG_B))) {
    numof_failed = 0;

    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (pckt) {

      pckt->header.transaction_id = tid;
      pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_QUERY);
#ifdef COMPILING_NBNS
      pckt->header.nm_flags = FLG_AA | FLG_RA;
#else
      pckt->header.nm_flags = FLG_AA;
#endif
      pckt->header.rcode = RCODE_NAM_ERR;
      pckt->for_del = TRUE;

      last_res = &(pckt->answers);

      qstn = unknown;
      while (qstn) {
	*last_res = malloc(sizeof(struct name_srvc_resource_lst));
	res = *last_res;
	if (! res) {
	  break;
	}
	res->res = malloc(sizeof(struct name_srvc_resource));
	if (! res->res) {
	  free(res);
	  *last_res = 0;
	  break;
	}

	numof_failed++;

	res->res->name = qstn->qstn->name;
	qstn->qstn->name = 0;

	res->res->rrtype = RRTYPE_NULL;
	res->res->rrclass = qstn->qstn->qclass;
	res->res->ttl = 0;
	res->res->rdata_len = 0;
	res->res->rdata_t = nb_type_null;
	res->res->rdata = 0;

	last_res = &(res->next);
	qstn = qstn->next;
      }
      *last_res = 0;
      pckt->header.numof_answers = numof_failed;

      ss_name_send_pckt(pckt, addr, trans);
    }

    destroy_name_srvc_qstn_lst(unknown, 1);
  } else {
    if (unknown)
      destroy_name_srvc_qstn_lst(unknown, 1);
  }

  return 0;
}

#define STATUS_DID_NONE   0x00
#define STATUS_DID_GROUP  0x01
#define STATUS_DID_UNIQ   0x02
struct name_srvc_resource *
  name_srvc_func_posnamqryresp(struct name_srvc_resource *res,
			       struct sockaddr_in *addr,
			       struct ss_queue *trans,
			       uint32_t tid,
			       time_t cur_time,
			       ipv4_addr_t in_addr) {
  struct addrlst_bigblock addrblock, *addrblock_ptr;
  struct name_srvc_resource *answer;
  struct cache_namenode *cache_namecard;
  struct ipv4_addr_list *ipv4_addr_list;
  unsigned int i;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];

  /* This function fully shadows the difference
   * between B mode and P-type mode of operation. */

  addrblock_ptr = &addrblock;
  answer = 0;

  if (!(res &&
	(res->name) &&
	(res->name->name) &&
	(res->name->len == NETBIOS_CODED_NAME_LEN) &&
	(res->rdata_t == nb_address_list) &&
	(res->rdata) &&
	(sort_nbaddrs(res->rdata, &addrblock_ptr))))
    return 0;

  if (! (addrblock.node_types & (~(CACHE_NODEFLG_PTYPE |
				   CACHE_NODEGRPFLG_PTYPE)))) {
    cleanout_bigblock(addrblock_ptr);
    return 0;
  }

  decode_nbnodename(res->name->name, decoded_name);

  cache_namecard = find_nblabel(decoded_name,
				NETBIOS_NAME_LEN,
				(ANY_NODETYPE & (~(CACHE_NODEFLG_PTYPE |
						   CACHE_NODEGRPFLG_PTYPE))),
				res->rrtype,
				res->rrclass,
				res->name->next_name);

  /*
   * DOS_BUG: It is interesting.
   * RFC 1002 requires me to delete the entry from the
   * cache if I receive a POSITIVE NAME QUERY RESPONSE.
   * That would imply it is possible for an attacker to
   * just send me a response, forcing the cache expulsion
   * and effectivelly preventing me from ever obtaining
   * any handles to other nodes.
   *
   * Attempt at mitigation: verify the following matches:
   * 1. sender IP
   * 2. sender IP listed in the rdata of the res
   * 3. sender IP is listed in my cache
   *          (Therefore, I will only ever delete or mark as
   *           conflicting a group name if a member of the
   *           group is the one doing the talking. Conversely,
   *           only the owner of the unique name will be
   *           listened to.) (In this, node types are not
   *           taken into account.)
   */

  if (!((cache_namecard) &&
	(cache_namecard->timeof_death > cur_time) &&
	(cache_namecard->endof_conflict_chance < cur_time))) {
    cleanout_bigblock(addrblock_ptr);
    return 0;
  }

  /* NO conflict check. */
  if (addrblock.node_types & (CACHE_ADDRBLCK_GRP_MASK & (~CACHE_NODEGRPFLG_PTYPE))) {
    /* Verify the sender lists themselves as a member of the
       group being updated. */
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (addrblock.addrs.recrd[i].node_type &
	  (CACHE_ADDRBLCK_GRP_MASK & (~CACHE_NODEGRPFLG_PTYPE))) {
	ipv4_addr_list = addrblock.addrs.recrd[i].addr;
	while (ipv4_addr_list) {
	  if (ipv4_addr_list->ip_addr == in_addr)
	    break;
	  else
	    ipv4_addr_list = ipv4_addr_list->next;
	}
	if (ipv4_addr_list)
	  break;
      }
    }

    if ((i<NUMOF_ADDRSES) && ipv4_addr_list) {
      /* Note to self: this was here (read below) because RFC 1002
       * requires that this be sent regardless of whether the name
       * is group name or unique name. */
      /* Problem: generally, if I ask for a group name, all members of
       * the group will respond. It may also take them some time to do
       * so. Thus, this code may get triggered in such an innocent case.
       * If the sending node has its conflict timer running, said node
       * could experience various problems. */

      /* ---8<---------8<---------8<--- */
      /* Before, there was a piece of code here that would send a conflict demand
       * to the packet-originating node. This would have been sent even if the
       * node in question was answering about a group name. */
      /* It has been removed, even if it is in RFC 1002 because of:
       * (1) The problem that is outlined in the previous comment.
       * (2) It simplifies the implementation of this function for the TCP
       *     name service. */
      /* --->8--------->8--------->8--- */

      /* Verify that the name in question previously had
       * the IP address in question listed as it's member. */

      for (i=0; i<NUMOF_ADDRSES; i++) {
	if (cache_namecard->addrs.recrd[i].node_type &
	    (CACHE_ADDRBLCK_GRP_MASK & (~CACHE_NODEGRPFLG_PTYPE))) {
	  ipv4_addr_list = cache_namecard->addrs.recrd[i].addr;
	  while (ipv4_addr_list) {
	    if (ipv4_addr_list->ip_addr == in_addr)
	      break;
	    else
	      ipv4_addr_list = ipv4_addr_list->next;
	  }
	}
	if (ipv4_addr_list) {
	  if (! cache_namecard->grp_tokens)
	    cache_namecard->timeof_death = 0;
	  else {
	    /* WRONG! But how do I fix it? */
	    name_srvc_enter_conflict(ISGROUP_YES, cache_namecard,
				     decoded_name,
				     res->name->next_name);
	  }
	  break;
	}
      }

    }
  }

  if (addrblock.node_types & (CACHE_ADDRBLCK_UNIQ_MASK & (~CACHE_NODEFLG_PTYPE))) {
    /* Verify the sender lists himself as the owner. */
    for (i=0; i<NUMOF_ADDRSES; i++) {
      if (addrblock.addrs.recrd[i].node_type &
	  (CACHE_ADDRBLCK_UNIQ_MASK & (~CACHE_NODEFLG_PTYPE))) {
	ipv4_addr_list = addrblock.addrs.recrd[i].addr;
	while (ipv4_addr_list) {
	  if (ipv4_addr_list->ip_addr == in_addr)
	    break;
	  else
	    ipv4_addr_list = ipv4_addr_list->next;
	}
	if (ipv4_addr_list)
	  break;
      }
    }

    if ((i<NUMOF_ADDRSES) && ipv4_addr_list) {
      answer = name_srvc_make_res_nbaddrlst(decoded_name, decoded_name[NETBIOS_NAME_LEN-1],
					    res->name->next_name, 0, 0,
					    addrblock.addrs.recrd[i].node_type);

      /* Verify that the name in question previously had
       * the IP address in question listed as it's owner. */

      for (i=0; i<NUMOF_ADDRSES; i++) {
	if (cache_namecard->addrs.recrd[i].node_type &
	    (CACHE_ADDRBLCK_UNIQ_MASK & (~CACHE_NODEFLG_PTYPE))) {
	  ipv4_addr_list = cache_namecard->addrs.recrd[i].addr;
	  while (ipv4_addr_list) {
	    if (ipv4_addr_list->ip_addr == in_addr)
	      break;
	    else
	      ipv4_addr_list = ipv4_addr_list->next;
	  }
	}
	if (ipv4_addr_list) {
	  if (! cache_namecard->unq_token)
	    cache_namecard->timeof_death = 0;
	  else {
	    /* Impossible. */
	    name_srvc_enter_conflict(ISGROUP_NO, cache_namecard,
				     decoded_name,
				     res->name->next_name);
	  }
	  break;
	}
      }

    }
  }

  /* TODO: THIS ISN'T OVER YET, DOS_BUG!!! */
  /* TODO: make the function cross-reference the addr lists,
     looking for inconsistencies, like the
     NAME RELEASE REQUEST section does. */

  cleanout_bigblock(addrblock_ptr);
  return answer;
}

struct name_srvc_resource_lst *
  name_srvc_do_posnamqryresp(struct name_srvc_packet *outpckt,
			     struct sockaddr_in *addr,
			     struct ss_queue *trans,
			     uint32_t tid,
			     time_t cur_time,
			     struct name_srvc_resource_lst *state,
			     unsigned long *numof_responses) {
  struct name_srvc_resource_lst *res, *response, *frst_respns, **last_respns;
  struct name_srvc_resource *answer;
  struct name_srvc_packet *pckt;
  unsigned long numof_clicks;
  ipv4_addr_t in_addr;

  /* This function fully shadows the difference
   * between B mode and P mode operation. */

  if (! (((outpckt && trans) || state) && addr))
    return 0;

  last_respns = &frst_respns;
  numof_clicks = 0;

  /* Make sure noone spoofs the response. */
  /* VAXism below. */
  read_32field((unsigned char *)&(addr->sin_addr.s_addr), &in_addr);

  if (state)
    res = state;
  else
    res = outpckt->answers;
  while (res) {
    answer = name_srvc_func_posnamqryresp(res->res, addr, trans, tid,
					    cur_time, in_addr);

    if (answer) {
      *last_respns = malloc(sizeof(struct name_srvc_resource_lst));
      if (! *last_respns)
	break;
      response = *last_respns;
      response->res = answer;

      last_respns = &(response->next);

      numof_clicks++;
    }

    res = res->next;
  }
  *last_respns = 0;

  if (numof_responses)
    *numof_responses = numof_clicks;

  if (state)
    return frst_respns;

  pckt = alloc_name_srvc_pckt(0, 0, 0, 0);

  if (pckt) {
    pckt->for_del = TRUE;

    pckt->header.transaction_id = tid;
    pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
    pckt->header.nm_flags = FLG_AA;
    pckt->header.rcode = RCODE_CFT_ERR;

    pckt->header.numof_answers = numof_clicks;
    pckt->answers = frst_respns;

    ss_name_send_pckt(pckt, addr, trans);

  } else {
    destroy_name_srvc_res_lst(frst_respns, 1, 1);
  }

  return 0;
}

void name_srvc_func_namcftdem(struct name_srvc_resource *res,
			      ipv4_addr_t in_addr,
			      uint32_t name_flags) {
  struct cache_namenode *cache_namecard;
  struct nbaddress_list *nbaddr_list;
  unsigned int status, sender_is_nbns;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];

  /* This function fully shadows the difference
   * between B-type mode and P mode of operation. */

  if (!((res) &&
	(res->name) &&
	(res->name->name) &&
	(res->name->len == NETBIOS_CODED_NAME_LEN) &&
	(res->rdata_t == nb_address_list)))
    return;

  status = STATUS_DID_NONE;

  if ((in_addr == get_nbnsaddr(res->name->next_name)) &&
      ((name_flags ^ FLG_B) & FLG_B))
    sender_is_nbns = TRUE;
  else
    sender_is_nbns = FALSE;
  decode_nbnodename(res->name->name, decoded_name);

  nbaddr_list = res->rdata;
  while (nbaddr_list) {
    if (((nbaddr_list->flags & NBADDRLST_NODET_MASK) == NBADDRLST_NODET_P) ?
	/* When running in P mode, only enter if the sender is NBNS. */
	(sender_is_nbns) :
	/* Otherwise, only enter if the sender lists itself as the owner of the name. */
	(nbaddr_list->there_is_an_address &&
	 (nbaddr_list->address == in_addr))) {

      if (nbaddr_list->flags & NBADDRLST_GROUP_MASK)
	status = status | STATUS_DID_GROUP;
      else
	status = status | STATUS_DID_UNIQ;
    }

    if (status & (STATUS_DID_UNIQ | STATUS_DID_GROUP))
      break;
    else
      nbaddr_list = nbaddr_list->next_address;
  }

  /* Group and unique are separate because the two classes
   * used to be stored separately in the cache. */
  if (status & STATUS_DID_GROUP) {
    cache_namecard = find_nblabel(decoded_name,
				  NETBIOS_NAME_LEN,
				  CACHE_ADDRBLCK_GRP_MASK,
				  res->rrtype,
				  res->rrclass,
				  res->name->next_name);
    if (cache_namecard) {
      if (cache_namecard->grp_tokens) {
	/* WRONG ? */
	name_srvc_enter_conflict(ISGROUP_YES, cache_namecard,
				 decoded_name,
				 res->name->next_name);
      }
    }
  }
  if (status & STATUS_DID_UNIQ) {
    cache_namecard = find_nblabel(decoded_name,
				  NETBIOS_NAME_LEN,
				  CACHE_ADDRBLCK_UNIQ_MASK,
				  res->rrtype,
				  res->rrclass,
				  res->name->next_name);
    if (cache_namecard) {
      if (cache_namecard->unq_token) {
	name_srvc_enter_conflict(ISGROUP_NO, cache_namecard,
				 decoded_name,
				 res->name->next_name);
      }
    }
  }

  return;
}

void name_srvc_do_namcftdem(struct name_srvc_packet *outpckt,
			    struct sockaddr_in *addr,
			    struct name_srvc_resource_lst *state) {
  struct name_srvc_resource_lst *res;
  ipv4_addr_t in_addr;
  uint32_t name_flags;

  /* This function fully shadows the difference
   * between B mode and P mode operation. */

  if (! ((outpckt || state) && addr))
    return;

  /* Make sure we only listen to NBNS in P mode. */
  /* VAXism below. */
  read_32field((unsigned char *)&(addr->sin_addr.s_addr), &in_addr);
  name_flags = outpckt->header.nm_flags;

  if (state)
    res = state;
  else
    res = outpckt->answers;
  while (res) {
    name_srvc_func_namcftdem(res->res, in_addr, name_flags);

    res = res->next;
  }

  return;
}

/* returns: !0 = success, 0 = failure */
unsigned int name_srvc_func_namrelreq(struct name_srvc_resource *res,
				      ipv4_addr_t in_addr,
				      uint32_t name_flags) {
  struct cache_namenode *cache_namecard;
  struct nbaddress_list *nbaddr_list;
  unsigned int sender_is_nbns, success, status, i;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];
#ifndef COMPILING_NBNS
  struct ipv4_addr_list *ipv4fordel;
#endif

  /* This function fully shadows the difference
   * between B mode and P-type mode of operation. */

  if (!(res &&
	res->name &&
	res->name->name &&
	(res->name->len == NETBIOS_CODED_NAME_LEN) &&
	(res->rdata_t == nb_address_list)))
    return FALSE;

#ifndef COMPILING_NBNS
  /* For P mode, only read this if the packet was not broadcast. That is,
   * if the packet does not have the broadcast flag set - we will still
   * process a broadcast packet with the broadcast flag off.
   * Unless we are NBNS. */
  if ((in_addr == get_nbnsaddr(res->name->next_name)) &&
      ((name_flags ^ FLG_B) & FLG_B))
    sender_is_nbns = TRUE;
  else
    sender_is_nbns = FALSE;
#else
  sender_is_nbns = FALSE;
#endif
  success = FALSE;

  nbaddr_list = res->rdata;
  status = STATUS_DID_NONE;

  /* Re: those fucking conditional compilation macros!
   *   I understand reading them may be a problem, but this
   *   was, literally, the easiest way to do this. If too many
   *   people have a problem with reading it, I guess I will
   *   break it up. */
  while (nbaddr_list) {
    if ((nbaddr_list->there_is_an_address) &&
#ifndef COMPILING_NBNS
	(((nbaddr_list->flags & NBADDRLST_NODET_MASK) == NBADDRLST_NODET_P) ?
	 /* If P mode, only take into account if the sender is NBNS. */
	 (sender_is_nbns) :
#endif
	 /* Otherwise, if the sender lists itself in the list. */
	 (nbaddr_list->address == in_addr)
#ifndef COMPILING_NBNS
	)
#endif
       ) {
      if (nbaddr_list->flags & NBADDRLST_GROUP_MASK)
	status = status | STATUS_DID_GROUP;
      else
	status = status | STATUS_DID_UNIQ;
    }

    if (status == (STATUS_DID_GROUP | STATUS_DID_UNIQ))
      break;
    else
      nbaddr_list = nbaddr_list->next_address;
  }

  if (! (status & (STATUS_DID_GROUP | STATUS_DID_UNIQ))) {
    return FALSE;
  }

  nbaddr_list = res->rdata;

  decode_nbnodename(res->name->name, decoded_name);

  if (status & STATUS_DID_GROUP) {
    cache_namecard = find_nblabel(decoded_name,
				  NETBIOS_NAME_LEN,
				  CACHE_ADDRBLCK_GRP_MASK,
				  res->rrtype,
				  res->rrclass,
				  res->name->next_name);
    if (cache_namecard) {
      /* In NBNS mode, sender_is_nbns == FALSE. */
      if (0 < remove_membrs_frmlst(nbaddr_list, cache_namecard,
				   nbworks__myip4addr, sender_is_nbns)) {
	destroy_tokens(cache_namecard->grp_tokens);
	cache_namecard->grp_tokens = 0;
      }

      for (i=0; i<NUMOF_ADDRSES; i++) {
	if (cache_namecard->addrs.recrd[i].addr)
	  break;
      }

      if (i>=NUMOF_ADDRSES)
	cache_namecard->timeof_death = 0;

      success = TRUE;
    }
  }

  if (status & STATUS_DID_UNIQ) {
    cache_namecard = find_nblabel(decoded_name,
				  NETBIOS_NAME_LEN,
				  CACHE_ADDRBLCK_UNIQ_MASK,
				  res->rrtype,
				  res->rrclass,
				  res->name->next_name);
    if (cache_namecard) {
      if (! cache_namecard->unq_token) {
	cache_namecard->timeof_death = 0;
	success = TRUE;
      }
#ifndef COMPILING_NBNS
      else {
	/* Did I just get a name release for my own name? */
	if (sender_is_nbns &&
	    (cache_namecard->node_types & (CACHE_NODEFLG_P | CACHE_NODEFLG_M |
					   CACHE_NODEFLG_H | CACHE_NODEGRPFLG_P |
					   CACHE_NODEGRPFLG_M | CACHE_NODEGRPFLG_H))) {
	  for (i=0; i<NUMOF_ADDRSES; i++) {
	    if (! (cache_namecard->addrs.recrd[i].node_type &
		   (CACHE_NODEFLG_B | CACHE_NODEGRPFLG_B))) {
	      ipv4fordel = cache_namecard->addrs.recrd[i].addr;
	      cache_namecard->addrs.recrd[i].addr = 0;
	      destroy_addrlist(ipv4fordel);

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
#endif /* COMPILING_NBNS */
    }
  }

  return success;
}

struct name_srvc_resource_lst *
  name_srvc_do_namrelreq(struct name_srvc_packet *outpckt,
			 struct sockaddr_in *addr,
#ifdef COMPILING_NBNS
			 struct ss_queue *trans,
			 uint32_t tid,
			 unsigned long *numof_OK,
			 unsigned long *numof_notOK,
#endif
			 struct name_srvc_resource_lst **state) {
  struct name_srvc_resource_lst *res;
  ipv4_addr_t in_addr;
  uint32_t name_flags;
#ifdef COMPILING_NBNS
  struct name_srvc_packet *pckt;
  struct name_srvc_resource_lst **last_res, *answer, **last_answr;
  unsigned long numof_succedded, numof_failed;
#endif

  /* This function fully shadows the difference
   * between B mode and P mode operation. */

  if (! ((outpckt || (state && *state)) && addr))
    return 0;

  /* Make sure noone spoofs the release request. */
  /* VAXism below. */
  read_32field((unsigned char *)&(addr->sin_addr.s_addr), &in_addr);

#ifdef COMPILING_NBNS
  if (state && *state)
    last_res = state;
  else
    last_res = &(outpckt->aditionals);

  last_answr = &(answer);

  numof_succedded = 0;
  numof_failed = 0;
#endif
  name_flags = outpckt->header.nm_flags;

  if (state && *state)
    res = *state;
  else
    res = outpckt->aditionals;
  while (res) {
#ifdef COMPILING_NBNS
    if (name_srvc_func_namrelreq(res->res, in_addr,
				 name_flags)) {
      *last_answr = res;
      last_answr = &(res->next);

      *last_res = res->next;

      numof_succedded++;
    } else {
      last_res = &(res->next);
      numof_failed++;
    }
#else
    name_srvc_func_namrelreq(res->res, in_addr, name_flags);
#endif

    res = res->next;
  }

#ifdef COMPILING_NBNS
  *last_answr = 0;
  *last_res = 0;

  if (numof_OK)
    *numof_OK = numof_succedded;
  if (numof_notOK)
    *numof_notOK = numof_failed;

  if (state && *state) {
    /* Failed ones are already resigning on *state and
     * therefore there is nothing that needs to be done. */

    return answer;
  }

  if (numof_succedded) {
    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (pckt) {

      pckt->header.transaction_id = tid;
      pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_RELEASE);
      pckt->header.nm_flags = FLG_AA | FLG_RA;
      pckt->header.rcode = 0;
      pckt->header.numof_answers = numof_succedded;

      pckt->answers = answer;

      pckt->for_del = TRUE;

      ss_name_send_pckt(pckt, addr, trans);
    } else {
      destroy_name_srvc_res_lst(answer, 1, 1);
    }
  }

  if (numof_failed) {
    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (pckt) {

      pckt->header.transaction_id = tid;
      pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_REFRESH);
      pckt->header.nm_flags = FLG_AA | FLG_RA;
      pckt->header.rcode = RCODE_NAM_ERR;
      pckt->header.numof_answers = numof_failed;

      pckt->answers = outpckt->aditionals;
      outpckt->aditionals = 0;

      pckt->for_del = TRUE;

      ss_name_send_pckt(pckt, addr, trans);
    }
  }
#endif

  return 0;
}
#undef STATUS_DID_NONE
#undef STATUS_DID_GROUP
#undef STATUS_DID_UNIQ

/* returns: !0 = success, 0 = failure */
unsigned int name_srvc_func_updtreq(struct name_srvc_resource *res,
				    ipv4_addr_t in_addr,
				    uint32_t name_flags,
				    time_t cur_time,
				    struct cache_namenode **namecard) {
  struct cache_namenode *cache_namecard;
  struct addrlst_bigblock *addr_bigblock;
  ipv4_addr_t nbns_addr;
  unsigned int succedded, i, j;
  unsigned char decoded_name[NETBIOS_NAME_LEN+1];

  /* This function fully shadows the difference
   * between B mode and P-type mode of operation. */

#define update_ttls						\
  if (res->ttl) {						\
    cache_namecard->timeof_death = cur_time + res->ttl;		\
    if (cache_namecard->timeof_death < cur_time)		\
      cache_namecard->timeof_death = INFINITY;			\
    cache_namecard->refresh_ttl = res->ttl;			\
  } else {							\
    cache_namecard->timeof_death = INFINITY;			\
    if (! cache_namecard->refresh_ttl)				\
      cache_namecard->refresh_ttl = DEFAULT_REFRESH_TTL;	\
  }								\
								\
  cache_namecard->endof_conflict_chance = cur_time +		\
    nbworks_namsrvc_cntrl.conflict_timer;			\
  if (cache_namecard->endof_conflict_chance < cur_time)		\
    cache_namecard->endof_conflict_chance = INFINITY;

#define remove_doubles							\
  for (i=0; i<NUMOF_ADDRSES; i++) {					\
    if (addr_bigblock->addrs.recrd[i].node_type) {			\
      cache_namecard->addrs.recrd[i].node_type =			\
	addr_bigblock->addrs.recrd[i].node_type;			\
									\
      cache_namecard->addrs.recrd[i].addr =				\
	merge_addrlists(0, addr_bigblock->addrs.recrd[i].addr);		\
									\
      cache_namecard->node_types |=					\
	cache_namecard->addrs.recrd[i].node_type;			\
    }									\
  }

#define remove_Pies							\
  /* This cachenode is not yet in the cache. It is maybe having its	\
   * P-type mode records removed if a bunch of conditions is not right.	\
   * After that, it will be inserted into the cache. */			\
  if ((in_addr != nbns_addr) || (name_flags & FLG_B)) {                 \
    for (i=0; i<NUMOF_ADDRSES; i++) {					\
      if (cache_namecard->addrs.recrd[i].node_type &			\
	  (CACHE_NODEFLG_PTYPE | CACHE_NODEGRPFLG_PTYPE)) {		\
									\
	destroy_addrlist(cache_namecard->addrs.recrd[i].addr);		\
	cache_namecard->addrs.recrd[i].addr = 0;			\
	cache_namecard->addrs.recrd[i].node_type = 0;			\
	cache_namecard->node_types = cache_namecard->node_types &	\
	  (~(cache_namecard->addrs.recrd[i].node_type));		\
									\
	if (! cache_namecard->node_types) {				\
	  destroy_namecard(cache_namecard);				\
	  cache_namecard = 0;						\
	  break;							\
	}								\
      }									\
    }									\
  }

#define addrses_go_in							\
  for (j=0; j<NUMOF_ADDRSES; j++) {					\
    if (cache_namecard->addrs.recrd[j].node_type ==			\
	addr_bigblock->addrs.recrd[i].node_type) {			\
      cache_namecard->addrs.recrd[j].addr =				\
	merge_addrlists(cache_namecard->addrs.recrd[j].addr,		\
			addr_bigblock->addrs.recrd[i].addr);		\
									\
      if (namecard)							\
	*namecard = cache_namecard;					\
      succedded = TRUE;							\
									\
      break;								\
    } else if (cache_namecard->addrs.recrd[j].node_type == 0) {		\
      cache_namecard->addrs.recrd[j].node_type =			\
	addr_bigblock->addrs.recrd[i].node_type;			\
      /* Remove duplicates. */						\
      cache_namecard->addrs.recrd[j].addr =				\
	merge_addrlists(0, addr_bigblock->addrs.recrd[i].addr);		\
									\
      cache_namecard->node_types |=					\
	addr_bigblock->addrs.recrd[i].node_type;			\
									\
      if (namecard)							\
	*namecard = cache_namecard;					\
      succedded = TRUE;							\
									\
      break;								\
    } /* else							        \
	 continue the loop */						\
  } /* End of the for loop. */


#ifdef COMPILING_NBNS
# define insert_addrses_in_old_namecard					\
  for (i=0; i<NUMOF_ADDRSES; i++) {					\
    addrses_go_in;							\
  } /* Master NUMOF_ADDRSES iterator. */
#else
# define insert_addrses_in_old_namecard					\
  for (i=0; i<NUMOF_ADDRSES; i++) {					\
    /* In P-type mode, only insert if the data is coming from the NBNS. */ \
    if (addr_bigblock->addrs.recrd[i].addr &&				\
	((addr_bigblock->addrs.recrd[i].node_type &	                \
	  (CACHE_NODEFLG_PTYPE | CACHE_NODEGRPFLG_PTYPE)) ?		\
	 ((nbns_addr == in_addr) && (!(name_flags & FLG_B))) :	        \
	 TRUE)) {					                \
									\
      addrses_go_in;							\
									\
    } /* End of the P-mode if test */					\
  } /* Master NUMOF_ADDRSES iterator. */
#endif /* COMPILING_NBNS */


  if (!(res &&
	res->name &&
	res->name->name &&
	(res->name->len == NETBIOS_CODED_NAME_LEN) &&
	(res->rdata_t == nb_address_list)))
    return FALSE;

  addr_bigblock = sort_nbaddrs(res->rdata, 0);
  if (!addr_bigblock)
    return FALSE;

#ifndef COMPILING_NBNS
  nbns_addr = get_nbnsaddr(res->name->next_name);

  /* If there are no non-P-type modes AND the request does not come from NBNS... */
  if ((!(addr_bigblock->node_types & (~(CACHE_NODEFLG_PTYPE |
					CACHE_NODEGRPFLG_PTYPE)))) &&
      (in_addr != nbns_addr)) {
    destroy_bigblock(addr_bigblock);

    return FALSE;
  }
#endif
  succedded = FALSE;
  decode_nbnodename(res->name->name, decoded_name);

  if (addr_bigblock->node_types & CACHE_ADDRBLCK_GRP_MASK) {
    cache_namecard = find_nblabel(decoded_name,
				  NETBIOS_NAME_LEN,
				  ANY_NODETYPE,
				  res->rrtype,
				  res->rrclass,
				  res->name->next_name);

    if (! cache_namecard) {
      cache_namecard = alloc_namecard(decoded_name, NETBIOS_NAME_LEN,
				      (addr_bigblock->node_types &
				       CACHE_ADDRBLCK_GRP_MASK),
				      FALSE, res->rrtype, res->rrclass);
#ifndef COMPILING_NBNS
      remove_Pies;
#endif

      if (cache_namecard) {

	update_ttls;
	remove_doubles;

	if (! (add_scope(res->name->next_name, cache_namecard,
			 nbworks__default_nbns) ||
	       add_name(cache_namecard, res->name->next_name))) {
	  destroy_namecard(cache_namecard);
	  /* failed */
	} else {
	  if (namecard)
	    *namecard = cache_namecard;
	  succedded = TRUE;
	}
      }

    } else { /* It found a cache_namecard. */
      /* BUG: The number of problems a rogue node can create is mind boggling. */
      update_ttls;

      insert_addrses_in_old_namecard;
    }
  } /* (addr_bigblock->node_types & CACHE_ADDRBLCK_GRP_MASK) */
  if (addr_bigblock->node_types & CACHE_ADDRBLCK_UNIQ_MASK) {
    cache_namecard = find_nblabel(decoded_name,
				  NETBIOS_NAME_LEN,
				  ANY_NODETYPE,
				  res->rrtype,
				  res->rrclass,
				  res->name->next_name);

    if (! cache_namecard) {
      cache_namecard = alloc_namecard(decoded_name, NETBIOS_NAME_LEN,
				      (addr_bigblock->node_types &
				       CACHE_ADDRBLCK_UNIQ_MASK),
				      FALSE, res->rrtype, res->rrclass);
#ifndef COMPILING_NBNS
      remove_Pies;
#endif

      if (cache_namecard) {

	update_ttls;
	remove_doubles;

        if (! (add_scope(res->name->next_name, cache_namecard,
			 nbworks__default_nbns) ||
	       add_name(cache_namecard, res->name->next_name))) {
          destroy_namecard(cache_namecard);
	  /* failed */
        } else {
	  if (namecard)
	    *namecard = cache_namecard;
	  succedded = TRUE;
	}
      }

    } else {
      if (! cache_namecard->unq_token) {
	update_ttls;

	insert_addrses_in_old_namecard;
      }
      /* else: Sorry honey baby, you're cute, but that just ain't gonna work.
	 MAYBE: send a NAME CONFLICT DEMAND packet (if I am not NBNS). */
    }
  } /* (addr_bigblock->node_types & CACHE_ADDRBLCK_UNIQ_MASK) */

  destroy_bigblock(addr_bigblock);

  return succedded;
}

struct name_srvc_resource_lst *
  name_srvc_do_updtreq(struct name_srvc_packet *outpckt,
		       struct sockaddr_in *addr,
#ifdef COMPILING_NBNS
		       struct ss_queue *trans,
		       uint32_t tid,
		       unsigned long *numof_OK,
		       unsigned long *numof_notOK,
#endif
		       time_t cur_time,
		       struct name_srvc_resource_lst **state,
		       struct cache_namenode **namecard) {
  struct name_srvc_resource_lst *res;
  uint32_t name_flags;
  ipv4_addr_t in_addr;
#ifdef COMPILING_NBNS
  struct name_srvc_packet *pckt;
  struct name_srvc_resource_lst **last_res, *answer, **last_answr;
  unsigned long numof_succedded, numof_failed;
#endif

  /* This function fully shadows the difference
   * between B mode and P mode operation. */

  if (! ((outpckt || (state && *state)) && addr))
    return 0;

#ifdef COMPILING_NBNS
  if ((outpckt->header.nm_flags & FLG_B) ||
      (! trans))
    return 0;

  if (state && *state)
    last_res = state;
  else
    last_res = &(outpckt->aditionals);
  last_answr = &answer;
  numof_succedded = 0;
  numof_failed = 0;
#endif
  name_flags = outpckt->header.nm_flags;

  /* Make sure only NBNS is listened to in P mode. */
  read_32field((unsigned char *)&(addr->sin_addr.s_addr), &in_addr);

  if (state && *state)
    res = *state;
  else
    res = outpckt->aditionals;
  while (res) {
#ifdef COMPILING_NBNS
    if (name_srvc_func_updtreq(res->res, in_addr, name_flags,
			       cur_time, namecard)) {
      *last_answr = res;
      last_answr = &(res->next);

      *last_res = res->next;

      numof_succedded++;
    } else {
      numof_failed++;
      last_res = &(res->next);
    }
#else
    name_srvc_func_updtreq(res->res, in_addr, name_flags,
			   cur_time, namecard);
#endif

    res = res->next;
  }

#ifdef COMPILING_NBNS
  *last_answr = 0;
  *last_res = 0; /* superflous */

  if (numof_OK)
    *numof_OK = numof_succedded;
  if (numof_notOK)
    *numof_notOK = numof_failed;

  if (state && *state) {
    /* Failed ones are already resigning on *state and
     * therefore there is nothing that needs to be done. */

    return answer;
  }

  if (numof_succedded) {
    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (pckt) {

      pckt->header.transaction_id = tid;
      pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_REFRESH);
      pckt->header.nm_flags = FLG_AA | FLG_RA;
      pckt->header.rcode = 0;
      pckt->header.numof_answers = numof_succedded;

      pckt->answers = answer;

      pckt->for_del = TRUE;

      ss_name_send_pckt(pckt, addr, trans);
    } else {
      destroy_name_srvc_res_lst(answer, 1, 1);
    }
  }

  if (numof_failed) {
    pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
    if (pckt) {

      pckt->header.transaction_id = tid;
      pckt->header.opcode = (OPCODE_RESPONSE | OPCODE_REFRESH);
      pckt->header.nm_flags = FLG_AA | FLG_RA;
      pckt->header.rcode = RCODE_SRV_ERR; /* MAYBE: make this more verbose. */
      pckt->header.numof_answers = numof_failed;

      pckt->answers = outpckt->aditionals;
      outpckt->aditionals = 0;

      pckt->for_del = TRUE;

      ss_name_send_pckt(pckt, addr, trans);
    }
  }
#endif

  return 0;
}
