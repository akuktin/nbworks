/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <poll.h>
#include <errno.h>

#include "nbworks.h"
#include "constdef.h"
#include "nodename.h"
#include "library.h"
#include "pckt_routines.h"
#include "rail-comm.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"
#include "ses_srvc_pckt.h"
#include "randomness.h"
#include "rail-flush.h"
#include "portability.h"


int lib_daemon_socket(void) {
  struct sockaddr_un address;
  int daemon;

  memset(&address, 0, sizeof(struct sockaddr_un));

  address.sun_family = AF_UNIX;
  memcpy(address.sun_path +1, NBWORKS_SCKT_NAME, NBWORKS_SCKT_NAMELEN);

  daemon = socket(PF_UNIX, SOCK_STREAM, 0);
  if (daemon < 0) {
    nbworks_errno = errno;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  /*
  if (0 != set_sockoption(daemon, NONBLOCKING)) {
    nbworks_errno = errno;
    close(daemon);
    return -1;
  }
  */

  if (0 != connect(daemon, (struct sockaddr *)&address, sizeof(struct sockaddr_un))) {
    nbworks_errno = errno;
    close(daemon);
    return -1;
  }

  return daemon;
}


void lib_dstry_packets(struct packet_cooked *forkill) {
  struct packet_cooked *fordel;

  while (forkill) {
    fordel = forkill->next;
    free(forkill->data);
    nbworks_dstr_nbnodename(forkill->src);
    free(forkill);
    forkill = fordel;
  }

  return;
}


void lib_destroy_frags(struct dtg_frag *flesh) {
  struct dtg_frag *deed;

  while (flesh) {
    deed = flesh->next;
    free(flesh->data);
    free(flesh);
    flesh = deed;
  }

  return;
}

void lib_destroy_fragbckbone(struct dtg_frag_bckbone *bone) {
  /* A most curious site: a stackless function. */

  if (bone) {
    nbworks_dstr_nbnodename(bone->src);
    lib_destroy_frags(bone->frags);
    free(bone);
  }

  return;
}

void lib_destroy_allfragbckbone(struct dtg_frag_bckbone *frags) {
  struct dtg_frag_bckbone *for_del;

  while (frags) {
    for_del = frags->next;
    lib_destroy_fragbckbone(frags);
    frags = for_del;
  }

  return;
}

struct dtg_frag_bckbone *lib_add_fragbckbone(uint16_t id,
					     struct nbworks_nbnamelst *src,
					     uint16_t offsetof_first,
					     uint16_t lenof_first,
					     void *first_data,
					     struct dtg_frag_bckbone **frags) {
  struct dtg_frag_bckbone *result, *cur_frag, **last_frag;

  if (! (src && frags))
    return 0;

  result = malloc(sizeof(struct dtg_frag_bckbone));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->frags = malloc(sizeof(struct dtg_frag));
  if (! result->frags) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->id = id;
  result->last_active = time(0);
  result->src = nbworks_clone_nbnodename(src);
  result->last_ishere = FALSE;

  result->frags->offset = offsetof_first;
  result->frags->len = lenof_first;
  result->frags->data = first_data;
  result->frags->next = 0;

  result->next = 0;


  while (0xeee) {
    last_frag = frags;
    cur_frag = *last_frag;

    while (cur_frag) {
      if ((cur_frag->id == id) &&
	  (0 == nbworks_cmp_nbnodename(cur_frag->src, src))) {
	if (result == cur_frag)
	  return result;
	else {
	  lib_destroy_fragbckbone(result);
	  return 0;
	}
      } else {
	last_frag = &(cur_frag->next);
	cur_frag = *last_frag;
      }
    }

    *last_frag = result;
  }
}

struct dtg_frag_bckbone *lib_find_fragbckbone(uint16_t id,
					      struct nbworks_nbnamelst *src,
					      struct dtg_frag_bckbone *frags) {
  struct dtg_frag_bckbone *cur_frag;

  if (! (frags && src))
    return 0;

  cur_frag = frags;
  while (cur_frag) {
    if ((cur_frag->id == id) &&
	(0 == nbworks_cmp_nbnodename(cur_frag->src, src)))
      break;
    else
      cur_frag = cur_frag->next;
  }

  return cur_frag;
}

struct dtg_frag_bckbone *lib_take_fragbckbone(uint16_t id,
					      struct nbworks_nbnamelst *src,
					      struct dtg_frag_bckbone **frags) {
  struct dtg_frag_bckbone *cur_frag, **last_frag;

  if (! (frags && src))
    return 0;

  last_frag = frags;
  cur_frag = *last_frag;

  while (cur_frag) {
    if ((cur_frag->id == id) &&
	(0 == nbworks_cmp_nbnodename(cur_frag->src, src))) {
      *last_frag = cur_frag->next;
      return cur_frag;
    } else {
      last_frag = &(cur_frag->next);
      cur_frag = *last_frag;
    }
  }

  return 0;
}

void lib_del_fragbckbone(uint16_t id,
			 struct nbworks_nbnamelst *src,
			 struct dtg_frag_bckbone **frags) {
  struct dtg_frag_bckbone *cur_frag, **last_frag;

  if (! (frags && src))
    return;

  last_frag = frags;
  cur_frag = *last_frag;

  while (cur_frag) {
    if ((cur_frag->id == id) &&
	(0 == nbworks_cmp_nbnodename(cur_frag->src, src))) {
      *last_frag = cur_frag->next;
      lib_destroy_fragbckbone(cur_frag);
      return;
    } else {
      last_frag = &(cur_frag->next);
      cur_frag = *last_frag;
    }
  }

  return;
}

/* This function prunes fragment backbones, while taking care to assemble
 * any datagrams that may have had all their pieces arrive in the meantime. */
void lib_prune_fragbckbone(struct dtg_frag_bckbone **frags,
			   time_t killtime,
			   struct packet_cooked **anchor) {
  struct dtg_frag_bckbone *cur_frag, **last_frag;
  struct packet_cooked **cooked_pckt, *toshow;
  uint32_t len;

  if (! frags)
    return;

  cooked_pckt = anchor;
  last_frag = frags;
  cur_frag = *last_frag;

  while (cur_frag) {
    if (cur_frag->last_active < killtime) {
      *last_frag = cur_frag->next;

      if (anchor && cur_frag->last_ishere) {
	if (lib_order_frags(&(cur_frag->frags), &len)) {
	  toshow = malloc(sizeof(struct packet_cooked));
	  if (! toshow) {
	    lib_destroy_fragbckbone(cur_frag);
	    cur_frag = *last_frag;
	    continue;
	  }

	  toshow->data = lib_assemble_frags(cur_frag->frags, len);
	  cur_frag->frags = 0;

	  toshow->len = len;
	  toshow->src = cur_frag->src;
	  cur_frag->src = 0;

	  *cooked_pckt = toshow;
	  cooked_pckt = &(toshow->next);
	}
      }

      lib_destroy_fragbckbone(cur_frag);
    } else {
      last_frag = &(cur_frag->next);
    }

    cur_frag = *last_frag;
  }

  if (cooked_pckt)
    *cooked_pckt = 0;

  return;
}

struct dtg_frag_bckbone *lib_add_frag_tobone(uint16_t id,
					     struct nbworks_nbnamelst *src,
					     uint16_t offset,
					     uint16_t len,
					     void *data,
					     struct dtg_frag_bckbone *frags) {
  struct dtg_frag_bckbone *bone;
  struct dtg_frag *result, *cur_frag, **last_frag;

  result = malloc(sizeof(struct dtg_frag));
  if (! result)
    return 0;

  result->offset = offset;
  result->len = len;
  result->data = data;
  result->next = 0;

  bone = lib_find_fragbckbone(id, src, frags);
  if (! bone) {
    free(result);
    return 0;
  }

  while (42) {
    last_frag = &(bone->frags);
    cur_frag = *last_frag;

    while (cur_frag) {
      if (cur_frag == result) {
	bone->last_active = time(0);
	return bone;
      }

      last_frag = &(cur_frag->next);
      cur_frag = *last_frag;
    }

    *last_frag = result;
  }
}

struct dtg_frag *lib_order_frags(struct dtg_frag **frags,
				 uint32_t *len) {
  /* Regarding the brute forcing happening below:
   * I am sorry.
   * I will fix this later. To my knowledge, the standard C
   * library does not have a list sorting function. Therefore,
   * I have to implement one. Which I will do, but sometime later.
   * In the meantime, enjoy the brutishness. */
  struct dtg_frag *best_offer, *remove, **last, **bef_remv,
    *master, *sorted;
  uint32_t size_todate, offer, offered_len;

  if (! (frags && (*frags)))
    return 0;

  size_todate = 0;

  sorted = 0;
  master = 0;

  while (*frags) {
    last = frags;
    remove = *last;

    best_offer = 0;
    bef_remv = 0;
    offer = ONES;
    offered_len = ONES;

    while (remove) {
      if (remove->offset == offer) {
	if (remove->len == offered_len) {
	  /* A duplicate packet has been received. */
	  /* The situation described below, when two identical
	   * but not *the same* fragment streams get interwoven
	   * on the same wire, can still happen in this case too.
	   * It turns out there IS a way to detect this. */

	  if (0 != memcmp(best_offer->data, remove->data, offered_len)) {
	    goto fatal_error;
	  }

	  *last = remove->next;
	  free(remove->data);
	  free(remove);
	  remove = *last;
	  continue;
	} else {
	fatal_error:
	  /* There has been a BIG fuckup. */
	  /* Basically, this sort of situation can happen if two
	   * datagram streams get iterwoven, if the wire carries
	   * two different sets of fragments from the same sender
	   * to the same receiver and using the same ID.
	   * Very, very unlikely, but still possible. Also: think
	   * of the evil chinese crackers. Or is it evil iranian 
	   * crackers this year? Gosh, following propaganda sure
	   * is a full time job. */
	  if (sorted) {
	    sorted->next = *frags;
	    lib_destroy_frags(master);
	  } else {
	    lib_destroy_frags(*frags);
	  }
	  *frags = 0;
	  return 0;
	}
      }

      if (remove->offset < offer) {
	offered_len = remove->len;
	offer = remove->offset;
	bef_remv = last;
	best_offer = remove;
      }

      last = &(remove->next);
      remove = *last;
    }

    if (offer != size_todate) {
      if (offer > size_todate) {
	/* IP has lost a fragment or two. Alternatively, fragments are
	 * coming in out of order and I simply have to wait a bit longer
	 * to get the missing pieces. In both cases, the pruner function
	 * will take care of it. */
	if (sorted) {
	  sorted->next = *frags;
	  *frags = master;
	}
	return 0;
      } else {
	/* offer < size_todate */
	/* Big fuckup, see second comment up. */
	if (sorted) {
	  sorted->next = *frags;
	  lib_destroy_frags(master);
	} else {
	  lib_destroy_frags(*frags);
	}
	*frags = 0;
	return 0;
      }
    } else
      size_todate = size_todate + offered_len;

    if (best_offer && bef_remv) {
      *bef_remv = best_offer->next;
      if (sorted) {
	sorted->next = best_offer;
	sorted = sorted->next;
      } else {
	master = best_offer;
	sorted = master;
      }
    } else {
      if (sorted) {
	sorted->next = *frags;
	lib_destroy_frags(master);
      } else {
	lib_destroy_frags(*frags);
      }
      *frags = 0;
      return 0;
    }
  }

  sorted->next = 0;

  if (len)
    *len = size_todate;

  *frags = master;
  return master;
}

void *lib_assemble_frags(struct dtg_frag *frags,
			 uint32_t len) {
  struct dtg_frag *tmp;
  uint32_t done;
  unsigned char *result;

  if (! frags)
    return 0;

  if (len == 0) {
    tmp = frags;
    while (tmp) {
      len = len+tmp->len;
      tmp = tmp->next;
    }
  }

  result = malloc(len);
  if (! result)
    return 0;

  tmp = frags;
  done = 0;
  while (frags) {
    if (done + frags->len > len) {
      /* OUT_OF_BOUNDS */
      free(result);
      lib_destroy_frags(tmp);
      return 0;
    }
    memcpy((result + done), frags->data, frags->len);
    done = done + frags->len;
    frags = frags->next;
  }

  lib_destroy_frags(tmp);
  return result;
}


/* returns: TRUE (AKA 1) = YES, listens to,
            FALSE (AKA 0) = NO, doesn't listen to */
unsigned int lib_doeslistento(struct nbworks_nbnamelst *query,
			      struct nbworks_nbnamelst *answerlist) {
  int labellen;
  unsigned char *label;

  if (! (query && answerlist)) {
    if (query == answerlist)
      return TRUE;
    else
      return FALSE;
  }

  labellen = query->len;
  label = query->name;
  while (answerlist) {
    if (answerlist->len == labellen)
      if (0 == memcmp(label, answerlist->name, labellen))
	return TRUE;

    answerlist = answerlist->next_name;
  }

  return FALSE;
}


/* returns: <0 = error, 0 or >0 = something was sent */
ssize_t lib_senddtg_138(struct name_state *handle,
			unsigned char *recepient,
			unsigned char recepient_type,
			void *data_ptr,
			size_t len,
			int brdcst_or_grp) {
  struct dtg_srvc_packet *pckt;
  struct dtg_pckt_pyld_normal *pyld;
  struct com_comm command;
  unsigned long pckt_len, hdr_len, max_wholefrag_len;
  int daemon_sckt;
  uint32_t basic_pckt_flags;
  uint32_t frag_len, max_frag_len, numof_frags, frag_offset, names_len;
  unsigned char readycommand[LEN_COMM_ONWIRE], *data;
  void *readypacket;

  if ((! (handle && recepient)) ||
      (len > DTG_MAXLEN)) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    data = data_ptr;
  }

  /* Which FUCKING IDIOT came up with the idea to include
   * the length of the names in the datagram_length field??? */
  names_len = align(0, (1 + NETBIOS_CODED_NAME_LEN +
			handle->lenof_scope), 4)*2;
  hdr_len = DTG_HDR_LEN + 2 + 2 + names_len;

  max_wholefrag_len = nbworks_libcntl.dtg_max_wholefrag_len;
  if (max_wholefrag_len > MAX_UDP_PACKET_LEN) {
    /* Be generous to evil users and don't throw a sissy fit here. */
    max_wholefrag_len = MAX_UDP_PACKET_LEN;
  }

  if (hdr_len >= max_wholefrag_len) {
    nbworks_errno = EOVERFLOW;
    return -1;
  }

  max_frag_len = max_wholefrag_len - hdr_len;
  /* if (max_frag_len > FURTHER_IDIOTISM) max_frag_len = FURTHER_IDIOTISM;
   * With FURTHER_IDIOTISM = ARBITRARY_maximum_length_of_user_data */

  /* Check if we can send the data with overloading.
   * Actually, see if the data is so big that not even
   * overloading can save our sorry asses. */
  if (len > (DTG_MAXOFFSET + max_frag_len)) {
    nbworks_errno = EMSGSIZE;
    return -1;
  }

  /* The scheme we use is to have the last fragment as big as possible, in order
   * to utilize overloading. Consequently, the first fragment is used to adjust
   * that which needs adjustments. */
  pckt_len = len;
  numof_frags = 1;
  while (pckt_len > max_frag_len) {
    numof_frags++;
    pckt_len = pckt_len - max_frag_len;
  }
  /* Hold on to this frag_len, as it will be reused below. */
  frag_len = pckt_len;

  /* Is this datagram sent to everyone, all members
   * of a group or only to a single node? */
  /* Reused below. */
  switch (brdcst_or_grp) {
  case DTGIS_BRDCST:
    brdcst_or_grp = BRDCST_DTG;
    break;
  case DTGIS_GRPCST:
    brdcst_or_grp = DIR_GRP_DTG;
    break;
  case DTGIS_UNQCST:
    brdcst_or_grp = DIR_UNIQ_DTG;
    break;
  default:
    nbworks_errno = EINVAL;
    return -1;
  }

  pckt = malloc(sizeof(struct dtg_srvc_packet));
  if (! pckt) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  pckt->for_del = 0;
  switch (handle->node_type) {
  case CACHE_NODEFLG_H:
    basic_pckt_flags = DTG_NODE_TYPE_M;
    command.node_type = RAIL_NODET_HUNQ;
    break;
  case CACHE_NODEGRPFLG_H:
    basic_pckt_flags = DTG_NODE_TYPE_M;
    command.node_type = RAIL_NODET_HGRP;
    break;

  case CACHE_NODEFLG_M:
    basic_pckt_flags = DTG_NODE_TYPE_M;
    command.node_type = RAIL_NODET_MUNQ;
    break;
  case CACHE_NODEGRPFLG_M:
    basic_pckt_flags = DTG_NODE_TYPE_M;
    command.node_type = RAIL_NODET_MGRP;
    break;

  case CACHE_NODEFLG_P:
    basic_pckt_flags = DTG_NODE_TYPE_P;
    command.node_type = RAIL_NODET_PUNQ;
    break;
  case CACHE_NODEGRPFLG_P:
    basic_pckt_flags = DTG_NODE_TYPE_P;
    command.node_type = RAIL_NODET_PGRP;
    break;

  case CACHE_NODEFLG_B:
    basic_pckt_flags = DTG_NODE_TYPE_B;
    command.node_type = RAIL_NODET_BUNQ;
    break;
  case CACHE_NODEGRPFLG_B:
  default:
    basic_pckt_flags = DTG_NODE_TYPE_B;
    command.node_type = RAIL_NODET_BGRP;
    break;
  }
  pckt->type = brdcst_or_grp;

  pckt->id = make_id();
  pckt->src_address = nbworks__myip4addr;
  pckt->src_port = 138;

  pckt->payload_t = normal;
  pckt->payload = dtg_srvc_make_pyld_normal(handle->name->name, handle->label_type,
					    recepient, recepient_type,
					    handle->scope, 0, 0, 0);
  if (! pckt->payload) {
    nbworks_errno = ADD_MEANINGFULL_ERRNO;
    free(pckt);
    return -1;
  }
  pckt->error_code = 0;

  readypacket = calloc(1, max_wholefrag_len);
  if (! readypacket) {
    nbworks_errno = ENOBUFS;
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  daemon_sckt = lib_daemon_socket();
  if (daemon_sckt == -1) {
    nbworks_errno = ADD_MEANINGFULL_ERRNO;
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }
  /* --------------------------------- */

  pckt->flags = basic_pckt_flags | DTG_FIRST_FLAG;
  if (numof_frags > 1) {
    pckt->flags |= DTG_MORE_FLAG;
  }

  len = 0;
  pyld = pckt->payload;
  frag_offset = 0;
  while (numof_frags) {
    numof_frags--;

    pyld->lenof_data = frag_len;
    pyld->len = frag_len + names_len; /* Idiot. */
    pyld->offset = frag_offset;
    pyld->payload = data + frag_offset;

    pckt_len = hdr_len + frag_len;

    /* pckt_len is fixed by master_dtg_srvc_pckt_writer() below
     * to be the real length of the packet in the call below. */

    if (! master_dtg_srvc_pckt_writer(pckt, &pckt_len, readypacket, 0)) {
      nbworks_errno = ADD_MEANINGFULL_ERRNO;
      pyld->payload = 0;
      destroy_dtg_srvc_pckt(pckt, 1, 1);
      return -1;
    }
    pyld->payload = 0;

    memset(&(command), 0, sizeof(struct com_comm));
    command.command = rail_send_dtg;
    command.token = handle->token;
    command.len = pckt_len;
    command.data = readypacket;

    fill_railcommand(&command, readycommand, (readycommand + LEN_COMM_ONWIRE));

    if (LEN_COMM_ONWIRE > send(daemon_sckt, readycommand, LEN_COMM_ONWIRE,
			       MSG_NOSIGNAL)) {
      nbworks_errno = errno;
      close(daemon_sckt);
      free(readypacket);
      destroy_dtg_srvc_pckt(pckt, 1, 1);
      return -1;
    }

    if (pckt_len > send(daemon_sckt, readypacket, pckt_len, MSG_NOSIGNAL)) {
      nbworks_errno = errno;
      close(daemon_sckt);
      free(readypacket);
      destroy_dtg_srvc_pckt(pckt, 1, 1);
      return -1;
    }

    if (LEN_COMM_ONWIRE > recv(daemon_sckt, readycommand, LEN_COMM_ONWIRE,
			       MSG_WAITALL)) {
      nbworks_errno = ADD_MEANINGFULL_ERRNO;
      close(daemon_sckt);
      free(readypacket);
      destroy_dtg_srvc_pckt(pckt, 1, 1);
      return -1;
    }

    if (0 == read_railcommand(readycommand, (readycommand +LEN_COMM_ONWIRE),
			      &command)) {
      close(daemon_sckt);
      nbworks_errno = ENOBUFS;
      destroy_dtg_srvc_pckt(pckt, 1, 1);
      return -1;
    }

    if ((command.command != rail_send_dtg) ||
	(command.nbworks_errno)) {
      close(daemon_sckt);
      nbworks_errno = command.nbworks_errno;
      destroy_dtg_srvc_pckt(pckt, 1, 1);
      return 0;
    } else {
      len = len + frag_len;
    }

    if (numof_frags) {
      frag_offset = frag_offset + frag_len;
      /* Only the first fragment has a variable size,
       * others are as big as possible. */
      frag_len = max_frag_len;

      if (numof_frags > 1) {
	pckt->flags = basic_pckt_flags | DTG_MORE_FLAG;
      } else {
	pckt->flags = basic_pckt_flags;
      }
    }
  }

  close(daemon_sckt);
  destroy_dtg_srvc_pckt(pckt, 1, 1);

  return len;
}


void *lib_dtgserver(void *arg) {
  struct pollfd pfd;
  struct name_state *handle;
  struct dtg_frag_bckbone *fragbone;
  struct packet_cooked *toshow;
  struct dtg_srvc_packet *dtg;
  struct dtg_pckt_pyld_normal *nrml_pyld;
  struct nbworks_nbnamelst decoded_nbnodename;
  time_t last_pruned, killtime;
  unsigned long frag_keeptime;
  uint32_t len;
  unsigned char lenbuf[4], decoded_name[NETBIOS_NAME_LEN+1];
  unsigned char *new_pckt, take_dtg;

  if (arg)
    handle = arg;
  else
    return 0;

  if (! (handle->dtg_listento || handle->dtg_takes)) {
    handle->dtg_srv_stop = TRUE;
    return 0;
  }

  pfd.fd = handle->dtg_srv_sckt;
  pfd.events = POLLIN;

  handle->in_server = handle->in_library = 0;

  decoded_nbnodename.name = decoded_name;
  decoded_nbnodename.len = NETBIOS_NAME_LEN;
  decoded_nbnodename.next_name = 0;
  toshow = 0;
  take_dtg = FALSE;
  last_pruned = time(0);

  while ((! nbworks_libcntl.stop_alldtg_srv) &&
	 (! handle->dtg_srv_stop)) {
    /* This is a bad solution because, in the event of a datagram torrent,
     * time() is called far too often. However, the alternative is to put
     * it in the poll test below, which would be an even worse proposition
     * because lib_prune_fragbckbone() will not be called at all in the
     * event of a datagram torrent, when datagrams are comming in in
     * intervals shorter than nbworks_libcntl.dtg_srv_polltimeout. */
    frag_keeptime = nbworks_libcntl.dtg_frag_keeptime;
    killtime = time(0) - frag_keeptime;

    if (last_pruned < killtime) {
      /* toshow equals zero */
      lib_prune_fragbckbone(&(handle->dtg_frags), killtime, &toshow);
      if (toshow) {
	if (handle->in_server) {
	  handle->in_server->next = toshow;
	  handle->in_server = toshow;
	} else {
	  handle->in_server = toshow;
	  handle->in_library = toshow;
	}

	toshow = 0;
      }
      /* Save us a call to time(). */
      last_pruned = killtime + frag_keeptime;
    }

    if (0 >= poll(&pfd, 1, nbworks_libcntl.dtg_srv_polltimeout)) {
      if (pfd.revents & (POLLHUP | POLLNVAL | POLLERR)) {
	break;
      } else
        continue;
    }

    if (4 > recv(handle->dtg_srv_sckt, lenbuf, 4,
		 MSG_WAITALL)) {
      break;
    }

    read_32field(lenbuf, &len);

    new_pckt = malloc(len);
    if (! new_pckt) {
      break;
    }

    if (len > recv(handle->dtg_srv_sckt, new_pckt, len, MSG_WAITALL)) {
      free(new_pckt);
      break;
    }

    dtg = master_dtg_srvc_pckt_reader(new_pckt, len, 0);
    free(new_pckt);
    if (! dtg) {
      /* Actually, this is not strictly a fatal error. */
      continue;
    }

    nrml_pyld = dtg->payload;
    if ((dtg->payload_t == normal) &&
	nrml_pyld &&
	nrml_pyld->src_name &&
	nrml_pyld->src_name->name &&
	(nrml_pyld->src_name->len == NETBIOS_CODED_NAME_LEN)) {
      decode_nbnodename(nrml_pyld->src_name->name, decoded_nbnodename.name);
    } else {
      /* Theoretically, I should send a SOURCE NAME BAD FORMAT
       * error message to the sender or something like that. */
      destroy_dtg_srvc_pckt(dtg, 1, 1);
      continue;
    }
    if (handle->dtg_takes == HANDLE_TAKES_ALL)
      take_dtg = TRUE;
    else {
      switch (dtg->type) {
      case BRDCST_DTG:
	if (handle->dtg_takes & HANDLE_TAKES_ALLBRDCST) {
	  take_dtg = TRUE;
	} else {
	  take_dtg = lib_doeslistento(&decoded_nbnodename,
				      handle->dtg_listento);
	}
	break;

      case DIR_UNIQ_DTG:
	if (! (handle->node_type & CACHE_ADDRBLCK_UNIQ_MASK))
	  break;
	if (handle->dtg_takes & HANDLE_TAKES_ALLUNCST) {
	  take_dtg = TRUE;
	} else {
	  take_dtg = lib_doeslistento(&decoded_nbnodename,
				      handle->dtg_listento);
	}
	break;

      case DIR_GRP_DTG:
	if (! (handle->node_type & CACHE_ADDRBLCK_GRP_MASK))
	  break;
	if (handle->dtg_takes & HANDLE_TAKES_ALLUNCST) {
	  take_dtg = TRUE;
	} else {
	  take_dtg = lib_doeslistento(&decoded_nbnodename,
				      handle->dtg_listento);
	}
	break;

      default:
	break;
      }
    }

    /* This is the only point in the code where take_dtg can be TRUE. */

    if (take_dtg == TRUE) {
      take_dtg = FALSE;

      if (! (dtg->flags & DTG_FIRST_FLAG)) {
      attempt_to_add_a_fragment:
	if (lib_add_frag_tobone(dtg->id, &(decoded_nbnodename),
				nrml_pyld->offset, nrml_pyld->lenof_data,
				nrml_pyld->payload, handle->dtg_frags)) {
	  nrml_pyld->payload = 0;
	} else {
	  /* Either there was an internal error in lib_add_frag_tobone() or
	   * this is the first fragment of the datagram that was received,
	   * in the event of fragments coming in out of order. */
	  /* Assume the latter is true and attempt to add a new fragbone. */
	  if (lib_add_fragbckbone(dtg->id, &(decoded_nbnodename),
				  nrml_pyld->offset, nrml_pyld->lenof_data,
				  nrml_pyld->payload, &(handle->dtg_frags))) {
	    nrml_pyld->payload = 0;
	  } else {
	    lib_del_fragbckbone(dtg->id, &(decoded_nbnodename),
				&(handle->dtg_frags));
	    destroy_dtg_srvc_pckt(dtg, 1, 1);
	    continue;
	  }
	}
      } else {
	if (dtg->flags & DTG_MORE_FLAG) {
	  /* I am using this goto to reduce the amount of code. It is somewhat ineficient. */
	  goto attempt_to_add_a_fragment;
	}
      }

      if (! (dtg->flags & DTG_MORE_FLAG)) {
	toshow = malloc(sizeof(struct packet_cooked));
	if (! toshow) {
	  destroy_dtg_srvc_pckt(dtg, 1, 1);
	  continue;
	}

	if (dtg->flags & DTG_FIRST_FLAG) {
	  if (! nrml_pyld->offset) {
	    toshow->data = nrml_pyld->payload;
	    nrml_pyld->payload = 0;

	    toshow->len = nrml_pyld->lenof_data;
	    toshow->src = nbworks_clone_nbnodename(&(decoded_nbnodename));
	    if (! toshow->src) {
	      free(toshow->data);
	      free(toshow);
	      toshow = 0;
	    } else {
	      toshow->next = 0;
	    }
	  } else {
	    /* Now, interestingly, I might be able to interpret the
	     * offset as meaning that the offsetted part is filled with
	     * well-known information (maybe NULLs?) and is thus not
	     * transmitted, but only the other, meaningfull part is
	     * transmitted. */
	    free(toshow);
	    toshow = 0;
	  }
	} else {
	  fragbone = lib_take_fragbckbone(dtg->id, &(decoded_nbnodename),
					  &(handle->dtg_frags));
	  if (fragbone) {

	    if (lib_order_frags(&(fragbone->frags), &(toshow->len))) {
	      toshow->data = lib_assemble_frags(fragbone->frags, toshow->len);
	    } else {
	      if (! fragbone->frags) {
		/* lib_order_frags() has detected an unrecoverable error.
		 * Fragbckbone is unusable. */
		nbworks_dstr_nbnodename(fragbone->src);
		free(fragbone);
	      } else {
		/* lib_order_frags() has detected a recoverable error.
		 * Fragbckbone is still usable but not in this iteration of the loop.*/
		/* This only works because only one datagram server can be used per
		 * nodename handle and said server is single-threaded. */
		fragbone->next = handle->dtg_frags;
		handle->dtg_frags = fragbone;
		fragbone->last_ishere = TRUE;
	      }

	      free(toshow);
	      toshow = 0;

	      destroy_dtg_srvc_pckt(dtg, 1, 1);
	      continue;
	    }

	    toshow->src = fragbone->src;

	    toshow->next = 0;

	    free(fragbone);
	  } else {
	    free(toshow);
	    toshow = 0;
	  }
	}
      }

      if (toshow) {
	if (handle->in_server) {
	  handle->in_server->next = toshow;
	  handle->in_server = toshow;
	} else {
	  handle->in_server = toshow;
	  handle->in_library = toshow;
	}

	toshow = 0;
      }
    }

    destroy_dtg_srvc_pckt(dtg, 1, 1);
  }

  close(handle->dtg_srv_sckt);
  handle->dtg_srv_sckt = -1;

  nbworks_dstr_nbnodename(handle->dtg_listento);
  handle->dtg_listento = 0;

  lib_destroy_allfragbckbone(handle->dtg_frags);
  handle->dtg_frags = 0;

  handle->dtg_srv_stop = TRUE;
  handle->in_server = 0;

  if (! (nbworks_libcntl.stop_alldtg_srv ||
	 handle->dtg_srv_stop)) {
    nbworks_isinconflict(handle);
  }

  return 0;
}

#define SMALL_BUFF_LEN (SES_HEADER_LEN +4+2)
int lib_open_session(struct name_state *handle,
		     struct nbworks_nbnamelst *dst) {
  struct nbworks_nbnamelst *name_id, *her; /* To vary names a bit. */
  struct ses_srvc_packet pckt;
  struct ses_pckt_pyld_two_names twins;
  struct sockaddr_in addr;
  int ses_sckt, retry_count;
  unsigned long lenof_pckt, wrotelenof_pckt;
  unsigned int max_retries;
  unsigned char *mypckt_buff, *herpckt_buff;
  unsigned char small_buff[SMALL_BUFF_LEN];
  unsigned char *decoded_name, isgroup;

  if (! (handle && dst)) {
    nbworks_errno = EINVAL;
    return -1;
  }
  if ((! dst->name) ||
      (dst->len < NETBIOS_NAME_LEN)) {
    nbworks_errno = EINVAL;
    return -1;
  }

  retry_count = 0;
  isgroup = FALSE;

  her = nbworks_clone_nbnodename(dst);
  if (! her) {
    nbworks_errno = ENOBUFS;
    return -1;
  }
  if (her->next_name)
    nbworks_dstr_nbnodename(her->next_name);
  her->next_name = nbworks_clone_nbnodename(handle->scope);
  if ((! her->next_name) && handle->scope) {
    nbworks_errno = ENOBUFS;
    nbworks_dstr_nbnodename(her);
    return -1;
  }

 try_to_resolve_name:
  fill_32field(nbworks_whatisIP4addrX(her, ONES, isgroup,
				      (1+NETBIOS_NAME_LEN+handle->lenof_scope)),
               (unsigned char *)&(addr.sin_addr.s_addr));
  if (! addr.sin_addr.s_addr) {
    if (! isgroup) {
      isgroup = TRUE;
      goto try_to_resolve_name;
    } else {
      nbworks_dstr_nbnodename(her);
      return -1;
    }
  }
  addr.sin_family = AF_INET;
  /* VAXism below */
  fill_16field(139, (unsigned char *)&(addr.sin_port));

  decoded_name = her->name;
  her->name = encode_nbnodename(decoded_name, 0);
  free(decoded_name);
  if (! her->name) {
    nbworks_errno = ENOBUFS;
    nbworks_dstr_nbnodename(her);
    return -1;
  }
  her->len = NETBIOS_CODED_NAME_LEN;


  name_id = nbworks_clone_nbnodename(handle->name);
  if (! name_id) {
    nbworks_errno = ENOBUFS;
    nbworks_dstr_nbnodename(her);
    return -1;
  }
  if (name_id->next_name)
    nbworks_dstr_nbnodename(name_id->next_name);
  name_id->next_name = nbworks_clone_nbnodename(handle->scope);
  if ((! name_id->next_name) && handle->scope) {
    nbworks_errno = ENOBUFS;
    nbworks_dstr_nbnodename(her);
    nbworks_dstr_nbnodename(name_id);
    return -1;
  }
  decoded_name = name_id->name;
  name_id->name = encode_nbnodename(decoded_name, 0);
  free(decoded_name);
  if (! name_id->name) {
    nbworks_errno = ENOBUFS;
    nbworks_dstr_nbnodename(her);
    nbworks_dstr_nbnodename(name_id);
    return -1;
  }
  name_id->len = NETBIOS_CODED_NAME_LEN;


  memset(&pckt, 0, sizeof(struct ses_srvc_packet));
  pckt.payload_t = two_names;
  pckt.payload = &twins;
  twins.called_name = her;
  twins.calling_name = name_id;

  lenof_pckt = 2 * align(0, (1 + NETBIOS_CODED_NAME_LEN +
			     handle->lenof_scope),
			 4);

  pckt.len = lenof_pckt;
  pckt.type = SESSION_REQUEST;

  wrotelenof_pckt = (lenof_pckt + SES_HEADER_LEN);

  mypckt_buff = malloc(wrotelenof_pckt);
  if (! mypckt_buff) {
    nbworks_errno = ENOBUFS;
    nbworks_dstr_nbnodename(her);
    nbworks_dstr_nbnodename(name_id);
    return -1;
  }
  memset(mypckt_buff, 0, wrotelenof_pckt);

  master_ses_srvc_pckt_writer(&pckt, &wrotelenof_pckt, mypckt_buff);

  nbworks_dstr_nbnodename(twins.called_name);
  nbworks_dstr_nbnodename(twins.calling_name);

  /* Now I have allocated: mypckt_buff. */
  /* Other that that, I will need: addr, wrotelenof_pckt,
                                   *herpckt_buff, pckt,
				   small_buff[] */
  max_retries = nbworks_libcntl.max_ses_retarget_retries;

 try_to_connect:
  ses_sckt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ses_sckt == -1) {
    free(mypckt_buff);
    nbworks_errno = EPIPE;
    return -1;
  }

  if (0 != connect(ses_sckt, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
    close(ses_sckt);
    if (retry_count < max_retries) {
      retry_count++;
      goto try_to_connect;
    } else {
      free(mypckt_buff);
      nbworks_errno = EPIPE;
      return -1;
    }
  }

  if (wrotelenof_pckt > send(ses_sckt, mypckt_buff, wrotelenof_pckt,
			     (MSG_DONTWAIT | MSG_NOSIGNAL))) {
    close(ses_sckt);
    if (retry_count < max_retries) {
      retry_count++;
      goto try_to_connect;
    } else {
      free(mypckt_buff);
      nbworks_errno = EPIPE;
      return -1;
    }
  }

  /* TCP layer implements it's own timeout here.
   * We will leachingly use that instead of using our own timeout. */
  if (SES_HEADER_LEN > recv(ses_sckt, small_buff, SES_HEADER_LEN,
			    MSG_WAITALL)) {
    close(ses_sckt);
    if (retry_count < max_retries) {
      retry_count++;
      goto try_to_connect;
    } else {
      free(mypckt_buff);
      nbworks_errno = EPIPE;
      return -1;
    }
  }

  herpckt_buff = small_buff;
  if (! read_ses_srvc_pckt_header(&herpckt_buff, (herpckt_buff + SES_HEADER_LEN),
				  &pckt)) {
    close(ses_sckt);
    free(mypckt_buff);
    nbworks_errno = EPIPE; /* Too lazy to change this. */
    return -1;
  }

  switch (pckt.type) {
  case POS_SESSION_RESPONSE:
    free(mypckt_buff);
    if (pckt.len)
      lib_flushsckt(ses_sckt, pckt.len, MSG_WAITALL);

    set_sockoption(ses_sckt, NONBLOCKING);
    /* --------------------------------------------------------------- */
    /* Looks like I will HAVE to implement some sort of errno,
       because a failure here is not fatal, but requires special care. */
    set_sockoption(ses_sckt, KEEPALIVE);
    /* --------------------------------------------------------------- */

    return ses_sckt;
    break;

  case NEG_SESSION_RESPONSE:
    free(mypckt_buff);
    if (pckt.len) {
      if (1 > recv(ses_sckt, herpckt_buff, 1, MSG_WAITALL)) {
	close(ses_sckt);
	nbworks_errno = EPIPE;
	return -1;
      }
    }
    close(ses_sckt);
    // session_error = *herpckt_buff;
    nbworks_errno = ECONNREFUSED;
    return -1;
    break;

  case RETARGET_SESSION:
    if (pckt.len < (4+2)) {
      close(ses_sckt);
      free(mypckt_buff);
      nbworks_errno = EPIPE;
      return -1;
    }
    if ((4+2) > recv(ses_sckt, herpckt_buff, (4+2), MSG_WAITALL)) {
      close(ses_sckt);
      free(mypckt_buff);
      nbworks_errno = EPIPE;
      return -1;
    }
    herpckt_buff = read_32field(herpckt_buff,
				&(addr.sin_addr.s_addr));
    herpckt_buff = read_16field(herpckt_buff,
				&(addr.sin_port));
    /* fall-through! */
  default:
    close(ses_sckt);
    if (retry_count < max_retries) {
      retry_count++;
      goto try_to_connect;
    } else {
      free(mypckt_buff);
      nbworks_errno = EPIPE;
      return -1;
    }
    break;
  }

  nbworks_errno = EPIPE;
  return -1;
}
#undef SMALL_BUFF_LEN


void *lib_ses_srv(void *arg) {
  struct pollfd pfd;
  struct name_state *handle;
  struct nbworks_nbnamelst *caller, decoded_nbnodename;
  struct nbworks_session *new_ses;
  struct ses_srvc_packet pckt;
  struct com_comm command;
  int new_sckt;
  unsigned char ok[] = { POS_SESSION_RESPONSE, 0, 0, 0 };
  unsigned char combuff[LEN_COMM_ONWIRE], decoded_name[NETBIOS_NAME_LEN+1];
  unsigned char *buff, *walker;

  if (arg)
    handle = arg;
  else
    return 0;

  if (! (handle->ses_listento || handle->ses_takes)) {
    handle->ses_srv_stop = TRUE;
    return 0;
  }

  handle->sesin_server = handle->sesin_library = 0;

  pfd.fd = handle->ses_srv_sckt;
  pfd.events = POLLIN;

  decoded_nbnodename.name = decoded_name;
  decoded_nbnodename.len = NETBIOS_NAME_LEN;
  decoded_nbnodename.next_name = handle->scope;

  while ((! nbworks_libcntl.stop_allses_srv) &&
	 (! handle->ses_srv_stop)) {
    if (0 >= poll(&pfd, 1, nbworks_libcntl.ses_srv_polltimeout)) {
      if (pfd.revents & (POLLHUP | POLLNVAL | POLLERR)) {
	break;
      } else
	continue;
    }

    caller = 0;
    memset(&pckt, 0, sizeof(struct ses_srvc_packet));

    if (LEN_COMM_ONWIRE > recv(handle->ses_srv_sckt, combuff,
			       LEN_COMM_ONWIRE, MSG_WAITALL)) {
      break;
    }

    if (0 == read_railcommand(combuff, (combuff +LEN_COMM_ONWIRE),
			      &command)) {
      break;
    }

    if (! (command.command == rail_stream_pending)) {
      /* Daemon mixed something up, big time. */
      break;
    }

    if (command.len)
      rail_flushrail(command.len, handle->ses_srv_sckt);

    command.command = rail_stream_take;
    command.len = 0;

    if (! fill_railcommand(&command, combuff, (combuff +LEN_COMM_ONWIRE))) {
      break;
    }

    new_sckt = lib_daemon_socket();
    if (new_sckt == -1) {
      break;
    }

    if (LEN_COMM_ONWIRE > send(new_sckt, combuff, LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
      close(new_sckt);
      break;
    }

    /* Because LEN_COMM_ONWIRE > SES_HEADER_LEN, we can reuse
     * combuff for the header of the session packet. */
    if (SES_HEADER_LEN > recv(new_sckt, combuff, SES_HEADER_LEN, MSG_WAITALL)) {
      close(new_sckt);
      continue;
    }

    if (combuff[0] != SESSION_REQUEST) {
      command.command = rail_stream_error;
      command.node_type = SES_ERR_UNSPEC;

      if (! fill_railcommand(&command, combuff, (combuff + LEN_COMM_ONWIRE))) {
	close(new_sckt);
	break;
      }

      if (LEN_COMM_ONWIRE > send(new_sckt, combuff, LEN_COMM_ONWIRE,
				 MSG_NOSIGNAL)) {
	close(new_sckt);
	break;
      }

      close(new_sckt);
      continue;
    }

    walker = combuff;
    if (! read_ses_srvc_pckt_header(&walker, (walker+SES_HEADER_LEN), &pckt)) {
      close(new_sckt);
      break;
    }

    /* The first SES_HEADER_LEN octets of buff are allocated only to allow
     * ses_srvc_get_callingname() to be consistent in operation. */
    buff = malloc(pckt.len + SES_HEADER_LEN);
    if (! buff) {
      close(new_sckt);
      break;
    }

    if (pckt.len > recv(new_sckt, (buff +SES_HEADER_LEN), pckt.len,
			MSG_WAITALL)) {
      free(buff);
      close(new_sckt);
      break;
    }

    caller = ses_srvc_get_callingname(buff, (pckt.len +SES_HEADER_LEN));
    free(buff);
    if (! caller) {
      close(new_sckt);
      continue;
    }

    if (caller->len != NETBIOS_CODED_NAME_LEN) {
      nbworks_dstr_nbnodename(caller);
      close(new_sckt);
      continue;
    } else {
      decode_nbnodename(caller->name, decoded_nbnodename.name);
      nbworks_dstr_nbnodename(caller);
    }

    if (! (handle->ses_takes & HANDLE_TAKES_ALL)) {
      if (! (lib_doeslistento(&decoded_nbnodename, handle->ses_listento))) {
	command.command = rail_stream_error;
	command.node_type = SES_ERR_NOTLISCALLING;

	if (! fill_railcommand(&command, combuff, (combuff + LEN_COMM_ONWIRE))) {
	  close(new_sckt);
	  break;
	}

	if (LEN_COMM_ONWIRE > send(new_sckt, combuff, LEN_COMM_ONWIRE,
				   MSG_NOSIGNAL)) {
	  close(new_sckt);
	  break;
	}

	close(new_sckt);
	continue;
      }
    }

    if (0 != set_sockoption(new_sckt, NONBLOCKING)) {
      close(new_sckt);
      break;
    }

    command.command = rail_stream_accept;
    command.len = 0;

    if (! fill_railcommand(&command, combuff, (combuff + LEN_COMM_ONWIRE))) {
      close(new_sckt);
      break;
    }

    if (LEN_COMM_ONWIRE > send(new_sckt, combuff, LEN_COMM_ONWIRE,
			       MSG_NOSIGNAL)) {
      close(new_sckt);
      break;
    }

    if (4 > send(new_sckt, ok, 4, MSG_NOSIGNAL)) {
      close(new_sckt);
      break;
    }

    new_ses = lib_make_session(new_sckt, &decoded_nbnodename, handle, FALSE);
    if (! new_ses) {
      close(new_sckt);
      break;
    }

    if (handle->sesin_server) {
      handle->sesin_server->next = new_ses;
      handle->sesin_server = new_ses;
    } else {
      handle->sesin_server = new_ses;
      handle->sesin_library = new_ses;
    }
  }

  close(handle->ses_srv_sckt);
  handle->ses_srv_sckt = -1;

  nbworks_dstr_nbnodename(handle->ses_listento);
  handle->ses_listento = 0;

  handle->ses_srv_stop = TRUE;
  handle->sesin_server = 0;

  if (! (nbworks_libcntl.stop_allses_srv ||
	 handle->ses_srv_stop)) {
    nbworks_isinconflict(handle);
  }

  return 0;
}


void *lib_caretaker(void *arg) {
  struct nbworks_session *handle;
  struct timespec sleeptime;
  struct pollfd pfd;
  ssize_t ret_val, sent;
  time_t lastkeepalive, cur_time;
  unsigned char buff[] = { SESSION_KEEP_ALIVE, 0, 0, 0 };

  if (arg)
    handle = arg;
  else
    return 0;

  if (! handle->keepalive) {
    handle->kill_caretaker = TRUE;
    return 0;
  }

  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_500MS;

  pfd.fd = handle->socket;
  pfd.events = POLLOUT;

  lastkeepalive = time(0);

  while ((! nbworks_libcntl.stop_allses_srv) ||
	 (! handle->kill_caretaker)) {
    poll(&pfd, 1, 0);
    if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
      close(handle->socket);
      handle->socket = -1;
      break;
    }

    cur_time = time(0);
    if (cur_time > (lastkeepalive + nbworks_libcntl.keepalive_interval)) {
      lastkeepalive = cur_time;
      if (0 != pthread_mutex_lock(&(handle->mutex))) {
	handle->kill_caretaker = TRUE;
	return 0;
      }
      sent = 0;
      while (sent < 4) {
	ret_val = send(handle->socket, (buff +(4-sent)), (4-sent), MSG_NOSIGNAL);
	if (ret_val < 0) {
	  if ((errno != EAGAIN) ||
	      (errno != EWOULDBLOCK)) {
	    close(handle->socket);
	    handle->socket = -1;
	    handle->kill_caretaker = TRUE;
	    return 0;
	  } else
	    break;
	} else {
	  if (ret_val) {
	    sent = sent + ret_val;
	  } else
	    break;
	}
      }
      if (0 != pthread_mutex_unlock(&(handle->mutex))) {
	/* This is a fatal error. If the mutex can not be unlocked,
	 * then the socket is useless. Therefore, close it and apologize. */
	close(handle->socket);
	handle->socket = -1;
	/* apologize(); */
	break;
      }
    }

    nanosleep(&(sleeptime), 0);
  }

  handle->kill_caretaker = TRUE;

  return 0;
}

struct nbworks_session *lib_make_session(int socket,
					 struct nbworks_nbnamelst *peer,
					 struct name_state *handle,
					 unsigned char keepalive) {
  struct nbworks_session *result;

  result = malloc(sizeof(struct nbworks_session));
  if (! result) {
    return 0;
  }

  if (peer)
    result->peer = nbworks_clone_nbnodename(peer);
  else
    result->peer = 0;
  result->handle = handle;
  result->cancel_send = 0;
  result->cancel_recv = 0;
  result->kill_caretaker = FALSE;
  result->keepalive = keepalive;
  result->nonblocking = TRUE; /* AKA non-blocking */
  result->socket = socket;
  result->len_left = 0;
  result->ooblen_left = 0;
  result->ooblen_offset = 0;
  result->oob_tmpstor = 0;
  if (0 != pthread_mutex_init(&(result->mutex), 0)) {
    free(result);
    return 0;
  }
  if (0 != pthread_mutex_init(&(result->receive_mutex), 0)) {
    pthread_mutex_destroy(&(result->mutex));
    free(result);
    return 0;
  }
  result->caretaker_tid = 0;
  result->next = 0;

  return result;
}

void lib_dstry_sesslist(struct nbworks_session *ses) {
  struct nbworks_session *next;

  while (ses) {
    if (ses->socket >= 0)
      close(ses->socket);

    if (ses->caretaker_tid) {
      ses->kill_caretaker = TRUE;

      pthread_join(ses->caretaker_tid, 0);
    }

    pthread_mutex_destroy(&(ses->mutex));
    pthread_mutex_destroy(&(ses->receive_mutex));

    if (ses->peer)
      nbworks_dstr_nbnodename(ses->peer);
    if (ses->oob_tmpstor)
      free(ses->oob_tmpstor);

    next = ses->next;
    free(ses);
    ses = next;
  }

  return;
}


#define ARBITRARY_VALUE 0xff
ssize_t lib_flushsckt(int socket,
		      ssize_t len,
		      int flags) {
  ssize_t ret_val, count;
  unsigned char buff[ARBITRARY_VALUE];

  if (len <= 0) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    count = 0;
  }

  while (len > ARBITRARY_VALUE) {
    ret_val = recv(socket, buff, ARBITRARY_VALUE, flags);
    if (ret_val <= 0) {
      if (ret_val == 0) {
	return 0;
      } else {
	if ((errno == EAGAIN) ||
	    (errno == EWOULDBLOCK)) {
	  continue;
	} else {
	  nbworks_errno = errno;
	  return ret_val;
	}
      }
    }
    len = len - ret_val;
    count = count + ret_val;
  }

  while (len > 0) {
    ret_val = recv(socket, buff, len, flags);
    if (ret_val <= 0) {
      if (ret_val == 0) {
	return 0;
      } else {
	if ((errno == EAGAIN) ||
	    (errno == EWOULDBLOCK)) {
	  continue;
	} else {
	  nbworks_errno = errno;
	  return ret_val;
	}
      }
    }
    len = len - ret_val;
    count = count + ret_val;
  }

  return count;
}
#undef ARBITRARY_VALUE
