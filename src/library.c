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
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <poll.h>
#include <errno.h>

#include "nodename.h"
#include "library_control.h"
#include "library.h"
#include "pckt_routines.h"
#include "rail-comm.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"
#include "ses_srvc_pckt.h"
#include "randomness.h"


void lib_init(void) {
  nbworks_libcntl.stop_alldtg_srv = 0;
  nbworks_libcntl.stop_allses_srv = 0;

  nbworks_libcntl.dtg_srv_polltimeout = TP_100MS;
  nbworks_libcntl.ses_srv_polltimeout = TP_100MS;

  nbworks_libcntl.max_ses_retarget_retries = 5; /*
	      What do I know? Just choose a random number,
	      it oughta work. I guess. */
  nbworks_libcntl.keepalive_interval = 120; /* seconds */

  nbworks_libcntl.dtg_frag_keeptime = 60; /* seconds */
}


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
  if (0 != fcntl(daemon, F_SETFL, O_NONBLOCK)) {
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


struct name_state *lib_regname(unsigned char *name,
			       unsigned char name_type,
			       struct nbnodename_list *scope,
			       unsigned char group_flg,
			       unsigned char node_type, /* only one type */
			       uint32_t ttl) {
  struct name_state *result;
  struct com_comm command;
  struct rail_name_data namedt;
  int daemon;
  unsigned char commbuff[LEN_COMM_ONWIRE], *namedtbuff;

  if ((! name) ||
      /* The explanation for the below test:
       * 1. at least one of bits ISGROUP_YES or ISGROUP_NO must be set.
       * 2. you can not set both bits at the same time. */
      (! ((group_flg & (ISGROUP_YES | ISGROUP_NO)) &&
	  (((group_flg & ISGROUP_YES) ? 1 : 0) ^
	   ((group_flg & ISGROUP_NO) ? 1 : 0))))) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_regname;
  switch (node_type) {
  case CACHE_NODEFLG_B:
    if (group_flg)
      command.node_type = 'B';
    else
      command.node_type = 'b';
    break;
  case CACHE_NODEFLG_P:
    if (group_flg)
      command.node_type = 'P';
    else
      command.node_type = 'p';
    break;
  case CACHE_NODEFLG_M:
    if (group_flg)
      command.node_type = 'M';
    else
      command.node_type = 'm';
    break;
  case CACHE_NODEFLG_H:
    if (group_flg)
      command.node_type = 'H';
    else
      command.node_type = 'h';
    break;

  default:
    nbworks_errno = EINVAL;
    return 0;
  }

  command.len = (LEN_NAMEDT_ONWIREMIN -1) + nbnodenamelen(scope);
  namedt.name = name;
  namedt.name_type = name_type;
  namedt.scope = scope;
  namedt.ttl = ttl;

  fill_railcommand(&command, commbuff, (commbuff + LEN_COMM_ONWIRE));
  namedtbuff = malloc(command.len);
  if (! namedtbuff) {
    nbworks_errno = ENOBUFS;
    return 0;
  }
  fill_rail_name_data(&namedt, namedtbuff, (namedtbuff + command.len));

  result = calloc(1, sizeof(struct name_state));
  if (! result) {
    free(namedtbuff);
    nbworks_errno = ENOMEM;
    return 0;
  }
  result->name = malloc(sizeof(struct nbnodename_list));
  if (! result->name) {
    free(result);
    free(namedtbuff);
    nbworks_errno = ENOMEM;
    return 0;
  }
  result->name->name = malloc(NETBIOS_NAME_LEN+1);
  if (! result->name->name) {
    free(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = ENOMEM;
    return 0;
  }
  result->name->next_name = 0;
  result->name->len = NETBIOS_NAME_LEN;
  memcpy(result->name->name, name, NETBIOS_NAME_LEN);
  /* Tramp stamp. */
  result->name->name[NETBIOS_NAME_LEN] = 0;

  result->scope = clone_nbnodename(scope);
  if ((! result->scope) &&
      scope) {
    free(result->name->name);
    free(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = ENOMEM;
    return 0;
  }

  daemon = lib_daemon_socket();
  if (daemon < 0) {
    destroy_nbnodename(result->scope);
    free(result->name->name);
    free(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = ECONNREFUSED;
    return 0;
  }

  if (LEN_COMM_ONWIRE > send(daemon, &commbuff, LEN_COMM_ONWIRE,
			     MSG_NOSIGNAL)) {
    close(daemon);
    destroy_nbnodename(result->scope);
    free(result->name->name);
    free(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = errno;
    return 0;
  }
  if (command.len > send(daemon, namedtbuff, command.len,
			 MSG_NOSIGNAL)) {
    close(daemon);
    destroy_nbnodename(result->scope);
    free(result->name->name);
    free(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = errno;
    return 0;
  }

  free(namedtbuff);

  if (LEN_COMM_ONWIRE > recv(daemon, &commbuff, LEN_COMM_ONWIRE,
			     MSG_WAITALL)) {
    close(daemon);
    destroy_nbnodename(result->scope);
    free(result->name->name);
    free(result->name);
    free(result);
    nbworks_errno = EPERM;
    return 0;
  }
  close(daemon);
  read_railcommand(commbuff, (commbuff + LEN_COMM_ONWIRE), &command);

  if ((command.command != rail_regname) ||
      (command.token < 2) ||
      (command.nbworks_errno)) {
    destroy_nbnodename(result->scope);
    free(result->name->name);
    free(result->name);
    free(result);
    nbworks_errno = EPERM;
    return 0;
  }

  result->token = command.token;

  result->lenof_scope = nbnodenamelen(scope);
  result->label_type = name_type;
  result->node_type = node_type;
  result->group_flg = group_flg;

  return result;
}

/* returns: >0 = success, 0 = fail, <0 = error */
int lib_delname(struct name_state *handle) {
  struct com_comm command;
  int daemon;
  unsigned char combuff[LEN_COMM_ONWIRE];

  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  }

  daemon = lib_daemon_socket();
  if (daemon < 0) {
    nbworks_errno = EPIPE;
    return -1;
  }

  if (handle->dtg_srv_tid) {
    handle->dtg_srv_stop = TRUE;

    pthread_join(handle->dtg_srv_tid, 0);
  }

  if (handle->ses_srv_tid) {
    handle->ses_srv_stop = TRUE;

    pthread_join(handle->ses_srv_tid, 0);
  }

  destroy_nbnodename(handle->name);
  if (handle->scope)
    destroy_nbnodename(handle->scope);

  if (handle->dtg_listento)
    destroy_nbnodename(handle->dtg_listento);
  if (handle->dtg_frags)
    lib_destroy_fragbckbone(handle->dtg_frags);
  if (handle->in_library)
    lib_dstry_packets(handle->in_library);

  if (handle->ses_listento)
    destroy_nbnodename(handle->ses_listento);
  if (handle->sesin_library)
    lib_dstry_sesslist(handle->sesin_library);

  memset(&command, 0, sizeof(struct com_comm));

  command.command = rail_delname;
  command.token = handle->token;

  free(handle); /* Bye-bye. */

  fill_railcommand(&command, combuff, (combuff + LEN_COMM_ONWIRE));
  send(daemon, combuff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
  /* Now, you may be thinking that some lossage may occur, and that it
   * can mess up our day something fierce. In effect, that can not happen.
   * The quiet loss of the name is something NetBIOS is designed to handle.
   * The only problem we may encounter is that the daemon keeps thinking
   * it still has a name and therefore keeps defending it. */
  close(daemon);

  return TRUE;
}


/* returns: >0 = success, 0 = fail, <0 = error */
int lib_start_dtg_srv(struct name_state *handle,
		      unsigned char takes_field,
		      struct nbnodename_list *listento) {
  struct com_comm command;
  int daemon;
  unsigned char buff[LEN_COMM_ONWIRE];

  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  if (! handle->token) {
    nbworks_errno = EPERM;
    return 0;
  }

  if (! (listento || takes_field)) {
    nbworks_errno = EINVAL;
    return -1;
  }

  if (handle->dtg_srv_tid) {
    handle->dtg_srv_stop = TRUE;

    pthread_join(handle->dtg_srv_tid, 0);
  }

  daemon = lib_daemon_socket();
  if (daemon < 0) {
    return -1;
  }

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_dtg_sckt;
  command.token = handle->token;

  fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));

  if (LEN_COMM_ONWIRE > send(daemon, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
    close(daemon);
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(daemon, buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
    close(daemon);
    return 0;
  }

  if (0 == read_railcommand(buff, (buff + LEN_COMM_ONWIRE), &command)) {
    close(daemon);
    return -1;
  }

  if (!((command.command == rail_dtg_sckt) &&
	(command.token == handle->token) &&
	(command.nbworks_errno == 0))) {
    close(daemon);
    return -1;
  }

  if (command.len)
    rail_flushrail(command.len, daemon);

  handle->dtg_srv_sckt = daemon;

  if (handle->dtg_listento)
    destroy_nbnodename(handle->dtg_listento);
  handle->dtg_listento = clone_nbnodename(listento);
  handle->dtg_takes = takes_field;
  handle->dtg_srv_stop = FALSE;
  if (handle->dtg_frags)
    lib_destroy_fragbckbone(handle->dtg_frags);
  handle->dtg_frags = 0;
  handle->in_server = 0;
  if (handle->in_library)
    lib_dstry_packets(handle->in_library);
  handle->in_library = 0;

  if (0 != pthread_create(&(handle->dtg_srv_tid), 0,
			  lib_dtgserver, handle)) {
    nbworks_errno = errno;
    handle->dtg_srv_tid = 0;

    close(daemon);
    destroy_nbnodename(handle->dtg_listento);
    handle->dtg_listento = 0;

    return -1;
  }

  return 1;
}

/* returns: >0 = success, 0 = fail, <0 = error */
int lib_start_ses_srv(struct name_state *handle,
		      unsigned char takes_field,
		      struct nbnodename_list *listento) {
  struct com_comm command;
  int daemon;
  unsigned char buff[LEN_COMM_ONWIRE];

  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  if (! handle->token) {
    nbworks_errno = EPERM;
    return 0;
  }

  if (! (listento || takes_field)) {
    nbworks_errno = EINVAL;
    return -1;
  }

  if (handle->ses_srv_tid) {
    handle->ses_srv_stop = TRUE;

    pthread_join(handle->ses_srv_tid, 0);
  }

  daemon = lib_daemon_socket();
  if (daemon < 0) {
    return -1;
  }

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_stream_sckt;
  command.token = handle->token;

  fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));

  if (LEN_COMM_ONWIRE > send(daemon, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
    close(daemon);
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(daemon, buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
    close(daemon);
    return 0;
  }

  if (0 == read_railcommand(buff, (buff + LEN_COMM_ONWIRE), &command)) {
    close(daemon);
    return -1;
  }

  if (!((command.command == rail_stream_sckt) &&
	(command.token == handle->token) &&
	(command.nbworks_errno == 0))) {
    close(daemon);
    return -1;
  }

  if (command.len)
    rail_flushrail(command.len, daemon);

  handle->ses_srv_sckt = daemon;

  handle->ses_listento = clone_nbnodename(listento);
  handle->ses_takes = takes_field;
  if (handle->sesin_library)
    lib_dstry_sesslist(handle->sesin_library);

  if (0 != pthread_create(&(handle->ses_srv_tid), 0,
			  lib_ses_srv, handle)) {
    nbworks_errno = errno;
    close(daemon);

    destroy_nbnodename(handle->ses_listento);
    handle->ses_listento = 0;

    handle->sesin_library = 0;

    handle->ses_srv_tid = 0;

    return -1;
  }

  return TRUE;
}


void lib_dstry_packets(struct packet_cooked *forkill) {
  struct packet_cooked *fordel;

  while (forkill) {
    fordel = forkill->next;
    free(forkill->data);
    destroy_nbnodename(forkill->src);
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
    destroy_nbnodename(bone->src);
    lib_destroy_frags(bone->frags);
    free(bone);
  }

  return;
}

struct dtg_frag_bckbone *lib_add_fragbckbone(uint16_t id,
					     struct nbnodename_list *src,
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
  result->src = clone_nbnodename(src);

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
	  (0 == cmp_nbnodename(cur_frag->src, src))) {
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
					      struct nbnodename_list *src,
					      struct dtg_frag_bckbone *frags) {
  struct dtg_frag_bckbone *cur_frag;

  if (! (frags && src))
    return 0;

  cur_frag = frags;
  while (cur_frag) {
    if ((cur_frag->id == id) &&
	(0 == cmp_nbnodename(cur_frag->src, src)))
      break;
    else
      cur_frag = cur_frag->next;
  }

  return cur_frag;
}

struct dtg_frag_bckbone *lib_take_fragbckbone(uint16_t id,
					      struct nbnodename_list *src,
					      struct dtg_frag_bckbone **frags) {
  struct dtg_frag_bckbone *cur_frag, **last_frag;

  if (! (frags && src))
    return 0;

  last_frag = frags;
  cur_frag = *last_frag;

  while (cur_frag) {
    if ((cur_frag->id == id) &&
	(0 == cmp_nbnodename(cur_frag->src, src))) {
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
			 struct nbnodename_list *src,
			 struct dtg_frag_bckbone **frags) {
  struct dtg_frag_bckbone *cur_frag, **last_frag;

  if (! (frags && src))
    return;

  last_frag = frags;
  cur_frag = *last_frag;

  while (cur_frag) {
    if ((cur_frag->id == id) &&
	(0 == cmp_nbnodename(cur_frag->src, src))) {
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

void lib_prune_fragbckbone(struct dtg_frag_bckbone **frags,
			   time_t killtime) {
  struct dtg_frag_bckbone *cur_frag, **last_frag;

  if (! frags)
    return;

  last_frag = frags;
  cur_frag = *last_frag;

  while (cur_frag) {
    if (cur_frag->last_active < killtime) {
      *last_frag = cur_frag->next;
      lib_destroy_fragbckbone(cur_frag);
    } else {
      last_frag = &(cur_frag->next);
    }

    cur_frag = *last_frag;
  }

  return;
}

struct dtg_frag_bckbone *lib_add_frag_tobone(uint16_t id,
					     struct nbnodename_list *src,
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

  bone->last_active = time(0);

  while (42) {
    last_frag = &(bone->frags);
    cur_frag = *last_frag;

    while (cur_frag) {
      if (cur_frag == result)
	return bone;
      else {
	free(result);
	return 0;
      }

      last_frag = &(cur_frag->next);
      cur_frag = *last_frag;
    }

    *last_frag = cur_frag;
  }
}

struct dtg_frag *lib_order_frags(struct dtg_frag *frags,
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

  if (! frags)
    return 0;

  size_todate = 0;

  sorted = 0;
  master = 0;

  while (frags) {
    last = &(frags);
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
	   * Unfortunately (or, in my case as the implementor,
	   * fortunately), there is no way for the NetBIOS layer
	   * to detect that the data does not make any sense.
	   * It is up to the application to not trust datagrams. */
	  /* Implementors note: we should add a new flag to the
	   * datagram header flags field: DO_NOT_FRAGMENT. */
	  *last = remove->next;
	  free(remove->data);
	  free(remove);
	  remove = *last;
	  continue;
	} else {
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
	    sorted->next = frags;
	    lib_destroy_frags(master);
	  } else {
	    lib_destroy_frags(frags);
	  }
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
      /* IP has lost a fragment or two. */
      if (sorted) {
	sorted->next = frags;
	lib_destroy_frags(master);
      } else {
	lib_destroy_frags(frags);
      }
      return 0;
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
	sorted->next = frags;
	lib_destroy_frags(master);
      } else {
	lib_destroy_frags(frags);
      }
      return 0;
    }
  }

  sorted->next = 0;

  if (len)
    *len = size_todate;

  return master;
}

void *lib_assemble_frags(struct dtg_frag *frags,
			 uint32_t len) {
  struct dtg_frag *tmp;
  uint32_t done;
  void *result;

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

  done = 0;
  while (frags) {
    if (done + frags->len > len) {
      /* OUT_OF_BOUNDS */
      free(result);
      /* There is a memory leak here, in the event
       * the pointer to the first frags is forfeit. */
      return 0;
    }
    memcpy((result + done), frags->data, frags->len);
    done = done + len;
    frags = frags->next;
  }

  return result;
}


/* returns: TRUE (AKA 1) = YES, listens to,
            FALSE (AKA 0) = NO, doesn't listen to */
unsigned int lib_doeslistento(struct nbnodename_list *query,
			      struct nbnodename_list *answerlist) {
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


uint32_t lib_whatisaddrX(struct nbnodename_list *X,
			 unsigned int len) {
  struct com_comm command;
  uint32_t result;
  int daemon_sckt;
  unsigned char combuff[LEN_COMM_ONWIRE], *buff;

  if ((! X) ||
      (len < (1+NETBIOS_NAME_LEN+1))) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_addr_ofXuniq;
  command.len = len;

  fill_railcommand(&command, combuff, (combuff +LEN_COMM_ONWIRE));

  buff = malloc(len);
  if (! buff) {
    nbworks_errno = ENOBUFS;
    return 0;
  }

  if (buff == fill_all_DNS_labels(X, buff, (buff +len), 0)) {
    free(buff);
    nbworks_errno = ENOBUFS;
    return 0;
  }

  daemon_sckt = lib_daemon_socket();
  if (daemon_sckt == -1) {
    free(buff);
    nbworks_errno = EPIPE;
    return 0;
  }

  if (LEN_COMM_ONWIRE > send(daemon_sckt, combuff,
			     LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
    close(daemon_sckt);
    free(buff);
    nbworks_errno = EPIPE;
    return 0;
  }

  if (len > send(daemon_sckt, buff, len, MSG_NOSIGNAL)) {
    close(daemon_sckt);
    free(buff);
    nbworks_errno = EPIPE;
    return 0;
  }

  free(buff);

  if (LEN_COMM_ONWIRE > recv(daemon_sckt, combuff,
			     LEN_COMM_ONWIRE, MSG_WAITALL)) {
    close(daemon_sckt);
    /* No error, genuine failure to resolve. */
    return 0;
  }

  if (0 == read_railcommand(combuff, (combuff +LEN_COMM_ONWIRE),
			    &command)) {
    close(daemon_sckt);
    nbworks_errno = ENOBUFS;
    return 0;
  }

  if ((command.command != rail_addr_ofXuniq) ||
      (command.len < 4) ||
      (command.nbworks_errno)) {
    close(daemon_sckt);
    nbworks_errno = EPIPE; /* What do I put here? */
    return 0;
  }

  if (4 > recv(daemon_sckt, combuff, 4, MSG_WAITALL)) {
    close(daemon_sckt);
    nbworks_errno = EPIPE;
    return 0;
  }

  read_32field(combuff, &result);

  close(daemon_sckt);

  return result;
}


/* returns: <0 = error, 0 or >0 = something was sent */
ssize_t lib_senddtg_138(struct name_state *handle,
			unsigned char *recepient,
			unsigned char recepient_type,
			void *data,
			size_t len,
			unsigned char group_flg,
			int isbroadcast) {
  struct dtg_srvc_packet *pckt;
  struct com_comm command;
  int daemon_sckt;
  unsigned int pckt_len;
  unsigned char readycommand[LEN_COMM_ONWIRE];
  void *readypacket;

  if ((! (handle && recepient)) ||
      (len > DTG_MAXLEN) ||
      /* The explanation for the below test:
       * 1. at least one of bits ISGROUP_YES or ISGROUP_NO must be set.
       * 2. you can not set both bits at the same time. */
      (! ((group_flg & (ISGROUP_YES | ISGROUP_NO)) &&
	  (((group_flg & ISGROUP_YES) ? 1 : 0) ^
	   ((group_flg & ISGROUP_NO) ? 1 : 0))))) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  pckt = malloc(sizeof(struct dtg_srvc_packet));
  if (! pckt) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  pckt->for_del = 0;
  /* Yes, but what if I want to send a broadcast datagram to a group name? */
  pckt->type = (isbroadcast) ? BRDCST_DTG :
                               ((group_flg & ISGROUP_YES) ? DIR_GRP_DTG :
                                                            DIR_UNIQ_DTG);
  pckt->flags = DTG_FIRST_FLAG; /* stub */
  switch (handle->node_type) {
  case CACHE_NODEFLG_B:
    pckt->flags = (pckt->flags | DTG_NODE_TYPE_B);
    command.node_type = 'B';
    break;
  case CACHE_NODEFLG_P:
    pckt->flags = (pckt->flags | DTG_NODE_TYPE_P);
    command.node_type = 'P';
    break;
  case CACHE_NODEFLG_M:
    pckt->flags = (pckt->flags | DTG_NODE_TYPE_M);
    command.node_type = 'M';
    break;
  case CACHE_NODEFLG_H:
  default:
    pckt->flags = (pckt->flags | DTG_NODE_TYPE_M);
    command.node_type = 'H';
    break;
  }
  pckt->id = make_weakrandom() & 0xffff;
  pckt->src_address = my_ipv4_address();
  pckt->src_port = 138;

  pckt->payload_t = normal;
  /* FIXME: the below is a stub. I have to implement datagram fragmentation. */
  pckt->payload = dtg_srvc_make_pyld_normal(handle->name->name, handle->label_type,
					    recepient, recepient_type, handle->scope,
					    data, len, 0);
  if (! pckt->payload) {
    nbworks_errno = ZEROONES; /* FIXME */
    free(pckt);
    return -1;
  }
  pckt->error_code = 0;

  pckt_len = DTG_HDR_LEN + 2 + 2 +
    ((1+NETBIOS_CODED_NAME_LEN) *2) + (handle->lenof_scope *2) +
    (2 * 4) /* extra space for name alignment, if performed */ + len;

  readypacket = master_dtg_srvc_pckt_writer(pckt, &pckt_len, 0, 0);
  if (! readypacket) {
    nbworks_errno = ZEROONES; /* FIXME */
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  daemon_sckt = lib_daemon_socket();
  if (daemon_sckt == -1) {
    nbworks_errno = ZEROONES; /* FIXME */
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

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
    nbworks_errno = ZEROONES; /* FIXME */
    close(daemon_sckt);
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  close(daemon_sckt);
  free(readypacket);
  destroy_dtg_srvc_pckt(pckt, 1, 1);

  if (0 == read_railcommand(readycommand, (readycommand +LEN_COMM_ONWIRE),
			    &command)) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  if ((command.command != rail_send_dtg) ||
      (command.nbworks_errno)) {
    nbworks_errno = command.nbworks_errno;
    return 0;
  }

  return len;
}


void *lib_dtgserver(void *arg) {
  struct pollfd pfd;
  struct name_state *handle;
  struct dtg_frag_bckbone *fragbone;
  struct packet_cooked *toshow;
  struct dtg_srvc_packet *dtg;
  struct dtg_pckt_pyld_normal *nrml_pyld;
  struct nbnodename_list decoded_nbnodename;
  time_t last_pruned, killtime;
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
    killtime = time(0) - nbworks_libcntl.dtg_frag_keeptime;

    if (last_pruned < killtime) {
      lib_prune_fragbckbone(&(handle->dtg_frags), killtime);
      /* Save us a call to time(). */
      last_pruned = killtime + nbworks_libcntl.dtg_frag_keeptime;
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

    if (dtg->payload_t == normal) {
      nrml_pyld = dtg->payload;
      if (nrml_pyld->src_name) {
	if (nrml_pyld->src_name->len != NETBIOS_CODED_NAME_LEN) {
	  /* Theoretically, I should send a SOURCE NAME BAD FORMAT error message to the sender. */
	  destroy_dtg_srvc_pckt(dtg, 1, 1);
	  continue;
	} else {
	  decode_nbnodename(nrml_pyld->src_name->name, decoded_nbnodename.name);
	}
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

	  /* I think I implemented the below wrong (groups again). */
	case DIR_UNIQ_DTG:
	case DIR_GRP_DTG:
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

	destroy_nbnodename(nrml_pyld->src_name->next_name);
	nrml_pyld->src_name->next_name = 0;

	if (! (dtg->flags & DTG_FIRST_FLAG)) {
	  if (lib_add_frag_tobone(dtg->id, nrml_pyld->src_name,
				  nrml_pyld->offset, nrml_pyld->len,
				  nrml_pyld->payload, handle->dtg_frags)) {
	    nrml_pyld->payload = 0;
	  } else {
	    lib_del_fragbckbone(dtg->id, nrml_pyld->src_name,
				&(handle->dtg_frags));
	    destroy_dtg_srvc_pckt(dtg, 1, 1);
	    continue;
	  }
	} else {
	  if (dtg->flags & DTG_MORE_FLAG) {
	    if (lib_add_fragbckbone(dtg->id, nrml_pyld->src_name,
				    nrml_pyld->offset, nrml_pyld->len,
				    nrml_pyld->payload, &(handle->dtg_frags))) {
	      nrml_pyld->payload = 0;
	    } else {
	      lib_del_fragbckbone(dtg->id, nrml_pyld->src_name,
				  &(handle->dtg_frags));
	      destroy_dtg_srvc_pckt(dtg, 1, 1);
	      continue;
	    }
	  }
	}

	if (! (dtg->flags & DTG_MORE_FLAG)) {
	  toshow = malloc(sizeof(struct packet_cooked));
	  if (! toshow) {
	    lib_del_fragbckbone(dtg->id, nrml_pyld->src_name,
				&(handle->dtg_frags));
	    destroy_dtg_srvc_pckt(dtg, 1, 1);
	    continue;
	  }

	  if (dtg->flags & DTG_FIRST_FLAG) {
	    if (! nrml_pyld->offset) {
	      toshow->data = nrml_pyld->payload;
	      nrml_pyld->payload = 0;

	      toshow->len = nrml_pyld->len;

	      toshow->src = nrml_pyld->src_name;
	      nrml_pyld->src_name = 0;

	      toshow->next = 0;
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
	    fragbone = lib_take_fragbckbone(dtg->id, nrml_pyld->src_name,
					    &(handle->dtg_frags));
	    if (fragbone) {
	      /* A spooky statement. */
	      /* Question: what if the compiler does not update the second
	       * argument to lib_assemble_frags() after calling
	       * lib_order_frags(), hmmm? */
	      toshow->data =
		lib_assemble_frags(lib_order_frags(fragbone->frags,
						   &(toshow->len)),
				   toshow->len);
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
    }

    destroy_dtg_srvc_pckt(dtg, 1, 1);
  }

  close(handle->dtg_srv_sckt);

  destroy_nbnodename(handle->dtg_listento);
  handle->dtg_listento = 0;

  lib_destroy_fragbckbone(handle->dtg_frags);
  handle->dtg_frags = 0;

  handle->dtg_srv_stop = TRUE;
  handle->in_server = 0;

  return 0;
}


#define SMALL_BUFF_LEN (SES_HEADER_LEN +4+2)
int lib_open_session(struct name_state *handle,
		     struct nbnodename_list *dst) {
  struct nbnodename_list *name_id, *her; /* To vary names a bit. */
  struct ses_srvc_packet pckt;
  struct ses_pckt_pyld_two_names *twins;
  struct sockaddr_in addr;
  int ses_sckt, retry_count;;
  unsigned int lenof_pckt, wrotelenof_pckt;
  unsigned int ones;
  unsigned char *mypckt_buff, *herpckt_buff;
  unsigned char small_buff[SMALL_BUFF_LEN];
  unsigned char *decoded_name;

  if (! (handle && dst)) {
    /* TODO: errno signaling stuff */
    return -1;
  }
  if ((! dst->name) ||
      (dst->len < NETBIOS_NAME_LEN)) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  ones = ONES;
  retry_count = 0;

  her = clone_nbnodename(dst);
  if (! her) {
    /* TODO: errno signaling stuff */
    return -1;
  }
  destroy_nbnodename(her->next_name);
  her->next_name = clone_nbnodename(handle->scope);
  if ((! her->next_name) && handle->scope) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    return -1;
  }


  fill_32field(lib_whatisaddrX(her, (1+ NETBIOS_NAME_LEN+ handle->lenof_scope)),
               (unsigned char *)&(addr.sin_addr.s_addr));
  if (! addr.sin_addr.s_addr) {
    destroy_nbnodename(her);
    return -1;
  }
  addr.sin_family = AF_INET;
  /* VAXism below */
  fill_16field(139, (unsigned char *)&(addr.sin_port));

  decoded_name = her->name;
  her->name = encode_nbnodename(decoded_name, 0);
  free(decoded_name);
  if (! her->name) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    return -1;
  }
  her->len = NETBIOS_CODED_NAME_LEN;


  name_id = clone_nbnodename(handle->name);
  if (! name_id) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    return -1;
  }
  destroy_nbnodename(name_id->next_name);
  name_id->next_name = clone_nbnodename(handle->scope);
  if ((! name_id->next_name) && handle->scope) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    destroy_nbnodename(name_id);
    return -1;
  }
  decoded_name = name_id->name;
  name_id->name = encode_nbnodename(decoded_name, 0);
  free(decoded_name);
  if (! name_id->name) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    destroy_nbnodename(name_id);
    return -1;
  }
  name_id->len = NETBIOS_CODED_NAME_LEN;


  memset(&pckt, 0, sizeof(struct ses_srvc_packet));
  pckt.payload_t = two_names;
  pckt.payload = malloc(sizeof(struct ses_pckt_pyld_two_names));
  if (! pckt.payload) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    destroy_nbnodename(name_id);
    return -1;
  }

  twins = pckt.payload;
  twins->called_name = her;
  twins->calling_name = name_id;

  lenof_pckt = (2 * (1+ NETBIOS_CODED_NAME_LEN)) +
    (2 * handle->lenof_scope);

  if (nbworks_do_align) {
    /* Questions, questions: if I leave it like this, how
     * many NetBIOS implementations are going to choke on it? */
    /* Choking hazard: trailing octets behind the end of the last name. */
    lenof_pckt = lenof_pckt + (2 * 4);
  }

  pckt.len = lenof_pckt;
  pckt.type = SESSION_REQUEST;

  wrotelenof_pckt = (lenof_pckt + SES_HEADER_LEN);

  mypckt_buff = malloc(wrotelenof_pckt);
  if (! mypckt_buff) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(name_id);
    return -1;
  }
  memset(mypckt_buff, 0, wrotelenof_pckt);

  master_ses_srvc_pckt_writer(&pckt, &wrotelenof_pckt, mypckt_buff);

  destroy_ses_srvc_pcktpyld(&pckt);

  /* Now I have allocated: mypckt_buff. */
  /* Other that that, I will need: addr, wrotelenof_pckt,
                                   *herpckt_buff, pckt,
				   small_buff[] */
 try_to_connect:
  ses_sckt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ses_sckt == -1) {
    free(mypckt_buff);
    return -1;
  }

  if (0 != connect(ses_sckt, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
    close(ses_sckt);
    if (retry_count < nbworks_libcntl.max_ses_retarget_retries) {
      retry_count++;
      goto try_to_connect;
    } else {
      free(mypckt_buff);
      return -1;
    }
  }

  if (wrotelenof_pckt > send(ses_sckt, mypckt_buff, wrotelenof_pckt,
			     (MSG_DONTWAIT | MSG_NOSIGNAL))) {
    close(ses_sckt);
    if (retry_count < nbworks_libcntl.max_ses_retarget_retries) {
      retry_count++;
      goto try_to_connect;
    } else {
      free(mypckt_buff);
      return -1;
    }
  }

  /* FIXME: a timeout must be implemented here. */
  if (SES_HEADER_LEN > recv(ses_sckt, small_buff, SES_HEADER_LEN,
			    MSG_WAITALL)) {
    close(ses_sckt);
    if (retry_count < nbworks_libcntl.max_ses_retarget_retries) {
      retry_count++;
      goto try_to_connect;
    } else {
      free(mypckt_buff);
      return -1;
    }
  }

  herpckt_buff = small_buff;
  if (! read_ses_srvc_pckt_header(&herpckt_buff, (herpckt_buff + SES_HEADER_LEN),
				  &pckt)) {
    close(ses_sckt);
    free(mypckt_buff);
    return -1;
  }

  switch (pckt.type) {
  case POS_SESSION_RESPONSE:
    free(mypckt_buff);
    if (pckt.len)
      lib_flushsckt(ses_sckt, pckt.len, MSG_WAITALL);

    if (0 != fcntl(ses_sckt, F_SETFL, O_NONBLOCK)) {
      //      close(ses_sckt);
      //      /* This also may not be a fatal error. */
      //      return -1;
    }
    /* --------------------------------------------------------------- */
    /* Looks like I will HAVE to implement some sort of errno,
       because a failure here is not fatal, but requires special care. */
    setsockopt(ses_sckt, SOL_SOCKET, SO_KEEPALIVE,
	       &ones, sizeof(unsigned int));
    ones = 75;
    setsockopt(ses_sckt, IPPROTO_TCP, TCP_KEEPIDLE,
	       &ones, sizeof(unsigned int));
    /* --------------------------------------------------------------- */

    return ses_sckt;
    break;

  case NEG_SESSION_RESPONSE:
    free(mypckt_buff);
    if (pckt.len) {
      if (1 > recv(ses_sckt, herpckt_buff, 1, MSG_WAITALL)) {
	close(ses_sckt);
	return -1;
      }
    }
    close(ses_sckt);
    // session_error = *herpckt_buff;
    return -1;
    break;

  case RETARGET_SESSION:
    if (pckt.len < (4+2)) {
      close(ses_sckt);
      free(mypckt_buff);
      return -1;
    }
    if ((4+2) > recv(ses_sckt, herpckt_buff, (4+2), MSG_WAITALL)) {
      close(ses_sckt);
      free(mypckt_buff);
      return -1;
    }
    herpckt_buff = read_32field(herpckt_buff,
				&(addr.sin_addr.s_addr));
    herpckt_buff = read_16field(herpckt_buff,
				&(addr.sin_port));
    /* fall-through! */
  default:
    close(ses_sckt);
    if (retry_count < nbworks_libcntl.max_ses_retarget_retries) {
      retry_count++;
      goto try_to_connect;
    } else {
      free(mypckt_buff);
      return -1;
    }
    break;
  }

  return -1;
}
#undef SMALL_BUFF_LEN

void *lib_ses_srv(void *arg) {
  struct pollfd pfd;
  struct name_state *handle;
  struct nbnodename_list *caller, decoded_nbnodename;
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
    if (! caller) {
      close(new_sckt);
      continue;
    }

    free(buff);

    if (caller->len != NETBIOS_CODED_NAME_LEN) {
      destroy_nbnodename(caller);
      close(new_sckt);
      continue;
    } else {
      decode_nbnodename(caller->name, decoded_nbnodename.name);
      destroy_nbnodename(caller);
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

    if (0 != fcntl(new_sckt, F_SETFL, O_NONBLOCK)) {
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

  destroy_nbnodename(handle->ses_listento);
  handle->ses_listento = 0;

  handle->ses_srv_stop = TRUE;
  handle->sesin_server = 0;

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
					 struct nbnodename_list *peer,
					 struct name_state *handle,
					 unsigned char keepalive) {
  struct nbworks_session *result;

  if (socket < 0) {
    nbworks_errno = EINVAL;
    return 0;
  }

  result = malloc(sizeof(struct nbworks_session));
  if (! result) {
    return 0;
  }

  if (peer)
    result->peer = clone_nbnodename(peer);
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
  result->caretaker_tid = 0;
  result->next = 0;

  return result;
}

struct nbworks_session *lib_take_session(struct name_state *handle) {
  struct nbworks_session *result, *clone;

  if (! handle) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  if (handle->sesin_library) {
    result = handle->sesin_library;

    if ((! result->peer) ||
	(result->socket < 0)) {
      if (result->next) {
	handle->sesin_library = result->next;
	lib_dstry_session(result);

	return lib_take_session(handle);
      } else {
	nbworks_errno = EAGAIN;
	return 0;
      }
    }

    if (result->next) {
      handle->sesin_library = result->next;
      result->next = 0;
    } else {
      clone = malloc(sizeof(struct nbworks_session));
      if (! clone) {
	nbworks_errno = ENOBUFS;
	return 0;
      }

      memcpy(clone, result, sizeof(struct nbworks_session));

      result->peer = 0;
      result->socket = -1;

      pthread_mutex_init(&(clone->mutex), 0);

      result = clone;
    }

    if (result->keepalive) {
      if (0 != pthread_create(&(result->caretaker_tid), 0,
			      lib_caretaker, handle)) {
	result->caretaker_tid = 0;
      }
    }

    return result;
  } else {
    return 0;
  }
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

    if (ses->peer)
      destroy_nbnodename(ses->peer);
    if (ses->oob_tmpstor)
      free(ses->oob_tmpstor);

    next = ses->next;
    free(ses);
    ses = next;
  }

  return;
}

void lib_dstry_session(struct nbworks_session *ses) {
  if (! ses)
    return;

  if (ses->socket >= 0)
    close(ses->socket);

  if (ses->caretaker_tid) {
    ses->kill_caretaker = TRUE;

    pthread_join(ses->caretaker_tid, 0);
  }

  pthread_mutex_destroy(&(ses->mutex));

  if (ses->peer)
    destroy_nbnodename(ses->peer);
  if (ses->oob_tmpstor)
    free(ses->oob_tmpstor);
  free(ses);

  return;
}


ssize_t lib_flushsckt(int socket,
		      ssize_t len,
		      int flags) {
  ssize_t ret_val, count;
  unsigned char buff[0xff];

  if (len <= 0) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    count = 0;
  }

  while (len > 0xff) {
    ret_val = recv(socket, buff, 0xff, flags);
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
