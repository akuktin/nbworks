#include "c_lang_extensions.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

#include "nodename.h"
#include "library_control.h"
#include "library.h"
#include "pckt_routines.h"
#include "rail-comm.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"
#include "randomness.h"

// temporary
#include "service_sector.h"


struct name_state *nbworks_allhandles;


void lib_init() {
  nbworks_allhandles = 0;

  nbworks_libcntl.stop_dtg_srv = 0;
}


/* returns: >0 = success, 0 = fail, <0 = error */
int lib_start_dtg_srv(struct name_state *handle,
		      unsigned char takes_field,
		      struct nbnodename_list *listento) {
  struct com_comm command;
  uint32_t len;
  int daemon;
  unsigned char buff[LEN_COMM_ONWIRE];

  if (! handle) {
    /* FIXME: errno signaling stuff */
    return -1;
  }

  if (handle->dtg_srv_tid) {
    /* FIXME: errno signaling stuff */
    return 0;
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
	(command.token == handle->token))) {
    close(daemon);
    return -1;
  }

  len = command.len;
  while (len) {
    if (len > LEN_COMM_ONWIRE) {
      if (LEN_COMM_ONWIRE > recv(daemon, buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
	close(daemon);
	return -1;
      } else
	len = len - LEN_COMM_ONWIRE;
    } else {
      if (len > recv(daemon, buff, len, MSG_WAITALL)) {
	close(daemon);
	return -1;
      } else
	len = 0;
    }
  }

  handle->dtg_listento = clone_nbnodename(listento);
  handle->dtg_takes = takes_field;
  handle->dtg_srv_stop = FALSE;
  handle->dtg_frags = 0;
  handle->in_server = 0;
  handle->in_library = 0;

  handle->dtg_srv_sckt = daemon;

  if (0 != pthread_create(&(handle->dtg_srv_tid), 0,
			  lib_dtgserver, handle)) {
    close(daemon);
    destroy_nbnodename(handle->dtg_listento);
    handle->dtg_listento = 0;
    return -1;
  }

  return 1;
}


void lib_destroy_frag(struct dtg_frag *flesh) {
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
  destroy_nbnodename(bone->src);
  lib_destroy_frag(bone->frags);
  free(bone);
}

struct dtg_frag_bckbone *lib_add_fragbckbone(uint16_t id,
					     struct nbnodename_list *src,
					     uint16_t offsetof_first,
					     uint16_t lenof_first,
					     void *first_data,
					     struct dtg_frag_bckbone **frags) {
  struct dtg_frag_bckbone *result, *cur_frag, **last_frag;

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
  result->last_active = ZEROONES;
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
	    lib_destroy_frag(master);
	  } else {
	    lib_destroy_frag(frags);
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
	lib_destroy_frag(master);
      } else {
	lib_destroy_frag(frags);
      }
      return 0;
    } else
      size_todate = size_todate + offered_len;

    *bef_remv = best_offer->next;
    if (sorted) {
      sorted->next = best_offer;
      sorted = sorted->next;
    } else {
      master = best_offer;
      sorted = master;
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
    memcpy((result + done), frags->data, frags->len);
    done = done + len;
    frags = frags->next;
  }

  return result;
}


/* returns: 0 = YES, listens to, !0 = NO, doesn't listen to */
int lib_doeslistento(struct nbnodename_list *query,
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


int lib_daemon_socket() {
  struct sockaddr_un address;
  int daemon;

  memset(&address, 0, sizeof(struct sockaddr_un));

  address.sun_family = AF_UNIX;
  memcpy(address.sun_path +1, NBWORKS_SCKT_NAME, NBWORKS_SCKT_NAMELEN);

  daemon = socket(PF_UNIX, SOCK_STREAM, 0);
  if (daemon < 0) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  if (0 != fcntl(daemon, F_SETFL, O_NONBLOCK)) {
    /* TODO: errno signaling stuff */
    close(daemon);
    return -1;
  }

  if (0 != connect(daemon, &address, sizeof(struct sockaddr_un))) {
    /* TODO: errno signaling stuff */
    close(daemon);
    return -1;
  }

  return daemon;
}


/* returns: <0 = error, 0 or >0 = something was sent */
int lib_senddtg_138(struct name_state *handle,
		    unsigned char *recepient,
		    unsigned char recepient_type,
		    void *data,
		    unsigned int len,
		    unsigned char isgroup,
		    unsigned char isbroadcast) {
  struct dtg_srvc_packet *pckt;
  struct com_comm command;
  int daemon_sckt;
  unsigned int pckt_len;
  unsigned char readycommand[LEN_COMM_ONWIRE];
  void *readypacket;

  if ((! (handle && recepient)) ||
      (len > 0xff00)) { /* A bit shorter because I have not yet
			   implemented a start-stop datagram writer. */
    /* FIXME: errno signaling stuff */
    return -1;
  }

  pckt = malloc(sizeof(struct dtg_srvc_packet));
  if (! pckt) {
    /* FIXME: errno signaling stuff */
    return -1;
  }

  pckt->for_del = 0;
  pckt->type = 0;
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
    /* FIXME: errno signaling stuff */
    free(pckt);
    return -1;
  }
  pckt->error_code = 0;

  pckt_len = DTG_HDR_LEN + 2 + 2 +
    ((1+NETBIOS_CODED_NAME_LEN) *2) + (handle->lenof_scope *2) +
    (2 * 4) /* extra space for name alignment, if performed */ + len;

  readypacket = master_dtg_srvc_pckt_writer(pckt, &pckt_len, 0);
  if (! readypacket) {
    /* FIXME: errno signaling stuff */
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  daemon_sckt = lib_daemon_socket();
  if (daemon_sckt == -1) {
    /* FIXME: errno signaling stuff */
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  command.command = rail_send_dtg;
  command.token = handle->token;
  memset(&(command.addr), 0, sizeof(struct sockaddr_in));
  command.len = pckt_len;
  command.data = readypacket;

  fill_railcommand(&command, readycommand, (readycommand + LEN_COMM_ONWIRE));

  if (LEN_COMM_ONWIRE > send(daemon_sckt, readycommand, LEN_COMM_ONWIRE,
			     MSG_NOSIGNAL)) {
    /* FIXME: errno signaling stuff */
    close(daemon_sckt);
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  if (pckt_len > send(daemon_sckt, readypacket, pckt_len, MSG_NOSIGNAL)) {
    /* FIXME: errno signaling stuff */
    close(daemon_sckt);
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(daemon_sckt, readycommand, LEN_COMM_ONWIRE,
			     MSG_WAITALL)) {
    /* FIXME: errno signaling stuff */
    close(daemon_sckt);
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  close(daemon_sckt);
  free(readypacket);
  destroy_dtg_srvc_pckt(pckt, 1, 1);

  return len;
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


void *lib_dtgserver(void *arg) {
  struct name_state *handle;
  struct pollfd pfd;
  struct dtg_frag_bckbone *fragbone;
  struct packet_cooked *toshow;
  struct dtg_srvc_packet *dtg;
  struct dtg_pckt_pyld_normal *nrml_pyld;
  uint32_t len;
  unsigned char lenbuf[sizeof(uint32_t)];
  unsigned char *new_pckt, take_dtg;

  if (arg)
    handle = arg;
  else
    return 0;

  pfd.fd = handle->dtg_srv_sckt;
  pfd.events = POLLIN;

  handle->in_server = handle->in_library = 0;

  toshow = 0;
  take_dtg = FALSE;

  while ((! nbworks_libcntl.stop_dtg_srv) ||
	 (! handle->dtg_srv_stop)) {
    if ((0 <= poll(&pfd, 1, TP_100MS)) ||
	(! (pfd.revents & POLLIN)) ||
	(pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) {
      if (pfd.revents & (POLLHUP | POLLNVAL)) {
	close(handle->dtg_srv_sckt);
	handle->dtg_srv_sckt = 0;
	return 0;
      } else
	continue;
    }

    if (sizeof(uint32_t) > recv(handle->dtg_srv_sckt, lenbuf,
				sizeof(uint32_t), MSG_WAITALL)) {
      break;
    }

    read_32field(lenbuf, &len);

    new_pckt = malloc(len);
    if (! new_pckt) {
      break;
    }

    if (len > recv(handle->dtg_srv_sckt, new_pckt, len, MSG_WAITALL)) {
      break;
    }

    dtg = master_dtg_srvc_pckt_reader(new_pckt, len, 0);
    free(new_pckt);
    if (! dtg) {
      break;
    }

    if (dtg->payload_t == normal) {
      nrml_pyld = dtg->payload;
      if (handle->dtg_takes == HANDLE_TAKES_ALL)
	take_dtg = TRUE;
      else {
	switch (dtg->type) {
	case BRDCST_DTG:
	  if (handle->dtg_takes & HANDLE_TAKES_ALLBRDCST) {
	    take_dtg = TRUE;
	  } else {
	    if (0 == lib_doeslistento(nrml_pyld->src_name,
				      handle->dtg_listento)) {
	      take_dtg = TRUE;
	    }
	  }
	  break;

	  /* I think I implemented the below wrong (groups again). */
	case DIR_UNIQ_DTG:
	case DIR_GRP_DTG:
	  if (handle->dtg_takes & HANDLE_TAKES_ALLUNCST) {
	    take_dtg = TRUE;
	  } else {
	    if (0 == lib_doeslistento(nrml_pyld->src_name,
				      handle->dtg_listento)) {
	      take_dtg = TRUE;
	    }
	  }
	  break;

	default:
	  break;
	}
      }

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
	    destroy_dtg_srvc_pckt(dtg, 1, 1);
	    lib_del_fragbckbone(dtg->id, nrml_pyld->src_name,
				&(handle->dtg_frags));
	    continue;
	  }
	} else {
	  if (dtg->flags & DTG_MORE_FLAG) {
	    if (lib_add_fragbckbone(dtg->id, nrml_pyld->src_name,
				    nrml_pyld->offset, nrml_pyld->len,
				    nrml_pyld->payload, &(handle->dtg_frags))) {
	      nrml_pyld->payload = 0;
	    } else {
	      destroy_dtg_srvc_pckt(dtg, 1, 1);
	      lib_del_fragbckbone(dtg->id, nrml_pyld->src_name,
				  &(handle->dtg_frags));
	      continue;
	    }
	  }
	}

	if (! (dtg->flags & DTG_MORE_FLAG)) {
	  toshow = malloc(sizeof(struct packet_cooked));
	  if (! toshow)
	    continue;

	  if (dtg->flags & DTG_FIRST_FLAG) {
	    toshow->data = nrml_pyld->payload;
	    nrml_pyld->payload = 0;

	    /* Ignore the offset field. */
	    toshow->len = nrml_pyld->len;

	    toshow->src = nrml_pyld->src_name;
	    nrml_pyld->src_name = 0;

	    toshow->next = 0;
	  } else {
	    fragbone = lib_take_fragbckbone(dtg->id, nrml_pyld->src_name,
					    &(handle->dtg_frags));
	    if (fragbone) {
	      /* A spooky statement. */
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

  handle->in_server = 0;

  return 0;
}


int lib_open_session(struct name_state *handle,
		     struct nbnodename_list *dst) {
  struct com_comm command;
  struct nbnodename_list *name_id, *her; /* To vary names a bit. */
  struct ses_srvc_packet *pckt;
  int lenof_pckt, wrotelenof_pckt;
  unsigned char *mypckt_buff, *herpckt_buff;
  unsigned char commandbuf[LEN_COMM_ONWIRE];

  if (! (handle && dst)) {
    /* TODO: errno signaling stuff */
    return -1;
  }
  if ((! dst->name) ||
      (dst->len < NETBIOS_NAME_LEN)) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  name_id = clone_nbnodename(handle->name);
  if (! name_id) {
    /* TODO: errno signaling stuff */
    return -1;
  }
  destroy_nbnodename(name_id->next_name);
  name_id->next_name = clone_nbnodename(handle->scope);
  if (! name_id->next_name) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(name_id);
    return -1;
  }

  her = clone_nbnodename(dst);
  if (! her) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(name_id);
    return -1;
  }
  her->next_name = destroy_nbnodename(her->next_name);
  her->next_name = clone_nbnodename(handle->scope);
  if (! her->next_name) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    destroy_nbnodename(name_id);
    return -1;
  }

  memset(command, 0, sizeof(struct com_comm));
  command.command = rail_addr_ofX;

  pckt = calloc(1, sizeof(struct ses_srvc_pckt));
  if (! pckt) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    destroy_nbnodename(name_id);
    return -1;
  }
  pckt->payload_t = two_names;
  pckt->payload = malloc(sizeof(struct ses_pckt_pyld_two_names));
  if (! pckt->payload) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    destroy_nbnodename(name_id);
    return -1;
  }

  ((struct ses_pckt_pyld_two_names *)(pckt->payload))->called_name = her;
  ((struct ses_pckt_pyld_two_names *)(pckt->payload))->called_name = name_id;

  lenof_pckt = (2 * NETBIOS_CODED_NAME_LEN) +
    (2 * handle->lenof_scope);

  if (nbworks_do_align) {
    /* Questions, questions: if I leave it like this, how
     * many NetBIOS implementations are going to choke on it? */
    /* Choking hazard: trailing octets behind the end of the last name. */
    lenof_pckt = lenof_pckt + (2 * 4);
  }

  pckt->len = lenof_pckt;
  pckt->type = SESSION_REQUEST;

  mypckt_buff = malloc(SES_HEADER_LEN + lenof_pckt);
  if (! mypckt_buff) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    destroy_nbnodename(name_id);
    return -1;
  }

  wrotelenof_pckt = (lenof_pckt + SES_HEADER_LEN);
  master_ses_srvc_pckt_writer(pckt, &wrotelenof_pckt, mypckt_buff);
  if (wrotelenof_pckt < (lenof_pckt + SES_HEADER_LEN)) {
    herpckt_buff = mypckt_buff + wrotelenof_pckt;
    while (herpckt_buff < (mypckt_buff + (lenof_pckt + SES_HEADER_LEN))) {
      *herpckt_buff = 0;
    }
  }
  destroy_ses_srvc_pckt(pckt);

  
}
