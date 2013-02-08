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

#include "nodename.h"
#include "library_control.h"
#include "library.h"
#include "pckt_routines.h"
#include "rail-comm.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"
#include "ses_srvc_pckt.h"
#include "randomness.h"


struct name_state *nbworks_allhandles;


void lib_init() {
  nbworks_allhandles = 0;

  nbworks_libcntl.stop_alldtg_srv = 0;
  nbworks_libcntl.stop_allses_srv = 0;
  nbworks_libcntl.max_ses_retarget_retries = 5; /*
	      What do I know? Just choose a random number,
	      it oughta work. I guess. */
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
  destroy_nbnodename(bone->src);
  lib_destroy_frags(bone->frags);
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
      (len < (1+NETBIOS_NAME_LEN+1)))
    return 0;

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_addr_ofX;
  command.len = len;

  fill_railcommand(&command, combuff, (combuff +LEN_COMM_ONWIRE));

  buff = malloc(len);
  if (! buff)
    return 0;

  if (buff == fill_all_DNS_labels(X, buff, (buff +len), 0)) {
    free(buff);
    return 0;
  }

  daemon_sckt = lib_daemon_socket();
  if (daemon_sckt == -1) {
    free(buff);
    return 0;
  }

  if (LEN_COMM_ONWIRE > send(daemon_sckt, combuff,
			     LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
    close(daemon_sckt);
    free(buff);
    return 0;
  }

  if (len > send(daemon_sckt, buff, len, MSG_NOSIGNAL)) {
    close(daemon_sckt);
    free(buff);
    return 0;
  }

  free(buff);

  if (LEN_COMM_ONWIRE > recv(daemon_sckt, combuff,
			     LEN_COMM_ONWIRE, MSG_WAITALL)) {
    close(daemon_sckt);
    return 0;
  }

  if (0 == read_railcommand(combuff, (combuff +LEN_COMM_ONWIRE),
			    &command)) {
    close(daemon_sckt);
    return 0;
  }

  if ((command.command != rail_addr_ofX) ||
      (command.len < 4)) {
    close(daemon_sckt);
    return 0;
  }

  if (4 > recv(daemon_sckt, combuff, 4, MSG_WAITALL)) {
    close(daemon_sckt);
    return 0;
  }

  read_32field(combuff, &result);

  close(daemon_sckt);

  return result;
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
  unsigned char lenbuf[4];
  unsigned char *new_pckt, take_dtg;

  if (arg)
    handle = arg;
  else
    return 0;

  if (! handle->dtg_listento) {
    handle->dtg_srv_stop = TRUE;
    return 0;
  }

  pfd.fd = handle->dtg_srv_sckt;
  pfd.events = POLLIN;

  handle->in_server = handle->in_library = 0;

  toshow = 0;
  take_dtg = FALSE;

  while ((! nbworks_libcntl.stop_alldtg_srv) ||
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
	    take_dtg = lib_doeslistento(nrml_pyld->src_name,
					handle->dtg_listento);
	  }
	  break;

	  /* I think I implemented the below wrong (groups again). */
	case DIR_UNIQ_DTG:
	case DIR_GRP_DTG:
	  if (handle->dtg_takes & HANDLE_TAKES_ALLUNCST) {
	    take_dtg = TRUE;
	  } else {
	    take_dtg = lib_doeslistento(nrml_pyld->src_name,
					handle->dtg_listento);
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
  struct com_comm command;
  struct nbnodename_list *name_id, *her; /* To vary names a bit. */
  struct ses_srvc_packet *pckt;
  struct ses_pckt_pyld_two_names *twins;
  struct sockaddr_in addr;
  int ses_sckt, retry_count;;
  unsigned int lenof_pckt, wrotelenof_pckt, ones;
  unsigned char *mypckt_buff, *herpckt_buff;
  unsigned char small_buff[SMALL_BUFF_LEN];

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
  if (! her->next_name) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    return -1;
  }

  addr.sin_addr.s_addr =
    lib_whatisaddrX(her, (1+ NETBIOS_NAME_LEN+ handle->lenof_scope));
  if (! addr.sin_addr.s_addr) {
    destroy_nbnodename(her);
    return -1;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = 139;

  name_id = clone_nbnodename(handle->name);
  if (! name_id) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    return -1;
  }
  destroy_nbnodename(name_id->next_name);
  name_id->next_name = clone_nbnodename(handle->scope);
  if (! name_id->next_name) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(her);
    destroy_nbnodename(name_id);
    return -1;
  }

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_addr_ofX;

  pckt = calloc(1, sizeof(struct ses_srvc_packet));
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

  twins = pckt->payload;
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

  pckt->len = lenof_pckt;
  pckt->type = SESSION_REQUEST;

  mypckt_buff = malloc(SES_HEADER_LEN + lenof_pckt);
  if (! mypckt_buff) {
    /* TODO: errno signaling stuff */
    destroy_nbnodename(name_id);
    return -1;
  }

  wrotelenof_pckt = (lenof_pckt + SES_HEADER_LEN);
  /* NOTE: if alignment is performed, fill_ses_srvc_pckt_payload_data()
   *       will leave up to three octets between the called name and the
   *       calling name that are not NULLed out, as well as up to three
   *       octets between the end of the calling name and the end of
   *       packet. */
  master_ses_srvc_pckt_writer(pckt, &wrotelenof_pckt, mypckt_buff);

  destroy_ses_srvc_pckt(pckt);
  destroy_nbnodename(name_id);
  destroy_nbnodename(her);

  /* Now I have allocated: mypckt_buff. */
  /* Other that that, I will need: addr, wrotelenof_pckt,
                                   *herpckt_buff, *pckt,
				   small_buff[] */
 try_to_connect:
  ses_sckt = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ses_sckt == -1) {
    free(mypckt_buff);
    return -1;
  }

  if (0 != fcntl(ses_sckt, F_SETFL, O_NONBLOCK)) {
    close(ses_sckt);
    /* This also may not be a fatal error. */
    free(mypckt_buff);
    return -1;
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

  if (0 != connect(ses_sckt, &addr, sizeof(struct sockaddr_in))) {
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
  pckt = read_ses_srvc_pckt_header(&herpckt_buff,
				   (herpckt_buff + SES_HEADER_LEN));
  if (! pckt) {
    close(ses_sckt);
    free(mypckt_buff);
    return -1;
  }

  switch (pckt->type) {
  case POS_SESSION_RESPONSE:
    free(mypckt_buff);
    while (pckt->len) {
      if (pckt->len > SMALL_BUFF_LEN) {
	if (SMALL_BUFF_LEN > recv(ses_sckt, herpckt_buff, SMALL_BUFF_LEN,
				  MSG_WAITALL)) {
	  close(ses_sckt);
	  free(mypckt_buff);
	  return -1;
	}
	pckt->len = pckt->len - SMALL_BUFF_LEN;
      } else {
	if (pckt->len > recv(ses_sckt, herpckt_buff, pckt->len,
			     MSG_WAITALL)) {
	  close(ses_sckt);
	  free(mypckt_buff);
	  return -1;
	}
	pckt->len = 0;
      }
    }
    free(pckt);
    return ses_sckt;
    break;

  case NEG_SESSION_RESPONSE:
    free(mypckt_buff);
    if (1 > recv(ses_sckt, herpckt_buff, 1, MSG_WAITALL)) {
      close(ses_sckt);
      free(pckt);
      return -1;
    }
    free(pckt);
    close(ses_sckt);
    // session_error = *herpckt_buff;
    return -1;
    break;

  case RETARGET_SESSION:
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
    free(pckt);
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

void *lib_ses_srv(void *arg) {
  struct pollfd pfd;
  struct name_state *handle;

  if (arg)
    handle = arg;
  else
    return 0;

  if (! handle->ses_listento) {
    handle->ses_srv_stop = TRUE;
    return 0;
  }

  handle->sesin_server = handle->sesin_library = 0;

  pfd.fd = handle->ses_srv_sckt;
  pfd.events = POLLIN;

  while ((! nbworks_libcntl.stop_allses_srv) ||
	 (! handle->ses_srv_stop)) {
    
  }

  close(handle->ses_srv_sckt);

  destroy_nbnodename(handle->ses_listento);
  handle->ses_listento = 0;

  handle->ses_srv_stop = TRUE;
  handle->sesin_server = 0;

  return 0;
}


struct nbworks_session *lib_make_session(int socket,
					 unsigned char keepalive) {
  struct nbworks_session *result;

  result = malloc(sizeof(struct nbworks_session));
  if (! result) {
    return 0;
  }

  if (0 != pthread_mutex_init(&(result->mutex), 0)) {
    free(result);
    return 0;
  }
  result->mutexlock = pthread_mutex_trylock;

  result->keepalive = keepalive;
  result->socket = socket;
  result->next = 0;

  return result;
}
