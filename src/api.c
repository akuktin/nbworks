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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "api.h"
#include "nodename.h"
#include "library_control.h"
#include "library.h"
#include "rail-comm.h"
#include "pckt_routines.h"
#include "ses_srvc_pckt.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"


void nbworks_libinit(void) {
  nbworks_libcntl.stop_alldtg_srv = 0;
  nbworks_libcntl.stop_allses_srv = 0;

  nbworks_libcntl.dtg_srv_polltimeout = TP_100MS;
  nbworks_libcntl.ses_srv_polltimeout = TP_100MS;

  nbworks_libcntl.max_ses_retarget_retries = SSN_RETRY_COUNT;
  nbworks_libcntl.close_timeout = SSN_CLOSE_TIMEOUT;
  nbworks_libcntl.keepalive_interval = SSN_KEEP_ALIVE_TIMEOUT;

  nbworks_libcntl.dtg_frag_keeptime = FRAGMENT_TO;

  /* It's a little sad to write an algorithm that can
   * handle hell and heaven and then cripple it like this. */
  nbworks_libcntl.dtg_max_wholefrag_len = MAX_DATAGRAM_LENGTH;
}


struct name_state *nbworks_regname(unsigned char *name,
				   unsigned char name_type,
				   struct nbnodename_list *scope,
				   unsigned char group_flg,
				   unsigned char node_type, /* only one type */
				   unsigned long ttl) {
  struct name_state *result;
  struct com_comm command;
  struct rail_name_data namedt;
  int daemon;
  unsigned int lenof_scope;
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

  lenof_scope = nbworks_nbnodenamelen(scope);

  command.len = (LEN_NAMEDT_ONWIREMIN -1) + lenof_scope;
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

  result->scope = nbworks_clone_nbnodename(scope);
  if ((! result->scope) &&
      scope) {
    free(result->name->name);
    free(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = ENOMEM;
    return 0;
  }

  result->lenof_scope = lenof_scope;
  result->label_type = name_type;
  result->node_type = node_type;
  result->group_flg = group_flg;

  /* ----------------------- */

  daemon = lib_daemon_socket();
  if (daemon < 0) {
    nbworks_dstr_nbnodename(result->scope);
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
    nbworks_dstr_nbnodename(result->scope);
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
    nbworks_dstr_nbnodename(result->scope);
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
    nbworks_dstr_nbnodename(result->scope);
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
    nbworks_dstr_nbnodename(result->scope);
    free(result->name->name);
    free(result->name);
    free(result);
    nbworks_errno = EPERM;
    return 0;
  }

  result->token = command.token;

  return result;
}

/* returns: >0 = success, 0 = fail, <0 = error */
int nbworks_delname(struct name_state *handle) {
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

  nbworks_dstr_nbnodename(handle->name);
  if (handle->scope)
    nbworks_dstr_nbnodename(handle->scope);

  if (handle->dtg_listento)
    nbworks_dstr_nbnodename(handle->dtg_listento);
  if (handle->dtg_frags)
    lib_destroy_allfragbckbone(handle->dtg_frags);
  if (handle->in_library)
    lib_dstry_packets(handle->in_library);

  if (handle->ses_listento)
    nbworks_dstr_nbnodename(handle->ses_listento);
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
int nbworks_listen_dtg(struct name_state *handle,
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
    nbworks_dstr_nbnodename(handle->dtg_listento);
  handle->dtg_listento = nbworks_clone_nbnodename(listento);
  handle->dtg_takes = takes_field;
  handle->dtg_srv_stop = FALSE;
  if (handle->dtg_frags) {
    lib_destroy_allfragbckbone(handle->dtg_frags);
    handle->dtg_frags = 0;
  }
  handle->in_server = 0;
  if (handle->in_library) {
    lib_dstry_packets(handle->in_library);
    handle->in_library = 0;
  }

  if (0 != pthread_create(&(handle->dtg_srv_tid), 0,
			  lib_dtgserver, handle)) {
    nbworks_errno = errno;
    handle->dtg_srv_tid = 0;

    close(daemon);
    handle->dtg_srv_sckt = -1;
    nbworks_dstr_nbnodename(handle->dtg_listento);
    handle->dtg_listento = 0;

    return -1;
  }

  return 1;
}

/* returns: >0 = success, 0 = fail, <0 = error */
int nbworks_listen_ses(struct name_state *handle,
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

  handle->ses_listento = nbworks_clone_nbnodename(listento);
  handle->ses_takes = takes_field;
  if (handle->sesin_library)
    lib_dstry_sesslist(handle->sesin_library);

  if (0 != pthread_create(&(handle->ses_srv_tid), 0,
			  lib_ses_srv, handle)) {
    nbworks_errno = errno;
    close(daemon);
    handle->ses_srv_sckt = -1;

    nbworks_dstr_nbnodename(handle->ses_listento);
    handle->ses_listento = 0;

    handle->sesin_library = 0;

    handle->ses_srv_tid = 0;

    return -1;
  }

  return TRUE;
}

struct nbworks_session *nbworks_accept_ses(struct name_state *handle) {
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
	nbworks_hangup_ses(result);

	return nbworks_accept_ses(handle);
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

    if ((result->keepalive) &&
	(! result->caretaker_tid)) {
      if (0 != pthread_create(&(result->caretaker_tid), 0,
			      lib_caretaker, handle)) {
	result->caretaker_tid = 0;
      }
    } else {
      result->caretaker_tid = 0;
    }

    return result;
  } else {
    return 0;
  }
}

struct nbworks_session *nbworks_sescall(struct name_state *handle,
					struct nbnodename_list *dst,
					unsigned char keepalive) {
  int this_is_a_socket;

  if (! (handle && dst)) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  this_is_a_socket = lib_open_session(handle, dst);

  if (this_is_a_socket < 0) {
    /* nbworks_errno is already set */
    return 0;
  } else {
    return lib_make_session(this_is_a_socket, dst, handle, keepalive);
  }
}


int nbworks_poll(unsigned char service,
		 struct nbworks_pollfd *handles,
		 int numof_pfd,
		 int timeout) {
  struct pollfd *pfd;
  struct timespec sleeptime;
  struct packet_cooked *trgt;
  int i, count, ret_val;

  if ((! handles) ||
      (numof_pfd <= 0)) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  switch (service) {
  case DTG_SRVC:
    sleeptime.tv_sec = 0;
    sleeptime.tv_nsec = T_12MS;

    ret_val = 0;
    for (i=0; i<numof_pfd; i++) {
      trgt = handles[i].handle->in_library;

      /* If trgt[i].data is non-NULL, then this particular packet
       * has an unread payload and we do not need to check for the
       * presence of other packets. However, it is possible the packet
       * was read, thus making trgt[i].data equal NULL, but a new
       * packet has arrived. In this case, move trgt[i] down the list,
       * then evaluate it. The maneuvre is done for it's side effect,
       * changing the contents of trgt[i]. The same thing can also be
       * done without the comma, but this is way sexier, IMHO. :)
       * One other thing: I am not using the "logical or" operator because
       * I want to exercise total control over memory contents.
       * After all - that is the reason I use C and not PHP. */
      if ((trgt->data) ? trgt :
	  ((trgt = trgt->next), trgt)) {
	ret_val++;

	/* Do not report a POLLIN event if the application has not
	 * asked for it. */
	handles[i].revents = ((handles[i].events & POLLIN) | POLLOUT);
      } else {
	handles[i].revents = POLLOUT;
      }
    }

    if (ret_val) {
      return ret_val;
    }

    if (timeout < 0) {
      while (0xce0) {

	for (i=0; i<numof_pfd; i++) {
	  trgt = handles[i].handle->in_library;

	  /* Same as above. */
	  if ((trgt->data) ? trgt :
	      ((trgt = trgt->next), trgt)) {
	    ret_val++;

	    handles[i].revents = ((handles[i].events & POLLIN) | POLLOUT);
	  } else {
	    handles[i].revents = POLLOUT;
	  }
	}

	if (ret_val)
	  break;

	if (-1 == nanosleep(&sleeptime, 0)) {
	  nbworks_errno = errno;
	  for (i=0; i<numof_pfd; i++) {
	    handles[i].revents = POLLERR;
	  }
	  return -1;
	}
      }
    } else {
      for (count = timeout / 12; count > 0; count--) {

	for (i=0; i<numof_pfd; i++) {
	  trgt = handles[i].handle->in_library;

	  /* Same as above. */
	  if ((trgt->data) ? trgt :
	      ((trgt = trgt->next), trgt)) {
	    ret_val++;

	    handles[i].revents = ((handles[i].events & POLLIN) | POLLOUT);
	  } else {
	    handles[i].revents = POLLOUT;
	  }
	}

	if (ret_val)
	  break;

	if (-1 == nanosleep(&sleeptime, 0)) {
	  nbworks_errno = errno;
	  for (i=0; i<numof_pfd; i++) {
	    handles[i].revents = POLLERR;
	  }
	  return -1;
	}
      }
    }

    return ret_val;


  case SES_SRVC:
    pfd = malloc(numof_pfd * sizeof(struct pollfd));
    if (! pfd) {
      nbworks_errno = ENOBUFS;
      for (i=0; i<numof_pfd; i++) {
	handles[i].revents = POLLERR;
      }
      return -1;
    }

    for (i=0; i<numof_pfd; i++) {
      pfd[i].fd = handles[i].session->socket;
      pfd[i].events = handles[i].events;
    }

    ret_val = poll(pfd, numof_pfd, timeout);
    nbworks_errno = errno;

    for (i=0; i<numof_pfd; i++) {
      handles[i].revents = pfd[i].revents;
    }

    free(pfd);

    return ret_val;

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
}


ssize_t nbworks_sendto(unsigned char service,
		       struct nbworks_session *ses,
		       void *buff,
		       size_t len,
		       int callflags,
		       struct nbnodename_list *dst) {
  struct nbnodename_list *peer;
  struct ses_srvc_packet pckt;
  time_t start_time;
  ssize_t ret_val, sent, notsent;
  int flags;
  unsigned char pcktbuff[SES_HEADER_LEN];

  /* Fun fact: since ssize_t is signed, and size_t is not,
   *           ssize_t has one bit less than size_t.
   *           The implication of this is that it is possible
   *           for an application to request sending of a
   *           larger number of octets than we can report back
   *           as being sent.
   *           max(ssize_t) < max(size_t) */

  if ((! (ses && buff)) ||
      (len <= 0) ||
      (len >= (SIZE_MAX / 2))) { /* This hack may not work everywhere. */
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    sent = 0;
    /* Turn off MSG_EOR in the flags we send to the socket. */
    flags = callflags & (ONES ^ (MSG_EOR | MSG_DONTROUTE));
  }

  switch (service) {
  case DTG_SRVC:
    /* FEATURE_REQUEST: for now, we only support sending
                        via the multiplexing daemon */
    if (! ses->handle) {
      nbworks_errno = EINVAL;
      return -1;
    }

    if (len > DTG_MAXLEN) {
      nbworks_errno = EMSGSIZE;
      return -1;
    }

    if (dst)
      peer = dst;
    else
      if (ses->peer) {
	peer = ses->peer;
      } else {
	nbworks_errno = ENOTCONN;
	return -1;
      }

    ret_val = lib_senddtg_138(ses->handle, peer->name,
			      (peer->name)[NETBIOS_NAME_LEN-1],
			      buff, len, ses->handle->group_flg,
			      (flags & MSG_BRDCAST));
    if (ret_val < len) {
      /* nbworks_errno is already set */
      return -1;
    } else
      return ret_val;

  case SES_SRVC:
#define handle_cancel				\
    if (ses->cancel_send) {			\
      ses->cancel_send = 0;			\
      close(ses->socket);			\
      nbworks_errno = ECANCELED;		\
      return -1;				\
    }
#define handle_timeout							\
    if ((start_time + nbworks_libcntl.close_timeout) > time(0)) {	\
      close(ses->socket);						\
      nbworks_errno = ETIME;						\
      return -1;							\
    }

    start_time = time(0);
    pckt.type = SESSION_MESSAGE;
    pckt.flags = 0;

    /* --> begin setup */
    if ((ses->nonblocking) ||
	(flags & MSG_DONTWAIT)) {
      if (0 != pthread_mutex_trylock(&(ses->mutex))) {
	if (errno == EBUSY) {
	  nbworks_errno = EAGAIN;
	  return -1;
	} else {
	  nbworks_errno = errno;
	  return -1;
	}
      }
    } else {
      if (0 != pthread_mutex_lock(&(ses->mutex))) {
	nbworks_errno = errno;
	return -1;
      }
    }
    /* --> end setup */

    /* --> begin send overweight stuff */
    while (len > SES_MAXLEN) {
      pckt.len = SES_MAXLEN;
      if (pcktbuff == fill_ses_packet_header(&pckt, pcktbuff,
					     (pcktbuff + SES_HEADER_LEN))) {
	pthread_mutex_unlock(&(ses->mutex));
	if (sent)
	  return sent;
	else {
	  nbworks_errno = ENOBUFS;
	  return -1;
	}
      }

      /* send header */
      notsent = SES_HEADER_LEN;
      while (notsent) {
	ret_val = send(ses->socket, (pcktbuff + (SES_HEADER_LEN - notsent)),
		       notsent, flags);
	if (ret_val <= 0) {
	  pthread_mutex_unlock(&(ses->mutex));
	  if (ret_val == 0) {
	    return sent;
	  } else {
	    if (((errno == EAGAIN) ||
		 (errno == EWOULDBLOCK)) &&
		sent) {
	      return sent;
	    } else {
	      nbworks_errno = errno;
	      return ret_val;
	    }
	  }
	} else {
	  notsent = notsent - ret_val;
	}

	handle_timeout;
	handle_cancel;
      }

      /* send data */
      notsent = SES_MAXLEN;
      while (notsent) {
	ret_val = send(ses->socket, (buff + (SES_MAXLEN - notsent)),
		       notsent, (flags & (ONES ^ MSG_DONTWAIT)));
	if (ret_val <= 0) {
	  /* So, basically, once you commit to a packet, you HAVE to send
	   * the whole thing because failure to do so would desync the stream. */

	  if (ret_val == 0) {
	    pthread_mutex_unlock(&(ses->mutex));

	    nbworks_errno = EREMOTEIO;
	    return -1;
	  } else {
	    if ((errno == EAGAIN) ||
		(errno == EWOULDBLOCK)) {
	      handle_timeout;
	      handle_cancel else continue;
	    }
	    pthread_mutex_unlock(&(ses->mutex));

	    nbworks_errno = errno;
	    return ret_val;
	  }
	} else {
	  notsent = notsent - ret_val;
	}

	handle_timeout;
	handle_cancel;
      }

      sent = sent + SES_MAXLEN;

      if (callflags & MSG_EOR) {
	pthread_mutex_unlock(&(ses->mutex));
	return sent;
      } else {
	buff = buff + SES_MAXLEN;
	len = len - SES_MAXLEN;
      }
    }

    if (len == 0) {
      pthread_mutex_unlock(&(ses->mutex));
      return sent;
    }
    /* --> end send overweight stuff */

    /* --> begin send normal stuff */
    pckt.len = len;
    if (pcktbuff == fill_ses_packet_header(&pckt, pcktbuff,
					   (pcktbuff + SES_HEADER_LEN))) {
      pthread_mutex_unlock(&(ses->mutex));
      if (sent)
	return sent;
      else {
	nbworks_errno = ENOBUFS;
	return -1;
      }
    }

    /* send header */
    notsent = SES_HEADER_LEN;
    while (notsent) {
      ret_val = send(ses->socket, (pcktbuff + (SES_HEADER_LEN - notsent)),
		     notsent, flags);
      if (ret_val <= 0) {
	pthread_mutex_unlock(&(ses->mutex));
	if (ret_val == 0) {
	  return sent;
	} else {
	  if (((errno == EAGAIN) ||
	       (errno == EWOULDBLOCK)) &&
	      sent) {
	    return sent;
	  } else {
	    nbworks_errno = errno;
	    return ret_val;
	  }
	}
      } else {
	notsent = notsent - ret_val;
      }

      handle_timeout;
      handle_cancel;
    }

    /* send data */
    notsent = len;
    while (notsent) {
      ret_val = send(ses->socket, (buff + (len - notsent)),
		     notsent, (flags & (ONES ^ MSG_DONTWAIT)));
      if (ret_val <= 0) {
	/* So, basically, once you commit to a packet, you HAVE to send
	 * the whole thing because failure to do so would desync the stream. */

	if (ret_val == 0) {
	  pthread_mutex_unlock(&(ses->mutex));

	  nbworks_errno = EREMOTEIO;
	  return -1;
	} else {
	  if ((errno == EAGAIN) ||
	      (errno == EWOULDBLOCK)) {
	    handle_timeout;
	    handle_cancel else continue;
	  }
	  pthread_mutex_unlock(&(ses->mutex));

	  nbworks_errno = errno;
	  return ret_val;
	}
      } else {
	notsent = notsent - ret_val;
      }

      handle_timeout;
      handle_cancel;
    }
    /* --> end sending normal stuff */

    pthread_mutex_unlock(&(ses->mutex));
    sent = sent + len;

    return sent;
#undef handle_timeout
#undef handle_cancel

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
}

ssize_t nbworks_recvfrom(unsigned char service,
			 struct nbworks_session *ses,
			 void **buff,
			 size_t len,
			 int callflags,
			 struct nbnodename_list **src) {
  struct timespec sleeptime;
  struct packet_cooked *in_lib;
  struct ses_srvc_packet hdr;
  time_t start_time;
  ssize_t recved, notrecved, ret_val, torecv;
  size_t *hndllen_left, len_left;
  int flags;
  unsigned char hdrbuff[SES_HEADER_LEN], *walker;

  if ((! (ses && buff)) ||
      (len <= 0) ||
      (len >= (SIZE_MAX / 2))) { /* This hack may not work everywhere. */
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    ret_val = 0;

    /* Turn off some flags. */
    flags = callflags & (ONES ^ (MSG_EOR | MSG_PEEK | MSG_ERRQUEUE));
  }

  switch (service) {
  case DTG_SRVC:
    if (! ses->handle) {
      nbworks_errno = EINVAL;
      return -1;
    } else {
      ret_val = 0;
      sleeptime.tv_sec = 0;
      sleeptime.tv_nsec = T_50MS;
    }

    do {
      if (ses->handle->in_library) {
	in_lib = ses->handle->in_library;
	if (in_lib->data) {
	  if (*buff) {
	    if (len < in_lib->len) {
	      if (flags & MSG_TRUNC) {
		ret_val = in_lib->len;
	      } else {
		ret_val = len;
	      }
	    } else {
	      ret_val = in_lib->len;
	      len = ret_val;
	    }

	    memcpy(*buff, in_lib->data, len);
	    free(in_lib->data);

	  } else {
	    ret_val = in_lib->len;

	    if (ret_val)
	      *buff = in_lib->data;
	    else
	      free(in_lib->data);
	  }
	  in_lib->data = 0;
	}

	if (in_lib->src) {
	  if (src)
	    *src = in_lib->src;
	  else
	    nbworks_dstr_nbnodename(in_lib->src);
	  in_lib->src = 0;
	}
	if (in_lib->next) {
	  ses->handle->in_library = in_lib->next;
	  free(in_lib);
	} else {
	  if (ret_val)
	    break;
	  if ((flags & MSG_DONTWAIT) ||
	      (ses->nonblocking)) {
	    nbworks_errno = EAGAIN;
	    ret_val = -1;
	    break;
	  } else
	    nanosleep(&sleeptime, 0);
	}
      } else {
	if ((flags & MSG_DONTWAIT) ||
	    (ses->nonblocking)) {
	  nbworks_errno = EAGAIN;
	  ret_val = -1;
	  break;
	} else
	  nanosleep(&sleeptime, 0);
      }
    } while (! ret_val);

    return ret_val;

  case SES_SRVC:
#define handle_cancel				\
    if (ses->cancel_recv) {			\
      ses->cancel_recv = 0;			\
      close(ses->socket);			\
      nbworks_errno = ECANCELED;		\
      return -1;				\
    }
#define handle_timeout							\
    if ((start_time + nbworks_libcntl.close_timeout) > time(0)) {	\
      *hndllen_left = *hndllen_left + len_left;				\
      nbworks_errno = ETIME;						\
      return recved;							\
    }

    /* --> begin setup */
    start_time = time(0);
    if (! *buff) {
      *buff = malloc(len);
      if (! *buff) {
	nbworks_errno = ENOMEM;
	return -1;
      }
    }

    recved = 0;
    notrecved = len;
    if (flags & MSG_OOB) {
      hndllen_left = &(ses->ooblen_left);
    } else {
      hndllen_left = &(ses->len_left);
    }
    len_left = *hndllen_left;
    /* --> end setup */

    while (notrecved) {
      if (len_left) {
	if (*hndllen_left >= notrecved) {
	  *hndllen_left = *hndllen_left - notrecved;
	  len_left = notrecved;
	} else {
	  *hndllen_left = 0;
	  len_left = *hndllen_left;
	}

	if (flags & MSG_OOB) {
	  if (! ses->oob_tmpstor) {
	    nbworks_errno = ENOBUFS;
	    *hndllen_left = 0;
	    return -1;
	  }

	  memcpy(*buff, (ses->oob_tmpstor + ses->ooblen_offset), len_left);

	  if (*hndllen_left) {
	    ses->ooblen_offset = ses->ooblen_offset + len_left;
	  } else {
	    ses->ooblen_offset = 0;

	    free(ses->oob_tmpstor);
	    ses->oob_tmpstor = 0;
	  }

	  notrecved = notrecved - len_left;
	  len_left = 0;
	} else {
	  do {
	    ret_val = recv(ses->socket, (*buff + (len - notrecved)),
			   len_left, flags);

	    if (ret_val <= 0) {
	      if (((errno == EAGAIN) ||
		   (errno == EWOULDBLOCK)) &&
		  (recved)) {
		return recved;
	      } else {
		nbworks_errno = errno;
		if (ret_val == 0)
		  return recved;
		else
		  return -1;
	      }
	    }
	    notrecved = notrecved - ret_val;
	    recved = recved + ret_val;
	    len_left = len_left - ret_val;

	    handle_timeout;
	    handle_cancel;
	  } while (len_left);
	}

	if ((callflags & MSG_EOR) ||
	    (! notrecved)) {
	  if (recved)
	    return recved;
	  else {
	    nbworks_errno = EAGAIN;
	    return -1;
	  }
	}
      }

      /* Headers MUST be read en-block. */
      ret_val = recv(ses->socket, hdrbuff, SES_HEADER_LEN,
		     ((flags & (ONES ^ MSG_DONTWAIT)) | MSG_WAITALL));
      if (ret_val < SES_HEADER_LEN) {
	if (ret_val == 0) {
	  return recved;
	} else {
	  nbworks_errno = EREMOTEIO;
	  return -1;
	}
      }
      walker = hdrbuff;
      if (0 == read_ses_srvc_pckt_header(&walker, (hdrbuff + SES_HEADER_LEN),
					 &hdr)) {
	nbworks_errno = EREMOTEIO;
	return -1;
      }

      if (hdr.type != SESSION_MESSAGE) {
	if (! ((hdr.type == SESSION_KEEP_ALIVE) ||
	       (hdr.type == POS_SESSION_RESPONSE))) {
	  close(ses->socket);
	  ses->kill_caretaker = TRUE;
	  pthread_mutex_unlock(&(ses->mutex));
	  nbworks_errno = EPROTO;
	  if (recved) {
	    return recved;
	  } else {
	    return -1;
	  }
	}
	if (hdr.len) {
	  ret_val = lib_flushsckt(ses->socket, hdr.len, flags);
	  if (ret_val <= 0) {
	    /* nbworks_errno is set */
	    return ret_val;
	  }
	}
	/* no timeouts here */
	handle_cancel else continue;
      }
      if (hdr.len > notrecved) {
	*hndllen_left = hdr.len - notrecved;
	len_left = notrecved;
      } else {
	len_left = hdr.len;
      }
      while (len_left) {
	ret_val = recv(ses->socket, (*buff + (len - notrecved)),
		       len_left, flags);
	if (ret_val <= 0) {
	  if (((errno == EAGAIN) ||
	       (errno == EWOULDBLOCK)) &&
	      (recved)) {
	    return recved;
	  } else {
	    nbworks_errno = errno;
	    if (ret_val == 0)
	      return recved;
	    else
	      return -1;
	  }
	}

	len_left = len_left - ret_val;
	notrecved = notrecved - ret_val;
	recved = recved + ret_val;

	if (! (flags & MSG_OOB)) {
	  handle_timeout;
	} else {
	  if ((start_time + nbworks_libcntl.close_timeout) > time(0)) {
	    *hndllen_left = *hndllen_left + len_left;
	    break; /* and enter the below if block */
	  }
	}
	handle_cancel;
      }

      if ((flags & MSG_OOB) &&
	  (*hndllen_left)) {
	len_left = *hndllen_left;
	torecv = len_left;

	ses->oob_tmpstor = malloc(len_left);
	if (! ses->oob_tmpstor) {
	  /* Emergency! The stream is about to get desynced. */
	  nbworks_errno = ENOBUFS;
	  return recved;
	}
	ses->ooblen_offset = 0;

	while (len_left) {
	  ret_val = recv(ses->socket, (ses->oob_tmpstor +(torecv - len_left)),
			 len_left, flags);
	  if (ret_val <= 0) {
	    if ((errno == EAGAIN) ||
		(errno == EWOULDBLOCK)) {
	      /* no timeouts here */
	      handle_cancel else continue;
	    } else {
	      nbworks_errno = errno;
	      if (ret_val == 0)
		return recved;
	      else
		return -1;
	    }
	  }

	  len_left = len_left - ret_val;
	  torecv = torecv - ret_val;

	  /* no timeouts here */
	  handle_cancel;
	}
      }

      if (callflags & MSG_EOR) {
	if (recved)
	  return recved;
	else {
	  nbworks_errno = EAGAIN;
	  return -1;
	}
      }

    }

    return recved;
#undef handle_timeout
#undef handle_cancel

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
}

void nbworks_cancel(struct nbworks_session *ses,
		    unsigned char what) {
  if (! (ses && what)) {
    nbworks_errno = EINVAL;
    return;
  } else {
    nbworks_errno = 0;
  }

  if (what & NBWORKS_CANCEL_SEND) {
    ses->cancel_send = TRUE;
  }
  if (what & NBWORKS_CANCEL_RECV) {
    ses->cancel_recv = TRUE;
  }

  return;
}


void nbworks_hangup_ses(struct nbworks_session *ses) {
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
    nbworks_dstr_nbnodename(ses->peer);
  if (ses->oob_tmpstor)
    free(ses->oob_tmpstor);
  free(ses);

  return;
}


unsigned long nbworks_whatisaddrX(struct nbnodename_list *X,
				  unsigned long len) {
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
