#include "c_lang_extensions.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "nodename.h"
#include "api.h"
#include "library_control.h"
#include "library.h"
#include "pckt_routines.h"
#include "ses_srvc_pckt.h"


int nbworks_poll(unsigned char service,
		 struct nbworks_pollfd *handles,
		 int numof_pfd,
		 int timeout) {
  struct pollfd *pfd;
  struct timespec sleeptime;
  struct packet_cooked **trgt;
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

    trgt = malloc(numof_pfd * sizeof(struct cooked_packet *));
    if (! trgt) {
      nbworks_errno = ENOMEM;
      for (i=0; i<numof_pfd; i++) {
	handles[i].revents = POLLERR;
      }
      return -1;
    }

    ret_val = 0;
    for (i=0; i<numof_pfd; i++) {
      trgt[i] = handles[i].handle->in_library;
      if (trgt[i]) {
	trgt[i] = (trgt[i])->next;
      }
      if (trgt[i]) {
	ret_val++;
	if (handles[i].events & POLLIN) {
	  handles[i].revents = (POLLIN | POLLOUT);
	} else {
	  handles[i].revents = POLLOUT;
	}
      } else {
	handles[i].revents = POLLOUT;
      }
    }

    if (ret_val) {
      free(trgt);
      return ret_val;
    }

    if (timeout < 0) {
      while (0xce0) {

	for (i=0; i<numof_pfd; i++) {
	  if (trgt[i]) {
	    ret_val++;
	    if (handles[i].events & POLLIN)
	      handles[i].revents |= POLLIN;
	  }
	}

	if (ret_val)
	  break;

	if (-1 == nanosleep(&sleeptime, 0)) {
	  nbworks_errno = errno;
	  for (i=0; i<numof_pfd; i++) {
	    handles[i].revents = POLLERR;
	  }
	  free(trgt);
	  return -1;
	}
      }
    } else {
      for (count = timeout / 12; count >= 0; count--) {

	for (i=0; i<numof_pfd; i++) {
	  if (trgt[i]) {
	    ret_val++;
	    if (handles[i].events & POLLIN)
	      handles[i].revents |= POLLIN;
	  }
	}

	if (ret_val)
	  break;

	if (-1 == nanosleep(&sleeptime, 0)) {
	  nbworks_errno = errno;
	  for (i=0; i<numof_pfd; i++) {
	    handles[i].revents = POLLERR;
	  }
	  free(trgt);
	  return -1;
	}
      }
    }

    free(trgt);

    return ret_val;


  case SES_SRVC:
    pfd = malloc(numof_pfd * sizeof(struct pollfd));
    if (! pfd) {
      nbworks_errno = ENOMEM;
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
    /* FEATURE_REQUEST: need to implement sender datagram fragmentation. */
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
			      ((flags & MSG_BRDCAST) ? ISGROUP_YES : ISGROUP_NO));
    if (ret_val < len) {
      /* nbworks_errno is already set */
      return -1;
    } else
      return ret_val;

  case SES_SRVC:
    pckt.type = SESSION_MESSAGE;
    pckt.flags = 0;

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

      notsent = SES_HEADER_LEN;
      while (notsent) {
	ret_val = send(ses->socket, (pcktbuff + (SES_HEADER_LEN - notsent)),
		       notsent, flags);
	if (ret_val <= 0) {
	  pthread_mutex_unlock(&(ses->mutex));
	  if (ret_val == 0) {
	    return sent;
	  } else {
	    if ((errno == EAGAIN) ||
		(errno == EWOULDBLOCK)) {
	      if (sent)
		return sent;
	    }
	    nbworks_errno = errno;
	    return ret_val;
	  }
	} else {
	  notsent = notsent - ret_val;
	}

	if (ses->cancel_send) {
	  ses->cancel_send = 0;
	  close(ses->socket);
	  nbworks_errno = ECANCELED;
	  return -1;
	}
      }

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
	      if (ses->cancel_send) {
		ses->cancel_send = 0;
		close(ses->socket);
		nbworks_errno = ECANCELED;
		return -1;
	      } else
		continue;
	    }
	    pthread_mutex_unlock(&(ses->mutex));

	    nbworks_errno = errno;
	    return ret_val;
	  }
	} else {
	  notsent = notsent - ret_val;
	}

	if (ses->cancel_send) {
	  ses->cancel_send = 0;
	  close(ses->socket);
	  nbworks_errno = ECANCELED;
	  return -1;
	}
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

    notsent = SES_HEADER_LEN;
    while (notsent) {
      ret_val = send(ses->socket, (pcktbuff + (SES_HEADER_LEN - notsent)),
		     notsent, flags);
      if (ret_val <= 0) {
	pthread_mutex_unlock(&(ses->mutex));
	if (ret_val == 0) {
	  return sent;
	} else {
	  if ((errno == EAGAIN) ||
	      (errno == EWOULDBLOCK)) {
	    if (sent)
	      return sent;
	  }
	  nbworks_errno = errno;
	  return ret_val;
	}
      } else {
	notsent = notsent - ret_val;
      }

      if (ses->cancel_send) {
	ses->cancel_send = 0;
	close(ses->socket);
	nbworks_errno = ECANCELED;
	return -1;
      }
    }

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
	    if (ses->cancel_send) {
	      ses->cancel_send = 0;
	      close(ses->socket);
	      nbworks_errno = ECANCELED;
	      return -1;
	    } else
	      continue;
	  }
	  pthread_mutex_unlock(&(ses->mutex));

	  nbworks_errno = errno;
	  return ret_val;
	}
      } else {
	notsent = notsent - ret_val;
      }

      if (ses->cancel_send) {
	ses->cancel_send = 0;
	close(ses->socket);
	nbworks_errno = ECANCELED;
	return -1;
      }
    }

    pthread_mutex_unlock(&(ses->mutex));
    sent = sent + len;

    return sent;

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

    while (! ret_val) {
      if (ses->handle->in_library) {
	in_lib = ses->handle->in_library;
	if (in_lib->data) {
	  if (*buff) {
	    if (len < in_lib->len) {
	      if (callflags & MSG_TRUNC) {
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
	    destroy_nbnodename(in_lib->src);
	  in_lib->src = 0;
	}
	if (in_lib->next) {
	  ses->handle->in_library = in_lib->next;
	  free(in_lib);
	} else {
	  if ((callflags & MSG_DONTWAIT) ||
	      (ses->nonblocking)) {
	    nbworks_errno = EAGAIN;
	    ret_val = -1;
	    break;
	  } else
	    nanosleep(&sleeptime, 0);
	}
      } else {
	if ((callflags & MSG_DONTWAIT) ||
	    (ses->nonblocking)) {
	  nbworks_errno = EAGAIN;
	  ret_val = -1;
	  break;
	} else
	  nanosleep(&sleeptime, 0);
      }
    }

    return ret_val;

  case SES_SRVC:
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

    while (notrecved) {
      if (len_left) {
	if (*hndllen_left >= notrecved) {
	  *hndllen_left = *hndllen_left - notrecved;
	  len_left = notrecved;
	} /* else
	     len_left is already filled before the master while loop. */

	if (flags & MSG_OOB) {
	  if (! ses->oob_tmpstor) {
	    nbworks_errno = ENOBUFS;
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


	    if (ses->cancel_recv) {
	      ses->cancel_recv = 0;
	      close(ses->socket);
	      nbworks_errno = ECANCELED;
	      return -1;
	    }
	  } while (len_left);
	}

	if ((callflags & MSG_EOR) ||
	    (! notrecved))
	  return recved;

      }

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
	/* MAYBE: implement (transparent?) mid-session retargeting. */
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
	if (ses->cancel_recv) {
	  ses->cancel_recv = 0;
	  close(ses->socket);
	  nbworks_errno = ECANCELED;
	  return -1;
	} else
	  continue;
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

	if (ses->cancel_recv) {
	  ses->cancel_recv = 0;
	  close(ses->socket);
	  nbworks_errno = ECANCELED;
	  return -1;
	}
      }

      if ((flags & MSG_OOB) &&
	  (*hndllen_left)) {
	len_left = *hndllen_left;
	torecv = len_left;

	ses->oob_tmpstor = malloc(len_left);
	if (! ses->oob_tmpstor) {
	  /* Emergency! The stream is about to get desynced. */
	  nbworks_errno = ENOBUFS;
	  /* I was going to make it return recved here, but then I remembered
	   * one of UNIX rules: when failing, fail as loud as possible and as
	   * soon as possible. */
	  return -1;
	}
	ses->ooblen_offset = 0;

	while (len_left) {
	  ret_val = recv(ses->socket, (ses->oob_tmpstor +(torecv - len_left)),
			 len_left, flags);
	  if (ret_val <= 0) {
	    if ((errno == EAGAIN) ||
		(errno == EWOULDBLOCK)) {
	      if (ses->cancel_recv) {
		ses->cancel_recv = 0;
		close(ses->socket);
		nbworks_errno = ECANCELED;
		return -1;
	      } else
		continue;
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

	  if (ses->cancel_recv) {
	    ses->cancel_recv = 0;
	    close(ses->socket);
	    nbworks_errno = ECANCELED;
	    return -1;
	  }
	}
      }

      if (callflags & MSG_EOR)
	return recved;

    }

    return recved;

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
}
