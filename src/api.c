#include "c_lang_extensions.h"

#include <stdlib.h>
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


ssize_t nbworks_send(unsigned char service,
		     struct nbworks_session *ses,
		     void *buff,
		     size_t len,
		     int flags) {
  struct ses_srvc_packet pckt;
  ssize_t ret_val, sent, notsent;
  unsigned char pcktbuff[SES_HEADER_LEN];

  /* Fun fact: since ssize_t is signed, and size_t is not,
   *           ssize_t has one bit less than size_t.
   *           The implication of this is that it is possible
   *           for an application to request sending of a
   *           larger number of octets than we can report back
   *           as being sent.
   *           max(ssize_t) < max(size_t) */

  if ((! (ses && buff)) ||
      (len < 0) ||
      (len >= (SIZE_MAX / 2))) { /* This hack may not work everywhere. */
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    sent = 0;
  }

  switch (service) {
  case DTG_SRVC:
    /* FEATURE_REQUEST: for now, we only support sending
                        via the multiplexing daemon */
    /* FEATURE_REQUEST: need to implement sender datagram fragmentation. */
    if (len > DTG_MAXLEN) {
      nbworks_errno = EMSGSIZE;
      return -1;
    }

    if (! ses->peer) {
      nbworks_errno = ENOTCONN;
      return -1;
    }

    ret_val = lib_senddtg_138(ses->handle, ses->peer->name,
			      (ses->peer->name)[NETBIOS_NAME_LEN-1],
			      buff, len, ses->handle->isgroup,
			      ((flags & MSG_BRDCAST) ? ISGROUP_YES : ISGROUP_NO));
    if (ret_val < len) {
      /* nbworks_errno is already set */
      return -1;
    } else
      return ret_val;

  case SES_SRVC:
    pckt.type = SESSION_MESSAGE;
    pckt.flags = 0;

    while (len > SES_MAXLEN) {
      pckt.len = SES_MAXLEN;
      if (pcktbuff == fill_ses_packet_header(&pckt, pcktbuff,
					     (pcktbuff + SES_HEADER_LEN))) {
	nbworks_errno = ZEROONES; /* FIXME */
	return -1;
      }

      notsent = SES_HEADER_LEN;
      while (notsent) {
	ret_val = send(ses->socket, (pcktbuff + (SES_HEADER_LEN - notsent)),
		       SES_HEADER_LEN, flags);
	if (ret_val < 0) {
	  nbworks_errno = errno;
	  return ret_val;
	} else {
	  notsent = notsent - ret_val;
	}
      }

      notsent = SES_MAXLEN;
      while (notsent) {
	ret_val = send(ses->socket, (buff + (SES_MAXLEN - notsent)),
		       notsent, flags);
	if (ret_val < 0) {
	  nbworks_errno = errno;
	  return ret_val;
	} else {
	  notsent = notsent - ret_val;
	}
      }

      sent = sent + SES_MAXLEN;
      buff = buff + SES_MAXLEN;
      len = len - SES_MAXLEN;
    }

    if (len == 0)
      return sent;

    pckt.len = len;
    if (pcktbuff == fill_ses_packet_header(&pckt, pcktbuff,
					   (pcktbuff + SES_HEADER_LEN))) {
      nbworks_errno = ZEROONES; /* FIXME */
      return -1;
    }

    notsent = SES_HEADER_LEN;
    while (notsent) {
      ret_val = send(ses->socket, (pcktbuff + (SES_HEADER_LEN - notsent)),
		     SES_HEADER_LEN, flags);
      if (ret_val < 0) {
	nbworks_errno = errno;
	return ret_val;
      } else {
	notsent = notsent - ret_val;
      }
    }

    notsent = len;
    while (notsent) {
      ret_val = send(ses->socket, (buff + (len - notsent)),
		     notsent, flags);
      if (ret_val < 0) {
	nbworks_errno = errno;
	return ret_val;
      } else {
	notsent = notsent - ret_val;
      }
    }

    sent = sent + len;

    return sent;

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
}


ssize_t nbworks_recv(unsigned char service,
		     struct nbworks_session *ses,
		     void **buff,
		     size_t len,
		     int callflags) {
  struct ses_srvc_packet hdr;
  ssize_t recved, notrecved, ret_val;
  ssize_t len_left;
  int flags;
  unsigned char hdrbuff[SES_HEADER_LEN], *walker;

  if ((! (ses && buff)) ||
      (len < 0) ||
      (len >= (SIZE_MAX / 2))) { /* This hack may not work everywhere. */
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    recved = 0;
    /* Turn off MSG_EOR in the flags we send to the socket. */
    flags = callflags & (ONES ^ MSG_EOR);
  }

  switch (service) {
  case DTG_SRVC:
    nbworks_errno = ENOSYS;
    return -1;

  case SES_SRVC:
    if (! *buff) {
      *buff = malloc(len);
      if (! *buff) {
	nbworks_errno = ENOMEM;
	return -1;
      }
    }

    notrecved = len;
    len_left = ses->len_left;

    while (notrecved) {
      if (len_left) {
	if (ses->len_left >= notrecved) {
	  ses->len_left = ses->len_left - notrecved;
	  len_left = notrecved;
	} /* else
	     len_left is already filled before the master while loop. */

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

	} while (len_left);

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
	if (hdr.len) {
	  ret_val = lib_flushsckt(ses->socket, hdr.len);
	  if (ret_val <= 0) {
	    /* nbworks_errno is set */
	    return ret_val;
	  }
	}
	continue;
      }
      if (hdr.len > notrecved) {
	ses->len_left = hdr.len - notrecved;
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
