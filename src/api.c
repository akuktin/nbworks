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


int nbworks_sespoll(struct nbworks_pollfd *sessions,
		    int numof_sess,
		    int timeout) {
  struct pollfd *pfd;
  int i, ret_val;

  if ((! sessions) ||
      (numof_sess <= 0)) {
    nbworks_errno = EFAULT;
    return -1;
  }

  pfd = malloc(numof_sess * sizeof(struct pollfd));
  if (! pfd) {
    nbworks_errno = errno;
    for (i=0; i<numof_sess; i++) {
      sessions[i].revents = POLLERR;
    }
    return -1;
  }

  for (i=0; i<numof_sess; i++) {
    pfd[i].fd = sessions[i].session->socket;
    pfd[i].events = sessions[i].events;
  }

  ret_val = poll(pfd, numof_sess, timeout);
  nbworks_errno = errno;

  for (i=0; i<numof_sess; i++) {
    sessions[i].revents = pfd[i].revents;
  }

  free(pfd);

  return ret_val;
}

int nbworks_dtgpoll(struct nbworks_pollfd *handles,
		    int numof_dtgs,
		    int timeout) {
  struct timespec sleeptime;
  struct packet_cooked **trgt;
  int i, count, ret_val;

  if ((! handles) ||
      (numof_dtgs <= 0)) {
    nbworks_errno = EFAULT;
    return -1;
  }

  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_12MS;

  trgt = malloc(numof_dtgs * sizeof(struct cooked_packet *));
  if (! trgt) {
    nbworks_errno = errno;
    for (i=0; i<numof_dtgs; i++) {
      handles[i].revents = POLLERR;
    }
    return -1;
  }

  ret_val = 0;
  for (i=0; i<numof_dtgs; i++) {
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

  nbworks_errno = 0;

  if (ret_val) {
    free(trgt);
    return ret_val;
  }

  if (timeout < 0) {
    while (0xce0) {

      for (i=0; i<numof_dtgs; i++) {
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
	for (i=0; i<numof_dtgs; i++) {
	  handles[i].revents = POLLERR;
	}
	free(trgt);
	return -1;
      }
    }
  } else {
    for (count = timeout / 12; count >= 0; count--) {

      for (i=0; i<numof_dtgs; i++) {
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
	for (i=0; i<numof_dtgs; i++) {
	  handles[i].revents = POLLERR;
	}
	free(trgt);
	return -1;
      }
    }
  }

  free(trgt);

  return ret_val;
}


ssize_t nbworks_send(unsigned char service,
		     void *handle,
		     void *buff,
		     size_t len,
		     int flags) {
  struct nbworks_session *ses;
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

  if ((! (handle && buff)) ||
      (len < 0) ||
      (len > (SIZE_MAX / 2))) { /* This hack may not work everywhere. */
    nbworks_errno = EARGS;
    return -1;
  } else {
    nbworks_errno = 0;
    sent = 0;
  }

  switch (service) {
  case DTG_SRVC:
    return 0;

  case SES_SRVC:
    ses = handle;

    pckt.type = SESSION_MESSAGE;
    pckt.flags = 0;

    while (len > SES_MAXLEN) {
      pckt.len = SES_MAXLEN;
      if (pcktbuff == fill_ses_packet_header(&pckt, pcktbuff,
					     (pcktbuff + SES_HEADER_LEN))) {
	nbworks_errno = 255; /* FIXME */
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
      nbworks_errno = 255;
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
    nbworks_errno = EARGS;
    return -1;
  }
}
