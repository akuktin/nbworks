#include "c_lang_extensions.h"

#include <stdlib.h>
#include <time.h>
#include <poll.h>
#include <errno.h>

#include "nodename.h"
#include "api.h"
#include "library_control.h"
#include "library.h"
#include "pckt_routines.h"


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
