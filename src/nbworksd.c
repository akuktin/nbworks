#include "c_lang_extensions.h"

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#define DEFAULT_TUNNEL_LEN 0x10000

int errno;

int tunnel_stream_sockets(int sckt_lcl, int sckt_rmt) {
  struct pollfd fds[2];
  nfds_t numof_fds;
  ssize_t trans_len, sent_len;
  int ret_val, i;
  unsigned char buf[DEFAULT_TUNNEL_LEN][2];

  numof_fds = 2;
  trans_len = sent_len = 0;

  fds[0].fd = sckt_lcl;
  fds[0].events = (POLLIN | POLLPRI);
  fds[1].fd = sckt_rmt;
  fds[1].events = (POLLIN | POLLPRI);

  while (1) {
    ret_val = poll(fds, numof_fds, 100 /* milisecond */);
    if (ret_val == 0) {
      continue;
    } else {
      if (ret_val < 0) {
	/* TODO: error handling */
	close(sckt_lcl);
	close(sckt_rmt);
	return -1;
      }
    }

    for (i = 0; i < 2; i++) {
      if (fds[i].revents | POLLIN) {
	trans_len = recv(fds[i].fd, buf[i], DEFAULT_TUNNEL_LEN,
			 (MSG_DONTWAIT));

	if (trans_len == 0) {
	  close(sckt_lcl);
	  close(sckt_rmt);
	  return 0;
	}

	if (trans_len < 0) {
	  /* TODO: error handling */
	  close(sckt_lcl);
	  close(sckt_rmt);
	  return -1;
	}

	sent_len = 0;
	while (sent_len < trans_len) {
	  errno = 0;
	  sent_len = sent_len + send(fds[((~i) & 0x1)].fd,
				     ((buf[i]) + sent_len),
				     (trans_len - sent_len),
				     0);

	  if (errno != 0) {
	    /* TODO: error handling */
	    close(sckt_lcl);
	    close(sckt_rmt);
	    return -1;
	  }
	}
      }

      if (fds[i].revents | POLLPRI) {
	trans_len = recv(fds[i].fd, buf[i], DEFAULT_TUNNEL_LEN,
			 (MSG_DONTWAIT | MSG_OOB));

	if (trans_len == 0) {
	  close(sckt_lcl);
	  close(sckt_rmt);
	  return 0;
	}

	if (trans_len < 0) {
	  /* TODO: error handling */
	  close(sckt_lcl);
	  close(sckt_rmt);
	  return -1;
	}

	sent_len = 0;
	while (sent_len < trans_len) {
	  errno = 0;
	  sent_len = sent_len + send(fds[((~i) & 0x1)].fd,
				     ((buf[i]) + sent_len),
				     (trans_len - sent_len),
				     MSG_OOB);

	  if (errno != 0) {
	    /* TODO: error handling */
	    close(sckt_lcl);
	    close(sckt_rmt);
	    return -1;
	  }
	}
      }

      if (fds[i].revents | POLLHUP) {
	close(sckt_lcl);
	close(sckt_rmt);
	return 0;
      }

      if (fds[i].revents | POLLERR | POLLNVAL) {
	/* TODO: errno handling */
	close(sckt_lcl);
	close(sckt_rmt);
	return -1;
      }

    }
  }

  return 0;
}
