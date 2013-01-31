#include "c_lang_extensions.h"

#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#include "constdef.h"

#define DEFAULT_TUNNEL_LEN (1600*30) /* The point with this is to figure
				      * out a number which equals maximum
				      * transmission unit times the number
				      * of TCP packets we will receive in
				      * the time it takes us to send the
				      * data down the tunnel. */

struct stream_connector_args {
  int sckt_lcl;
  int sckt_rmt;
};

//int errno;

void *tunnel_stream_sockets(void *arg) {
  struct stream_connector_args *params;
  struct pollfd fds[2];
  ssize_t trans_len, sent_len;
  int sckt_lcl, sckt_rmt;
  int ret_val, i;
  unsigned char buf[DEFAULT_TUNNEL_LEN][2];

  params = arg;
  sckt_lcl = params->sckt_lcl;
  sckt_rmt = params->sckt_rmt;

  trans_len = sent_len = 0;

  fds[0].fd = sckt_lcl;
  fds[0].events = (POLLIN | POLLPRI);
  fds[1].fd = sckt_rmt;
  fds[1].events = (POLLIN | POLLPRI);

  while (0xdeaf) {
    ret_val = poll(fds, 2, TP_100MS);
    if (ret_val == 0) {
      continue;
    } else {
      if (ret_val < 0) {
	/* TODO: error handling */
	close(sckt_lcl);
	close(sckt_rmt);
	return 0;
      }
    }

    for (i = 0; i < 2; i++) {
      if (fds[i].revents & POLLIN) {
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
	  return 0;
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
	    return 0;
	  }
	}
      }

      if (fds[i].revents & POLLPRI) {
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
	  return 0;
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
	    return 0;
	  }
	}
      }

      if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
	if (fds[i].revents & POLLHUP) {
	  close(sckt_lcl);
	  close(sckt_rmt);
	  return 0;
	} else {
	  /* TODO: error handling */
	  close(sckt_lcl);
	  close(sckt_rmt);
	  return 0;
	}
      }
    }
  }

  return 0;
}
