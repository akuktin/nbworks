#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <nbworks.h>
#include <stdlib.h>
#include <poll.h>
#include <errno.h>
#include <sys/socket.h>

#define FALSE 0
#define TRUE  1
#define ONES (~0)

unsigned int scram = 0;

void do_scram(int signal) {
  scram = 1;

  return;
}

int main() {
  struct sigaction new_signal;
  struct timespec sleeptime;
  nbworks_session_p session;
  nbworks_namestate_p name;
  struct nbworks_pollfd nbw_pfd;
  struct nbworks_nbnamelst *name_lst;
  size_t ret_val;
  ssize_t have_read;
  int pollret, result;
  unsigned char name_label[] = "TARGETSES";
  unsigned char return_buff[0x1ffff], *walker, *buff_ptr, **buff_pptr;

  result = 0;
  buff_ptr = return_buff;
  buff_pptr = &buff_ptr;
  //  buff_pptr = &return_buff;
  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = (50 * 1000000);
  memset(&new_signal, 0, sizeof(struct sigaction));
  memset(return_buff, 0, 0x1ffff);
  memset(&nbw_pfd, 0, sizeof(struct nbworks_pollfd));

  new_signal.sa_handler = &do_scram;

  if (sigaction(SIGTERM, &new_signal, 0)) {
    fprintf(stderr, "Could not install signal handler. Aborting.\n");
    return 1;
  }

  nbworks_libinit();
  //  sleep(10);

  name = nbworks_regname(name_label, 0, 0, FALSE, NBWORKS_NODE_B, 60, TRUE);
  if (! name) {
    fprintf(stderr, "Could not register name.\nnbworks_errno = %i\n",
            nbworks_errno);
    return 1;
  }

  fprintf(stderr, "Name registered...\n");

  if (0 >= nbworks_listen_ses(name, ONES, 0)) {
    fprintf(stderr, "Could not set up ses server.\nnbworks_errno = %i\n",
            nbworks_errno);
    result = 1;
    goto endof_function;
  }

  session = nbworks_accept_ses(name, -1);
  if (! session) {
    fprintf(stderr, "Could not accept session\nnbworks_errno = %i\n",
	    nbworks_errno);
    result = 1;
    goto endof_function;
  }

  nbw_pfd.session = session;
  nbw_pfd.events = POLLIN;
  while (! scram) {
    pollret = nbworks_poll(NBWORKS_SES_SRVC, &nbw_pfd, 1, 30);
    if (pollret <= 0) {
      if (pollret == 0) {
	continue;
      } else {
	fprintf(stderr, "Poll errored. nbworks_errno = %i\n", nbworks_errno);
	result = 1;
	goto endof_function;
      }
    }

    have_read = nbworks_recv(NBWORKS_SES_SRVC, session, buff_pptr,
                             0x1ffff, 0);
    if (have_read <= 0) {
      if (have_read == 0) {
	fprintf(stderr, "breaking out of the loop.\n");
	break;
      } else {
	if (nbworks_errno == EAGAIN)
	  continue;
	else {
	  fprintf(stderr, "Error reading stuff. nbworks_errno = %i\n",
		  nbworks_errno);
	  result = 1;
	  goto endof_function;
	}
      }
    }

    fprintf(stdout, "--> Something received! Contents:\n");
    walker = return_buff;
    for (; have_read > 0; have_read--, walker++) {
//      fputc(*walker, stdout);
      putchar(*walker);
    }
    if ((*(walker -1)) != '\n') {
//      fputc('\n', stdout);
      putchar('\n');
    }
    fprintf(stdout, "--> End of contents.\n");
  }

  nbworks_haltsrv(NBWORKS_SES_SRVC, name);

 endof_function:
  ret_val = nbworks_delname(name);
  if (ret_val <= 0) {
    fprintf(stderr, "ret_val of nbworks_delname() is: %li\n", ret_val);
  }

  return result;
}
