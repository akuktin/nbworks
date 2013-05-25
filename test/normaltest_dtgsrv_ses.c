#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <nbworks.h>
#include <stdlib.h>
#include <errno.h>

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
  nbworks_session_p session;
  nbworks_namestate_p name;
  struct nbworks_pollfd nbw_pfd;
  struct nbworks_nbnamelst *name_lst, *target1, *target2;
  size_t ret_val;
  ssize_t have_read;
  int pollret, result;
  unsigned char name_label[] = "TARGETUNQ";
  unsigned char target1_label[] = "TEST3";
  unsigned char target2_label[] = "TEST5";
  unsigned char return_buff[0x1ffff], *walker, *buff_ptr, **buff_pptr;

  result = 0;
  buff_ptr = return_buff;
  buff_pptr = &buff_ptr;
  memset(&new_signal, 0, sizeof(struct sigaction));
  memset(return_buff, 0, 0x1ffff);

  new_signal.sa_handler = &do_scram;

  if (sigaction(SIGTERM, &new_signal, 0)) {
    fprintf(stderr, "Could not install signal handler. Aborting.\n");
    return 1;
  }

  nbworks_libinit();
  //  sleep(10);
  nbworks_libcntl.close_timeout = 3600;

  target1 = nbworks_create_nbnodename(target1_label, 0);
  if (! target1) {
    fprintf(stderr, "Could not create target1!\n");
    return 1;
  }
  target2 = nbworks_create_nbnodename(target2_label, 0);
  if (! target2) {
    fprintf(stderr, "Could not create target2!\n");
    nbworks_dstr_nbnodename(target1);
    return 1;
  }

  name = nbworks_regname(name_label, 0, 0, FALSE, NBWORKS_NODE_B, 60, TRUE);
  if (! name) {
    fprintf(stderr, "Could not register name.\nnbworks_errno = %u\n",
            nbworks_errno);
    nbworks_dstr_nbnodename(target1);
    nbworks_dstr_nbnodename(target2);
    return 1;
  }

  fprintf(stderr, "Name registered...\n");

  if (0 >= nbworks_listen_dtg(name, NBWORKS_TAKES_UNQCST, 0)) {
    fprintf(stderr, "Could not set up dtg server.\nnbworks_errno = %u\n",
            nbworks_errno);
    result = 1;
    goto endof_function;
  }

  session = nbworks_castdtgsession(name, 0);
  if (! session) {
    fprintf(stderr, "Could not cast for datagram session\nnbworks_errno = %u\n",
            nbworks_errno);
    result = 1;
    goto endof_function;
  }

  nbw_pfd.session = session;
  nbw_pfd.events = ONES;
  while (! scram) {
    have_read = nbworks_recvwait(session, buff_pptr, 0x1ffff, 0,
                                 10, &target2);
    if (have_read <= 0) {
      if ((have_read == -1) &&
          (nbworks_errno == EAGAIN)) {
        continue;
      }
      fprintf(stderr, "Error reading stuff. nbworks_errno = %u\n",
              nbworks_errno);
      result = 1;
      goto endof_function;
    }

    fprintf(stdout, "--> Packet received! Contents:\n");
    walker = return_buff;
    for (; have_read > 0; have_read--, walker++) {
//      fputc(*walker, stdout);
      putchar(*walker);
    }
    if ((*(walker -1)) != '\n') {
//      fputc('\n', stdout);
      putchar('\n');
    }
    fprintf(stdout, "--> End of packet.\n");
  }

  nbworks_haltsrv(NBWORKS_DTG_SRVC, name);

  have_read = nbworks_recvfrom(NBWORKS_DTG_SRVC, session, buff_pptr, 0x1ffff,
                               0, &target1);
  if (have_read > 0) {
    fprintf(stdout, "--> Packet received! Contents:\n");
    walker = return_buff;
    for (; have_read > 0; have_read--, walker++) {
//      fputc(*walker, stdout);
      putchar(*walker);
    }
    if ((*(walker -1)) != '\n') {
//      fputc('\n', stdout);
      putchar('\n');
    }
    fprintf(stdout, "--> End of packet.\n");
  }


 endof_function:
  ret_val = nbworks_delname(name);
  if (ret_val <= 0) {
    fprintf(stderr, "ret_val of nbworks_delname() is: %li\n", ret_val);
  }

  nbworks_dstr_nbnodename(target1);
  nbworks_dstr_nbnodename(target2);

  return result;
}
