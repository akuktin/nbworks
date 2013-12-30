#include <stdio.h>
#include <nbworks.h>

#define FALSE 0
#define TRUE  1

int main() {
  nbworks_namestate_p name;
  nbworks_session_p session;
  struct nbworks_nbnamelst *name_lst;
  size_t ret_val;
  unsigned char name_label[] = "TEST3";
  unsigned char target_label[] = "TARGETUNQ";

  nbworks_libinit();
  //  sleep(10);

  name = nbworks_regname(name_label, 0, 0, FALSE, NBWORKS_NODE_B, 60, FALSE);
  if (! name) {
    fprintf(stderr, "Could not register name.\n"
                    "nbworks_errno = %li\n",
            nbworks_errno);
    return 1;
  }

  fprintf(stdout, "Name registered...\n");

  nbworks_libcntl.dtg_max_wholefrag_len =
                  (14 + (2*(1+NBWORKS_CODED_NBNAME_LEN+1)) +3);
  fprintf(stdout, "Maximum datagram length is:\n"
	          " with fragmentation: %li\n"
	          " without fragmentation: %li\n",
	  nbworks_maxdtglen(name, TRUE),
	  nbworks_maxdtglen(name, FALSE));

  session = nbworks_castdtgsession(name, 0);
  if (! session) {
    fprintf(stderr, "Could not cast datagram session.\nnbworks_errno = %li\n"
	    "Deleting name...\n", nbworks_errno);
    nbworks_delname(name);
    return 1;
  }

  name_lst = nbworks_create_nbnodename(target_label, 0);
  if (! name_lst) {
    fprintf(stderr, "Could not create target label.\nnbworks_errno = %li\n"
	    "Deleting name...\n", nbworks_errno);
    nbworks_delname(name);
    nbworks_destroy_ses(session);
    return 1;
  }

  if (! nbworks_dtgconnect(session, name_lst)) {
    fprintf(stderr, "Could not set the peer of session.\nnbworks_errno = %li\n"
	    "Deleting name...\n", nbworks_errno);
    nbworks_delname(name);
    nbworks_destroy_ses(session);
    return 1;
  }

  nbworks_dstr_nbnodename(name_lst);

  fprintf(stderr, "About to try sending a datagram.\n");
  ret_val = nbworks_send(NBWORKS_DTG_SRVC, session,
                         "Hello World!", 12, 0);
  if (ret_val != 12) {
    fprintf(stderr, "Warning! Something is wrong with ret_val. It is: %li\n"
	    "nbworks_errno = %li\n", ret_val, nbworks_errno);
  } else {
    fprintf(stderr, "Datagram sent successfully.\n");
  }

  nbworks_hangup_ses(session);

  ret_val = nbworks_delname(name);
  if (ret_val <= 0) {
    fprintf(stderr, "ret_val of nbworks_delname() is: %li\n", ret_val);
  }

  return 0;
}
