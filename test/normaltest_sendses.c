#include <stdint.h>
#include <stdio.h>
#include <nbworks.h>

#define FALSE 0
#define TRUE  1

int main() {
  nbworks_namestate_p name;
  nbworks_session_p session;
  struct nbworks_nbnamelst name_lst;
  size_t ret_val;
  unsigned char name_label[] = "TEST7";
  unsigned char target_label[] = "TARGETSES";
  unsigned char cast_label[NBWORKS_NBNAME_LEN];

  nbworks_libinit();
  //  sleep(10);

  name = nbworks_regname(name_label, 0, 0, FALSE, NBWORKS_NODE_B, 60, 0);
  if (! name) {
    fprintf(stderr, "Could not register name.\nnbworks_errno = %i\n",
            nbworks_errno);
    return 1;
  }

  fprintf(stdout, "Name registered...\n");

  if (! nbworks_create_nbnamelabel(target_label, 0, cast_label)) {
    fprintf(stderr, "Could not create target label.\nnbworks_errno = %i\n"
	    "Deleting name...\n", nbworks_errno);
    nbworks_delname(name);
    return 1;
  }

  name_lst.name = cast_label;
  name_lst.len = NBWORKS_NBNAME_LEN;
  name_lst.next_name = 0;

  session = nbworks_sescall(name, &name_lst, FALSE);
  if (! session) {
    fprintf(stderr, "Could not connect session.\nnbworks_errno = %i\n"
	    "Deleting name...\n", nbworks_errno);
    nbworks_delname(name);
    return 1;
  }

  fprintf(stderr, "About to try sending down a connection.\n");
  ret_val = nbworks_send(NBWORKS_SES_SRVC, session, "Hello World!", 12, 0);
  if (ret_val != 12) {
    fprintf(stderr, "Warning! Something is wrong with ret_val. It is: %li\n"
	    "nbworks_errno = %i\n", ret_val, nbworks_errno);
  } else {
    fprintf(stderr, "Stuff sent successfully.\n");
  }

  sleep(5);

  nbworks_hangup_ses(session);

  ret_val = nbworks_delname(name);
  if (ret_val <= 0) {
    fprintf(stderr, "ret_val of nbworks_delname() is: %li\n", ret_val);
  }

  return 0;
}
