#ifndef NBWORKS_LIBRARYCONTROL_H
# define NBWORKS_LIBRARYCONTROL_H 1

# include <time.h>

struct {
  unsigned char stop_alldtg_srv;
  unsigned char stop_allses_srv;

  int dtg_srv_polltimeout;
  int ses_srv_polltimeout;

  int max_ses_retarget_retries;
  time_t keepalive_interval;

  time_t dtg_frag_keeptime;
} nbworks_libcntl;

#endif /* NBWORKS_LIBRARYCONTROL_H */
