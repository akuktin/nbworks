#ifndef NBWORKS_LIBRARYCONTROL_H
# define NBWORKS_LIBRARYCONTROL_H 1

struct {
  unsigned char stop_alldtg_srv;
  unsigned char stop_allses_srv;
  int max_ses_retarget_retries;
} nbworks_libcntl;

#endif /* NBWORKS_LIBRARYCONTROL_H */
