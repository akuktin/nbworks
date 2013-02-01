#ifndef NBWORKS_DAEMONCONTROL_H
# define NBWORKS_DAEMONCONTROL_H 1

# include <time.h>

struct {
  unsigned char all_stop;
  struct timespec sleeptime;
  int poll_timeout; /* miliseconds */
} nbworks_all_port_cntl;

struct {
  unsigned char all_stop;
  struct timespec sleeptime;
} nbworks_threadcontrol;

struct {
  unsigned char all_stop;
  struct timespec sleeptime;
} nbworks_cache_control;

struct {
  unsigned char all_stop;
  int poll_timeout;
} nbworks__rail_control;

struct {
  unsigned char all_stop;
  struct timespec dtg_srv_sleeptime;
} nbworks_dtg_srv_cntrl;

struct {
  unsigned char all_stop;
} nbworks_ses_srv_cntrl;

#endif /* NBWORKS_DAEMONCONTROL_H */
