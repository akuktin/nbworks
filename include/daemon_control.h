#ifndef NBWORKS_DAEMONCONTROL_H
# define NBWORKS_DAEMONCONTROL_H 1

struct {
  unsigned char all_stop;
} nbworks_all_port_cntl;

struct {
  unsigned char all_stop;
} nbworks_threadcontrol;

struct {
  unsigned char all_stop;
} nbworks_cache_control;

#endif /* NBWORKS_DAEMONCONTROL_H */
