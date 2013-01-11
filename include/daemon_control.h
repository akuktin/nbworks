#ifndef NBWORKS_DAEMONCONTROL_H
# define NBWORKS_DAEMONCONTROL_H 1

struct {
  int all_stop;
} nbworks_all_port_cntl;

struct {
  int all_stop;
} nbworks_threadcontrol;

struct {
  unsigned int all_stop;
} nbworks_cache_control;

#endif /* NBWORKS_DAEMONCONTROL_H */
