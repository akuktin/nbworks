#ifndef NBWORKS_DAEMON_H
# define NBWORKS_DAEMON_H 1

struct thread_cache {
  pthread_t thread_joiner_tid;
  pthread_t prune_scopes_tid;
  pthread_t ss__port137_tid;
  pthread_t ss__port138_tid;
  pthread_t ss__port139_tid;
};


struct thread_cache *
  daemon_internal_initializer(struct thread_cache *tcache);

#endif /* NBWORKS_DAEMON_H */
