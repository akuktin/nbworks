#ifndef NBWORKS_SERVICESECTORTHREADS_H
# define NBWORKS_SERVICESECTORTHREADS_H 1

# include <pthread.h>

struct thread_node {
  pthread_t tid;
  int dead;
  struct thread_node *next;
};

void init_service_sector_threads();

struct thread_node *add_thread(pthread_t tid);
void thread_joiner();

#endif /* NBWORKS_SERVICESECTORTHREADS_H */
