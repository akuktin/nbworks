#ifndef NBWORKS_SERVICESECTORTHREADS_H
# define NBWORKS_SERVICESECTORTHREADS_H 1

# include <pthread.h>
# include <time.h>

struct thread_node {
  pthread_t tid;
  int dead;
  struct thread_node *next;
};

void init_service_sector_threads();

struct thread_node *add_thread(pthread_t tid);
void thread_joiner(time_t run_for_how_long);

#endif /* NBWORKS_SERVICESECTORTHREADS_H */
