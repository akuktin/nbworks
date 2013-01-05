#include "c_lang_extensions.h"

#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "service_sector_threads.h"


struct thread_node *nbworks_all_threads;

struct {
  int all_stop;
} nbworks_threadcontrol;


void init_service_sector_threads() {
  nbworks_threadcontrol.all_stop = 0;
  nbworks_all_threads = 0;
}


struct thread_node *add_thread(pthread_t tid) {
  struct thread_node *node, *threads, **last;

  node = malloc(sizeof(struct thread_node));
  if (! node)
    return 0;

  node->tid = tid;
  node->dead = 0;
  node->next = 0;

  while (0xcafe) {
    threads = nbworks_all_threads;
    last = &(nbworks_all_threads);

    while (threads) {
      if (threads->tid == tid) {
	if (threads != node)
	  free(node);
	return threads;
      } else {
	last = &(threads->next);
	threads = threads->next;
      }
    }

    *last = node;
  }
}

void *thread_joiner(void *placeholder) { /* AKA "the body collector" */
  struct timespec sleeptime;
  struct thread_node *node, *for_del, **last;

  sleeptime.tv_sec = 1;
  sleeptime.tv_nsec = 0;

  while (0xfeed) {
    if (nbworks_threadcontrol.all_stop)
      break;

    node = nbworks_all_threads;
    last = &(nbworks_all_threads);

    while (node) {
      if (node->dead != 0) { /* Test for all stages of decomposition. */
	if (0 == pthread_join(node->tid, 0)) {
	  *last = node->next;
	  for_del = node;
	  node = node->next;
	  free(for_del);
	  continue;
	}
      }

      last = &(node->next);
      node = node->next;
    }

    nanosleep(&sleeptime, 0);
  }

  return nbworks_all_threads;
}