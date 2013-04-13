/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "c_lang_extensions.h"

#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "constdef.h"
#include "daemon_control.h"
#include "service_sector_threads.h"


struct thread_node *nbworks_all_threads;


void init_service_sector_threads(void) {
  nbworks_all_threads = 0;
}


void *get_allthreads(void) {
  return nbworks_all_threads;
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

void thread_joiner(void) { /* AKA "the body collector" */
  struct thread_node *node, *for_del, **last;

  node = nbworks_all_threads;
  last = &(nbworks_all_threads);

  while (node) {
    if (node->dead != 0) { /* Test for all stages of decomposition. */
      if (node->dead < 0) {
	if (0 == pthread_join(node->tid, 0)) {
	  *last = node->next;
	  for_del = node;
	  node = node->next;
	  free(for_del);
	  continue;
	}
      } else
	node->dead = -1;
    }

    last = &(node->next);
    node = node->next;
  }

  return;
}
