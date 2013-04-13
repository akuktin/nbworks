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

#ifndef NBWORKS_SERVICESECTORTHREADS_H
# define NBWORKS_SERVICESECTORTHREADS_H 1

# include <pthread.h>

struct thread_node {
  pthread_t tid;
  int dead;
  struct thread_node *next;
};

void init_service_sector_threads(void);

void *get_allthreads(void);
struct thread_node *add_thread(pthread_t tid);
void thread_joiner(void);

#endif /* NBWORKS_SERVICESECTORTHREADS_H */
