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

#ifndef NBWORKS_DAEMON_H
# define NBWORKS_DAEMON_H 1

struct thread_cache {
  pthread_t pruners_tid;
  pthread_t ss__port137_tid;
  pthread_t ss__port138_tid;
  pthread_t ss__port139_tid;
};


struct thread_cache *
  daemon_internal_initializer(struct thread_cache *tcache);

void *
  pruners(void *arg_ignored);

#endif /* NBWORKS_DAEMON_H */
