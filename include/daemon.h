/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3 of the License.
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
  pthread_t refresh_scopes_tid;
#ifdef COMPILING_NBNS
  pthread_t nbns_newtid_tid;
#endif
};


struct thread_cache *
  daemon_allstart(struct thread_cache *tcache);
void *
  daemon_allstop(struct thread_cache *tcache);
void
  daemon_sighandler(int signal);
void
  daemon_init_resetables(void);
void
  daemon_init_nonresetables(void);

void *
  pruners(void *arg_ignored);

#endif /* NBWORKS_DAEMON_H */
