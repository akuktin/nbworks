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

#include "c_lang_extensions.h"

#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#include "constdef.h"
#include "daemon.h"

unsigned int scram;

int main() {
  struct timespec sleeptime;
  struct sigaction signal_action;
  struct thread_cache tcache;

#ifndef VISIBLE_BREAKERS
  if (0 != daemon(0, 0)) {
    return 1;
  }
#endif

  memset(&signal_action, 0, sizeof(struct sigaction));
  memset(&tcache, 0, sizeof(struct thread_cache));

  signal_action.sa_handler = &daemon_sighandler;
  scram = 0;

  if (0 != sigaction(SIGTERM, &signal_action, 0)) {
    return 2;
  }
  if (0 != sigaction(SIGUSR2, &signal_action, 0)) {
    return 3;
  }

  signal_action.sa_handler = SIG_IGN;
  if (0 != sigaction(SIGPIPE, &signal_action, 0)) {
    return 4;
  }

  if (! daemon_allstart(&tcache)) {
    return 5;
  }

  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_500MS;
  while (! scram)
    nanosleep(&sleeptime, 0);

  daemon_allstop(&tcache);

  return 0;
}
