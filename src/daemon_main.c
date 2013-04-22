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

  //  if (0 != daemon(0, 0)) {
  //    return 1;
  //  }

  memset(&signal_action, 0, sizeof(struct sigaction));

  signal_action.sa_handler = SIG_IGN;
  scram = 0;

  if (0 != sigaction(SIGTERM, &signal_action, 0)) {
    return 2;
  }

  if (! daemon_allstart(&tcache)) {
    return 3;
  }

  signal_action.sa_handler = &daemon_sighandler;

  if (0 != sigaction(SIGTERM, &signal_action, 0)) {
    daemon_allstop(&tcache);
    return 4;
  }

  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_500MS;
  while (! scram)
    nanosleep(&sleeptime, 0);

  daemon_allstop(&tcache);

  return 0;
}
