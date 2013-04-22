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

#include <time.h>

#include "constdef.h"
#include "daemon.h"

int main() {
  struct timespec sleeptime;
  struct thread_cache tcache;

  if (! daemon_allstart(&tcache)) {
    return 1;
  }

  /* --------------------------------------------- */
  /* FORRELEASE: change this into a signal handler */
  sleeptime.tv_sec = (60 * 30);
  sleeptime.tv_nsec = 0;

  nanosleep(&sleeptime, 0);
  /* --------------------------------------------- */

  daemon_allstop(&tcache);

  return 0;
}
