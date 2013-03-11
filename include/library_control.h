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

#ifndef NBWORKS_LIBRARYCONTROL_H
# define NBWORKS_LIBRARYCONTROL_H 1

# include <time.h>

extern struct nbworks_libcntl_t {
  unsigned char stop_alldtg_srv;
  unsigned char stop_allses_srv;

  int dtg_srv_polltimeout;
  int ses_srv_polltimeout;

  int max_ses_retarget_retries;
  time_t keepalive_interval;

  time_t dtg_frag_keeptime;
} nbworks_libcntl;

#endif /* NBWORKS_LIBRARYCONTROL_H */
