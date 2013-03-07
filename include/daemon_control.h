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

#ifndef NBWORKS_DAEMONCONTROL_H
# define NBWORKS_DAEMONCONTROL_H 1

# include <time.h>
# include <stdint.h>

struct {
  unsigned char all_stop;
  struct timespec sleeptime;
  int poll_timeout; /* miliseconds */
} nbworks_all_port_cntl;

struct {
  unsigned char all_stop;
  int poll_timeout;
} nbworks__rail_control;

struct {
  int retries_NBNS;
  uint32_t max_wack_sleeptime;
  time_t Ptimer_refresh_margin;
} nbworks_namsrvc_cntrl;

struct {
  unsigned char all_stop;
  struct timespec dtg_srv_sleeptime;
} nbworks_dtg_srv_cntrl;

struct {
  unsigned char all_stop;
} nbworks_ses_srv_cntrl;

struct {
  unsigned char all_stop;
  struct timespec timeout;
  unsigned int passes_ses_srv_ses;
  time_t lifetimeof_queue_storage;
} nbworks_pruners_cntrl;

#endif /* NBWORKS_DAEMONCONTROL_H */
