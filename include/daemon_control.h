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

#ifndef NBWORKS_DAEMONCONTROL_H
# define NBWORKS_DAEMONCONTROL_H 1

# ifndef COMPILING_DAEMON
#  define COMPILING_DAEMON 1
# endif

extern struct nbworks_all_port_cntl_t {
  unsigned char all_stop;
  struct timespec sleeptime;
  struct timespec newtid_sleeptime;
  int poll_timeout; /* miliseconds */
} nbworks_all_port_cntl;

extern struct nbworks__rail_control_t {
  unsigned char all_stop;
  int poll_timeout;
} nbworks__rail_control;

extern struct nbworks_namsrvc_cntrl_t {
  struct timespec NBNSnewtid_sleeptime;
  unsigned int NBNS_retries;
  struct timespec bcast_sleeptime;
  unsigned int bcast_req_retry_count;
  struct timespec ucast_sleeptime;
  unsigned int ucast_req_retry_count;

  uint32_t max_wack_sleeptime;
  uint32_t NBNS_threshold_ttl;
  uint32_t refresh_threshold;

  unsigned int name_srvc_max_udppckt_len;
  unsigned int conflict_timer;
} nbworks_namsrvc_cntrl;

extern struct nbworks_dtg_srv_cntrl_t {
  unsigned char all_stop;
  struct timespec dtg_srv_sleeptime;
} nbworks_dtg_srv_cntrl;

extern struct nbworks_ses_srv_cntrl_t {
  unsigned char all_stop;
  int poll_timeout;
} nbworks_ses_srv_cntrl;

extern struct nbworks_pruners_cntrl_t {
  unsigned char all_stop;
  struct timespec timeout;
  unsigned int passes_ses_srv_ses;
  time_t lifetimeof_queue_storage;
  time_t addrcheck_interval;
} nbworks_pruners_cntrl;

extern ipv4_addr_t nbworks__default_nbns;
extern ipv4_addr_t brdcst_addr;

extern unsigned int scram;

#endif /* NBWORKS_DAEMONCONTROL_H */
