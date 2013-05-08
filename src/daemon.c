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
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>

#include "constdef.h"
#include "daemon_control.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_func.h"
#include "service_sector.h"
#include "service_sector_threads.h"
#include "daemon.h"
#include "rail-comm.h"
#include "portability.h"
#include "config.h"


struct thread_cache *daemon_allstart(struct thread_cache *tcache) {
  struct thread_cache *result;
  struct rail_params railparams;

  if (tcache)
    result = tcache;
  else {
    result = malloc(sizeof(struct thread_cache));
    if (! result)
      return 0;
  }

  daemon_init_nonresetables();
  daemon_init_resetables();

  do_configure();

  railparams.isbusy = 0xda;
  railparams.rail_sckt = open_rail();
  if (railparams.rail_sckt < 0) {
    if (! tcache)
      free(result);
    return 0;
  }

  if (0 != pthread_create(&(result->pruners_tid), 0,
			  pruners, 0)) {
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(result->ss__port137_tid), 0,
			  ss__port137, 0)) {
    pthread_cancel(result->pruners_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(result->ss__port138_tid), 0,
			  ss__port138, 0)) {
    pthread_cancel(result->pruners_tid);
    pthread_cancel(result->ss__port137_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(result->ss__port139_tid), 0,
			  ss__port139, 0)) {
    pthread_cancel(result->pruners_tid);
    pthread_cancel(result->ss__port137_tid);
    pthread_cancel(result->ss__port138_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(result->refresh_scopes_tid), 0,
			  refresh_scopes, 0)) {
    pthread_cancel(result->pruners_tid);
    pthread_cancel(result->ss__port137_tid);
    pthread_cancel(result->ss__port138_tid);
    pthread_cancel(result->ss__port139_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(railparams.thread_id), 0,
			  poll_rail, &railparams)) {
    pthread_cancel(result->pruners_tid);
    pthread_cancel(result->ss__port137_tid);
    pthread_cancel(result->ss__port138_tid);
    pthread_cancel(result->ss__port139_tid);
    pthread_cancel(result->refresh_scopes_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

#ifdef COMPILING_NBNS
  if (0 != pthread_create(&(result->nbns_newtid_tid), 0,
			  name_srvc_NBNS_newtid, 0)) {
    pthread_cancel(result->pruners_tid);
    pthread_cancel(result->ss__port137_tid);
    pthread_cancel(result->ss__port138_tid);
    pthread_cancel(result->ss__port139_tid);
    pthread_cancel(result->refresh_scopes_tid);
    pthread_cancel(railparams.thread_id);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }
#endif

  while (railparams.isbusy) {
    /* busy-wait */
  }

  return result;
}

void *daemon_allstop(struct thread_cache *tcache) {
  void *all_threads_cache;

  if (! tcache)
    return 0;
  else
    all_threads_cache = 0; /* Stupid GCC warnings. */

  nbworks_ses_srv_cntrl.all_stop = TRUE;
  nbworks__rail_control.all_stop = TRUE;
  nbworks_all_port_cntl.all_stop = TRUE;
  nbworks_dtg_srv_cntrl.all_stop = TRUE;

  pthread_join(tcache->ss__port137_tid, 0);
  pthread_join(tcache->ss__port138_tid, 0);
  pthread_join(tcache->ss__port139_tid, 0);
  pthread_join(tcache->refresh_scopes_tid, 0);
#ifdef COMPILING_NBNS
  pthread_join(tcache->nbns_newtid_tid, 0);
#endif

  nbworks_pruners_cntrl.all_stop = TRUE;

  pthread_join(tcache->pruners_tid, all_threads_cache);

  return all_threads_cache;
}

void daemon_sighandler(int signal) {
  switch (signal) {
  case SIGTERM:
    scram = TRUE;
    break;

  case SIGUSR1: /* Not used. */
    do_configure();
    break;

  case SIGUSR2:
    daemon_init_resetables();
    break;

  default:
    break;
  }

  return;
}

void daemon_init_resetables(void) {
  init_rail();
  init_service_sector();
  init_default_nbns();
  init_brdcts_addr();
  init_my_ip4_address();

  nbworks_pruners_cntrl.all_stop = 0;
  nbworks_pruners_cntrl.timeout.tv_sec = 0;
  nbworks_pruners_cntrl.timeout.tv_nsec = T_250MS;
  nbworks_pruners_cntrl.passes_ses_srv_ses = 8; /* AKA 2 seconds */
  nbworks_pruners_cntrl.lifetimeof_queue_storage = 25; /* seconds */
  nbworks_pruners_cntrl.addrcheck_interval = 60;


  nbworks_namsrvc_cntrl.NBNSnewtid_sleeptime.tv_sec = 0;
  nbworks_namsrvc_cntrl.NBNSnewtid_sleeptime.tv_nsec = T_250MS;
  nbworks_namsrvc_cntrl.NBNS_retries = 3;
  nbworks_namsrvc_cntrl.bcast_sleeptime.tv_sec = BCAST_REQ_RETRY_TIMEOUT_s;
  nbworks_namsrvc_cntrl.bcast_sleeptime.tv_nsec = BCAST_REQ_RETRY_TIMEOUT_ns;
  nbworks_namsrvc_cntrl.bcast_req_retry_count = BCAST_REQ_RETRY_COUNT;
  nbworks_namsrvc_cntrl.ucast_sleeptime.tv_sec = UCAST_REQ_RETRY_TIMEOUT_s;
  nbworks_namsrvc_cntrl.ucast_sleeptime.tv_nsec = UCAST_REQ_RETRY_TIMEOUT_ns;
  nbworks_namsrvc_cntrl.ucast_req_retry_count = UCAST_REQ_RETRY_COUNT;

  nbworks_namsrvc_cntrl.max_wack_sleeptime = 120;
  nbworks_namsrvc_cntrl.NBNS_threshold_ttl = 5; /* Ignore ultra-short leases. */
  nbworks_namsrvc_cntrl.refresh_threshold = 4;

  nbworks_namsrvc_cntrl.name_srvc_max_udppckt_len = MAX_DATAGRAM_LENGTH;
  nbworks_namsrvc_cntrl.conflict_timer = CONFLICT_TTL;
}

void daemon_init_nonresetables(void) {
  init_service_sector_threads();
  init_service_sector_runonce();
  init_name_srvc_cache();
}


void *pruners(void *arg_ignored) {
  time_t now, next_check, check_interval;

  next_check = time(0);
  check_interval = nbworks_pruners_cntrl.addrcheck_interval;
  next_check = next_check + check_interval;
  if (next_check < check_interval)
    next_check = INFINITY;

  do {
    now = time(0);

    prune_scopes(now);
#ifndef COMPILING_NBNS
    ss_prune_queuestorage(now -
	     nbworks_pruners_cntrl.lifetimeof_queue_storage);
#endif
    ss__prune_sessions();
    ss_check_all_ses_server_rails();
    thread_joiner();

    if (now == next_check) {
      init_default_nbns();
      init_brdcts_addr();
      init_my_ip4_address();

      check_interval = nbworks_pruners_cntrl.addrcheck_interval;
      next_check = next_check + check_interval;
      if (next_check < check_interval)
	next_check = INFINITY;
    }

    nanosleep(&(nbworks_pruners_cntrl.timeout), 0);
  } while (! nbworks_pruners_cntrl.all_stop);

  return get_allthreads();
}
