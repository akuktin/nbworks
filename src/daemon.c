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
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "daemon_control.h"
#include "constdef.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_func.h"
#include "service_sector.h"
#include "service_sector_threads.h"
#include "daemon.h"
#include "rail-comm.h"


struct thread_cache *daemon_internal_initializer(struct thread_cache *tcache) {
  struct thread_cache *result;
  struct rail_params railparams;

  if (tcache)
    result = tcache;
  else {
    result = malloc(sizeof(struct thread_cache));
    if (! result)
      return 0;
  }

  init_service_sector_threads();
  init_rail();
  init_service_sector();
  init_name_srvc_cache();

  nbworks_pruners_cntrl.all_stop = 0;
  nbworks_pruners_cntrl.timeout.tv_sec = 0;
  nbworks_pruners_cntrl.timeout.tv_nsec = T_250MS;
  nbworks_pruners_cntrl.passes_ses_srv_ses = 8; /* AKA 2 seconds */
  nbworks_pruners_cntrl.lifetimeof_queue_storage = 25; /* seconds */

  nbworks_namsrvc_cntrl.retries_NBNS = 3;
  nbworks_namsrvc_cntrl.bcast_req_retry_count = BCAST_REQ_RETRY_COUNT;
  nbworks_namsrvc_cntrl.ucast_req_retry_count = UCAST_REQ_RETRY_COUNT;
  nbworks_namsrvc_cntrl.max_wack_sleeptime = 120;
  nbworks_namsrvc_cntrl.Ptimer_refresh_margin = 2; /* I will increase it later on. */
  nbworks_namsrvc_cntrl.NBNS_threshold_ttl = 5; /* Ignore ultra-short leases. */
  nbworks_namsrvc_cntrl.func_sleeptime.tv_sec = 0;
  nbworks_namsrvc_cntrl.func_sleeptime.tv_nsec = T_250MS;
  

  /* RELEASE: This has to be changed, somehow. */
  /* No srsly, how do I do this? If the config file is empty? */
  /* Maybe: do whatever get_inaddr() will do to get the network prefix,
   *        then call host 1 in that network prefix. */
  nbworks__default_nbns = 0xc0a8012a;

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

#ifdef DO_ALIGN_FIELDS
  nbworks_do_align = 1;
#else
  nbworks_do_align = 0;
#endif

  while (railparams.isbusy) {
    /* busy-wait */
  }

  return result;
}


void *pruners(void *arg_ignored) {
  time_t now;

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

    nanosleep(&(nbworks_pruners_cntrl.timeout), 0);
  } while (! nbworks_pruners_cntrl.all_stop);

  return 0;
}
