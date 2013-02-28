#include "c_lang_extensions.h"

#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "daemon_control.h"
#include "constdef.h"
#include "name_srvc_cache.h"
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

  if (0 != pthread_create(&(railparams.thread_id), 0,
			  poll_rail, &railparams)) {
    pthread_cancel(result->pruners_tid);
    pthread_cancel(result->ss__port137_tid);
    pthread_cancel(result->ss__port138_tid);
    pthread_cancel(result->ss__port139_tid);
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
    ss_prune_queuestorage(now +
	     nbworks_pruners_cntrl.lifetimeof_queue_storage);
    ss__prune_sessions();
    ss_check_all_ses_server_rails();
    thread_joiner();

    nanosleep(&(nbworks_pruners_cntrl.timeout), 0);
  } while (! nbworks_pruners_cntrl.all_stop);

  return 0;
}
