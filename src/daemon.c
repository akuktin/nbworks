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

  railparams.isbusy = 0xda;
  railparams.rail_sckt = open_rail();
  if (railparams.rail_sckt < 0) {
    if (! tcache)
      free(result);
    return 0;
  }

  if (0 != pthread_create(&(result->thread_joiner_tid), 0,
			  thread_joiner, 0)) {
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(result->prune_scopes_tid), 0,
			  prune_scopes, 0)) {
    pthread_cancel(result->thread_joiner_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(result->ss__port137_tid), 0,
			  ss__port137, 0)) {
    pthread_cancel(result->thread_joiner_tid);
    pthread_cancel(result->prune_scopes_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(result->ss__port138_tid), 0,
			  ss__port138, 0)) {
    pthread_cancel(result->thread_joiner_tid);
    pthread_cancel(result->prune_scopes_tid);
    pthread_cancel(result->ss__port137_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(result->ss__port139_tid), 0,
			  ss__port139, 0)) {
    pthread_cancel(result->thread_joiner_tid);
    pthread_cancel(result->prune_scopes_tid);
    pthread_cancel(result->ss__port137_tid);
    pthread_cancel(result->ss__port138_tid);
    if (! tcache)
      free(result);
    close(railparams.rail_sckt);
    return 0;
  }

  if (0 != pthread_create(&(railparams.thread_id), 0,
			  poll_rail, &railparams)) {
    pthread_cancel(result->thread_joiner_tid);
    pthread_cancel(result->prune_scopes_tid);
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


