#include "c_lang_extensions.h"

#include <stdlib.h>
#include <time.h>
#include <pthread.h>

#include "daemon_control.h"
#include "constdef.h"
#include "name_srvc_cache.h"
#include "service_sector.h"
#include "service_sector_threads.h"


struct thread_cache {
  pthread_t thread_joiner_tid;
  pthread_t prune_scopes_tid;
  pthread_t ss__port137_tid;
};


struct thread_cache *daemon_internal_initializer(struct thread_cache *tcache) {
  struct thread_cache *result;

  if (tcache)
    result = tcache;
  else {
    result = malloc(sizeof(struct thread_cache));
    if (! result)
      return 0;
  }

  init_service_sector_threads();
  init_service_sector();
  init_name_srvc_cache();

  if (pthread_create(&(result->thread_joiner_tid), 0,
		     thread_joiner, 0)) {
    free(result);
    return 0;
  }

  if (pthread_create(&(result->prune_scopes_tid), 0,
		     prune_scopes, 0)) {
    pthread_cancel(result->thread_joiner_tid);
    free(result);
    return 0;
  }

  if (pthread_create(&(result->ss__port137_tid), 0,
		     ss__port137, 0)) {
    pthread_cancel(result->thread_joiner_tid);
    pthread_cancel(result->prune_scopes_tid);
    free(result);
    return 0;
  }

  return result;
}


