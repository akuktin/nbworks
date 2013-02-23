#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <time.h>

struct {
  uint64_t period;
  unsigned int weakstate;
} nbworks_random_state;

uint32_t make_weakrandom() {
  if (! nbworks_random_state.weakstate) {
    nbworks_random_state.weakstate = time(0);
  }

  return rand_r(&(nbworks_random_state.weakstate));
}
