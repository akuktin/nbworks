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

#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "constdef.h"

struct {
  uint64_t period;
  unsigned int weakstate;
} nbworks_random_state;

uint32_t make_weakrandom(void) {
  if (! nbworks_random_state.weakstate) {
    nbworks_random_state.weakstate = time(0);
  }

  return rand_r(&(nbworks_random_state.weakstate));
}


uint16_t make_id(void) {
  uint16_t result;

  do {
    result = make_weakrandom() & 0xffff;
  } while (result == 0);

  return result;
}


token_t make_token(void) {
  token_t result;

  do {
    result = make_weakrandom();
    result = result << (8*(sizeof(uint64_t)/2));
    result = make_weakrandom() + result;
  } while (! result);
  return result;
}
