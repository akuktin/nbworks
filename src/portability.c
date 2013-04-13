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

#include <stdint.h>

#include "constdef.h"

#ifdef COMPILING_NBNS
# ifndef COMPILING_DAEMON
#  define COMPILING_DAEMON 1
# endif
#endif

#ifdef COMPILING_DAEMON
# include "daemon_control.h"

ipv4_addr_t init_default_nbns(void) {
  /* FORRELEASE: This has to be changed, somehow. */
  /* No srsly, how do I do this? If the config file is empty? */
  /* Maybe: do whatever get_inaddr() will do to get the network prefix,
   *        then call host 1 in that network prefix. */
  nbworks__default_nbns = 0xc0a8012a;

  return nbworks__default_nbns;
}

ipv4_addr_t init_brdcts_addr(void) {
  // FORRELEASE: stub
  //        192.168.1.255/24

  brdcst_addr = 0xc0a801ff;

  return brdcst_addr;
}

#else
# include "library_control.h"
#endif

ipv4_addr_t my_ipv4_address(void) {
  // FORRELEASE: stub
  //        192.168.1.8/24
  return 0xc0a80108;
}
