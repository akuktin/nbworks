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

#ifdef SYSTEM_IS_LINUX
# include <sys/ioctl.h>
# include <net/if.h>
#endif

#ifdef COMPILING_NBNS
# ifndef COMPILING_DAEMON
#  define COMPILING_DAEMON 1
# endif
#endif

#ifdef COMPILING_DAEMON
# include "constdef.h"
# include "daemon_control.h"
#else
# include "nbworks.h"
# include "constdef.h"
#endif
#include "pckt_routines.h"


#define NUMOF_REQUESTS 32

#ifdef COMPILING_DAEMON
# ifdef SYSTEM_IS_LINUX
ipv4_addr_t init_default_nbns(void) {
  /* FORRELEASE: This has to be changed, somehow. */
  /* No srsly, how do I do this? If the config file is empty? */
  /* Maybe: do whatever get_inaddr() will do to get the network prefix,
   *        then call host 1 in that network prefix. */
  nbworks__default_nbns = 0xc0a8012a;

  return nbworks__default_nbns;
}
# endif

# ifdef SYSTEM_IS_LINUX
ipv4_addr_t init_brdcts_addr(void) {
  // FORRELEASE: stub
  //        192.168.1.255/24

  brdcst_addr = 0xc0a801ff;

  return brdcst_addr;
}
# endif
#endif /* COMPILING_DAEMON */

#ifdef SYSTEM_IS_LINUX
ipv4_addr_t init_my_ip4_address(void) {
  struct ifreq request[NUMOF_REQUESTS];
  struct ifconf for_ioctl;
  struct sockaddr_in *addr_p;
  int count, sckt;

  for_ioctl.ifc_len = (sizeof(struct ifreq) * NUMOF_REQUESTS);
  for_ioctl.ifc_req = request;

  memset(&request, 0, (sizeof(struct ifreq) * NUMOF_REQUESTS));

  sckt = socket(PF_INET, SOCK_DGRAM, 0);
  if (sckt == -1) {
    nbworks__myip4addr = 0;
    nbworks_errno = ADD_MEANINGFULL_ERRNO;
    return 0;
  }

  if (0 > ioctl(sckt, SIOCGIFCONF, &for_ioctl)) {
    close(sckt);

    nbworks__myip4addr = 0;
    nbworks_errno = ADD_MEANINGFULL_ERRNO;
    return 0;
  }

  close(sckt);

  for (count = 0; count < (for_ioctl.ifc_len / sizeof(struct ifreq));
       count ++) {
    /* Weed out the loopback interface. */
    if (0 != strcmp(request[count].ifr_name, "lo\0")) {
      break;
    }
  }

  if (count < NUMOF_REQUESTS) {
    addr_p = (struct sockaddr_in *)&(request[count].ifr_addr);
    read_32field((unsigned char *)&(addr_p->sin_addr.s_addr),
		 &nbworks__myip4addr);
  } else {
    nbworks__myip4addr = 0;
  }
    
  return nbworks__myip4addr;
}
#endif

#ifdef SYSTEM_IS_LINUX
/* return: 0 = success; !0 = !success */
int set_sockoption(int socket,
		   unsigned int what) {
  // FORRELEASE: nonexistant
  return 0;
}
#endif
