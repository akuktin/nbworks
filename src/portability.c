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

#include <stdint.h>
#include <unistd.h>

#ifdef SYSTEM_IS_LINUX
# include <sys/ioctl.h>
# include <net/if.h>
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
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
#include "portability.h"


#define NUMOF_REQUESTS 32

/* One block starting with #ifdef SYSTEM_IS_<whatever> and ending with
 * #endif for each system this has been ported to. */
/* Mind the (COMPILING_DAEMON macro)-controlled conditional compilation. */
/* API:
 *    #ifdef COMPILING_DAEMON
 *      char *config_files[];
 *      ipv4_addr_t init_default_nbns(void);
 *      ipv4_addr_t init_brdcts_addr(void);
 *    #endif
 *      ipv4_addr_t init_my_ip4_address(void);
 *      int set_sockoption(int socket, unsigned int what);
 *      int open_configfile(char *path)
 *
 * The above functions MUST be implemented. They are called by the code.
 * Other functions may also be implemented, but they MUST remain in the
 * scope of this file and MUST not be used elsewhere in nbworks' code or,
 * God forbid, be exported to the application as part of the API.
 */

#ifdef SYSTEM_IS_LINUX
# ifdef COMPILING_DAEMON
char *config_files[] = {ENVIRONMENT_CONFIG_FILE_PLACEHOLDER,
                        "~/.nbworks.conf", "/etc/nbworks.conf", 0};
# endif

/* return: >0 = success; 0 = fail; <0 = error */
/* FUNCTION NOT IN ANY HEADER! */
struct ifreq *find_address_and_interface(struct ifreq *fieldof_all,
					 unsigned int numof_all) {
  struct ifconf for_ioctl;
  struct ifreq *this_one;
  int sckt;
  unsigned int count;

  if (! (fieldof_all && numof_all)) {
    return 0;
  }

  for_ioctl.ifc_len = (sizeof(struct ifreq) * numof_all);
  for_ioctl.ifc_req = fieldof_all;

  memset(fieldof_all, 0, (sizeof(struct ifreq) * numof_all));

  sckt = socket(PF_INET, SOCK_DGRAM, 0);
  if (sckt == -1) {
    return 0;
  }

  if (0 > ioctl(sckt, SIOCGIFCONF, &for_ioctl)) {
    close(sckt);
    return 0;
  }

  close(sckt);

  for (this_one = fieldof_all, count = 0;
       count < numof_all;
       count++, this_one++) {
    /* Weed out the loopback interface. */
    if (0 != strcmp(this_one->ifr_name, "lo\0")) {
      return this_one;
    }
  }

  return 0;
}


# ifdef COMPILING_DAEMON
/* return: >0 = success; 0 = fail; <0 = error */
/* FUNCTION NOT IN ANY HEADER! */
int find_netmask(ipv4_addr_t *netmask,
		 ipv4_addr_t *address) {
  struct ifreq request[NUMOF_REQUESTS], *ptr;
  struct sockaddr_in *addr_p;
  int sckt;

  if (! netmask) {
    return -1;
  }

  ptr = find_address_and_interface(request, NUMOF_REQUESTS);

  if (! ptr) {
    return 0;
  }

  if (address) {
    addr_p = (struct sockaddr_in *)&(ptr->ifr_addr);
    read_32field((unsigned char *)&(addr_p->sin_addr.s_addr),
		 address);
  }

  sckt = socket(PF_INET, SOCK_DGRAM, 0);
  if (sckt < 0) {
    return -1;
  }

  if (0 > ioctl(sckt, SIOCGIFNETMASK, ptr)) {
    close(sckt);
    return -1;
  }

  close(sckt);

  addr_p = (struct sockaddr_in *)&(ptr->ifr_netmask);
  read_32field((unsigned char *)&(addr_p->sin_addr.s_addr),
	       netmask);

  return 1;
}

ipv4_addr_t init_default_nbns(void) {
  /* No srsly, how do I do this? If the config file is empty? */
  /* Maybe: do whatever get_inaddr() will do to get the network prefix,
   *        then call host 1 in that network prefix. */
  ipv4_addr_t netmask, address;

  if (0 >= find_netmask(&netmask, &address)) {
    nbworks__default_nbns = 0;
  }

  if (netmask == ONES) {
    nbworks__default_nbns = address;
  } else {
    nbworks__default_nbns = (address & netmask) +1;
  }

  return nbworks__default_nbns;
}

ipv4_addr_t init_brdcts_addr(void) {
  ipv4_addr_t netmask, address;

  if (0 >= find_netmask(&netmask, &address)) {
    brdcst_addr = ONES;
  }

  brdcst_addr = address | (~netmask);

  return brdcst_addr;
}
# endif /* COMPILING_DAEMON */

ipv4_addr_t init_my_ip4_address(void) {
  struct ifreq request[NUMOF_REQUESTS], *ptr;
  struct sockaddr_in *addr_p;

  ptr = find_address_and_interface(request, NUMOF_REQUESTS);

  if (ptr) {
    addr_p = (struct sockaddr_in *)&(ptr->ifr_addr);
    read_32field((unsigned char *)&(addr_p->sin_addr.s_addr),
		 &nbworks__myip4addr);
  } else {
    nbworks_errno = ADD_MEANINGFULL_ERRNO;
    nbworks__myip4addr = 0;
  }

  return nbworks__myip4addr;
}

/* return: 0 = success; !0 = !success */
int set_sockoption(int sckt,
		   unsigned int what) {
  unsigned int ones = SSN_KEEP_ALIVE_TIMEOUT;

  switch (what) {
  case NONBLOCKING:
    return fcntl(sckt, F_SETFL, O_NONBLOCK);

  case KEEPALIVE:
    if (0 != setsockopt(sckt, SOL_SOCKET, SO_KEEPALIVE,
			&ones, sizeof(unsigned int)))
      return -1;
    if (0 != setsockopt(sckt, IPPROTO_TCP, TCP_KEEPIDLE,
			&ones, sizeof(unsigned int)))
      return -1;
    return setsockopt(sckt, IPPROTO_TCP, TCP_KEEPINTVL,
		      &ones, sizeof(unsigned int));

  case BROADCAST:
    return setsockopt(sckt, SOL_SOCKET, SO_BROADCAST,
		      &ones, sizeof(unsigned int));

  default:
    return -1;
  }
}

int open_configfile(char *path) {
  return open(path, O_RDONLY);
}
#endif /* SYSTEM_IS_LINUX */
