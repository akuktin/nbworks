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

#ifndef NBWORKS_PORTABILITY_H
# define NBWORKS_PORTABILITY_H 1

# define NONBLOCKING 0x0001
//fcntl(socket, F_SETFL, O_NONBLOCK)
# define KEEPALIVE 0x0002
//setsockopt(ses_sckt, SOL_SOCKET, SO_KEEPALIVE, &ones, sizeof(unsigned int));
# define KEEPIDLE 0x0004
//setsockopt(ses_sckt, IPPROTO_TCP, TCP_KEEPIDLE, &ones, sizeof(unsigned int));
# define BROADCAST 0x0008
//setsockopt(sckts.udp_sckt, SOL_SOCKET, SO_BROADCAST, &ones, sizeof(unsigned int))

# ifdef COMPILING_NBNS
#  ifndef COMPILING_DAEMON
#   define COMPILING_DAEMON 1
#  endif
# endif

# ifdef COMPILING_DAEMON
ipv4_addr_t
  init_default_nbns(void);
ipv4_addr_t
  init_brdcts_addr(void);
# endif
ipv4_addr_t
  init_my_ip4_address(void);
int
  set_sockoption(int socket,
                 unsigned int what);

#endif /* NBWORKS_PORTABILITY_H */
