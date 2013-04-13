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

# include <stdint.h>

# define NONBLOCKING 1
//fcntl(socket, F_SETFL, O_NONBLOCK)
# define KEEPALIVE 2
//setsockopt(ses_sckt, SOL_SOCKET, SO_KEEPALIVE, &ones, sizeof(unsigned int));
# define KEEPIDLE 4
//setsockopt(ses_sckt, IPPROTO_TCP, TCP_KEEPIDLE, &ones, sizeof(unsigned int));


uint32_t
  init_default_nbns(void);
uint32_t
  get_inaddr(void);
uint32_t
  my_ipv4_address(void);
int
  set_sockoption(int socket,
                 unsigned int what);

#endif /* NBWORKS_PORTABILITY_H */
