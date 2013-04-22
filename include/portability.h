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

# define NONBLOCKING   0x0001
# define KEEPALIVE     0x0002
# define BROADCAST     0x0004

# ifdef COMPILING_NBNS
#  ifndef COMPILING_DAEMON
#   define COMPILING_DAEMON 1
#  endif
# endif

# ifdef SYSTEM_IS_LINUX
#  define SYSTEMS_NEWLINE '\n'
# endif
# ifdef SYSTEM_IS_BSD
#  define SYSTEMS_NEWLINE '\n'
# endif
# ifdef SYSTEM_IS_WINDOWS
#  define SYSTEMS_NEWLINE '\n'
# endif
# ifdef SYSTEM_IS_MACOS
#  define SYSTEMS_NEWLINE '\r'
# endif

# ifdef SYSTEM_IS_WINDOWS
#  define SYSTEMS_STRINGSTOP '\r'
# else
#  define SYSTEMS_STRINGSTOP SYSTEMS_NEWLINE
# endif

# ifdef COMPILING_DAEMON
#  define ENVIRONMENT_CONFIG_FILE_PLACEHOLDER 0
#  ifdef SYSTEM_IS_LINUX
#   define ENVIRONMENT_CONFIG_FILE_INDEXOF_POSITION 2
#  endif
extern char *config_files[];

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
int open_configfile(char *path);

#endif /* NBWORKS_PORTABILITY_H */
