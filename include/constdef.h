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

#ifndef NBWORKS_CONSTDEF_H
# define NBWORKS_CONSTDEF_H 1

/* Force inclusion of all system headers here. */
# include <stdint.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <pthread.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <sys/un.h>
# include <time.h>
# include <poll.h>


# ifdef COMPILING_NBNS
#  ifndef COMPILING_DAEMON
#   define COMPILING_DAEMON 1
#  endif
# endif

# ifdef NULL
#  undef NULL
# endif
# define NULL 0

# ifdef ONES
#  undef ONES
# endif
# define ONES (~0)

# ifdef ONESZERO
#  undef ONESZERO
# endif
# define ONESZERO (~1)

# ifdef ONEZEROS
#  undef ONEZEROS
# endif
# define ONEZEROS (1 >> 1)

# ifdef ZEROONES
#  undef ZEROONES
# endif
# define ZEROONES (~(1 >> 1))

# ifdef INFINITY
#  undef INFINITY
# endif
# define INFINITY ((time_t)(SIZE_MAX / 2))

# ifdef TRUE
#  undef TRUE
# endif
# define TRUE 1

# ifdef FALSE
#  undef FALSE
# endif
# define FALSE 0

# define T_1MS    (1000000)       /*   1 ms */
# define T_10MS   (10 * 1000000)  /*  10 ms */
# define T_12MS   (12 * 1000000)  /*  12 ms */
# define T_25MS   (25 * 1000000)  /*  25 ms */
# define T_50MS   (50 * 1000000)  /*  50 ms */
# define T_100MS  (100 * 1000000) /* 100 ms */
# define T_250MS  (250 * 1000000) /* 250 ms */
# define T_500MS  (500 * 1000000) /* 500 ms */

# define TP_1MS   (1)   /*   1 ms, for poll() */
# define TP_10MS  (10)  /*  10 ms, for poll() */
# define TP_12MS  (12)  /*  12 ms, for poll() */
# define TP_25MS  (25)  /*  25 ms, for poll() */
# define TP_50MS  (50)  /*  50 ms, for poll() */
# define TP_100MS (100) /* 100 ms, for poll() */
# define TP_250MS (250) /* 250 ms, for poll() */
# define TP_500MS (500) /* 500 ms, for poll() */

/* general */
# define BCAST_REQ_RETRY_TIMEOUT_s  0
# define BCAST_REQ_RETRY_TIMEOUT_ns T_250MS
# define BCAST_REQ_RETRY_COUNT      3

# define UCAST_REQ_RETRY_TIMEOUT_s  5
# define UCAST_REQ_RETRY_TIMEOUT_ns 0
# define UCAST_REQ_RETRY_COUNT      3

# define MAX_DATAGRAM_LENGTH     576 /* bytes, that is, octets */

/* REFRESH_TIMER is name-specific */
# define CONFLICT_TTL  1 /* as per RFC1002 */

# define INFINITE_TTL NULL

# define SSN_RETRY_COUNT        4
# define SSN_CLOSE_TIMEOUT      30
# define SSN_KEEP_ALIVE_TIMEOUT 60

# define FRAGMENT_TO 2

# define DEFAULT_REFRESH_TTL 3600 /* seconds */


# ifdef align_incr
#  undef align_incr
# endif
# ifdef align
#  undef align
# endif

# ifndef NBWORKS_NBWORKS_H
typedef unsigned int nbworks_errno_t;
extern nbworks_errno_t nbworks_errno;

typedef unsigned int nbworks_do_align_t;
extern nbworks_do_align_t nbworks_do_align;
# endif
# define ADD_MEANINGFULL_ERRNO ONES

# define align_incr(base, ptr, incr) (nbworks_do_align ? \
                                      ((incr- ((ptr-base) %incr)) %incr) : 0)
# define align(base, ptr, incr) (ptr + align_incr(base, ptr, incr))

# define NAME_SRVC 1
# define DTG_SRVC  0
# define SES_SRVC  2

# ifndef NBWORKS_NBWORKS_H
#  define MSG_BRDCAST MSG_PROXY     /* Trying hard to be portable... */
#  define MSG_GROUP   MSG_DONTROUTE /* by fitting everything into uint16_t. */
# endif /* NBWORKS_NBWORKS_H */

typedef uint64_t token_t;
typedef uint32_t ipv4_addr_t;
typedef unsigned short node_type_t;

extern ipv4_addr_t nbworks__myip4addr;


/* DEBUG */
# ifdef VISIBLE_BREAKERS
#  include <stdio.h>
#  define OUT_OF_BOUNDS(a) { fprintf(stderr, "OUT_OF_BOUNDS(%i)\n", a); };
#  define BULLSHIT_IN_PACKET(a) { fprintf(stderr, "BULLSHIT_IN_PACKET(%i)\n", a); };
#  define DIDNT_READ_NAME(a) { fprintf(stderr, "DIDNT_READ_NAME(%i)\n", a); };
# else
#  define OUT_OF_BOUNDS(a)
#  define BULLSHIT_IN_PACKET(a)
#  define DIDNT_READ_NAME(a)
# endif

# include "c-lib.h"

#endif /* NBWORKS_CONSTDEF_H */
