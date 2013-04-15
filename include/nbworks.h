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

#ifndef NBWORKS_NBWORKS_H
# define NBWORKS_NBWORKS_H 1

# include <time.h>
# include <unistd.h>

# define NBWORKS_CANCEL_SEND 1
# define NBWORKS_CANCEL_RECV 2

# define NBWORKS_NBNAME_LEN 16
# define NBWORKS_CODED_NBNAME_LEN 32

# define NBWORKS_NAME_SRVC 1
# define NBWORKS_DTG_SRVC  0
# define NBWORKS_SES_SRVC  2


extern struct nbworks_libcntl_t {
  /* Stop all datagram servers ASAP. */
  unsigned char stop_alldtg_srv;
  /* Stop all session listeners ASAP. */
  unsigned char stop_allses_srv;

  /* Latency for servers and listeners. */
  int dtg_srv_polltimeout;
  int ses_srv_polltimeout;

  /* How many times to retry establishing a session. */
  unsigned int max_ses_retarget_retries;
  /* Interval when sending NetBIOS keepalive packets. */
  time_t keepalive_interval;

  /* Timeout when receiving or sending on sessions. */
  time_t close_timeout;
  /* How long to keep dtg fragments around, waiting for the rest. */
  time_t dtg_frag_keeptime;

  /* Maximum length of the WHOLE datagram packet, as sent to the UDP layer. */
  unsigned int dtg_max_wholefrag_len;
} nbworks_libcntl;

typedef unsigned int nbworks_errno_t;
extern nbworks_errno_t nbworks_errno;

typedef unsigned int nbworks_do_align_t;
extern nbworks_do_align_t nbworks_do_align;

typedef void* nbworks_session_p;
typedef void* nbworks_namestate_p;

struct nbworks_nbnamelst {
  unsigned char *name;
  unsigned char len; /* Not int because the field is
                        6 bits wide in the packet. */
  struct nbworks_nbnamelst *next_name;
};

struct nbworks_pollfd {
  nbworks_namestate_p handle;
  nbworks_session_p session;
  short int events;
  short int revents;
};

void
  nbworks_libinit(void);

/* BEGIN auxiliary API */
unsigned char *
  nbworks_make_nbnodename(const unsigned char *string,
                          const unsigned char type_char,
                          unsigned char *field);
void
  nbworks_dstr_nbnodename(struct nbworks_nbnamelst *nbnodename);
struct nbworks_nbnamelst *
  nbworks_clone_nbnodename(struct nbworks_nbnamelst *nbnodename);
/* returns: 0 = equal, >0 = not equal, <0 = error */
int
  nbworks_cmp_nbnodename(struct nbworks_nbnamelst *name_one,
                         struct nbworks_nbnamelst *name_two);
unsigned int
  nbworks_nbnodenamelen(struct nbworks_nbnamelst *nbnodename);
/* END auxiliatry API */

/* BEGIN base API */
/* BEGIN core API */
nbworks_namestate_p
  nbworks_regname(unsigned char *name,
                  unsigned char name_type,
                  struct nbworks_nbnamelst *scope,
                  unsigned char group_flg,
                  unsigned char node_type, /* only one type */
                  unsigned long ttl);
/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_delname(nbworks_namestate_p handle);

nbworks_session_p
  nbworks_castdtgsession(nbworks_namestate_p handle);

/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_listen_dtg(nbworks_namestate_p handle,
                     unsigned char takes_field,
                     struct nbworks_nbnamelst *listento);
/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_listen_ses(nbworks_namestate_p handle,
                     unsigned char takes_field,
                     struct nbworks_nbnamelst *listento);
nbworks_session_p
  nbworks_accept_ses(nbworks_namestate_p handle);
nbworks_session_p
  nbworks_sescall(nbworks_namestate_p handle,
                  struct nbworks_nbnamelst *dst,
                  unsigned char keepalive);
nbworks_session_p
  nbworks_dtgconnect(nbworks_session_p session,
                     struct nbworks_nbnamelst *dst);

int
  nbworks_poll(unsigned char service,
               struct nbworks_pollfd *handles,
               int numof_sess,
               int timeout);

ssize_t
  nbworks_sendto(unsigned char service,
                 nbworks_session_p ses,
                 void *buff,
                 size_t len,
                 int flags,
                 struct nbworks_nbnamelst *dst);
# define nbworks_send(a, b, c, d, e) nbworks_sendto(a, b, c, d, e, 0)
ssize_t
  nbworks_recvfrom(unsigned char service,
                   nbworks_session_p ses,
                   void **buff,
                   size_t len,
                   int callflags,
                   struct nbworks_nbnamelst **src);
# define nbworks_recv(a, b, c, d, e) nbworks_recvfrom(a, b, c, d, e, 0)
void
  nbworks_cancel(nbworks_session_p ses,
                 unsigned char what);

/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_haltsrv(unsigned int service,
                  nbworks_namestate_p namehandle);
void
  nbworks_hangup_ses(nbworks_session_p ses);
# define nbworks_destroy_ses(a) nbworks_hangup_ses(a)
/* END core API */

unsigned long
  nbworks_whatisaddrX(struct nbworks_nbnamelst *X,
                      unsigned long ten);
/* END base API */


#endif /* NBWORKS_NBWORKS_H */
