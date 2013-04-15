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
  unsigned char stop_alldtg_srv;
  unsigned char stop_allses_srv;

  int dtg_srv_polltimeout;
  int ses_srv_polltimeout;

  unsigned int max_ses_retarget_retries;
  time_t keepalive_interval;

  time_t close_timeout;
  time_t dtg_frag_keeptime;

  unsigned int dtg_max_wholefrag_len;
} nbworks_libcntl;

typedef unsigned int nbworks_errno_t;
extern nbworks_errno_t nbworks_errno;

typedef unsigned int nbworks_do_align_t;
extern nbworks_do_align_t nbworks_do_align;



struct nbworks_nbnamelst {
  unsigned char *name;
  unsigned char len; /* Not int because the field is
                        6 bits wide in the packet. */
  struct nbworks_nbnamelst *next_name;
};

struct nbworks_pollfd {
  struct name_state *handle;
  struct nbworks_session *session;
  short int events;
  short int revents;
};

void
  nbworks_libinit(void);

unsigned char *
  nbworks_make_nbnodename(const unsigned char *string,
                          const unsigned char type_char,
                          unsigned char *field);
void
  nbworks_dstr_nbnodename(struct nbworks_nbnamelst *nbnodename);
struct nbworks_nbnamelst *
  nbworks_clone_nbnodename(struct nbworks_nbnamelst *nbnodename);
int
  nbworks_cmp_nbnodename(struct nbworks_nbnamelst *name_one,
                         struct nbworks_nbnamelst *name_two);
unsigned int
  nbworks_nbnodenamelen(struct nbworks_nbnamelst *nbnodename);

struct name_state *
  nbworks_regname(unsigned char *name,
                  unsigned char name_type,
                  struct nbworks_nbnamelst *scope,
                  unsigned char group_flg,
                  unsigned char node_type, /* only one type */
                  unsigned long ttl);
/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_delname(struct name_state *handle);

/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_listen_dtg(struct name_state *handle,
                     unsigned char takes_field,
                     struct nbworks_nbnamelst *listento);
/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_listen_ses(struct name_state *handle,
                     unsigned char takes_field,
                     struct nbworks_nbnamelst *listento);
struct nbworks_session *
  nbworks_accept_ses(struct name_state *handle);
struct nbworks_session *
  nbworks_sescall(struct name_state *handle,
                  struct nbworks_nbnamelst *dst,
                  unsigned char keepalive);

int
  nbworks_poll(unsigned char service,
               struct nbworks_pollfd *handles,
               int numof_sess,
               int timeout);

ssize_t
  nbworks_sendto(unsigned char service,
                 struct nbworks_session *ses,
                 void *buff,
                 size_t len,
                 int flags,
                 struct nbworks_nbnamelst *dst);
# define nbworks_send(a, b, c, d, e) nbworks_sendto(a, b, c, d, e, 0)
ssize_t
  nbworks_recvfrom(unsigned char service,
                   struct nbworks_session *ses,
                   void **buff,
                   size_t len,
                   int callflags,
                   struct nbworks_nbnamelst **src);
# define nbworks_recv(a, b, c, d, e) nbworks_recvfrom(a, b, c, d, e, 0)
void
  nbworks_cancel(struct nbworks_session *ses,
                 unsigned char what);

void
  nbworks_hangup_ses(struct nbworks_session *ses);
# define nbworks_destroy_ses(a) nbworks_hangup_ses(a)

unsigned long
  nbworks_whatisaddrX(struct nbworks_nbnamelst *X,
                      unsigned long ten);


#endif /* NBWORKS_NBWORKS_H */
