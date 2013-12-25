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

#ifndef NBWORKS_NBWORKS_H
# define NBWORKS_NBWORKS_H 1

# include <unistd.h>
/***********************/
# include <sys/socket.h>

# ifndef MSG_BRDCAST
#  define MSG_BRDCAST MSG_PROXY     /* Trying hard to be portable by... */
# endif
# ifndef MSG_GROUP
#  define MSG_GROUP   MSG_DONTROUTE /* ...fitting everything into int16_t. */
# endif
/***********************/
/* FIXME: this needs to be done in a portable way. */
# define NBWORKS_PUBLIC __attribute__ ((visibility ("default")))
/***********************/

# define NBWORKS_NBNAME_LEN 16
# define NBWORKS_CODED_NBNAME_LEN 32

# define NBWORKS_NAME_SRVC 1
# define NBWORKS_DTG_SRVC  0
# define NBWORKS_SES_SRVC  2

# define NBWORKS_CANCEL_SEND 1
# define NBWORKS_CANCEL_RECV 2

# define NBWORKS_NODE_B 0x01
# define NBWORKS_NODE_P 0x02
# define NBWORKS_NODE_M 0x04
# define NBWORKS_NODE_H 0x08
# define NBWORKS_NODE_BTYPE (NBWORKS_NODE_B | NBWORKS_NODE_M | \
                             NBWORKS_NODE_H)
# define NBWORKS_NODE_PTYPE (NBWORKS_NODE_P | NBWORKS_NODE_M | \
                             NBWORKS_NODE_H)
# define NBWORKS_NODE_ALL   (NBWORKS_NODE_B | NBWORKS_NODE_P | \
                             NBWORKS_NODE_M | NBWORKS_NODE_H)

# define NBWORKS_TAKES_ALL    0xff
# define NBWORKS_TAKES_BRDCST 0x0f
# define NBWORKS_TAKES_UNQCST 0xf0

# define NBWORKS_MAXLEN_LABEL 0x3f

extern NBWORKS_PUBLIC const char nbworks_jokername[];
extern NBWORKS_PUBLIC const char nbworks_jokernamecoded[];

extern NBWORKS_PUBLIC struct nbworks_libcntl_t {
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
  unsigned long keepalive_interval;

  /* Timeout when receiving or sending on sessions. */
  unsigned long close_timeout;
  /* How long to keep dtg fragments around, waiting for the rest. */
  unsigned long dtg_frag_keeptime;

  /* Maximum length of the WHOLE datagram packet, as sent to the UDP layer. */
  unsigned int dtg_max_wholefrag_len;

} nbworks_libcntl;

typedef unsigned int nbworks_errno_t;
extern NBWORKS_PUBLIC nbworks_errno_t nbworks_errno;

typedef void* nbworks_session_p;
typedef void* nbworks_namestate_p;

struct nbworks_nbnamelst {
  struct nbworks_nbnamelst *next_name;
  unsigned char len; /* Not int because the field is
                        6 bits wide in the packet. */
  unsigned char name[]; /* Does not include the tramp stamp. */
};

struct nbworks_pollfd {
  nbworks_session_p session;
  short int events;
  short int revents;
};

NBWORKS_PUBLIC void
  nbworks_libinit(void);
NBWORKS_PUBLIC void
  nbworks_reinit_myIP4address(void);

/* BEGIN auxiliary API */
NBWORKS_PUBLIC struct nbworks_nbnamelst *
  nbworks_create_nbnodename(unsigned char *string,
                            unsigned char type_char);
NBWORKS_PUBLIC unsigned char *
  nbworks_create_nbnamelabel(const unsigned char *string,
                             const unsigned char type_char,
                             unsigned char *field);
NBWORKS_PUBLIC void
  nbworks_dstr_nbnodename(struct nbworks_nbnamelst *nbnodename);
NBWORKS_PUBLIC struct nbworks_nbnamelst *
  nbworks_clone_nbnodename(struct nbworks_nbnamelst *nbnodename);
/* returns: 0 = equal, !0 = not equal */
NBWORKS_PUBLIC int
  nbworks_cmp_nbnodename(struct nbworks_nbnamelst *name_one,
                         struct nbworks_nbnamelst *name_two);
NBWORKS_PUBLIC unsigned int
  nbworks_nbnodenamelen(struct nbworks_nbnamelst *nbnodename);

NBWORKS_PUBLIC struct nbworks_nbnamelst *
  nbworks_buff2nbname(unsigned char *buff,
                      unsigned long lenof_string);
NBWORKS_PUBLIC unsigned long
  nbworks_nbname2buff(unsigned char **destination,
                      struct nbworks_nbnamelst *name);
NBWORKS_PUBLIC struct nbworks_nbnamelst *
  nbworks_makescope(unsigned char *buff);

NBWORKS_PUBLIC unsigned long
  nbworks_maxdtglen(nbworks_namestate_p handle,
                    unsigned int withfrag);

/* returns: >0 = success; 0 = fail; <0 = error */
NBWORKS_PUBLIC int
  nbworks_grab_railguard(nbworks_namestate_p namehandle);
/* returns: >0 = success; 0 = fail; <0 = error */
NBWORKS_PUBLIC int
  nbworks_release_railguard(nbworks_namestate_p namehandle);

/* returns: >0 = success, 0 = fail, <0 = error */
NBWORKS_PUBLIC int
  nbworks_setsignal(nbworks_namestate_p namehandle,
                    int signal);
/* returns: >0 = success, 0 = fail, <0 = error */
NBWORKS_PUBLIC int
  nbworks_rmsignal(nbworks_namestate_p namehandle);
/* END auxiliatry API */

/* BEGIN base API */
/* BEGIN core API */
NBWORKS_PUBLIC nbworks_namestate_p
  nbworks_regname(unsigned char *name,   /* len <= (NBWORKS_NBNAME_LEN-1) */
                  unsigned char name_type,    /* these are Microsofts idea */
                  struct nbworks_nbnamelst *scope, /* 0 is a valid value */
                  unsigned char isgroup,      /* boolean */
                  unsigned char node_type,    /* only one type */
                  unsigned long refresh_time, /* seconds */
                  unsigned int withguard);    /* insure yourself or not */
/* returns: >0 = success, 0 = fail, <0 = error */
NBWORKS_PUBLIC int
  nbworks_delname(nbworks_namestate_p handle);

NBWORKS_PUBLIC nbworks_session_p
  nbworks_castdtgsession(nbworks_namestate_p handle,
                         struct nbworks_nbnamelst *defaultpeer);

/* returns: >0 = success, 0 = fail, <0 = error */
NBWORKS_PUBLIC int
  nbworks_listen_dtg(nbworks_namestate_p handle,
                     unsigned char takes_field,
                     struct nbworks_nbnamelst *listento);
/* returns: >0 = success, 0 = fail, <0 = error */
NBWORKS_PUBLIC int
  nbworks_listen_ses(nbworks_namestate_p handle,
                     unsigned char takes_field,
                     struct nbworks_nbnamelst *listento);
/* returns: >0 = success; 0 = fail; <0 = error */
NBWORKS_PUBLIC int
  nbworks_update_listentos(unsigned char service,
                           nbworks_namestate_p namehandle,
                           unsigned char newtakes_field,
                           struct nbworks_nbnamelst *newlistento);
NBWORKS_PUBLIC nbworks_session_p
  nbworks_accept_ses(nbworks_namestate_p handle,
                     int timeout);
NBWORKS_PUBLIC nbworks_session_p
  nbworks_sescall(nbworks_namestate_p handle,
                  struct nbworks_nbnamelst *dst,
                  unsigned char keepalive);
NBWORKS_PUBLIC nbworks_session_p
  nbworks_dtgconnect(nbworks_session_p session,
                     struct nbworks_nbnamelst *dst);

NBWORKS_PUBLIC int
  nbworks_poll(unsigned char service,
               struct nbworks_pollfd *handles,
               int numof_sess,
               int timeout);

NBWORKS_PUBLIC ssize_t
  nbworks_sendto(unsigned char service,
                 nbworks_session_p ses,
                 void *buff,
                 size_t len,
                 int flags,
                 struct nbworks_nbnamelst *dst);
# define nbworks_send(a, b, c, d, e) nbworks_sendto(a, b, c, d, e, 0)
NBWORKS_PUBLIC ssize_t
  nbworks_recvfrom(unsigned char service,
                   nbworks_session_p ses,
                   void **buff,
                   size_t len,
                   int callflags,
                   struct nbworks_nbnamelst **src);
# define nbworks_recv(a, b, c, d, e) nbworks_recvfrom(a, b, c, d, e, 0)
NBWORKS_PUBLIC ssize_t
  nbworks_recvwait(nbworks_session_p session,
                   void **buff,
                   size_t len,
                   int callflags,
                   int timeout,
                   struct nbworks_nbnamelst **src);
NBWORKS_PUBLIC void
  nbworks_cancel(nbworks_session_p ses,
                 unsigned char what);

/* returns: >0 = success, 0 = fail, <0 = error */
NBWORKS_PUBLIC int
  nbworks_haltsrv(unsigned int service,
                  nbworks_namestate_p namehandle);
NBWORKS_PUBLIC void
  nbworks_hangup_ses(nbworks_session_p ses);
# define nbworks_destroy_ses(a) nbworks_hangup_ses(a)
/* END core API */

NBWORKS_PUBLIC unsigned long
  nbworks_whatisIP4addrX(struct nbworks_nbnamelst *X,
                         unsigned char node_types, /* can be more than one */
                         unsigned char isgroup,
                         unsigned long len);
/* returns: >0 = yes; 0 = no; <0 = error */
NBWORKS_PUBLIC int
  nbworks_isinconflict(nbworks_namestate_p namehandle);
/* END base API */

# undef NBWORKS_PUBLIC

#endif /* NBWORKS_NBWORKS_H */
