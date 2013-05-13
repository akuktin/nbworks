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

#ifndef NBWORKS_LIBRARY_H
# define NBWORKS_LIBRARY_H 1

# include "nodename.h"
# include "name_srvc_cache.h"
# include "dtg_srvc_pckt.h"

# define HANDLE_TAKES_ALLBRDCST 0x01
# define HANDLE_TAKES_ALLUNCST  0x02
# define HANDLE_TAKES_ALL       0x03

struct packet_cooked {
  unsigned char *data;
  uint32_t len;
  struct nbworks_nbnamelst *src;
  struct packet_cooked *next;
};

struct dtg_frag {
  uint32_t offset;
  uint32_t len;
  unsigned char *data;
  struct dtg_frag *next;
};

struct dtg_frag_bckbone {
  uint16_t id;
  time_t last_active;
  struct nbworks_nbnamelst *src;
  struct dtg_frag *frags;
  unsigned char last_ishere;
  struct dtg_frag_bckbone *next;
};

struct name_state {
/* identification */
  token_t token;
  struct nbworks_nbnamelst *name;
  struct nbworks_nbnamelst *scope;

/* datagram server */
  pthread_t dtg_srv_tid;
  int dtg_srv_sckt;
  struct nbworks_nbnamelst *dtg_listento;
  unsigned char dtg_takes;  /* flag field */
  unsigned char dtg_srv_stop;
  struct dtg_frag_bckbone *dtg_frags;
  struct packet_cooked *in_server;
  struct packet_cooked *in_library;
  pthread_mutex_t dtg_recv_mutex;
  pthread_mutex_t dtg_srv_work_inprog;

/* session taker server */
  pthread_t ses_srv_tid;
  int ses_srv_sckt;
  struct nbworks_nbnamelst *ses_listento;
  unsigned char ses_takes;  /* flag field */
  unsigned char ses_srv_stop;
  struct nbworks_session *sesin_server;
  struct nbworks_session *sesin_library;
  pthread_mutex_t ses_srv_work_inprog;

/* metadata for the name and scope */
  short lenof_scope;         /* the amount of octets the encoded scope takes,
                              * incl. the terminating NULL in the packet */
  unsigned char label_type;  /* the type octet of the name */
  node_type_t node_type;     /* flag field */
  unsigned int isinconflict;

/* guard rail */
  pthread_mutex_t guard_mutex;
  int guard_rail;

/* maybe we will daysie-chain them */
  struct name_state *next;
};

struct nbworks_session {
  struct nbworks_nbnamelst *peer; /* name + scope */
  struct name_state *handle;      /* pointer back to the whole name_handle */
  unsigned char cancel_send;
  unsigned char cancel_recv;
  unsigned char kill_caretaker;
  unsigned char keepalive;
  unsigned char nonblocking;      /* TRUE by default */
  int socket;
  size_t len_left;
  size_t ooblen_left;
  size_t ooblen_offset;
  unsigned char *oob_tmpstor;
  pthread_mutex_t mutex;
  pthread_mutex_t receive_mutex;
  pthread_t caretaker_tid;
  struct nbworks_session *next;
};

union nbworks_handle {
  struct name_state *dtg;
  struct nbworks_session *ses;
};

int
  lib_daemon_socket(void);

void
  lib_dstry_packets(struct packet_cooked *forkill);

void
  lib_destroy_frags(struct dtg_frag *flesh);
void
  lib_destroy_fragbckbone(struct dtg_frag_bckbone *bone);
void
  lib_destroy_allfragbckbone(struct dtg_frag_bckbone *frags);
struct dtg_frag_bckbone *
  lib_add_fragbckbone(uint16_t id,
                      struct nbworks_nbnamelst *src,
                      uint16_t offsetof_first,
                      uint16_t lenof_first,
                      void *first_data,
                      struct dtg_frag_bckbone **frags);
struct dtg_frag_bckbone *
  lib_find_fragbckbone(uint16_t id,
                       struct nbworks_nbnamelst *src,
                       struct dtg_frag_bckbone *frags);
struct dtg_frag_bckbone *
  lib_take_fragbckbone(uint16_t id,
                       struct nbworks_nbnamelst *src,
                       struct dtg_frag_bckbone **frags);
void
  lib_del_fragbckbone(uint16_t id,
                      struct nbworks_nbnamelst *src,
                      struct dtg_frag_bckbone **frags);
void
  lib_prune_fragbckbone(struct dtg_frag_bckbone **frags,
                        time_t killtime,
                        struct packet_cooked **anchor);
struct dtg_frag_bckbone *
  lib_add_frag_tobone(uint16_t id,
                      struct nbworks_nbnamelst *src,
                      uint16_t offset,
                      uint16_t len,
                      void *data,
                      struct dtg_frag_bckbone *frags);
struct dtg_frag *
  lib_order_frags(struct dtg_frag **frags,
                  uint32_t *len);
void *
  lib_assemble_frags(struct dtg_frag *frags,
                     uint32_t len);

/* returns: TRUE (AKA 1) = YES, listens to,
            FALSE (AKA 0) = NO, doesn't listen to */
unsigned int
  lib_doeslistento(struct nbworks_nbnamelst *query,
                   struct nbworks_nbnamelst *answerlist);

ssize_t
  lib_senddtg_138(struct name_state *handle,
                  unsigned char *recepient,
                  unsigned char recepient_type,
                  void *data,
                  size_t len,
                  int brdcst_or_grp);

void *
  lib_dtgserver(void *arg);

int
  lib_open_session(struct name_state *handle,
                   struct nbworks_nbnamelst *dst);

void *
  lib_ses_srv(void *arg);

void *
  lib_caretaker(void *arg);
struct nbworks_session *
  lib_make_session(int socket,
                   struct nbworks_nbnamelst *caller,
                   struct name_state *handle,
                   unsigned char keepalive);
void
  lib_dstry_sesslist(struct nbworks_session *ses);

ssize_t
  lib_flushsckt(int socket,
                ssize_t len,
                int flags);

#endif /* NBWORKS_LIBRARY_H */
