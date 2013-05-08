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

#ifndef NBWORKS_SERVICESECTOR_H
# define NBWORKS_SERVICESECTOR_H 1

# define MAX_NAME_TCP_QUEUE 16

# include "name_srvc_pckt.h"
# include "dtg_srvc_pckt.h"

# define TRANSIS_UDP 1
# define TRANSIS_TCP 2

# define MAXNUMOF_TIDS (0xffff +1)

enum trans_status {
  nmtrst_normal = 0,
  nmtrst_indrop,
  nmtrst_deregister
};


union trans_id {
  uint16_t tid;
  struct nbworks_nbnamelst *name_scope;
};

struct rail_list {
  int rail_sckt;
  struct rail_list *next;
};

struct ss_unif_pckt_list {
  uint16_t for_del;
  void *packet;
  void (*dstry)(void *, unsigned int, unsigned int);
  struct sockaddr_in addr;
  struct ss_unif_pckt_list *next;
};

/* This one is private to the service sector. */
struct ss_priv_trans {
  union trans_id id;
  enum trans_status status;
  struct ss_unif_pckt_list *in;
  struct ss_unif_pckt_list *out;
  struct ss_priv_trans *next;
};

/* This one is for the name/datagram sector. */
struct ss_queue {
  struct ss_unif_pckt_list *incoming;
  struct ss_unif_pckt_list *outgoing;
};

struct ss_queue_storage {
  unsigned char branch;
  union trans_id id;
  time_t last_active;
  struct rail_list *rail;
  struct ss_queue queue;
  struct ss_queue_storage *next;
};


struct ss_sckts {
  unsigned char isbusy;
  int udp_sckt;
  int tcp_sckt;
  unsigned char branch; /* passthrough for ss_register_tid() */
  void *(*master_reader)(void *, unsigned long, uint16_t *);
  void *(*master_writer)(void *, unsigned long *, void *, unsigned char);
  void  (*pckt_dstr)(void *, unsigned int, unsigned int);
  void *(*newtid_handler)(void *);
  struct ss_priv_trans **all_trans;
};

struct newtid_params {
  unsigned char isbusy;
  pthread_t thread_id;
  union trans_id id;
  struct ss_queue *trans;
};

struct ss_tcp_sckts {
  unsigned char isbusy;
  pthread_t thread_id;
  int sckt139;
  struct ses_srv_rails **servers;
};

struct ses_srv_rails {
  struct nbworks_nbnamelst *name;
  int rail;
  struct ses_srv_rails *next;
};

struct ses_srv_sessions {
  token_t token;
  int out_sckt;
  unsigned char *first_buff;
  unsigned int numof_passes;
  struct ses_srv_sessions *next;
};

# ifdef COMPILING_NBNS
struct ss__NBNStrans {
  unsigned char ss_iosig;
  struct ss_priv_trans *privtrans;
  struct ss_queue trans;
};

extern struct ss__NBNStrans ss_alltrans[MAXNUMOF_TIDS];
#  define SS_IOSIG_IN       0x10
#  define SS_IOSIG_TAKEN    0x20
#  define SS_IOSIG_OUT      0x01

#  define SS_IOSIG_TIDING   0x40 /* This trans is having a tid handler installed. */
#  define SS_IOSIG_TIDED    0x80 /* This trans has a tid handler installed. */

#  define SS_IOSIG_MASK_IN  0x30
#  define SS_IOSIG_MASK_OUT 0x0f
#  define SS_IOSIG_MASK_TID 0xc0
# endif

void
  init_service_sector_runonce(void);
void
  init_service_sector(void);

struct ss_queue *
  ss_register_tid(union trans_id *trans_id,
                  unsigned char branch);
void
  ss_deregister_tid(union trans_id *trans_id,
                    unsigned char branch);
struct ss_queue_storage *
  ss_add_queuestorage(struct ss_queue *queue,
                      union trans_id *trans_id,
                      unsigned char branch);
void
  ss_del_queuestorage(union trans_id *trans_id,
                      unsigned char branch);
struct ss_queue_storage *
  ss_take_queuestorage(union trans_id *arg,
                       unsigned char branch);
struct ss_queue_storage *
  ss_find_queuestorage(union trans_id *trans_id,
                       unsigned char branch);
void
  ss_prune_queuestorage(time_t killtime);

void
  ss_set_inputdrop_tid(union trans_id *trans_id,
                       unsigned char branch);
void
  ss_set_normalstate_tid(union trans_id *trans_id,
                         unsigned char branch);

inline int
  ss_name_send_pckt(struct name_srvc_packet *pckt,
                    struct sockaddr_in *addr,
                    struct ss_queue *trans);
inline int
  ss_dtg_send_pckt(struct dtg_srvc_recvpckt *pckt,
                   struct sockaddr_in *addr,
                   struct ss_queue *trans);
inline void *
  ss__recv_pckt(struct ss_queue *trans,
                ipv4_addr_t listen);
inline struct ss_unif_pckt_list *
  ss__recv_entry(struct ss_queue *trans);
inline void
  ss__dstry_recv_queue(struct ss_queue *trans);

struct ses_srv_rails *
  ss__add_sessrv(struct nbworks_nbnamelst *name,
                 int rail);
struct ses_srv_rails *
  ss__find_sessrv(struct nbworks_nbnamelst *name);
void
  ss__del_sessrv(struct nbworks_nbnamelst *name);

/* Complicated arguments because this is a convenience function. */
void
  ss__kill_allservrs(unsigned char *name_ptr, /* len == NETBIOS_NAME_LEN */
                     struct nbworks_nbnamelst *scope);

struct ses_srv_sessions *
  ss__add_session(token_t token,
                  int out_sckt,
                  unsigned char *first_buff);
struct ses_srv_sessions *
  ss__find_session(token_t token);
struct ses_srv_sessions *
  ss__take_session(token_t token);
void
  ss__del_session(token_t token,
                  unsigned char close_sckt);
void
  ss__prune_sessions(void);

int
  fill_all_nametrans(struct ss_priv_trans **where);

void *
  ss__port137(void *placeholder);
void *
  ss__port138(void *i_dont_actually_use_this);
void *
  ss__port139(void *non_args);

void *
  ss__udp_recver(void *sckts_ptr);
void *
  ss__udp_sender(void *sckts_ptr);

void *
  take_incoming_session(void *arg);
void
  ss_check_all_ses_server_rails(void);

# define ss_register_name_tid(tid)        ss_register_tid(tid, NAME_SRVC)
# define ss_deregister_name_tid(tid)      ss_deregister_tid(tid, NAME_SRVC)
# define ss_set_inputdrop_name_tid(tid)   ss_set_inputdrop_tid(tid, NAME_SRVC)
# define ss_set_normalstate_name_tid(tid) ss_set_normalstate_tid(tid, NAME_SRVC)

# define ss_register_dtg_tid(tid)        ss_register_tid(tid, DTG_SRVC)
# define ss_deregister_dtg_tid(tid)      ss_deregister_tid(tid, DTG_SRVC)
# define ss_set_inputdrop_dtg_tid(tid)   ss_set_inputdrop_tid(tid, DTG_SRVC)
# define ss_set_normalstate_dtg_tid(tid) ss_set_normalstate_tid(tid, DTG_SRVC)

#endif /* NBWORKS_SERVICESECTOR_H */
