#ifndef NBWORKS_SERVICESECTOR_H
# define NBWORKS_SERVICESECTOR_H 1

# define MAX_NAME_TCP_QUEUE 16

# include <time.h>
# include <sys/time.h>
# include <pthread.h>
# include <netinet/in.h>

# include "name_srvc_pckt.h"
# include "dtg_srvc_pckt.h"


enum trans_status {
  nmtrst_normal = 0,
  nmtrst_indrop,
  nmtrst_deregister
};


union trans_id {
  uint16_t tid;
  struct nbnodename_list *name_scope;
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
  void *(*master_reader)(void *, int, uint16_t *);
  void *(*master_writer)(void *, unsigned int *, void *);
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
  struct nbnodename_list *name;
  int rail;
  struct ses_srv_rails *next;
};

struct ses_srv_sessions {
  uint64_t token;
  int out_sckt;
  unsigned char *first_buff;
  struct ses_srv_sessions *next;
};

struct ss_queue_storage *nbworks_queue_storage[2];

void init_service_sector();
struct ss_queue *
  ss_register_tid(union trans_id *trans_id,
                  unsigned char branch);
void
  ss_deregister_tid(union trans_id *trans_id,
                    unsigned char branch);
struct ss_queue_storage *
  ss_add_queuestorage(struct ss_queue *queue,
                      union trans_id *trans_id,
                      unsigned char branch,
                      struct ss_queue_storage **queue_stor);
void
  ss_del_queuestorage(union trans_id *trans_id,
                      unsigned char branch,
                      struct ss_queue_storage **queue_stor);
struct ss_queue_storage *
  ss_find_queuestorage(union trans_id *trans_id,
                       unsigned char branch,
                       struct ss_queue_storage *queue_stor);

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
  ss_dtg_send_pckt(struct dtg_srvc_packet *pckt,
                   struct sockaddr_in *addr,
                   struct ss_queue *trans);
inline void *
  ss__recv_pckt(struct ss_queue *trans);
inline struct ss_unif_pckt_list *
  ss__recv_entry(struct ss_queue *trans);
inline void
  ss__dstry_recv_queue(struct ss_queue *trans);

struct ses_srv_rails *
  ss__add_sessrv(struct nbnodename_list *name,
                 int rail);
struct ses_srv_rails *
  ss__find_sessrv(struct nbnodename_list *name);
void
  ss__del_sessrv(struct nbnodename_list *name);

struct ses_srv_sessions *
  ss__add_session(uint64_t token,
                  int out_sckt,
                  unsigned char *first_buff);
struct ses_srv_sessions *
  ss__find_session(uint64_t token);
struct ses_srv_sessions *
  ss__take_session(uint64_t token);
void
  ss__del_session(uint64_t token,
                  unsigned char close_sckt);

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
  ss_check_all_ses_server_rails();

uint32_t
  get_inaddr();
uint32_t
  my_ipv4_address();

# define ss_register_name_tid(tid)        ss_register_tid(tid, NAME_SRVC)
# define ss_deregister_name_tid(tid)      ss_deregister_tid(tid, NAME_SRVC)
# define ss_set_inputdrop_name_tid(tid)   ss_set_inputdrop_tid(tid, NAME_SRVC)
# define ss_set_normalstate_name_tid(tid) ss_set_normalstate_tid(tid, NAME_SRVC)

# define ss_register_dtg_tid(tid)        ss_register_tid(tid, DTG_SRVC)
# define ss_deregister_dtg_tid(tid)      ss_deregister_tid(tid, DTG_SRVC)
# define ss_set_inputdrop_dtg_tid(tid)   ss_set_inputdrop_tid(tid, DTG_SRVC)
# define ss_set_normalstate_dtg_tid(tid) ss_set_normalstate_tid(tid, DTG_SRVC)

#endif /* NBWORKS_SERVICESECTOR_H */
