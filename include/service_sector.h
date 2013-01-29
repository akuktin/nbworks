#ifndef NBWORKS_SERVICESECTOR_H
# define NBWORKS_SERVICESECTOR_H 1

# define MAX_NAME_TCP_QUEUE 16

# include <time.h>
# include <sys/time.h>
# include <pthread.h>
# include <netinet/in.h>

# include "name_srvc_pckt.h"
# include "dtg_srvc_pckt.h"

# define NAME_SRVC 1
# define DTG_SRVC  0


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
  pthread_t thread_id;
  union trans_id id;
  struct ss_queue *trans;
};

struct dtg_srv_params {
  pthread_t thread_id;
  struct nbnodename_list *nbname;
  struct ss_queue_storage *queue;
  struct ss_queue_storage **all_queues;
};

struct ss_queue_storage *nbworks_queue_storage[2];

void init_service_sector();
# define UNION__TRANS_ID void
struct ss_queue *
  ss_register_tid(UNION__TRANS_ID *trans_id,
                  unsigned char branch);
void
  ss_deregister_tid(UNION__TRANS_ID *trans_id,
                    unsigned char branch);
struct ss_queue_storage *
  ss_add_queuestorage(struct ss_queue *queue,
                      UNION__TRANS_ID *trans_id,
                      unsigned char branch,
                      struct ss_queue_storage **queue_stor);
void
  ss_del_queuestorage(UNION__TRANS_ID *trans_id,
                      unsigned char branch,
                      struct ss_queue_storage **queue_stor);
struct ss_queue_storage *
  ss_find_queuestorage(UNION__TRANS_ID *trans_id,
                       unsigned char branch,
                       struct ss_queue_storage *queue_stor);

void
  ss_set_inputdrop_tid(UNION__TRANS_ID *trans_id,
                       unsigned char branch);
void
  ss_set_normalstate_tid(UNION__TRANS_ID *trans_id,
                         unsigned char branch);
# undef UNION__TRANS_ID

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

void *ss__port137(void *placeholder);
void *ss__port138(void *i_dont_actually_use_this);

void *ss__udp_recver(void *sckts_ptr);
void *ss__udp_sender(void *sckts_ptr);

uint32_t get_inaddr();
uint32_t my_ipv4_address();

# define ss_register_name_tid(tid)        ss_register_tid(tid, NAME_SRVC)
# define ss_deregister_name_tid(tid)      ss_deregister_tid(tid, NAME_SRVC)
# define ss_set_inputdrop_name_tid(tid)   ss_set_inputdrop_tid(tid, NAME_SRVC)
# define ss_set_normalstate_name_tid(tid) ss_set_normalstate_tid(tid, NAME_SRVC)

# define ss_register_dtg_tid(tid)        ss_register_tid(tid, DTG_SRVC)
# define ss_deregister_dtg_tid(tid)      ss_deregister_tid(tid, DTG_SRVC)
# define ss_set_inputdrop_dtg_tid(tid)   ss_set_inputdrop_tid(tid, DTG_SRVC)
# define ss_set_normalstate_dtg_tid(tid) ss_set_normalstate_tid(tid, DTG_SRVC)

#endif /* NBWORKS_SERVICESECTOR_H */
