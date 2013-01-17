#ifndef NBWORKS_SERVICESECTOR_H
# define NBWORKS_SERVICESECTOR_H 1

# define MAX_NAME_TCP_QUEUE 16

# include <pthread.h>
# include <netinet/in.h>

# define NAME_SRVC 0
# define DTG_SRVC  1

enum trans_status {
  nmtrst_normal = 0,
  nmtrst_indrop,
  nmtrst_deregister
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
  uint16_t tid;
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
  uint16_t tid;
  struct ss_queue *trans;
};

void init_service_sector();
struct ss_queue *
  ss_register_tid(uint16_t tid,
                  unsigned char branch);
void
  ss_deregister_tid(uint16_t tid,
                    unsigned char branch);
void
  ss_set_inputdrop_tid(uint16_t tid,
                       unsigned char branch);
void
  ss_set_normalstate_tid(uint16_t tid,
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

void *ss__port137(void *placeholder);
void *ss__port138(void *i_dont_actually_use_this);

void *ss__udp_recver(void *sckts_ptr);
void *ss__udp_sender(void *sckts_ptr);

unsigned int get_inaddr();

#endif /* NBWORKS_SERVICESECTOR_H */
