#ifndef NBWORKS_SERVICESECTOR_H
# define NBWORKS_SERVICESECTOR_H 1

# define MAX_NAME_TCP_QUEUE 16

struct ss_name_pckt_list {
  struct name_srvc_packet *packet;
  struct sockaddr_in addr;
  struct ss_name_pckt_list *next;
};

enum nametrans_status {
  nmtrst_normal = 0,
  nmtrst_indrop,
  nmtrst_deregister
};

/* This one is private to the service sector. */
struct ss_name_trans {
  uint16_t tid;
  enum nametrans_status status;
  struct ss_name_pckt_list *incoming;
  struct ss_name_pckt_list *outgoing;
  struct ss_name_trans *next;
};

/* This one is for the name sector. */
struct ss_queue {
  struct ss_name_pckt_list *incoming;
  struct ss_name_pckt_list *outgoing;
};

struct ss_sckts {
  int udp_sckt;
  int tcp_sckt;
  struct ss_name_trans *all_trans;
};

void init_service_sector();
struct ss_queue *
  ss_register_name_tid(uint16_t tid);
void
  ss_deregister_name_tid(uint16_t tid);
void
  ss_set_inputdrop_name_tid(uint16_t tid);
void
  ss_set_normalstate_name_tid(uint16_t tid);

inline int
  ss_name_send_pckt(struct name_srvc_packet *pckt,
                    struct sockaddr_in *addr,
                    struct ss_queue *trans);
inline struct name_srvc_packet *
  ss_name_recv_pckt(struct ss_queue *trans);
inline struct ss_name_pckt_list *
  ss_name_recv_entry(struct ss_queue *trans);
inline void
  ss_name_dstry_recv_queue(struct ss_queue *trans);

int ss__port137();
void *ss_name_udp_recver(void *sckts_ptr);
void *ss_name_udp_sender(void *sckts_ptr);
unsigned int get_inaddr();

#endif /* NBWORKS_SERVICESECTOR_H */
