#ifndef NBWORKS_SERVICESECTOR_H
# define NBWORKS_SERVICESECTOR_H 1

struct ss_name_pckt_list {
  struct name_srvc_packet *packet;
  struct ss_name_pckt_list *next;
};

/* This one is private to the service sector. */
struct ss_name_trans {
  uint16_t tid;
  struct ss_name_pckt_list *incoming;
  struct ss_name_pckt_list *outgoing;
  struct ss_name_trans *next;
};

/* This one is for the name sector. */
struct ss_queue {
  struct ss_name_pckt_list *incoming;
  struct ss_name_pckt_list *outgoing;
};

void init_service_sector();
struct ss_queue *ss_register_name_tid(uint16_t tid);
void ss_deregister_name_tid(uint16_t tid);

inline int ss_name_send_pckt(struct name_srvc_packet *pckt,
                             struct ss_queue *trans);
inline struct name_srvc_packet *ss_recv_name_pckt(struct ss_queue *trans);

void ss_rcv_port137();

#endif /* NBWORKS_SERVICESECTOR_H */
