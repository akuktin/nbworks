#ifndef NBWORKS_SERVICESECTOR_H
# define NBWORKS_SERVICESECTOR_H 1

struct ss_name_pckt_list {
  struct name_srvc_packet *packet;
  struct ss_name_pckt_list *next;
}

/* This one is private to the service sector. */
struct ss_name_trans {
  uint16_t tid;
  struct ss_name_pckt_list *incoming;
  struct ss_name_pckt_list *outgoing;
  struct ss_name_trans *next;
}

/* This one is for the name sector. */
struct ss_queue {
  struct ss_name_pckt_list *incoming;
  struct ss_name_pckt_list *outgoing;
  int keep_me_alive;
}

struct ss_queue *ss_register_name_tid(uint16_t tid);
void ss_deregister_name_tid(uint16_t tid);

#endif /* NBWORKS_SERVICESECTOR_H */