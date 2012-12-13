#ifndef NBWORKS_NAMESRVCPCKT_H
# define NBWORKS_NAMESRVCPCKT_H 1

# include <stdint.h>

# define MAX_DNS_LABEL_LEN 0x3f

struct name_srvc_pckt_header {
  uint16_t transaction_id;
  unsigned int opcode   :5;
  unsigned int nm_flags :7;
  unsigned int rcode    :4;
  uint16_t numof_questions;
  uint16_t numof_answers;
  uint16_t numof_authorities;
  uint16_t numof_additional_recs;
};

struct nbnodename_list {
  unsigned char *name;
  unsigned char len; /* Not int because the field is 6 bits wide in the packet. */
  struct nbnodename_list *next_name;
};

struct name_srvc_question {
  struct nbnodename_list *name;
  uint16_t qtype;
  uint16_t qclass;
};

struct name_srvc_pckt_header *read_name_srvc_pckt_header(void **master_packet_walker);
void fill_name_srvc_pckt_header(const struct name_srvc_pckt_header *header,
                                void **master_packet_walker);
struct name_srvc_question *read_name_srvc_pckt_question(void **master_packet_walker,
							void *start_of_packet);
void fill_name_srvc_pckt_question(struct name_srvc_question *question,
				  void **master_packet_walker);

#endif /* NBWORKS_NAMESRVCPCKT_H */
