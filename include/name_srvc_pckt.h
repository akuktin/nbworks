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

enum name_srvc_rdata_type {
  unknown_type = 0,
  bad_type
};

struct name_srvc_resource {
  struct nbnodename_list *name;
  uint16_t rrtype;
  uint16_t rrclass;
  uint32_t ttl;
  uint16_t rdlength;
  enum name_srvc_rdata_type rdata_t;
  void *rdata;
  unsigned char *rdata_raw; /* Design decisions, design decisions... */
};

struct name_srvc_pckt_header *read_name_srvc_pckt_header(void **master_packet_walker);
unsigned char *fill_name_srvc_pckt_header(const struct name_srvc_pckt_header *header,
                                          void **master_packet_walker);
struct name_srvc_question *read_name_srvc_pckt_question(void **master_packet_walker,
							void *start_of_packet);
unsigned char *fill_name_srvc_pckt_question(struct name_srvc_question *question,
                                            void **master_packet_walker);
struct name_srvc_resource *read_name_srvc_resource(void **master_packet_walker,
						   void *start_of_packet);
unsigned char *fill_name_srvc_resource(struct name_srvc_resource *resource,
				       void **master_packet_walker);
struct name_srvc_resource_data *read_name_srvc_resource_data(unsigned char **start_of_walk,
                                                             struct name_srvc_resource *resource,
                                                             void *start_of_packet);
unsigned char *fill_name_srvc_resource_data(struct name_srvc_resource *content,
                                            unsigned char *field);

#endif /* NBWORKS_NAMESRVCPCKT_H */
