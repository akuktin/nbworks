#ifndef NBWORKS_NAMESRVCPCKT_H
# define NBWORKS_NAMESRVCPCKT_H 1

# include <stdint.h>

# define MAX_DNS_LABEL_LEN 0x3f

# define QTYPE_NB      0x0020
# define QTYPE_NBSTAT  0x0021

# define QCLASS_IN     0x0001

# define RRTYPE_A      0x0001
# define RRTYPE_NS     0x0002
# define RRTYPE_NULL   0x000a
# define RRTYPE_NB     0x0020
# define RRTYPE_NBSTAT 0x0021

# define RRCLASS_IN    0x0001

enum name_srvc_rdata_type {
  unknown_type = 0,
  unknown_important_resource,
  nb_address_list, /* Array of (NB_FLAGS, IPv4addr).
                      Can contain only NB_FLAGS, check rdata_len. */
                   /* Or not, there is a confict in RFC1002, page 25.
                      IETF resources are not enlighning.
                      http://www.rfc-editor.org/errata_search.php?rfc=1002 */
  nb_type_null, /* Nothing. */
  nb_nodename, /* NetBIOS name+scope, like in questions. */ /* Aligned! */
  nb_NBT_node_ip_address, /* Array of (IPv4addr). */
  nb_statistics_rfc1002, /* Array of (nbnodename+name_flags), aligned in its
			    every member nodename+scope, and also aligned as
			    a whole (by my interpretation) followed by the
			    statistics blob. */
  bad_type
};

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

struct nbaddress_list {
  uint16_t flags;
  unsigned char there_is_an_address;
  uint32_t address;
  struct nbaddress_list *next_address;
};

struct nbnodename_list {
  unsigned char *name;
  unsigned char len; /* Not int because the field is 6 bits wide in the packet. */
  struct nbnodename_list *next_name;
};

struct nbnodename_list_backbone {
  struct nbnodename_list *nbnodename;
  uint16_t name_flags;
  struct nbnodename_list_backbone *next_nbnodename;
};

struct name_srvc_question {
  struct nbnodename_list *name;
  uint16_t qtype;
  uint16_t qclass;
};

struct name_srvc_statistics_rfc1002 {
  unsigned char numof_names;
  struct nbnodename_list_backbone *listof_names;
  uint64_t unique_id; /* Actually 48 bits wide in the packet. */
  unsigned char jumpers;
  unsigned char test_results;
  uint16_t version_number;
  uint16_t period_of_statistics;
  uint16_t numof_crc;
  uint16_t numof_alignment_errs;
  uint16_t numof_collisions;
  uint16_t numof_send_aborts;
  uint32_t numof_good_sends;
  uint32_t numof_good_receives;
  uint16_t numof_retransmits;
  uint16_t numof_no_res_conditions;
  uint16_t numof_free_commnd_blocks;
  uint16_t total_numof_commnd_blocks;
  uint16_t max_total_numof_commnd_blocks;
  uint16_t numof_pending_sessions;
  uint16_t max_numof_pending_sessions;
  uint16_t max_total_sessions_possible;
  uint16_t session_data_pckt_size;
};

struct name_srvc_resource {
  struct nbnodename_list *name;
  uint16_t rrtype;
  uint16_t rrclass;
  uint32_t ttl;
  uint16_t rdata_len;
  enum name_srvc_rdata_type rdata_t;
  void *rdata;
};

struct name_srvc_pckt_header *
  read_name_srvc_pckt_header(unsigned char **master_packet_walker,
                             unsigned char *end_of_packet);
unsigned char *
  fill_name_srvc_pckt_header(const struct name_srvc_pckt_header *header,
                             unsigned char **master_packet_walker);
struct name_srvc_question *
  read_name_srvc_pckt_question(unsigned char **master_packet_walker,
                               unsigned char *start_of_packet,
                               unsigned char *end_of_packet);
unsigned char *
  fill_name_srvc_pckt_question(struct name_srvc_question *question,
                               unsigned char **master_packet_walker);
struct name_srvc_resource *
  read_name_srvc_resource(unsigned char **master_packet_walker,
                          unsigned char *start_of_packet,
                          unsigned char *end_of_packet);
unsigned char *
  fill_name_srvc_resource(struct name_srvc_resource *resource,
                          unsigned char **master_packet_walker);
void *
  read_name_srvc_resource_data(unsigned char **start_and_end_of_walk,
                               struct name_srvc_resource *resource,
                               unsigned char *start_of_packet,
                               unsigned char *end_of_packet);
unsigned char *
  fill_name_srvc_resource_data(struct name_srvc_resource *content,
                               unsigned char *field);
inline enum name_srvc_rdata_type
  name_srvc_understand_resource(uint16_t rrtype,
                                uint16_t rrclass);

#endif /* NBWORKS_NAMESRVCPCKT_H */
