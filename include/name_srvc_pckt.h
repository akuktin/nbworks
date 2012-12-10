#include <stdint.h>

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

struct name_srvc_pckt_header *read_name_srvc_pckt_header(const void *packet);
void fill_name_srvc_pckt_header(const struct name_srvc_pckt_header *header,
                                void *packet);
