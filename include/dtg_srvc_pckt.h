#ifndef NBWORKS_DTGSRVCPCKT_H
# define NBWORKS_DTGSRVCPCKT_H 1

# include "nodename.h"

# define DIR_UNIQ_DTG      0x10
# define DIR_GRP_DTG       0x11
# define BRDCST_DTG        0x12
# define DTG_ERROR         0x13
# define DTG_QRY_RQST      0x14
# define DTG_POS_QRY_RSPNS 0x15
# define DTG_NEG_QRY_RSPNS 0x16

enum dtg_packet_payload_t {
  unknown = 0,
  normal,
  error_code,
  nbnodename,
  bad_type_dtg
};

struct dtg_pckt_pyld_normal {
  uint16_t len;
  uint16_t offset;
  struct nbnodename_list *src_name;
  struct nbnodename_list *dst_name;
  void *payload;
};

struct dtg_srvc_packet {
  unsigned char type;
  unsigned char flags;
  uint16_t id;
  uint32_t src_address;
  uint16_t src_port;
  enum dtg_packet_payload_t payload_t;
  void *payload;
  unsigned char error_code;
};

struct dtg_srvc_packet *
  read_dtg_packet_header(unsigned char **master_packet_walker,
                         unsigned char *end_of_packet);
unsigned char *
  fill_dtg_packet_header(struct dtg_srvc_packet *content,
                         unsigned char *field,
                         unsigned char *endof_pckt);
void *
  read_dtg_srvc_pckt_payload_data(struct dtg_srvc_packet *packet,
                                  unsigned char **master_packet_walker,
                                  unsigned char *start_of_packet,
                                  unsigned char *end_of_packet);
unsigned char *
  fill_dtg_srvc_pckt_payload_data(struct dtg_srvc_packet *content,
                                  unsigned char *field,
                                  unsigned char *endof_pckt);
inline enum dtg_packet_payload_t
  understand_dtg_pckt_type(unsigned char type_octet);

void *
  master_dtg_srvc_pckt_reader(void *packet,
                              int len);
void *
  master_dtg_srvc_pckt_writer(void *packet_ptr,
                              unsigned int *pckt_len,
                              void *packet_field);

#endif /* NBWORKS_DTGSRVCPCKT_H */
