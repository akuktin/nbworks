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

/* datagram flags field */
# define DTG_MORE_FLAG      0x01
# define DTG_FIRST_FLAG     0x02
# define DTG_NODE_TYPE_MASK 0x0c

# define DTG_NODE_TYPE_B    0x00
# define DTG_NODE_TYPE_P    0x04
# define DTG_NODE_TYPE_M    0x08
# define DTG_NODE_TYPE_NBDD 0x0c

/* datagram errors */
# define DTG_ERR_DSTNAM_NOTHERE 0x82 /* Destination name not present here. */
# define DTG_ERR_SRCNAM_BADFORM 0x83 /* Invalid format of the source name. */
# define DTG_ERR_DSTNAM_BADFORM 0x84 /* Invalid format of the destination name. */

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
  unsigned char do_del_pyldpyld;
  void *pyldpyld_delptr;
};

struct dtg_srvc_packet {
  unsigned char for_del;
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
                                  unsigned char *end_of_packet,
                                  unsigned char read_allpyld);
unsigned char *
  fill_dtg_srvc_pckt_payload_data(struct dtg_srvc_packet *content,
                                  unsigned char *field,
                                  unsigned char *endof_pckt);
inline enum dtg_packet_payload_t
  understand_dtg_pckt_type(unsigned char type_octet);

void *
  master_dtg_srvc_pckt_reader(void *packet,
                              int len,
                              uint16_t *tid);
void *
  partial_dtg_srvc_pckt_reader(void *packet,
                               int len,
                               uint16_t *tid);
void *
  master_dtg_srvc_pckt_writer(void *packet_ptr,
                              unsigned int *pckt_len,
                              void *packet_field);

void
  destroy_dtg_srvc_pckt(void *packet,
                        unsigned int placeholder1,
                        unsigned int placeholder2);

#endif /* NBWORKS_DTGSRVCPCKT_H */
