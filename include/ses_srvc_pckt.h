#ifndef NBWORKS_SESSRVCPCKT_H
# define NBWORKS_SESSRVCPCKT_H 1

# include "nodename.h"

# define SESSION_MESSAGE      0x00
# define SESSION_REQUEST      0x81
# define POS_SESSION_RESPONSE 0x82
# define NEG_SESSION_RESPONSE 0x83
# define RETARGET_SESSION     0x84
# define SESSION_KEEP_ALIVE   0x85

enum ses_packet_payload_t {
  unknown = 0,
  two_names,
  null,
  error_code,
  retarget_blob_rfc1002,
  payloadpayload,
  bad_type_ses
};

struct ses_pckt_pyld_two_names {
  struct nbnodename_list *called_name;
  struct nbnodename_list *calling_name;
};

struct ses_srvc_retarget_blob_rfc1002 {
  uint32_t new_address;
  uint16_t new_port;
};

struct ses_srvc_packet {
  unsigned char type;
  unsigned int flags : 7;
  uint32_t len;
  enum ses_packet_payload_t payload_t;
  void *payload;
  unsigned char error_code; /* To avoid having to malloc() a SINGLE BYTE
                               in the event payload_t is error_code. */
};

struct ses_srvc_packet *
  read_ses_srvc_pckt_header(unsigned char **master_packet_walker,
                            unsigned char *end_of_packet);
unsigned char *
  fill_ses_packet_header(struct ses_srvc_packet *content,
                         unsigned char *field,
                         unsigned char *endof_pckt);
void *
  read_ses_srvc_pckt_payload_data(struct ses_srvc_packet *packet,
                                  unsigned char **master_packet_walker,
                                  unsigned char *start_of_packet,
                                  unsigned char *end_of_packet);
unsigned char *
  fill_ses_srvc_pckt_payload_data(struct ses_srvc_packet *content,
                                  unsigned char *field,
                                  unsigned char *endof_pckt);
inline enum ses_packet_payload_t
  understand_ses_pckt_type(unsigned char type_octet);

struct ses_srvc_packet *
  master_ses_srvc_pckt_reader(void *packet,
			      int len);
void *
  master_ses_srvc_pckt_writer(struct ses_srvc_packet *packet,
                              unsigned int *pckt_len);

#endif /* NBWORKS_SESSRVCPCKT_H */
