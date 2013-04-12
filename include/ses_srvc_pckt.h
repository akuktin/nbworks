/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NBWORKS_SESSRVCPCKT_H
# define NBWORKS_SESSRVCPCKT_H 1

# include "nodename.h"

# define SESSION_MESSAGE      0x00
# define SESSION_REQUEST      0x81
# define POS_SESSION_RESPONSE 0x82
# define NEG_SESSION_RESPONSE 0x83
# define RETARGET_SESSION     0x84
# define SESSION_KEEP_ALIVE   0x85

# define SES_ERR_NOTLISCALLED  0x80 /* not listening on called name */
# define SES_ERR_NOTLISCALLING 0x81 /* not listening for calling name */
# define SES_ERR_NOCALLED      0x82 /* called name not present */
# define SES_ERR_NORES         0x83 /* called name present, no resources */
# define SES_ERR_UNSPEC        0x8f /* unspecified error */

# define SES_HEADER_LEN 4
# define SES_MAXLEN 0x1ffff

enum ses_packet_payload_t {
  unknown_ses = 0,
  two_names,
  null,
  error_code_ses,
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
  unsigned char for_del;
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
                            unsigned char *end_of_packet,
                            struct ses_srvc_packet *field);
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
			      long len);
/* Call with whole packet, len is total len of whole packet. */
struct nbnodename_list *
  ses_srvc_get_calledname(void *packet,
                          long len);
/* Call with whole packet, len is total len of whole packet. */
struct nbnodename_list *
  ses_srvc_get_callingname(void *packet,
                           long len);
void *
  master_ses_srvc_pckt_writer(void *packet_ptr,
                              unsigned long *pckt_len,
                              void *packet_field);

void
  destroy_ses_srvc_pcktpyld(struct ses_srvc_packet *pckt);
void
  destroy_ses_srvc_pckt(struct ses_srvc_packet *pckt);

#endif /* NBWORKS_SESSRVCPCKT_H */
