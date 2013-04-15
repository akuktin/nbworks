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

/* Datagram overloading. The offset field contains 0xffff and the
 * datagram length field contains 0xffff, meaning that the last octet of
 * the datagram is the (0xffff + 0xffff)'th. */
# define DTG_MAXLEN (0xffff + 0xffff)
/* Maximum offset the datagram can handle. */
# define DTG_MAXOFFSET (0xffff)

# define FRAG_TIMEOUT  1 /* seconds */

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
  struct nbworks_nbnamelst *src_name;
  struct nbworks_nbnamelst *dst_name;
  void *payload;
  unsigned char do_del_pyldpyld;
  void *pyldpyld_delptr;
};

# define DTG_HDR_LEN (1+1+2+4+2)
struct dtg_srvc_packet {
  unsigned char for_del;
  unsigned char type;
  unsigned char flags;
  uint16_t id;
  ipv4_addr_t src_address;
  uint16_t src_port;
  enum dtg_packet_payload_t payload_t;
  void *payload;
  unsigned char error_code;
};

struct dtg_srvc_recvpckt {
  unsigned char for_del;
  struct nbworks_nbnamelst *dst;
  void *packetbuff;
  uint32_t len;
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
                              unsigned long len,
                              uint16_t *tid);
void *
  partial_dtg_srvc_pckt_reader(void *packet,
                               unsigned long len,
                               uint16_t *tid);
void *
  recving_dtg_srvc_pckt_reader(void *packet,
                               unsigned long len,
                               uint16_t *tid);
void *
  master_dtg_srvc_pckt_writer(void *packet_ptr,
                              unsigned long *pckt_len,
                              void *packet_field,
                              unsigned char placeholder);
void *
  sending_dtg_srvc_pckt_writer(void *packet_ptr,
                               unsigned long *pckt_len,
                               void *packt_field,
                               unsigned char placeholder);

void
  destroy_dtg_srvc_pckt(void *packet,
                        unsigned int placeholder1,
                        unsigned int placeholder2);
void
  destroy_dtg_srvc_recvpckt(void *packet_ptr,
                            unsigned int placeholder1,
                            unsigned int placeholder2);

#endif /* NBWORKS_DTGSRVCPCKT_H */
