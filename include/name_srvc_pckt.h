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

#ifndef NBWORKS_NAMESRVCPCKT_H
# define NBWORKS_NAMESRVCPCKT_H 1

# include <stdint.h>

# include "nodename.h"

# define ISGROUP_YES   1
# define ISGROUP_NO    2


# define QTYPE_NB      0x0020
# define QTYPE_NBSTAT  0x0021

# define QCLASS_IN     0x0001

# define RRTYPE_A      0x0001
# define RRTYPE_NS     0x0002
# define RRTYPE_NULL   0x000a
# define RRTYPE_NB     0x0020
# define RRTYPE_NBSTAT 0x0021

# define RRCLASS_IN    0x0001


# define OPCODE_REQUEST      0x00
# define OPCODE_RESPONSE     0x10

# define OPCODE_MASK         0x0f

# define OPCODE_QUERY        0x00
# define OPCODE_REGISTRATION 0x05
# define OPCODE_RELEASE      0x06
# define OPCODE_WACK         0x07
# define OPCODE_REFRESH      0x08
# define OPCODE_REFRESH2     0x09


/* nm_flag */
# define FLG_B  0x01 /* Packet is broadcast. */
# define FLG_RA 0x08 /* Recursion available. */
# define FLG_RD 0x10 /* Recursion desired. */
# define FLG_TC 0x20 /* Truncated. */
# define FLG_AA 0x40 /* Authoritative answer. */


/* rcode */
# define RCODE_FMT_ERR 0x1 /* Request was incorrectly formated. */
# define RCODE_SRV_ERR 0x2 /* NBNS server failed. */
# define RCODE_NAM_ERR 0x3 /* Requested name does not exist. */
# define RCODE_IMP_ERR 0x4 /* Not implemented or implementation error. */
# define RCODE_RFS_ERR 0x5 /* Refused. Against the policy. */
# define RCODE_ACT_ERR 0x6 /* Name in active use by someone else. */
# define RCODE_CFT_ERR 0x7 /* Name in conflict. */


/* nbaddress_list */
# define NBADDRLST_GROUP_MASK 0x8000
# define NBADDRLST_NODET_MASK 0x6000

# define NBADDRLST_GROUP_YES  0x8000
# define NBADDRLST_GROUP_NO   0x0000

# define NBADDRLST_NODET_B    0x0000
# define NBADDRLST_NODET_P    0x2000
# define NBADDRLST_NODET_M    0x4000
# define NBADDRLST_NODET_H    0x6000


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

struct name_srvc_question_lst {
  struct name_srvc_question *qstn;
  struct name_srvc_question_lst *next;
};

struct name_srvc_resource_lst {
  struct name_srvc_resource *res;
  struct name_srvc_resource_lst *next;
};

struct name_srvc_packet {
  unsigned char for_del;
  struct name_srvc_pckt_header *header;
  struct name_srvc_question_lst *questions;
  struct name_srvc_resource_lst *answers;
  struct name_srvc_resource_lst *authorities;
  struct name_srvc_resource_lst *aditionals;
};

struct name_srvc_pckt_header *
  read_name_srvc_pckt_header(unsigned char **master_packet_walker,
                             unsigned char *end_of_packet);
unsigned char *
  fill_name_srvc_pckt_header(const struct name_srvc_pckt_header *header,
                             unsigned char *field,
                             unsigned char *end_of_packet);
struct name_srvc_question *
  read_name_srvc_pckt_question(unsigned char **master_packet_walker,
                               unsigned char *start_of_packet,
                               unsigned char *end_of_packet);
unsigned char *
  fill_name_srvc_pckt_question(struct name_srvc_question *question,
                               unsigned char *field,
                               unsigned char *end_of_packet);
struct name_srvc_resource *
  read_name_srvc_resource(unsigned char **master_packet_walker,
                          unsigned char *start_of_packet,
                          unsigned char *end_of_packet);
unsigned char *
  fill_name_srvc_resource(struct name_srvc_resource *resource,
                          unsigned char *field,
                          unsigned char *end_of_packet);
void *
  read_name_srvc_resource_data(unsigned char **start_and_end_of_walk,
                               struct name_srvc_resource *resource,
                               unsigned char *start_of_packet,
                               unsigned char *end_of_packet);
unsigned char *
  fill_name_srvc_resource_data(struct name_srvc_resource *content,
                               unsigned char *field,
                               unsigned char *end_of_packet);
inline enum name_srvc_rdata_type
  name_srvc_understand_resource(uint16_t rrtype,
                                uint16_t rrclass);

void *
  master_name_srvc_pckt_reader(void *packet,
                               int len,
                               uint16_t *tid);
void *
  master_name_srvc_pckt_writer(void *packet_ptr,
                               unsigned int *pckt_len,
                               void *packet_field);
struct name_srvc_packet *
  alloc_name_srvc_pckt(unsigned int qstn,
                       unsigned int answ,
                       unsigned int auth,
                       unsigned int adit);
void
  destroy_name_srvc_pckt(void *packet,
                         unsigned int complete,
                         unsigned int really_complete);
void
  destroy_name_srvc_res_lst(struct name_srvc_resource_lst *cur_res,
                            unsigned int complete,
                            unsigned int really_complete);

#endif /* NBWORKS_NAMESRVCPCKT_H */
