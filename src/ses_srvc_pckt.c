/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "c_lang_extensions.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "ses_srvc_pckt.h"

struct ses_srvc_packet *read_ses_srvc_pckt_header(unsigned char **master_packet_walker,
					          unsigned char *end_of_packet,
						  struct ses_srvc_packet *field) {
  struct ses_srvc_packet *packet;
  unsigned char *walker;

  if (! master_packet_walker)
    return 0;

  if ((*master_packet_walker + 4) > end_of_packet) {
    OUT_OF_BOUNDS(43);
    /* TODO: errno signaling stuff */
    return 0;
  }

  if (field) {
    packet = field;
  } else {
    packet = malloc(sizeof(struct ses_srvc_packet));
    if (! packet) {
      /* TODO: errno signaling stuff */
      return 0;
    }
  }
  packet->for_del = 0;
  walker = *master_packet_walker;

  packet->type = *walker;
  walker++;
  packet->flags = (*walker & 0xfe) >> 1;
  packet->len = (*walker & 0x01) << 8;
  walker++;
  packet->len = (packet->len | *walker) << 8;
  walker++;
  packet->len = packet->len | *walker;

  *master_packet_walker = walker +1;

  return packet;
}

unsigned char *fill_ses_packet_header(struct ses_srvc_packet *content,
				      unsigned char *field,
				      unsigned char *endof_pckt) {
  unsigned char *walker;

  if (! (content && field))
    return field;

  walker = field;

  if ((walker +4) > endof_pckt) {
    OUT_OF_BOUNDS(44);
    /* TODO: errno signaling stuff */
    return walker;
  }

  *walker = content->type;
  walker++;
  *walker = content->flags << 1;
  *walker = *walker | ((content->len & 0x10000) >> 16);
  walker++;
  *walker = (content->len & 0x0ff00) >> 8;
  walker++;
  *walker = content->len & 0x000ff;

  return walker +1;
}

void *read_ses_srvc_pckt_payload_data(struct ses_srvc_packet *packet,
				      unsigned char **master_packet_walker,
				      unsigned char *start_of_packet,
				      unsigned char *end_of_packet) {
  struct ses_pckt_pyld_two_names *two_names_payload;
  struct ses_srvc_retarget_blob_rfc1002 *retarget_payload;
  unsigned char *walker, *remember_walker;
  void *payload_ptr;

  if (! master_packet_walker)
    return 0;

  if ((*master_packet_walker < start_of_packet) ||
      (*master_packet_walker > end_of_packet)) {
    OUT_OF_BOUNDS(45);
    /* TODO: errno signaling stuff */
    packet->payload_t = unknown_ses;
    return 0;
  }

  walker = *master_packet_walker;
  if ((walker + packet->len) > end_of_packet) {
    OUT_OF_BOUNDS(46);
    *master_packet_walker = end_of_packet;
    return 0;
  } else
    *master_packet_walker = walker + packet->len;

  switch (understand_ses_pckt_type(packet->type)) {
  case two_names:
    packet->payload_t = two_names;
    if ((walker +2) > end_of_packet) {
      OUT_OF_BOUNDS(47);
      /* TODO: errno signaling stuff */
      return 0;
    }
    two_names_payload = malloc(sizeof(struct ses_pckt_pyld_two_names));
    if (! two_names_payload) {
      /* TODO: errno signaling stuff */
      return 0;
    }

    /* read_all_DNS_labels() is guaranteed to
       increase the pointer by at least one. */
    remember_walker = walker +1;
    two_names_payload->called_name =
      read_all_DNS_labels(&walker, start_of_packet, end_of_packet,
                          0, 0, 0, 0);
    if (! two_names_payload->called_name) {
      DIDNT_READ_NAME(5);
      free(two_names_payload);
      return 0;
    }

    walker = align(remember_walker, walker, 4);

    if ((walker +1) > end_of_packet) {
      OUT_OF_BOUNDS(48);
      /* TODO: errno signaling stuff */
      nbworks_dstr_nbnodename(two_names_payload->called_name);
      free(two_names_payload);
      return 0;
    }

    two_names_payload->calling_name =
      read_all_DNS_labels(&walker, start_of_packet, end_of_packet,
                          0, 0, 0, 0);
    if (! two_names_payload->calling_name) {
      DIDNT_READ_NAME(6);
      /* TODO: errno signaling stuff */
      nbworks_dstr_nbnodename(two_names_payload->called_name);
      free(two_names_payload);
      return 0;
    }

    return two_names_payload;
    break;

  case null:
    packet->payload_t = null;
    return 0;
    break;

  case error_code_ses:
    packet->payload_t = error_code_ses;
    if (walker < end_of_packet) {
      packet->error_code = *walker;
    } else {
      OUT_OF_BOUNDS(49);
    }
    return 0;
    break;

  case retarget_blob_rfc1002:
    packet->payload_t = retarget_blob_rfc1002;
    if ((walker + 4 + 2) > end_of_packet) {
      OUT_OF_BOUNDS(50);
      /* TODO: errno signaling stuff */
      return 0;
    }
    retarget_payload = malloc(sizeof(struct ses_srvc_retarget_blob_rfc1002));
    if (! retarget_payload) {
      /* TODO: errno signaling stuff */
      return 0;
    }

    walker = read_32field(walker, &(retarget_payload->new_address));
    walker = read_16field(walker, &(retarget_payload->new_port));
    return retarget_payload;
    break;

  case payloadpayload:
    packet->payload_t = payloadpayload;
    /* Bounds already checked. */
    payload_ptr = malloc(packet->len);
    if (! payload_ptr) {
      /* TODO: errno signaling stuff */
      return packet;
    }
    memcpy(payload_ptr, walker, packet->len);
    return payload_ptr;
    break;

  case bad_type_ses:
  default:
    packet->payload_t = bad_type_ses;
    return 0;
  }

  /* Never reached. */
  return 0;
}

unsigned char *fill_ses_srvc_pckt_payload_data(struct ses_srvc_packet *content,
					       unsigned char *field,
					       unsigned char *endof_pckt) {
  struct ses_pckt_pyld_two_names *two_names_payload;
  struct ses_srvc_retarget_blob_rfc1002 *retarget_payload;
  unsigned char *walker, *endof_buff, *save_walker, *remember_walker;

  if (! (content && field))
    return field;

  if ((field + content->len) > endof_pckt) {
    OUT_OF_BOUNDS(51);
    return field;
  }
  walker = field;
  endof_buff = walker + content->len;

  switch (content->payload_t) {
  case two_names:
    if (! content->payload) {
      BULLSHIT_IN_PACKET(4);
      memset(field, 0, content->len);
      return endof_buff;
    }

    two_names_payload = content->payload;
    if ((walker +2) > endof_buff) {
      OUT_OF_BOUNDS(52);
      memset(field, 0, content->len);
      return field;
    }

    remember_walker = walker +1;
    walker = fill_all_DNS_labels(two_names_payload->called_name, walker,
				 endof_pckt, 0);

    save_walker = walker;
    walker = align(remember_walker, walker, 4);
    if ((walker +1) > endof_buff) {
      OUT_OF_BOUNDS(53);
      memset(field, 0, content->len);
      return field;
    }
    if (save_walker < walker)
      memset(save_walker, 0, (walker - save_walker));

    walker = fill_all_DNS_labels(two_names_payload->calling_name, walker,
				 endof_pckt, 0);
    if (walker > endof_buff) {
      OUT_OF_BOUNDS(54);
      memset(field, 0, content->len);
      return field;
    }
    if (endof_buff > walker)
      memset(walker, 0, (endof_buff - walker));
    return endof_buff;
    break;

  case null:
    memset(field, 0, content->len);
    return endof_buff;
    break;

  case error_code_ses:
    if ((walker +1) > endof_buff) {
      OUT_OF_BOUNDS(55);
      memset(field, 0, content->len);
      return field;
    }
    *walker = content->error_code;
    walker++;
    if (endof_buff > walker)
      memset(walker, 0, (endof_buff - walker));
    return endof_buff;
    break;

  case retarget_blob_rfc1002:
    if (! content->payload) {
      BULLSHIT_IN_PACKET(7);
      memset(field, 0, content->len);
      return endof_buff;
    }

    if ((walker +4+2) > endof_buff) {
      OUT_OF_BOUNDS(56);
      memset(field, 0, content->len);
      return field;
    }
    retarget_payload = content->payload;
    walker = fill_32field(retarget_payload->new_address, walker);
    walker = fill_16field(retarget_payload->new_port, walker);
    if (endof_buff > walker)
      memset(walker, 0, (endof_buff - walker));
    return endof_buff;
    break;

  case payloadpayload:
    if (! content->payload) {
      BULLSHIT_IN_PACKET(8);
      memset(field, 0, content->len);
      return endof_buff;
    }

    /* Bounds already checked. */
    memcpy(walker, content->payload, content->len);
    return endof_buff;
    break;

  case bad_type_ses:
  default:
    memset(field, 0, content->len);
    return endof_buff;
    break;
  }

  /* Never reached. */
  memset(field, 0, content->len);
  return endof_buff;
}

inline enum ses_packet_payload_t understand_ses_pckt_type(unsigned char type_octet) {
  switch (type_octet) {
  case SESSION_REQUEST:
    return two_names;
    break;

  case POS_SESSION_RESPONSE:
    return null;
    break;

  case NEG_SESSION_RESPONSE:
    return error_code_ses;
    break;

  case RETARGET_SESSION:
    return retarget_blob_rfc1002;
    break;

  case SESSION_MESSAGE:
    return payloadpayload;
    break;

  case SESSION_KEEP_ALIVE:
    return null;
    break;

  default:
    return bad_type_ses;
    break;
  }

  /* Never reached. */
  return unknown_ses;
}


struct ses_srvc_packet *master_ses_srvc_pckt_reader(void *packet,
						    unsigned long len) {
  struct ses_srvc_packet *result;
  unsigned char *startof_pckt, *endof_pckt, *walker;

  if ((len <= 0) ||
      (! packet))
    return 0;

  startof_pckt = (unsigned char *)packet;
  walker = startof_pckt;
  endof_pckt = startof_pckt + len;

  result = read_ses_srvc_pckt_header(&walker, endof_pckt, 0);
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->payload = read_ses_srvc_pckt_payload_data(result, &walker,
						    startof_pckt, endof_pckt);

  return result;
}

/* Call with whole packet, len is total len of whole packet. */
struct nbworks_nbnamelst *ses_srvc_get_calledname(void *packet,
						  unsigned long len) {
  unsigned char *walker, *startof_pckt;

  if ((! packet) ||
      (len < (2 + SES_HEADER_LEN))) {
    OUT_OF_BOUNDS(65);
    return 0;
  }

  startof_pckt = packet;
  walker = startof_pckt + SES_HEADER_LEN;

  return read_all_DNS_labels(&walker, startof_pckt, (startof_pckt + len),
                             0, 0, 0, 0);
}

/* Call with whole packet, len is total len of whole packet. */
struct nbworks_nbnamelst *ses_srvc_get_callingname(void *packet_ptr,
						   unsigned long len) {
  unsigned char *packet;
  unsigned char *walker;

  if ((! packet_ptr) ||
      (len < (2 + SES_HEADER_LEN))) {
    OUT_OF_BOUNDS(66);
    return 0;
  } else {
    packet = packet_ptr;
  }

  walker = packet + SES_HEADER_LEN;

  fastfrwd_all_DNS_labels(&walker, packet+len);

  align(packet, walker, 4);
  if (walker >= (packet + len)) {
    OUT_OF_BOUNDS(57);
    return 0;
  }

  return read_all_DNS_labels(&walker, packet, (packet + len), 0, 0, 0, 0);
}

void *master_ses_srvc_pckt_writer(void *packet_ptr,
				  unsigned long *pckt_len,
				  void *packet_field) {
  struct ses_srvc_packet *packet;
  unsigned char *result, *walker, *endof_pckt;

  if (! (packet_ptr && pckt_len)) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  if (*pckt_len < SES_HEADER_LEN) {
    *pckt_len = 0;
    return packet_ptr;
  }

  packet = packet_ptr;

  if (packet_field) {
    result = packet_field;
  } else {
    result = nbw_calloc(1, *pckt_len);
    if (! result) {
      /* TODO: errno signaling stuff */
      return 0;
    }
  }

  walker = result;
  endof_pckt = result + *pckt_len;

  walker = fill_ses_packet_header(packet, walker, endof_pckt);
  walker = fill_ses_srvc_pckt_payload_data(packet, walker,
					   endof_pckt);

  *pckt_len = walker - result;
  return result;
}


void destroy_ses_srvc_pcktpyld(struct ses_srvc_packet *pckt) {
  struct ses_pckt_pyld_two_names *two_names_ptr;

  if (! pckt)
    return;

  if (pckt->payload) {
    if (pckt->payload_t == two_names) {
      two_names_ptr = pckt->payload;
      nbworks_dstr_nbnodename(two_names_ptr->called_name);
      nbworks_dstr_nbnodename(two_names_ptr->calling_name);
    }

    free(pckt->payload);
  }

  return;
}

void destroy_ses_srvc_pckt(struct ses_srvc_packet *pckt) {
  struct ses_pckt_pyld_two_names *two_names_ptr;

  if (! pckt)
    return;

  if (pckt->payload) {
    if (pckt->payload_t == two_names) {
      two_names_ptr = pckt->payload;
      nbworks_dstr_nbnodename(two_names_ptr->called_name);
      nbworks_dstr_nbnodename(two_names_ptr->calling_name);
    }

    free(pckt->payload);
  }

  free(pckt);

  return;
}
