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

#include "c_lang_extensions.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "dtg_srvc_pckt.h"

struct dtg_srvc_packet *read_dtg_packet_header(unsigned char **master_packet_walker,
                                               unsigned char *end_of_packet) {
  struct dtg_srvc_packet *packet;
  unsigned char *walker;

  if (! master_packet_walker)
    return 0;

  if ((! *master_packet_walker) ||
      ((*master_packet_walker + 10) > end_of_packet)) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

  packet = malloc(sizeof(struct dtg_srvc_packet));
  if (! packet) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  packet->for_del = 0;
  walker = *master_packet_walker;

  packet->type = *walker;
  walker++;
  packet->flags = *walker;
  walker++;
  walker = read_16field(walker, &(packet->id));
  walker = read_32field(walker, &(packet->src_address));
  walker = read_16field(walker, &(packet->src_port));

  *master_packet_walker = walker;

  return packet;
}

unsigned char *fill_dtg_packet_header(struct dtg_srvc_packet *content,
                                      unsigned char *field,
				      unsigned char *endof_pckt) {
  unsigned char *walker;

  if (! (content && field))
    return field;

  walker = field;

  if ((walker + 5*2) > endof_pckt) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return walker;
  }

  *walker = content->type;
  walker++;
  *walker = content->flags;
  walker++;
  walker = fill_16field(content->id, walker);
  walker = fill_32field(content->src_address, walker);
  walker = fill_16field(content->src_port, walker);

  return walker;
}

void *read_dtg_srvc_pckt_payload_data(struct dtg_srvc_packet *packet,
                                      unsigned char **master_packet_walker,
                                      unsigned char *start_of_packet,
                                      unsigned char *end_of_packet,
				      unsigned char read_allpyld) {
  struct dtg_pckt_pyld_normal *normal_pckt;
  unsigned char *walker, *remember_walker;

  if (! (packet && master_packet_walker))
    return 0;

  if (*master_packet_walker > end_of_packet ||
      *master_packet_walker < start_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = *master_packet_walker;

  switch (understand_dtg_pckt_type(packet->type)) {
  case normal:
    packet->payload_t = normal;
    if ((walker + 2 + (2*sizeof(uint16_t))) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      return 0;
    }
    normal_pckt = malloc(sizeof(struct dtg_pckt_pyld_normal));
    if (! normal_pckt) {
      /* TODO: errno signaling stuff */
      return 0;
    }

    walker = read_16field(walker, &(normal_pckt->len));
    walker = read_16field(walker, &(normal_pckt->offset));
    if ((walker + 2 + normal_pckt->len) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      free(normal_pckt);
      return 0;
    }

    /* read_all_DNS_labels() increments the walker by at least one. */
    remember_walker = walker +1;
    normal_pckt->src_name = read_all_DNS_labels(&walker, start_of_packet,
						end_of_packet, 0, 0, 0, 0);
    if (! normal_pckt->src_name) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      free(normal_pckt);
      return 0;
    }

    walker = align(remember_walker, walker, 4);
    if ((walker + 1 + normal_pckt->len) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      destroy_nbnodename(normal_pckt->src_name);
      free(normal_pckt);
      return 0;
    }

    remember_walker = walker +1;
    normal_pckt->dst_name = read_all_DNS_labels(&walker, start_of_packet,
						end_of_packet, 0, 0, 0, 0);
    if (! normal_pckt->dst_name) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      destroy_nbnodename(normal_pckt->src_name);
      free(normal_pckt);
      return 0;
    }

    /* However, maybe I should ignore alignment things
       and instead focus on the PACKET_OFFSET field. */

    walker = align(remember_walker, walker, 4);
    if ((walker + normal_pckt->len) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      destroy_nbnodename(normal_pckt->src_name);
      destroy_nbnodename(normal_pckt->dst_name);
      free(normal_pckt);
      return 0;
    }

    normal_pckt->pyldpyld_delptr = 0;
    if (read_allpyld) {
      normal_pckt->do_del_pyldpyld = TRUE;
      normal_pckt->payload = malloc(normal_pckt->len);
      if (! normal_pckt->payload) {
	/* TODO: errno signaling stuff */
	destroy_nbnodename(normal_pckt->src_name);
	destroy_nbnodename(normal_pckt->dst_name);
	free(normal_pckt);
	return 0;
      }
      walker = mempcpy(normal_pckt->payload, walker,
		       normal_pckt->len);
    } else {
      normal_pckt->do_del_pyldpyld = FALSE;
      normal_pckt->payload = walker;
      walker = walker + normal_pckt->len;
    }

    *master_packet_walker = walker;
    return normal_pckt;
    break;

  case error_code:
    packet->payload_t = error_code;
    packet->error_code = *walker;
    *master_packet_walker = walker +1;
    return 0;
    break;

  case nbnodename:
    packet->payload_t = nbnodename;
    return read_all_DNS_labels(master_packet_walker, start_of_packet,
			       end_of_packet, 0, 0, 0, 0);
    break;

  case bad_type_dtg:
  default:
    packet->payload_t = bad_type_dtg;
    return 0;
    break;
  }

  /* Never reached. */
  return 0;
}

unsigned char *fill_dtg_srvc_pckt_payload_data(struct dtg_srvc_packet *content,
					       unsigned char *field,
					       unsigned char *endof_pckt) {
  struct dtg_pckt_pyld_normal *normal_pckt;
  unsigned char *walker, *remember_walker, *save_walker;

  if ((! (content && field)) ||
      (field > endof_pckt))
    return field;

  walker = field;

  switch (content->payload_t) {
  case normal:
    if (! content->payload)
      return walker;
    normal_pckt = content->payload;
    if ((walker + normal_pckt->len +2+2*2) > endof_pckt) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      return walker;
    }
    walker = fill_16field(normal_pckt->len, walker);
    walker = fill_16field(normal_pckt->offset, walker);

    remember_walker = walker;

    walker = fill_all_DNS_labels(normal_pckt->src_name, walker,
				 endof_pckt, 0);

    save_walker = walker;
    walker = align(remember_walker, walker, 4);
    if ((walker + normal_pckt->len +1) > endof_pckt) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      memset(field, 0, (save_walker-field));
      return field;
    }

    walker = fill_all_DNS_labels(normal_pckt->dst_name, walker,
				 endof_pckt, 0);

    save_walker = walker;
    walker = align(remember_walker, walker, 4);
    if ((walker + normal_pckt->len) > endof_pckt) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      memset(field, 0, (save_walker-field));
      return field;
    }

    return mempcpy(walker, normal_pckt->payload,
		   normal_pckt->len);
    break;

  case error_code:
    if ((walker +1) > endof_pckt) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      return walker;
    }
    *walker = content->error_code;
    return walker +1;
    break;

  case nbnodename:
    if (! content->payload)
      return walker;
    return fill_all_DNS_labels(content->payload, walker,
			       endof_pckt, 0);
    break;

  case bad_type_dtg:
  default:
    return walker;
    break;
  }

  /* Never reached. */
  return walker;
}

inline enum dtg_packet_payload_t understand_dtg_pckt_type(unsigned char type_octet) {
  switch (type_octet) {
  case DIR_UNIQ_DTG:
  case DIR_GRP_DTG:
  case BRDCST_DTG:
    return normal;
    break;

  case DTG_ERROR:
    return error_code;
    break;

  case DTG_QRY_RQST:
  case DTG_POS_QRY_RSPNS:
  case DTG_NEG_QRY_RSPNS:
    return nbnodename;
    break;

  default:
    return bad_type_dtg;
    break;
  }

  /* Never reached. */
  return bad_type_dtg;
}


void *master_dtg_srvc_pckt_reader(void *packet,
				  int len,
				  uint16_t *tid) {
  struct dtg_srvc_packet *result;
  unsigned char *startof_pckt, *endof_pckt, *walker;

  if ((len <= 0) ||
      (! packet))
    return 0;

  startof_pckt = (unsigned char *)packet;
  walker = startof_pckt;
  endof_pckt = startof_pckt + len;

  result = read_dtg_packet_header(&walker, endof_pckt);
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->payload = read_dtg_srvc_pckt_payload_data(result, &walker,
						    startof_pckt, endof_pckt,
						    TRUE);

  if (tid)
    *tid = result->id;

  return (void *)result;
}

/* The difference to the master reader is in the call to
   read_dtg_srvc_pckt_payload_data(). */
void *partial_dtg_srvc_pckt_reader(void *packet,
				   int len,
				   uint16_t *tid) {
  struct dtg_srvc_packet *result;
  unsigned char *startof_pckt, *endof_pckt, *walker;

  if ((len <= 0) ||
      (! packet))
    return 0;

  startof_pckt = (unsigned char *)packet;
  walker = startof_pckt;
  endof_pckt = startof_pckt + len;

  result = read_dtg_packet_header(&walker, endof_pckt);
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->payload = read_dtg_srvc_pckt_payload_data(result, &walker,
						    startof_pckt, endof_pckt,
						    FALSE);

  if (tid)
    *tid = result->id;

  return (void *)result;
}

void *recving_dtg_srvc_pckt_reader(void *packet,
				   int len,
				   uint16_t *tid) {
  struct dtg_srvc_recvpckt *result;
  unsigned char *readhead, *startof_pckt;

  if ((! packet) ||
      (len < (DTG_HDR_LEN +2+2+1+1)))
    return 0;

  startof_pckt = packet;

  if (! ((*startof_pckt == DIR_UNIQ_DTG) ||
	 (*startof_pckt == DIR_GRP_DTG) ||
	 (*startof_pckt == BRDCST_DTG)))
    return 0;

  result = malloc(sizeof(struct dtg_srvc_recvpckt));
  if (! result)
    return 0;

  readhead = startof_pckt;
  readhead = readhead + (DTG_HDR_LEN +2+2);
  if (! fastfrwd_all_DNS_labels(&readhead, (packet + len))) {
    free(result);
    return 0;
  }

  align(startof_pckt, readhead, 4);

  result->dst = read_all_DNS_labels(&readhead, packet, (startof_pckt + len),
				    0, 0, 0, 0);
  if (! result->dst) {
    free(result);
    return 0;
  }

  result->packetbuff = malloc(len);
  if (! result->packetbuff) {
    destroy_nbnodename(result->dst);
    free(result);
    return 0;
  }
  memcpy(result->packetbuff, packet, len);

  result->len = len;

  if (tid) {
    readhead = result->packetbuff;
    readhead = readhead +1+1;
    *tid = *((uint16_t *)readhead);
  }

  return result;
}

void *master_dtg_srvc_pckt_writer(void *packet_ptr,
				  unsigned int *pckt_len,
				  void *packet_field,
				  unsigned char placeholder) {
  struct dtg_srvc_packet *packet;
  unsigned char *result, *walker, *endof_pckt;

  if (! (packet_ptr && pckt_len)) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  packet = packet_ptr;

  if (packet_field) {
    result = packet_field;
  } else {
    result = calloc(1, *pckt_len);
    if (! result) {
      /* TODO: errno signaling stuff */
      return 0;
    }
  }

  walker = result;
  endof_pckt = result + *pckt_len;

  walker = fill_dtg_packet_header(packet, walker, endof_pckt);
  walker = fill_dtg_srvc_pckt_payload_data(packet, walker, endof_pckt);

  *pckt_len = walker - result;
  return (void *)result;
}


void destroy_dtg_srvc_pckt(void *packet_ptr,
			   unsigned int placeholder1,
			   unsigned int placeholder2) {
  struct dtg_srvc_packet *packet;
  struct dtg_pckt_pyld_normal *normal_pyld;

  if (! packet_ptr)
    return;

  packet = packet_ptr;

  if (packet->payload_t == normal) {
    normal_pyld = packet->payload;

    destroy_nbnodename(normal_pyld->src_name);
    destroy_nbnodename(normal_pyld->dst_name);
    if (normal_pyld->do_del_pyldpyld)
      free(normal_pyld->payload);
    else
      free(normal_pyld->pyldpyld_delptr);
    free(normal_pyld);
  } else
    if (packet->payload_t == nbnodename)
      destroy_nbnodename(packet->payload);
    else
      free(packet->payload);

  free(packet);

  return;
}

void destroy_dtg_srvc_recvpckt(void *packet_ptr,
			       unsigned int placeholder1,
			       unsigned int placeholder2) {
  struct dtg_srvc_recvpckt *pckt;

  if (! packet_ptr)
    return;

  pckt = packet_ptr;

  destroy_nbnodename(pckt->dst);
  free(pckt->packetbuff);
  free(pckt);

  return;
}
