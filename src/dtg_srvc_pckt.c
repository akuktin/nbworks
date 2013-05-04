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
    OUT_OF_BOUNDS(23);
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
    OUT_OF_BOUNDS(24);
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
  unsigned char *walker, *remember_walker, *endof_buff;

  if (! (packet && master_packet_walker))
    return 0;

  /* There must be at least one octet for us to read. */
  if (*master_packet_walker > end_of_packet ||
      *master_packet_walker < start_of_packet) {
    OUT_OF_BOUNDS(25);
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = *master_packet_walker;

  switch (understand_dtg_pckt_type(packet->type)) {
  case normal:
    packet->payload_t = normal;
    if ((walker + 2 + (2*2)) > end_of_packet) {
      OUT_OF_BOUNDS(26);
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
    if ((normal_pckt->len <= 2) ||
	((walker + normal_pckt->len) > end_of_packet)) {
      if ((walker + normal_pckt->len) > end_of_packet) {
	OUT_OF_BOUNDS(27);
      }
      if (normal_pckt->len <= 2) {
	BULLSHIT_IN_PACKET(6);
      }
      free(normal_pckt);
      return 0;
    }
    /* Set the new bound. */
    endof_buff = walker + normal_pckt->len;

    /* read_all_DNS_labels() increments the walker by at least one. */
    remember_walker = walker +1;
    normal_pckt->src_name = read_all_DNS_labels(&walker, start_of_packet,
						end_of_packet, 0, 0, 0, 0);
    if (! normal_pckt->src_name) {
      DIDNT_READ_NAME(3);
      free(normal_pckt);
      return 0;
    }

    walker = align(remember_walker, walker, 4);
    if (walker >= endof_buff) {
      OUT_OF_BOUNDS(28);
      nbworks_dstr_nbnodename(normal_pckt->src_name);
      free(normal_pckt);
      return 0;
    }

    remember_walker = walker +1;
    normal_pckt->dst_name = read_all_DNS_labels(&walker, start_of_packet,
						end_of_packet, 0, 0, 0, 0);
    if (! normal_pckt->dst_name) {
      DIDNT_READ_NAME(4);
      nbworks_dstr_nbnodename(normal_pckt->src_name);
      free(normal_pckt);
      return 0;
    }

    /* However, maybe I should ignore alignment things. */
    walker = align(remember_walker, walker, 4);

    if (walker > endof_buff) {
      OUT_OF_BOUNDS(29);
      nbworks_dstr_nbnodename(normal_pckt->src_name);
      nbworks_dstr_nbnodename(normal_pckt->dst_name);
      free(normal_pckt);
      return 0;
    }

    normal_pckt->pyldpyld_delptr = 0;
    normal_pckt->lenof_data = endof_buff - walker;
    if (read_allpyld) {
      normal_pckt->do_del_pyldpyld = TRUE;
      normal_pckt->payload = malloc(normal_pckt->lenof_data);
      if (! normal_pckt->payload) {
	/* TODO: errno signaling stuff */
	nbworks_dstr_nbnodename(normal_pckt->src_name);
	nbworks_dstr_nbnodename(normal_pckt->dst_name);
	free(normal_pckt);
	return 0;
      }
      walker = mempcpy(normal_pckt->payload, walker,
		       normal_pckt->lenof_data);
    } else {
      normal_pckt->do_del_pyldpyld = FALSE;
      normal_pckt->payload = walker;
      walker = endof_buff;
    }

    *master_packet_walker = walker;
    return normal_pckt;
    break;

  case error_code:
    packet->payload_t = error_code;
    if (walker < end_of_packet) {
      packet->error_code = *walker;
      *master_packet_walker = walker +1;
    }
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
    if (((walker + normal_pckt->len +2+2) > endof_pckt) ||
	(normal_pckt->len <= 2)) {
      if ((walker + normal_pckt->len +2+2) > endof_pckt) {
	OUT_OF_BOUNDS(30);
      }
      if (normal_pckt->len <= 2) {
	BULLSHIT_IN_PACKET(5);
      }
      return walker;
    }
    walker = fill_16field(normal_pckt->len, walker);
    walker = fill_16field(normal_pckt->offset, walker);

    /* Set the new bound. */
    endof_pckt = walker + normal_pckt->len;

    remember_walker = walker;

    walker = fill_all_DNS_labels(normal_pckt->src_name, walker,
				 endof_pckt, 0);

    save_walker = walker;
    walker = align(remember_walker, walker, 4);
    if ((walker + normal_pckt->lenof_data +1) > endof_pckt) {
      OUT_OF_BOUNDS(31);
      memset(field, 0, (save_walker-field));
      return field;
    }
    if (save_walker < walker)
      memset(save_walker, 0, (walker - save_walker));

    walker = fill_all_DNS_labels(normal_pckt->dst_name, walker,
				 endof_pckt, 0);

    save_walker = walker;
    walker = align(remember_walker, walker, 4);
    if ((walker + normal_pckt->lenof_data) > endof_pckt) {
      OUT_OF_BOUNDS(32);
      memset(field, 0, (save_walker-field));
      return field;
    }
    if (save_walker < walker)
      memset(save_walker, 0, (walker - save_walker));

    return mempcpy(walker, normal_pckt->payload,
		   normal_pckt->lenof_data);
    break;

  case error_code:
    if ((walker +1) > endof_pckt) {
      OUT_OF_BOUNDS(33);
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
				  unsigned long len,
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
				   unsigned long len,
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
				   unsigned long len,
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
  result->for_del = 0;

  readhead = startof_pckt;
  readhead = readhead + (DTG_HDR_LEN +2+2);
  if (0 == fastfrwd_all_DNS_labels(&readhead, (startof_pckt + len))) {
    DIDNT_READ_NAME(7);
    free(result);
    return 0;
  }

  align(startof_pckt, readhead, 4);

  result->dst = read_all_DNS_labels(&readhead, packet, (startof_pckt + len),
				    0, 0, 0, 0);
  if (! result->dst) {
    DIDNT_READ_NAME(8);
    free(result);
    return 0;
  }

  result->packetbuff = malloc(len);
  if (! result->packetbuff) {
    nbworks_dstr_nbnodename(result->dst);
    free(result);
    return 0;
  }
  memcpy(result->packetbuff, packet, len);

  result->len = len;

  if (tid) {
    readhead = result->packetbuff;
    readhead = readhead +1+1;
    /* VAXism below */
    read_16field(readhead, tid);
  }

  return result;
}

void *master_dtg_srvc_pckt_writer(void *packet_ptr,
				  unsigned long *pckt_len,
				  void *packet_field,
				  unsigned char placeholder) {
  struct dtg_srvc_packet *packet;
  unsigned char *result, *walker, *endof_pckt;

  if (! (packet_ptr && pckt_len)) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  packet = packet_ptr;

  if (*pckt_len < DTG_HDR_LEN) {
    /* TODO: errno signaling stuff */
    *pckt_len = 0;
    return packet_field;
  }
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
  if (walker == result) {
    goto endof_function;
  }
  walker = fill_dtg_srvc_pckt_payload_data(packet, walker, endof_pckt);

 endof_function:
  *pckt_len = walker - result;
  return (void *)result;
}

void *sending_dtg_srvc_pckt_writer(void *packet_ptr,
				   unsigned long *pckt_len,
				   void *packet_field,
				   unsigned char placeholder) {
  struct dtg_srvc_recvpckt *packet;
  unsigned char *result;

  if (! (packet_ptr && pckt_len)) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  packet = packet_ptr;

  if (packet->len > *pckt_len) {
    /* TODO: errno signaling stuff */
    *pckt_len = 0;
    return packet_field;
  }

  if (packet_field) {
    result = packet_field;
  } else {
    result = calloc(1, *pckt_len);
    if (! result) {
      /* TODO: errno signaling stuff */
      return 0;
    }
  }

  memcpy(result, packet->packetbuff, packet->len);

  *pckt_len = packet->len;
  return result;
}


void destroy_dtg_srvc_pckt(void *packet_ptr,
			   unsigned int placeholder1,
			   unsigned int placeholder2) {
  struct dtg_srvc_packet *packet;
  struct dtg_pckt_pyld_normal *normal_pyld;

  if (! packet_ptr)
    return;

  packet = packet_ptr;

  if (packet->payload) {
    if (packet->payload_t == normal) {
      normal_pyld = packet->payload;

      nbworks_dstr_nbnodename(normal_pyld->src_name);
      nbworks_dstr_nbnodename(normal_pyld->dst_name);
      if (normal_pyld->do_del_pyldpyld)
	free(normal_pyld->payload);
      else
	free(normal_pyld->pyldpyld_delptr);
      free(normal_pyld);
    } else
      if (packet->payload_t == nbnodename)
	nbworks_dstr_nbnodename(packet->payload);
      else
	free(packet->payload);
  }

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

  nbworks_dstr_nbnodename(pckt->dst);
  free(pckt->packetbuff);
  free(pckt);

  return;
}
