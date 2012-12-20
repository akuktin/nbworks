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

  if ((*master_packet_walker + 10) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

  packet = malloc(sizeof(struct dtg_srvc_packet));
  if (! packet) {
    /* TODO: errno signaling stuff */
    return 0;
  }
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
                                      unsigned char *field) {
  unsigned char *walker;

  walker = field;

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
                                      unsigned char *end_of_packet) {
  struct dtg_pckt_pyld_normal *normal_pckt;
  unsigned char *walker, *remember_walker;

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
    if ((walker + 2 + normal_pckt->len) >= end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      free(normal_pckt);
      return 0;
    }

    /* read_all_DNS_labels() increments the walker by at least one. */
    remember_walker = walker +1;
    normal_pckt->src_name = read_all_DNS_labels(&walker, start_of_packet,
						end_of_packet);
    if (! normal_pckt->src_name) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      free(normal_pckt);
      return 0;
    }

    walker = (walker +
              ((4- ((walker - remember_walker) %4)) %4));
    if ((walker + 1 + normal_pckt->len) >= end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      free(normal_pckt->src_name);
      free(normal_pckt);
      return 0;
    }

    remember_walker = walker +1;
    normal_pckt->dst_name = read_all_DNS_labels(&walker, start_of_packet,
						end_of_packet);
    if (! normal_pckt->dst_name) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      free(normal_pckt->src_name);
      free(normal_pckt);
      return 0;
    }

    /* However, maybe I should ignore alignment things
       and instead focus on the PACKET_OFFSET field. */

    walker = (walker +
              ((4- ((walker - remember_walker) %4)) %4));
    if ((walker + normal_pckt->len) >= end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      free(normal_pckt->src_name);
      free(normal_pckt->dst_name);
      free(normal_pckt);
      return 0;
    }

    normal_pckt->payload = malloc(normal_pckt->len);
    if (! normal_pckt->payload) {
      /* TODO: errno signaling stuff */
      free(normal_pckt->src_name);
      free(normal_pckt->dst_name);
      free(normal_pckt);
      return 0;
    }
    walker = mempcpy(normal_pckt->payload, walker,
		     normal_pckt->len);

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
			       end_of_packet);
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
					       unsigned char *field) {
  struct dtg_pckt_pyld_normal *normal_pckt;
  unsigned char *walker, *remember_walker;

  walker = field;

  switch (content->payload_t) {
  case normal:
    normal_pckt = content->payload;
    walker = fill_16field(normal_pckt->len, walker);
    walker = fill_16field(normal_pckt->offset, walker);

    remember_walker = walker;

    walker = fill_all_DNS_labels(normal_pckt->src_name, walker);
    walker = (walker +
              ((4- ((walker - remember_walker) %4)) %4));

    walker = fill_all_DNS_labels(normal_pckt->dst_name, walker);
    walker = (walker +
              ((4- ((walker - remember_walker) %4)) %4));

    walker = mempcpy(walker, normal_pckt->payload,
		     normal_pckt->len);

    return walker;
    break;

  case error_code:
    *walker = content->error_code;
    walker++;
    return walker;
    break;

  case nbnodename:
    walker = fill_all_DNS_labels(content->payload, walker);
    return walker;
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


struct dtg_srvc_packet *master_dtg_srvc_pckt_reader(void *packet,
						    int len) {
  struct dtg_srvc_packet *result;
  unsigned char *startof_pckt, *endof_pckt, *walker;

  if (len <= 0) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  startof_pckt = (unsigned char *)packet;
  walker = startof_pckt;
  endof_pckt = startof_pckt + len;

  result = read_dtg_packet_header(&walker, endof_pckt);
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->payload = read_dtg_srvc_pckt_payload_data(result, &walker,
						    startof_pckt, endof_pckt);

  return result;
}
