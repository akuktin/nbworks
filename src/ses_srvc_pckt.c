#include "c_lang_extensions.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "ses_srvc_pckt.h"

struct ses_srvc_packet *read_ses_packet_header(unsigned char **master_packet_walker,
					       unsigned char *end_of_packet) {
  struct ses_srvc_packet *packet;
  unsigned char *walker;

  if ((*master_packet_walker + 4) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

  packet = malloc(sizeof(struct ses_srvc_packet));
  if (! packet) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  walker = *master_packet_walker;

  packet->type = *walker;
  walker++;
  packet->flags = (*walker & 0xfe) >> 1;
  packet->len = (*walker & 0x01) << 8;
  walker++;
  packet->len = (packet->len & *walker) << 8;
  walker++;
  packet->len = packet->len & *walker;

  *master_packet_walker = walker +1;

  return packet;
}

unsigned char *fill_ses_packet_header(struct ses_srvc_packet *content,
				      unsigned char *field) {
  unsigned char *walker;

  walker = field;

  *walker = content->type;
  walker++;
  *walker = content->flags << 1;
  *walker = *walker | ((content->len & 0x100) >> 16);
  walker++;
  *walker = (content->len & 0x0f0) >> 8;
  walker++;
  *walker = content->len & 0x00f;

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

  if (*master_packet_walker > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    packet->payload_t = unknown;
    return 0;
  }

  walker = *master_packet_walker;

  switch (understand_ses_pckt_type(packet->type)) {
  case two_names:
    packet->payload_t = two_names;
    if ((walker +2) > end_of_packet) {
      /* OUT_OF_BOUNDS */
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
    two_names_payload->called_name = read_all_DNS_labels(&walker, start_of_packet,
							 end_of_packet);
    if (! two_names_payload->called_name) {
      /* TODO: errno signaling stuff */
      free(two_names_payload);
      return 0;
    }

    walker = (walker +
	      ((4- ((walker - remember_walker) %4)) %4));

    if ((walker +1) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      free(two_names_payload->called_name);
      free(two_names_payload);
      return 0;
    }

    two_names_payload->calling_name = read_all_DNS_labels(&walker, start_of_packet,
							  end_of_packet);
    if (! two_names_payload->calling_name) {
      /* TODO: errno signaling stuff */
      free(two_names_payload->called_name);
      free(two_names_payload);
      return 0;
    }

    /* No aligning do the 32-bit boundary in this case. */
    *master_packet_walker = walker;
    return two_names_payload;
    break;

  case null:
    packet->payload_t = null;
    return 0;
    break;

  case error_code:
    packet->payload_t = error_code;
    packet->error_code = *walker;
    *master_packet_walker = walker +1;
    return 0;
    break;

  case retarget_blob_rfc1002:
    packet->payload_t = retarget_blob_rfc1002;
    if ((walker + sizeof(uint32_t) + sizeof(uint16_t)) > end_of_packet) {
      /* OUT_OF_BOUNDS */
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
    *master_packet_walker = walker;
    return retarget_payload;
    break;

  case payloadpayload:
    packet->payload_t = payloadpayload;
    if ((walker + packet->len) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      return 0;
    }
    payload_ptr = malloc(packet->len);
    if (! payload_ptr) {
      /* TODO: errno signaling stuff */
      return packet;
    }
    *master_packet_walker = mempcpy(payload_ptr, walker,
				    packet->len);
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
					       unsigned char *field) {
  struct ses_pckt_pyld_two_names *two_names_payload;
  struct ses_srvc_retarget_blob_rfc1002 *retarget_payload;
  unsigned char *walker, *remember_walker;

  walker = field;

  switch (content->payload_t) {
  case two_names:
    two_names_payload = content->payload;
    remember_walker = walker +1;
    walker = fill_all_DNS_labels(two_names_payload->called_name, walker);
    walker = (walker +
	      ((4- ((walker - remember_walker) %4)) %4));
    walker = fill_all_DNS_labels(two_names_payload->calling_name, walker);
    return walker;
    break;

  case null:
    return walker;
    break;

  case error_code:
    *walker = content->error_code;
    walker++;
    return walker;
    break;

  case retarget_blob_rfc1002:
    retarget_payload = content->payload;
    walker = fill_32field(retarget_payload->new_address, walker);
    walker = fill_16field(retarget_payload->new_port, walker);
    return walker;
    break;

  case payloadpayload:
    walker = mempcpy(walker, content->payload, content->len);
    return walker;
    break;

  case bad_type_ses:
  default:
    return walker;
    break;
  }

  /* Never reached. */
  return walker;
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
    return error_code;
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
  return unknown;
}


struct ses_srvc_packet *master_ses_srvc_pckt_reader(voit *packet,
						    int len) {
  struct ses_srvc_packet *result;
  unsigned char *startof_pckt, *endof_pckt, *walker;

  if (len <= 0) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  startof_pckt = (unsigned char *)packet;
  walker = startof_pckt;
  endof_pckt = startof_pckt + len;

  result = read_ses_srvc_pckt_header(&walker, endof_pckt);
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->payload = read_ses_srvc_pckt_payload_data(result, &walker,
						    startof_pckt, endof_pckt);

  return result;
}