#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"


struct name_srvc_pckt_header *read_name_srvc_pckt_header(unsigned char **master_packet_walker) {
  struct name_srvc_pckt_header *header;
  unsigned char *walker;

  header = malloc(sizeof(struct name_srvc_pckt_header));
  if (! header) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = *master_packet_walker;

  walker = read_16field(walker, &(header->transaction_id));

  header->opcode = (*walker & 0xf8) >> 3;
  header->nm_flags = (*walker & 0x7) << 4;
  walker++;
  header->nm_flags = header->nm_flags | ((*walker & 0xf0) >> 4);
  header->rcode = (*walker & 0xf);
  walker++;

  walker = read_16field(walker, &(header->numof_questions));
  walker = read_16field(walker, &(header->numof_answers));
  walker = read_16field(walker, &(header->numof_authorities));
  walker = read_16field(walker, &(header->numof_additional_recs));

  *master_packet_walker = walker;

  return header;
}

unsigned char *fill_name_srvc_pckt_header(const struct name_srvc_pckt_header *header,
					  unsigned char **master_packet_walker) {
  unsigned char *walker;

  walker = *master_packet_walker;

  walker = fill_16field(header->transaction_id, walker);

  *walker = header->opcode << 3;
  *walker = *walker | ((header->nm_flags & 0x70) >> 4);
  walker++;
  *walker = (header->nm_flags & 0x0f) << 4;
  *walker = *walker | (header->rcode);
  walker++;

  walker = fill_16field(header->numof_questions, walker);
  walker = fill_16field(header->numof_answers, walker);
  walker = fill_16field(header->numof_authorities, walker);
  walker = fill_16field(header->numof_additional_recs, walker);

  return walker;
}

struct name_srvc_question *read_name_srvc_pckt_question(unsigned char **master_packet_walker,
							unsigned char *start_of_packet) {
  struct name_srvc_question *question;
  unsigned char *walker, *remember_walker;

  question = malloc(sizeof(struct name_srvc_question));
  if (! question) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* Part of the mechanism to respect the 32-bit boundaries.
     It's done because read_all_DNS_labels() is guaranteed
     to increment the *master_packet_walker by at least one. */
  remember_walker = *master_packet_walker +1;

  question->name = read_all_DNS_labels(master_packet_walker, start_of_packet);
  if (! question->name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* Fields in the packet are aligned to 32-bit boundaries. */
  walker = (*master_packet_walker +
	    ((4- ((*master_packet_walker - remember_walker) %4)) %4));

  walker = read_16field(walker, &(question->qtype));
  walker = read_16field(walker, &(question->qclass));

  *master_packet_walker = walker;

  return question;
}

unsigned char *fill_name_srvc_pckt_question(struct name_srvc_question *question,
					    unsigned char **master_packet_walker) {
  unsigned char *walker;

  walker = *master_packet_walker;

  walker = fill_all_DNS_labels(question->name, walker);

  /* Respect the 32-bit boundary. */
  walker = (walker +
	    ((4- ((*master_packet_walker - walker) % 4)) %4));

  walker = fill_16field(question->qtype, walker);
  walker = fill_16field(question->qclass, walker);

  return walker;
}

struct name_srvc_resource *read_name_srvc_resource(unsigned char **master_packet_walker,
						   unsigned char *start_of_packet) {
  struct name_srvc_resource *resource;
  unsigned char *walker, *remember_walker;

  resource = malloc(sizeof(struct name_srvc_resource));
  if (! resource) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* See read_name_srvc_pckt_question() for deails. */
  remember_walker = *master_packet_walker +1;

  resource->name = read_all_DNS_labels(master_packet_walker, start_of_packet);
  if (! resource->name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* Fields in the packet are aligned to 32-bit boundaries. */
  walker = (*master_packet_walker +
	    ((4- ((*master_packet_walker - remember_walker) %4)) %4));

  walker = read_16field(walker, &(resource->rrtype));
  walker = read_16field(walker, &(resource->rrclass));
  walker = read_32field(walker, &(resource->ttl));
  walker = read_16field(walker, &(resource->rdata_len));
  resource->rdata_t = unknown_type;
  resource->rdata = read_name_srvc_resource_data(&walker, resource, start_of_packet);

  /* No 32-bit boundary alignment. */
  *master_packet_walker = walker;

  return resource;
}

unsigned char *fill_name_srvc_resource(struct name_srvc_resource *resource,
				       unsigned char **master_packet_walker) {
  unsigned char *walker;

  walker = *master_packet_walker;

  walker = fill_all_DNS_labels(resource->name, walker);

  /* Respect the 32-bit boundary. */
  walker = (walker +
	    ((4- ((*master_packet_walker - walker) % 4)) %4));

  walker = fill_16field(resource->rrtype, walker);
  walker = fill_16field(resource->rrclass, walker);
  walker = fill_32field(resource->ttl, walker);
  walker = fill_16field(resource->rdata_len, walker);
  walker = fill_name_srvc_resource_data(resource->rdata, walker);

  return walker;
}

void *read_name_srvc_resource_data(unsigned char **start_and_end_of_walk,
				   struct name_srvc_resource *resource,
				   unsigned char *start_of_packet) {
  struct nbnodename_list *nbnodename;
  unsigned char *weighted_companion_cube;

  switch (name_srvc_understand_resource(resource->rrtype, resource->rrclass)) {
  case bad_type:
    resource->rdata_t = bad_type;
    *start_and_end_of_walk = *start_and_end_of_walk + resource->rdata_len;
    return 0;
    break;

  case unknown_important_resource:
    resource->rdata_t = unknown_important_resource;
    weighted_companion_cube = malloc(resource->rdata_len);
    if (! weighted_companion_cube) {
      /* TODO: errno signaling stuff */
      return 0;
    }
    *start_and_end_of_walk = mempcpy(weighted_companion_cube, *start_and_end_of_walk,
				     resource->rdata_len);
    return weighted_companion_cube;
    break;

  case nb_address_list:
    resource->rdata_t = nb_address_list;
    return read_nbaddress_list(start_and_end_of_walk, resource->rdata_len);
    break;

  case nb_nodename:
    resource->rdata_t = nb_nodename;
    weighted_companion_cube = *start_and_end_of_walk +1;

    nbnodename = read_all_DNS_labels(start_and_end_of_walk, start_of_packet);
    if (! nbnodename) {
      /* TODO: errno signaling stuff */
      return 0;
    }
    *start_and_end_of_walk = (*start_and_end_of_walk +
			      ((4- ((*start_and_end_of_walk - weighted_companion_cube) %4)) %4));
    return weighted_companion_cube;
    break;

  default:
    /* Never triggered. */
    break;
  }

  /* Never reached. */
  return 0;
}

inline enum name_srvc_rdata_type name_srvc_understand_resource(uint16_t rrtype,
							       uint16_t rrclass) {
  switch (rrtype) {
  case RRTYPE_NB:
    switch (rrclass) {
    case RRCLASS_IN:
      return nb_address_list;
    default:
      return bad_type;
    };
    break;

  case RRTYPE_NULL:
    switch (rrclass) {
    case RRCLASS_IN:
      return nb_type_null;
    default:
      return bad_type;
    };
    break;

  case RRTYPE_NS:
    switch (rrclass) {
    case RRCLASS_IN:
      return nb_nodename;
    default:
      return bad_type;
    };
    break;

  case RRTYPE_A:
    switch (rrclass) {
    case RRCLASS_IN:
      return nb_NBT_node_ip_address;
    default:
      return bad_type;
    };
    break;

  case RRTYPE_NBSTAT:
    switch (rrclass) {
    case RRCLASS_IN:
      return nb_statistics;
    default:
      return bad_type;
    };
    break;

  default:
    return unknown_important_resource;
  }

  /* Never reached */
  return bad_type;
}
