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
  resource->rdata_t = virgin;
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
  struct nbnodename_list_backbone *listof_names;
  struct name_srvc_statistics_rfc1002 *nbstat;
  unsigned char *weighted_companion_cube, *walker, num_names;

  switch (name_srvc_understand_resource(resource->rrtype, resource->rrclass)) {
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
    *start_and_end_of_walk = *start_and_end_of_walk + resource->rdata_len;
    return read_nbaddress_list(start_and_end_of_walk, resource->rdata_len);
    break;

  case nb_type_null:
    resource->rdata_t = nb_type_null;
    *start_and_end_of_walk = *start_and_end_of_walk + resource->rdata_len;
    return 0;
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

  case nb_NBT_node_ip_address:
    resource->rdata_t = nb_NBT_node_ip_address;
    *start_and_end_of_walk = *start_and_end_of_walk + resource->rdata_len;
    return read_ipv4_address_list(start_and_end_of_walk, resource->rdata_len);
    break;

  case nb_statistics:
    resource->rdata_t = nb_statistics;
    walker = *start_and_end_of_walk;
    nbstat = malloc(sizeof(struct name_srvc_statistics_rfc1002));
    if (! nbstat) {
      /* TODO: errno signaling stuff */
      return 0;
    }
    num_names = *walker;
    nbstat->numof_names = num_names;
    walker++;
    weighted_companion_cube = walker +1;
    if (num_names > 0) {
      listof_names = malloc(sizeof(struct nbnodename_list_backbone));
      if (! listof_names) {
	/* TODO: errno signaling stuff */
	free(nbstat);
	return 0;
      }
      nbstat->listof_names = listof_names;
      while (0xbeefbeef) {
	listof_names->nbnodename = read_all_DNS_labels(&walker, start_of_packet);
	walker = walker + ((4- ((walker - weighted_companion_cube) %4)) %4);
	walker = read_16field(walker, &(listof_names->name_flags));

	num_names--;
	if (num_names > 0) {
	  listof_names->next_nbnodename = malloc(sizeof(struct nbnodename_list_backbone));
	  if (! listof_names->next_nbnodename) {
	    /* TODO: errno signaling stuff */
	    listof_names = nbstat->listof_names;
	    while (listof_names) {
	      nbstat->listof_names = listof_names->next_nbnodename;
	      free(listof_names);
	      listof_names = nbstat->listof_names;
	    }
	    free(nbstat);

	    return 0;
	  }
	  listof_names = listof_names->next_nbnodename;
	} else {
	  listof_names->next_nbnodename = 0;
	  break;
	}
      }
    } else {
      nbstat->listof_names = 0;
      /* I have to increment walker by at least one.
	 Also read the next comment. */
      walker++;
    }

    walker = walker + ((4- ((walker - weighted_companion_cube) %4)) %4);

    /* I am interpreting the RFC 1002 to mean the statistics blob is aligned
       to 32-bit boundaries. */
    walker = read_48field(walker, &(nbstat->unique_id));
    nbstat->jumpers = *walker;
    walker++;
    nbstat->test_results = *walker;
    walker++;
    walker = read_16field(walker, &(nbstat->version_number));
    walker = read_16field(walker, &(nbstat->period_of_statistics));
    walker = read_16field(walker, &(nbstat->numof_crc));
    walker = read_16field(walker, &(nbstat->numof_alignment_errs));
    walker = read_16field(walker, &(nbstat->numof_collisions));
    walker = read_16field(walker, &(nbstat->numof_send_aborts));
    walker = read_32field(walker, &(nbstat->numof_good_sends));
    walker = read_32field(walker, &(nbstat->numof_good_receives));
    walker = read_16field(walker, &(nbstat->numof_retransmits));
    walker = read_16field(walker, &(nbstat->numof_no_res_conditions));
    walker = read_16field(walker, &(nbstat->numof_free_commnd_blocks));
    walker = read_16field(walker, &(nbstat->total_numof_commnd_blocks));
    walker = read_16field(walker, &(nbstat->max_total_numof_commnd_blocks));
    walker = read_16field(walker, &(nbstat->numof_pending_sessions));
    walker = read_16field(walker, &(nbstat->max_numof_pending_sessions));
    walker = read_16field(walker, &(nbstat->max_total_sessions_possible));
    walker = read_16field(walker, &(nbstat->session_data_pckt_size));

    *start_and_end_of_walk = walker;

    return nbstat;
    break;

  case bad_type:
  default:
    resource->rdata_t = bad_type;
    *start_and_end_of_walk = *start_and_end_of_walk + resource->rdata_len;
    return 0;
    break;
  }

  /* Never reached. */
  return 0;
}

unsigned char *fill_name_srvc_resource_data(struct name_srvc_resource *content,
					    unsigned char *field) {
  struct nbaddress_list *address_list;
  struct nbnodename_list_backbone *names;
  struct name_srvc_statistics_rfc1002 *nbstat;
  unsigned char *walker;

  walker = field;

  switch (content->rdata_t) {
  case unknown_important_resource:
    return mempcpy(walker, content->rdata, content->rdata_len);
    break;

  case nb_address_list:
    address_list = content->rdata;
    while (address_list) {
      walker = fill_16field(address_list->flags, walker);
      if (address_list->there_is_an_address) {
	walker = fill_32field(address_list->address, walker);
      }
      address_list = address_list->next_address;
    }
    return walker;
    break;

  case nb_type_null:
    return (walker +1);
    break;

  case nb_nodename:
    walker = fill_all_DNS_labels(content->rdata, walker);
    return (walker + ((4- ((walker - field) %4)) %4));
    break;

  case nb_NBT_node_ip_address:
    address_list = content->rdata;
    while (address_list) {
      walker = fill_32field(address_list->address, walker);
      address_list = address_list->next_address;
    }
    return walker;
    break;

  case nb_statistics:
    nbstat = content->rdata;
    *walker = nbstat->numof_names;
    names = nbstat->listof_names;
    while (names) {
      walker = fill_all_DNS_labels(names->nbnodename, walker);
      walker = walker + ((4- ((walker - field) %4)) %4);
      walker = fill_16field(names->name_flags, walker);
      walker = walker + ((4- ((walker - field) %4)) %4);
      names = names->next_nbnodename;
    }
    walker = fill_48field(nbstat->unique_id, walker);
    *walker = nbstat->jumpers;
    walker++;
    *walker = nbstat->test_results;
    walker++;
    walker = fill_16field(nbstat->version_number, walker);
    walker = fill_16field(nbstat->period_of_statistics, walker);
    walker = fill_16field(nbstat->numof_crc, walker);
    walker = fill_16field(nbstat->numof_alignment_errs, walker);
    walker = fill_16field(nbstat->numof_collisions, walker);
    walker = fill_16field(nbstat->numof_send_aborts, walker);
    walker = fill_32field(nbstat->numof_good_sends, walker);
    walker = fill_32field(nbstat->numof_good_receives, walker);
    walker = fill_16field(nbstat->numof_retransmits, walker);
    walker = fill_16field(nbstat->numof_no_res_conditions, walker);
    walker = fill_16field(nbstat->numof_free_commnd_blocks, walker);
    walker = fill_16field(nbstat->total_numof_commnd_blocks, walker);
    walker = fill_16field(nbstat->max_total_numof_commnd_blocks, walker);
    walker = fill_16field(nbstat->numof_pending_sessions, walker);
    walker = fill_16field(nbstat->max_numof_pending_sessions, walker);
    walker = fill_16field(nbstat->max_total_sessions_possible, walker);
    walker = fill_16field(nbstat->session_data_pckt_size, walker);

    return walker;
    break;

  default:
    return field;
    break;
  }

  /* Never reached. */
  return field;
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
