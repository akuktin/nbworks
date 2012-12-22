#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"


struct name_srvc_pckt_header *read_name_srvc_pckt_header(unsigned char **master_packet_walker,
							 unsigned char *end_of_packet) {
  struct name_srvc_pckt_header *header;
  unsigned char *walker;

  if ((*master_packet_walker + 6 * sizeof(uint16_t)) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

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
					  unsigned char *field,
					  unsigned char *end_of_packet) {
  unsigned char *walker;

  walker = field;

  if ((walker + 6*2) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return walker;
  }

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
							unsigned char *start_of_packet,
							unsigned char *end_of_packet) {
  struct name_srvc_question *question;
  unsigned char *walker, *remember_walker;

  if (*master_packet_walker >= end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

  question = malloc(sizeof(struct name_srvc_question));
  if (! question) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* Part of the mechanism to respect the 32-bit boundaries.
     It's done because read_all_DNS_labels() is guaranteed
     to increment the *master_packet_walker by at least one. */
  remember_walker = *master_packet_walker +1;

  question->name = read_all_DNS_labels(master_packet_walker,
				       start_of_packet, end_of_packet);
  if (! question->name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* Fields in the packet are aligned to 32-bit boundaries. */
  walker = (*master_packet_walker +
	    ((4- ((*master_packet_walker - remember_walker) %4)) %4));

  if ((walker + 2 * sizeof(uint16_t)) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    struct nbnodename_list *names_list;
    while (question->name) {
      names_list = question->name->next_name;
      free(question->name->name);
      free(question->name);
      question->name = names_list;
    }
    free(question);
    *master_packet_walker = end_of_packet;
    return 0;
  }

  walker = read_16field(walker, &(question->qtype));
  walker = read_16field(walker, &(question->qclass));

  *master_packet_walker = walker;

  return question;
}

unsigned char *fill_name_srvc_pckt_question(struct name_srvc_question *question,
					    unsigned char *field,
					    unsigned char *end_of_packet) {
  unsigned char *walker;

  walker = field;

  walker = fill_all_DNS_labels(question->name, walker, end_of_packet);

  /* Respect the 32-bit boundary. */
  walker = (walker +
	    ((4- ((field - walker) % 4)) %4));

  if ((walker +4) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return walker;
  }

  walker = fill_16field(question->qtype, walker);
  walker = fill_16field(question->qclass, walker);

  return walker;
}

struct name_srvc_resource *read_name_srvc_resource(unsigned char **master_packet_walker,
						   unsigned char *start_of_packet,
						   unsigned char *end_of_packet) {
  struct name_srvc_resource *resource;
  unsigned char *walker, *remember_walker;

  if (*master_packet_walker >= end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

  resource = malloc(sizeof(struct name_srvc_resource));
  if (! resource) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* See read_name_srvc_pckt_question() for deails. */
  remember_walker = *master_packet_walker +1;

  resource->name = read_all_DNS_labels(master_packet_walker,
				       start_of_packet, end_of_packet);
  if (! resource->name) {
    /* TODO: errno signaling stuff */
    free(resource);
    return 0;
  }

  /* Fields in the packet are aligned to 32-bit boundaries. */
  walker = (*master_packet_walker +
	    ((4- ((*master_packet_walker - remember_walker) %4)) %4));

  if ((walker + 5 * sizeof(uint16_t)) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    struct nbnodename_list *names_list;
    while (resource->name) {
      names_list = resource->name->next_name;
      free(resource->name->name);
      free(resource->name);
      resource->name = names_list;
    }
    free(resource);
    *master_packet_walker = end_of_packet;
    return 0;
  }

  walker = read_16field(walker, &(resource->rrtype));
  walker = read_16field(walker, &(resource->rrclass));
  walker = read_32field(walker, &(resource->ttl));
  walker = read_16field(walker, &(resource->rdata_len));
  resource->rdata = read_name_srvc_resource_data(&walker, resource,
						 start_of_packet, end_of_packet);

  /* No 32-bit boundary alignment. */
  *master_packet_walker = walker;

  return resource;
}

unsigned char *fill_name_srvc_resource(struct name_srvc_resource *resource,
				       unsigned char *field,
				       unsigned char *end_of_packet) {
  unsigned char *walker;

  walker = field;

  walker = fill_all_DNS_labels(resource->name, walker, end_of_packet);

  /* Respect the 32-bit boundary. */
  walker = (walker +
	    ((4- ((field - walker) % 4)) %4));

  if ((walker +3*2+4) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return walker;
  }

  walker = fill_16field(resource->rrtype, walker);
  walker = fill_16field(resource->rrclass, walker);
  walker = fill_32field(resource->ttl, walker);
  walker = fill_16field(resource->rdata_len, walker);
  walker = fill_name_srvc_resource_data(resource->rdata, walker,
					end_of_packet);

  return walker;
}

void *read_name_srvc_resource_data(unsigned char **start_and_end_of_walk,
				   struct name_srvc_resource *resource,
				   unsigned char *start_of_packet,
				   unsigned char *end_of_packet) {
  struct nbnodename_list *nbnodename;
  struct nbnodename_list_backbone *listof_names;
  struct name_srvc_statistics_rfc1002 *nbstat;
  unsigned char *weighted_companion_cube, *walker, num_names;

  if ((*start_and_end_of_walk + resource->rdata_len) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

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
    return read_nbaddress_list(start_and_end_of_walk, resource->rdata_len,
			       end_of_packet);
    break;

  case nb_type_null:
    resource->rdata_t = nb_type_null;
    *start_and_end_of_walk = *start_and_end_of_walk + resource->rdata_len;
    return 0;
    break;

  case nb_nodename:
    resource->rdata_t = nb_nodename;
    if (! resource->rdata_len) {
      /* BULLSHIT_IN_PACKET */
      /* TODO: errno signaling stuff */
      return 0;
    }
    weighted_companion_cube = *start_and_end_of_walk +1;

    nbnodename = read_all_DNS_labels(start_and_end_of_walk,
				     start_of_packet, end_of_packet);
    if (! nbnodename) {
      /* TODO: errno signaling stuff */
      return 0;
    }
    *start_and_end_of_walk = (*start_and_end_of_walk +
			      ((4- ((*start_and_end_of_walk - weighted_companion_cube) %4)) %4));
    if (*start_and_end_of_walk > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      /* question: should you, and how exactly should you, signal this? */
      *start_and_end_of_walk = end_of_packet;
    }
    return nbnodename;
    break;

  case nb_NBT_node_ip_address:
    resource->rdata_t = nb_NBT_node_ip_address;
    return read_ipv4_address_list(start_and_end_of_walk, resource->rdata_len,
				  end_of_packet);
    break;

  case nb_statistics_rfc1002:
    resource->rdata_t = nb_statistics_rfc1002;
    if (! resource->rdata_len) {
      /* BULLSHIT_IN_PACKET */
      /* TODO: errno signaling stuff */
      return 0;
    }
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
	if (walker >= end_of_packet) {
	  /* OUT_OF_BOUNDS */
	  /* TODO: errno signaling stuff */
	  listof_names = nbstat->listof_names;
	  while (listof_names) {
	    nbstat->listof_names = listof_names->next_nbnodename;
	    while (listof_names->nbnodename) {
	      free(listof_names->nbnodename->name);
	      nbnodename = listof_names->nbnodename->next_name;
	      free(listof_names->nbnodename);
	      listof_names->nbnodename = nbnodename;
	    }
	    free(listof_names);
	    listof_names = nbstat->listof_names;
	  }
	  free(nbstat);

	  return 0;
	}
	listof_names->nbnodename = read_all_DNS_labels(&walker, start_of_packet,
						       end_of_packet);
	walker = walker + ((4- ((walker - weighted_companion_cube) %4)) %4);
	if ((walker + 1 * sizeof(uint16_t)) > end_of_packet) {
	  /* OUT_OF_BOUNDS */
	  /* TODO: errno signaling stuff */
	  listof_names = nbstat->listof_names;
	  while (listof_names) {
	    nbstat->listof_names = listof_names->next_nbnodename;
	    while (listof_names->nbnodename) {
	      free(listof_names->nbnodename->name);
	      nbnodename = listof_names->nbnodename->next_name;
	      free(listof_names->nbnodename);
	      listof_names->nbnodename = nbnodename;
	    }
	    free(listof_names);
	    listof_names = nbstat->listof_names;
	  }
	  free(nbstat);

	  return 0;
	}
	walker = read_16field(walker, &(listof_names->name_flags));

	num_names--;
	if (num_names > 0) {
	  listof_names->next_nbnodename = malloc(sizeof(struct nbnodename_list_backbone));
	  if (! listof_names->next_nbnodename) {
	    /* TODO: errno signaling stuff */
	    listof_names = nbstat->listof_names;
	    while (listof_names) {
	      nbstat->listof_names = listof_names->next_nbnodename;
	      while (listof_names->nbnodename) {
		free(listof_names->nbnodename->name);
		nbnodename = listof_names->nbnodename->next_name;
		free(listof_names->nbnodename);
		listof_names->nbnodename = nbnodename;
	      }
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
	 Also read the comment after the next one. */
      walker++;
    }

    walker = walker + ((4- ((walker - weighted_companion_cube) %4)) %4);

    if ((walker + 23 * sizeof(uint16_t)) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      listof_names = nbstat->listof_names;
      while (listof_names) {
	nbstat->listof_names = listof_names->next_nbnodename;
	while (listof_names->nbnodename) {
	  free(listof_names->nbnodename->name);
	  nbnodename = listof_names->nbnodename->next_name;
	  free(listof_names->nbnodename);
	  listof_names->nbnodename = nbnodename;
	}
	free(listof_names);
	listof_names = nbstat->listof_names;
      }
      free(nbstat);

      return 0;
    }

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
					    unsigned char *field,
					    unsigned char *end_of_packet) {
  struct nbnodename_list_backbone *names;
  struct name_srvc_statistics_rfc1002 *nbstat;
  unsigned char *walker;

  walker = field;

  switch (content->rdata_t) {
  case unknown_important_resource:
    if ((walker + content->rdata_len) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      return walker;
    }
    return mempcpy(walker, content->rdata, content->rdata_len);
    break;

  case nb_address_list:
    return fill_nbaddress_list(content->rdata, walker, end_of_packet);
    break;

  case nb_type_null:
    return walker;
    break;

  case nb_nodename:
    walker = fill_all_DNS_labels(content->rdata, walker, end_of_packet);
    walker = walker + ((4- ((walker - field) %4)) %4);
    if (walker > end_of_packet) {
      /* TODO: maybe do errno signaling stuff */
      return end_of_packet;
    } else {
      return walker;
    }
    break;

  case nb_NBT_node_ip_address:
    return fill_ipv4_address_list(content->rdata, walker, end_of_packet);
    break;

  case nb_statistics_rfc1002:
    nbstat = content->rdata;
    if ((walker +1+3+6+2+19*2) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      return walker;
    }
    *walker = nbstat->numof_names;
    names = nbstat->listof_names;
    while (names) {
      walker = fill_all_DNS_labels(names->nbnodename, walker, end_of_packet);
      walker = walker + ((4- ((walker - field) %4)) %4);
      if ((walker +2+6+2+19*2) > end_of_packet) {
	/* OUT_OF_BOUNDS */
	/* TODO: errno signaling stuff */
	return walker;
      }
      walker = fill_16field(names->name_flags, walker);
      walker = walker + ((4- ((walker - field) %4)) %4);
      names = names->next_nbnodename;
    }
    if ((walker +6+2+19*2) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      return walker;
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
      return nb_statistics_rfc1002;
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


struct name_srvc_packet *master_name_srvc_pckt_reader(void *packet,
						      int len) {
  struct name_srvc_packet *result;
  struct name_srvc_question_lst *cur_qstn;
  struct name_srvc_resource_lst *cur_res;
  int i;
  unsigned char *startof_pckt, *endof_pckt, *walker;

  if (len <= 0) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  startof_pckt = (unsigned char *)packet;
  walker = startof_pckt;
  endof_pckt = startof_pckt + len;

  result = malloc(sizeof(struct name_srvc_packet));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  result->questions = 0;
  result->answers = 0;
  result->authorities = 0;
  result->aditionals = 0;

  result->header = read_name_srvc_pckt_header(&walker, endof_pckt);
  if (! result->header) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }

  i = result->header->numof_questions;
  if (i) {
    cur_qstn = malloc(sizeof(struct name_srvc_question_lst));
    if (! cur_qstn) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->questions = cur_qstn;
    cur_qstn->next = 0;

    i--;
    while (1) {
      cur_qstn->qstn = read_name_srvc_pckt_question(&walker, startof_pckt,
						    endof_pckt);
      if (i) {
	cur_qstn->next = malloc(sizeof(struct name_srvc_question_lst));
	if (! cur_qstn->next) {
	  /* TODO: errno signaling stuff */
	  destroy_name_srvc_pckt(result, 1, 1);
	  return 0;
	}
	cur_qstn = cur_qstn->next;
	cur_qstn->next = 0;
	i--;
      } else {
	break;
      }
    }
  } else {
    result->questions = 0;
  }

  i = result->header->numof_answers;
  if (i) {
    cur_res = malloc(sizeof(struct name_srvc_resource_lst));
    if (! cur_res) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->answers = cur_res;
    cur_res->next = 0;

    i--;
    while (1) {
      cur_res->res = read_name_srvc_resource(&walker, startof_pckt,
					     endof_pckt);
      if (i) {
	cur_res->next = malloc(sizeof(struct name_srvc_resource_lst));
	if (! cur_res->next) {
	  /* TODO: errno signaling stuff */
	  destroy_name_srvc_pckt(result, 1, 1);
	  return 0;
	}
	cur_res = cur_res->next;
	cur_res->next = 0;
	i--;
	} else {
	break;
      }
    }
  } else {
    result->answers = 0;
  }

  i = result->header->numof_authorities;
  if (i) {
    cur_res = malloc(sizeof(struct name_srvc_resource_lst));
    if (! cur_res) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->authorities = cur_res;
    cur_res->next = 0;

    i--;
    while (1) {
      cur_res->res = read_name_srvc_resource(&walker, startof_pckt,
					     endof_pckt);
      if (i) {
	cur_res->next = malloc(sizeof(struct name_srvc_resource_lst));
	if (! cur_res->next) {
	  /* TODO: errno signaling stuff */
	  destroy_name_srvc_pckt(result, 1, 1);
	  return 0;
	}
	cur_res = cur_res->next;
	cur_res->next = 0;
	i--;
	} else {
	break;
      }
    }
  } else {
    result->authorities = 0;
  }

  i = result->header->numof_additional_recs;
  if (i) {
    cur_res = malloc(sizeof(struct name_srvc_resource_lst));
    if (! cur_res->next) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->aditionals = cur_res;
    cur_res->next = 0;

    i--;
    while (1) {
      cur_res->res = read_name_srvc_resource(&walker, startof_pckt,
					     endof_pckt);
      if (i) {
	cur_res->next = malloc(sizeof(struct name_srvc_resource_lst));
	if (! cur_res->next) {
	  /* TODO: errno signaling stuff */
	  destroy_name_srvc_pckt(result, 1, 1);
	  return 0;
	}
	cur_res = cur_res->next;
	cur_res->next = 0;
	i--;
	} else {
	break;
      }
    }
  } else {
    result->aditionals = 0;
  }

  return result;
}

void *master_name_srvc_pckt_writer(struct name_srvc_packet *packet,
				   unsigned int *pckt_len) {
  struct name_srvc_question_lst *cur_qstn;
  struct name_srvc_resource_lst *cur_res;
  unsigned char *result, *walker, *endof_pckt;

  if (! (packet && pckt_len)) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result = calloc(1, MAX_UDP_PACKET_LEN);
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = result;
  endof_pckt = result + MAX_UDP_PACKET_LEN;

  walker = fill_name_srvc_pckt_header(packet->header, walker,
				      endof_pckt);

  cur_qstn = packet->questions;
  while (cur_qstn) {
    walker = fill_name_srvc_pckt_question(cur_qstn->qstn, walker,
					  endof_pckt);
    if (walker >= endof_pckt) {
      /* TODO: errno signaling stuff */
      *pckt_len = walker - result;
      return result;
    }
    cur_qstn = cur_qstn->next;
  }

  cur_res = packet->answers;
  while (cur_res) {
    walker = fill_name_srvc_resource(cur_res->res, walker,
				     endof_pckt);
    if (walker >= endof_pckt) {
      /* TODO: errno signaling stuff */
      *pckt_len = walker - result;
      return result;
    }
    cur_res = cur_res->next;
  }

  cur_res = packet->authorities;
  while (cur_res) {
    walker = fill_name_srvc_resource(cur_res->res, walker,
				     endof_pckt);
    if (walker >= endof_pckt) {
      /* TODO: errno signaling stuff */
      *pckt_len = walker - result;
      return result;
    }
    cur_res = cur_res->next;
  }

  cur_res = packet->aditionals;
  while (cur_res) {
    walker = fill_name_srvc_resource(cur_res->res, walker,
				     endof_pckt);
    if (walker >= endof_pckt) {
      /* TODO: errno signaling stuff */
      *pckt_len = walker - result;
      return result;
    }
    cur_res = cur_res->next;
  }

  *pckt_len = walker - result;
  return (void *)result;
}

struct name_srvc_packet *alloc_name_srvc_pckt(unsigned int qstn,
					      unsigned int answ,
					      unsigned int auth,
					      unsigned int adit) {
  struct name_srvc_packet *result;
  struct name_srvc_question_lst *cur_qstn;
  struct name_srvc_resource_lst *cur_res;

  result = calloc(1, sizeof(struct name_srvc_packet));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->header = malloc(sizeof(struct name_srvc_pckt_header));
  if (! result->header) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }

  if (qstn) {
    cur_qstn = malloc(sizeof(struct name_srvc_question_lst));
    if (! cur_qstn) {
      /* TODO: errno signaling stuff */
      free(result->header);
      free(result);
      return 0;
    }
    result->questions = cur_qstn;
    result->questions->qstn = 0;
    result->questions->next = 0;

    qstn--;
    while (qstn) {
      cur_qstn->next = calloc(1, sizeof(struct name_srvc_question_lst));
      if (! cur_qstn->next) {
	/* TODO: errno signaling stuff */
	destroy_name_srvc_pckt(result);
	return 0;
      }
      cur_qstn = cur_qstn->next;
      qstn--;
    }
  }

  if (answ) {
    cur_res = malloc(sizeof(struct name_srvc_resource_lst));
    if (! result->answers) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result);
      return 0;
    }
    result->answers = cur_res;
    result->answers->res = 0;
    result->answers->next = 0;

    answ--;
    while (answ) {
      cur_res->next = calloc(1, sizeof(struct name_srvc_resource_lst));
      if (! result->answers) {
	/* TODO: errno signaling stuff */
	destroy_name_srvc_pckt(result);
	return 0;
      }
      cur_res = cur_res->next;
      answ--;
    }
  }

  if (auth) {
    cur_res = malloc(sizeof(struct name_srvc_resource_lst));
    if (! result->authorities) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result);
      return 0;
    }
    result->authorities = cur_res;
    result->authorities->res = 0;
    result->authorities->next = 0;

    auth--;
    while (auth) {
      cur_res->next = calloc(1, sizeof(struct name_srvc_resource_lst));
      if (! result->authorities) {
	/* TODO: errno signaling stuff */
	destroy_name_srvc_pckt(result);
	return 0;
      }
      cur_res = cur_res->next;
      auth--;
    }
  }

  if (adit) {
    cur_res = malloc(sizeof(struct name_srvc_resource_lst));
    if (! result->aditionals) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result);
      return 0;
    }
    result->aditionals = cur_res;
    result->aditionals->res = 0;
    result->aditionals->next = 0;

    adit--;
    while (adit) {
      cur_res->next = calloc(1, sizeof(struct name_srvc_resource_lst));
      if (! result->aditionals) {
	/* TODO: errno signaling stuff */
	destroy_name_srvc_pckt(result);
	return 0;
      }
      cur_res = cur_res->next;
      adit--;
    }
  }

  return result;
}

void destroy_name_srvc_pckt(struct name_srvc_packet *packet,
			    unsigned int complete,
			    unsigned int really_complete) {
  struct name_srvc_question_lst *qstn;
  struct name_srvc_resource_lst *res, *cur_res, **all_res;
  struct nbnodename_list_backbone *nbnodename_bckbone,
    *next_nbnodename_bckbone;
  struct nbnodename_list *nbnodename, *next_nbnodename;
  struct nbaddress_list *addr_list, *next_addr_list;
  struct name_srvc_statistics_rfc1002 *stats;
  int i;

  all_res = malloc(sizeof(struct name_srvc_resource_lst *) *3);

  free(packet->header);

  while (packet->questions) {
    qstn = packet->questions->next;
    if (packet->questions->qstn) {
      if (complete) {
	while (packet->questions->qstn->name) {
	  nbnodename = packet->questions->qstn->name->next_name;
	  free(packet->questions->qstn->name->name);
	  free(packet->questions->qstn->name);
	  packet->questions->qstn->name = nbnodename;
	}
      } else {
	free(packet->questions->qstn->name->name);
	free(packet->questions->qstn->name);
      }
      free(packet->questions->qstn);
    }
    free(packet->questions);
    packet->questions = qstn;
  }

  all_res[0] = packet->answers;
  all_res[1] = packet->authorities;
  all_res[2] = packet->aditionals;

  for (i=0; i<3; i++) {
    cur_res = all_res[i];
    while (cur_res) {
      res = cur_res->next;
      if (cur_res->res) {
	if (complete) {
	  while (cur_res->res->name) {
	    nbnodename = cur_res->res->name->next_name;
	    free(cur_res->res->name->name);
	    free(cur_res->res->name);
	    cur_res->res->name = nbnodename;
	  }
	} else {
	  free(cur_res->res->name->name);
	  free(cur_res->res->name);
	}
	switch (cur_res->res->rdata_t) {
	case nb_statistics_rfc1002:
	  stats = cur_res->res->rdata;
	  nbnodename_bckbone = stats->listof_names;
	  while (nbnodename_bckbone) {
	    next_nbnodename_bckbone = nbnodename_bckbone->next_nbnodename;
	    nbnodename = nbnodename_bckbone->nbnodename;
	    if (really_complete) {
	      while (nbnodename) {
		next_nbnodename = nbnodename->next_name;
		free(nbnodename->name);
		free(nbnodename);
		nbnodename = next_nbnodename;
	      }
	    } else {
	      free(nbnodename->name);
	      free(nbnodename);
	    }
	    free(nbnodename_bckbone);
	    nbnodename_bckbone = next_nbnodename_bckbone;
	  }
	  free(stats);
	  break;

	case nb_nodename:
	  nbnodename = cur_res->res->rdata;
	  if (really_complete) {
	    while (nbnodename) {
	      next_nbnodename = nbnodename->next_name;
	      free(nbnodename->name);
	      free(nbnodename);
	      nbnodename = next_nbnodename;
	    }
	  } else {
	    free(nbnodename->name);
	    free(nbnodename);
	  }
	  break;

	case nb_address_list:
	case nb_NBT_node_ip_address:
	  addr_list = cur_res->res->rdata;
	  while (addr_list) {
	    next_addr_list = addr_list->next_address;
	    free(addr_list);
	    addr_list = next_addr_list;
	  }
	  break;

	case unknown_important_resource:
	default:
	  free(cur_res->res->rdata);
	  break;
	}
	free(cur_res->res);
      }
      free(cur_res);
      cur_res = res;
    }
  }

  free(packet);

  /* I now understand why garbage collectors were invented. */

  return;
}
