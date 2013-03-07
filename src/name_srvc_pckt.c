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
#include <stdint.h>
#include <string.h>

#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_cache.h"
#include "name_srvc_pckt.h"
#include "daemon_control.h"


#define OVERFLOW_BUF      1
#define OVERFLOW_RDATALEN 2


struct name_srvc_pckt_header *read_name_srvc_pckt_header(unsigned char **master_packet_walker,
							 unsigned char *end_of_packet) {
  struct name_srvc_pckt_header *header;
  unsigned char *walker;

  if (! master_packet_walker)
    return 0;

  if ((! *master_packet_walker) ||
      ((*master_packet_walker + 6 * sizeof(uint16_t)) > end_of_packet)) {
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

  if (! (header && field))
    return field;

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

  if (! master_packet_walker)
    return 0;

  if ((! *master_packet_walker) ||
      (*master_packet_walker < start_of_packet) ||
      (*master_packet_walker >= end_of_packet)) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* BUG: This line can cause a VERY bizzare failure, when I am receiving a
   *      packet that I have sent to a broadcast address udp__recver() is
   *      listening to, if udp__recver() does not filter out the packets from
   *      my IP address.
   *      Failure manifests by the malloc failing, either by segfaulting or by
   *      glibc detecting the corruption of the heap (?) and killing the
   *      application (multiplexing daemon).
   *      The only possible cause of failure on my end that I can think of is a
   *      buffer overflow somewhere. */
  /* After checking all instances of memset(), memcpy() and mempcpy(), and
   * fixing a bunch of errors, I can still not make the bug go away. */
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
				       start_of_packet, end_of_packet, 0);
  if (! question->name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* Fields in the packet are aligned to 32-bit boundaries. */
  walker = align(remember_walker, *master_packet_walker, 4);

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
					    unsigned char *end_of_packet,
					    unsigned char *overflow) {
  unsigned char *walker;

  if (! (question && field))
    return field;
  else {
    if (overflow)
      *overflow = FALSE;
    walker = field;
  }

  if ((walker +1 +1 +4) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    if (overflow)
      *overflow = OVERFLOW_BUF;
    return field;
  }

  walker = fill_all_DNS_labels(question->name, walker, end_of_packet, 0);
  if (walker == field) {
    /* OUT_OF_BOUNDS */
    if (overflow)
      *overflow = OVERFLOW_BUF;
    return field;
  }

  /* Respect the 32-bit boundary. */
  walker = align(field, walker, 4);

  if ((walker +4) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    if (overflow)
      *overflow = OVERFLOW_BUF;
    memset(field, 0, (walker-field));
    return field;
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

  if (! master_packet_walker) {
    return 0;
  }

  if ((! *master_packet_walker) ||
      (*master_packet_walker < start_of_packet) ||
      (*master_packet_walker >= end_of_packet)) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return 0;
  }

  resource = malloc(sizeof(struct name_srvc_resource));
  if (! resource) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* See read_name_srvc_pckt_question() for details. */
  remember_walker = *master_packet_walker +1;

  resource->name = read_all_DNS_labels(master_packet_walker,
				       start_of_packet, end_of_packet, 0);
  if (! resource->name) {
    /* TODO: errno signaling stuff */
    free(resource);
    return 0;
  }

  /* Fields in the packet are aligned to 32-bit boundaries. */
  walker = align(remember_walker, *master_packet_walker, 4);

  if ((walker + 5 * sizeof(uint16_t)) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    destroy_nbnodename(resource->name);
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

#define VIRTUAL_OVERHANG (NETBIOS_CODED_NAME_LEN+1+2)
unsigned char *fill_name_srvc_resource(struct name_srvc_resource *resource,
				       unsigned char *field,
				       unsigned char *end_of_packet,
				       unsigned char *overflow) {
  unsigned char *walker, *save_walker;

  if (! (resource && field))
    return field;
  else {
    if (overflow)
      *overflow = FALSE;
    walker = field;
  }

  walker = fill_all_DNS_labels(resource->name, walker, end_of_packet, 0);
  if (walker == field) {
    /* OUT_OF_BOUNDS */
    if (overflow)
      *overflow = OVERFLOW_BUF;
    return field;
  }

  /* Respect the 32-bit boundary. */
  walker = align(field, walker, 4);

  if ((walker +3*2+4+ resource->rdata_len) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    if (overflow)
      *overflow = OVERFLOW_BUF;
    memset(field, 0, (walker-field));
    return field;
  }

  walker = fill_16field(resource->rrtype, walker);
  walker = fill_16field(resource->rrclass, walker);
  walker = fill_32field(resource->ttl, walker);
  walker = fill_16field(resource->rdata_len, walker);

  save_walker = walker;
  walker = fill_name_srvc_resource_data(resource, walker,
		      (((walker +VIRTUAL_OVERHANG +resource->rdata_len) > end_of_packet) ?
		       end_of_packet : (walker +VIRTUAL_OVERHANG +resource->rdata_len)));

  if (walker > (save_walker + resource->rdata_len)) {
    /* Overflow. */
    /* Hypothesis #1: the data itself is fucked up, probably a loose pointer.
     *                This implies that we are currently undergoing a fandago-on-core
     *                and are not having the best of days. */
    /* Hypothesis #2: there is *SO MUCH* data, that the RDATA_LEN field has overflown.
     *                There is pretty much no way to recover from this at this point
     *                that I know of. */
    if (overflow)
      *overflow = OVERFLOW_RDATALEN;
    memset((save_walker + resource->rdata_len), 0, (walker-(save_walker + resource->rdata_len)));
    return (save_walker + resource->rdata_len);
  }

  return walker;
}
#undef VIRTUAL_OVERHANG

void *read_name_srvc_resource_data(unsigned char **start_and_end_of_walk,
				   struct name_srvc_resource *resource,
				   unsigned char *start_of_packet,
				   unsigned char *end_of_packet) {
  struct nbnodename_list *nbnodename;
  struct nbnodename_list_backbone *listof_names;
  struct name_srvc_statistics_rfc1002 *nbstat;
  unsigned char *weighted_companion_cube, *walker, num_names;

  if ((! start_and_end_of_walk) ||
      (! resource))
    return 0;

  if ((! *start_and_end_of_walk) ||
      (*start_and_end_of_walk < start_of_packet) ||
      (*start_and_end_of_walk + resource->rdata_len) > end_of_packet) {
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
				     start_of_packet, end_of_packet, 0);
    if (! nbnodename) {
      /* TODO: errno signaling stuff */
      return 0;
    }
    *start_and_end_of_walk = align(weighted_companion_cube, *start_and_end_of_walk, 4);
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

	    destroy_nbnodename(listof_names->nbnodename);

	    free(listof_names);
	    listof_names = nbstat->listof_names;
	  }
	  free(nbstat);

	  return 0;
	}
	listof_names->nbnodename = read_all_DNS_labels(&walker, start_of_packet,
						       end_of_packet, 0);
	walker = align(weighted_companion_cube, walker, 4);
	if ((walker + 1 * sizeof(uint16_t)) > end_of_packet) {
	  /* OUT_OF_BOUNDS */
	  /* TODO: errno signaling stuff */
	  listof_names = nbstat->listof_names;
	  while (listof_names) {
	    nbstat->listof_names = listof_names->next_nbnodename;

	    destroy_nbnodename(listof_names->nbnodename);

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

	      destroy_nbnodename(listof_names->nbnodename);

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

    walker = align(weighted_companion_cube, walker, 4);

    if ((walker + 23 * sizeof(uint16_t)) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      listof_names = nbstat->listof_names;
      while (listof_names) {
	nbstat->listof_names = listof_names->next_nbnodename;

	destroy_nbnodename(listof_names->nbnodename);

	free(listof_names);
	listof_names = nbstat->listof_names;
      }
      free(nbstat);

      return 0;
    }

    /* I am interpreting the RFC 1002 to mean the statistics blob is aligned
       to 32-bit boundaries. */ /* Or not... */
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

  if ((! (content && field)) ||
      (field > end_of_packet))
    return field;

  walker = field;

  if ((walker + content->rdata_len) > end_of_packet)) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return walker;
  }
  if (! content->rdata) {
    memset(walker, 0, content->rdata_len);
    return (walker + content->rdata_len);
  }

  switch (content->rdata_t) {
  case unknown_important_resource:
    return mempcpy(walker, content->rdata, content->rdata_len);
    break;

  case nb_address_list:
    return fill_nbaddress_list(content->rdata, walker, end_of_packet);
    break;

  case nb_type_null:
    return walker;
    break;

  case nb_nodename:
    walker = fill_all_DNS_labels(content->rdata, walker, end_of_packet, 0);
    if (walker == field) {
      /* OUT_OF_BOUNDS */
      memset(field, 0, content->rdata_len);
      return (field + content->rdata_len);
    }
    walker = align(field, walker, 4);
    if (walker > end_of_packet) {
      /* TODO: maybe do errno signaling stuff? */
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
      memset(field, 0, content->rdata_len);
      return (field + content->rdata_len);
    }
    *walker = nbstat->numof_names;
    names = nbstat->listof_names;
    while (names) {
      walker = fill_all_DNS_labels(names->nbnodename, walker, end_of_packet, 0);
      if (walker == field) {
	/* OUT_OF_BOUNDS */
	memset(field, 0, (((walker-field) > content->rdata_len) ?
			  (walker-field) : content->rdata_len));
	return (field + content->rdata_len);
      }

      walker = align(field, walker, 4);
      if ((walker +2+6+2+19*2) > end_of_packet) {
	/* OUT_OF_BOUNDS */
	/* TODO: errno signaling stuff */
	memset(field, 0, (((walker-field) > content->rdata_len) ?
			  (walker-field) : content->rdata_len));
	return (field + content->rdata_len);
      }
      walker = fill_16field(names->name_flags, walker);
      walker = align(field, walker, 4);
      names = names->next_nbnodename;
    }
    if ((walker +6+2+19*2) > end_of_packet) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      memset(field, 0, (((walker-field) > content->rdata_len) ?
			(walker-field) : content->rdata_len));
      return (field + content->rdata_len);
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
    memset(walker, 0, content->rdata_len);
    return (walker + content->rdata_len);
    break;
  }

  /* Never reached. */
  memset(walker, 0, content->rdata_len);
  return (walker + content->rdata_len);
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


void *master_name_srvc_pckt_reader(void *packet,
				   int len,
				   uint16_t *tid) {
  struct name_srvc_packet *result;
  struct name_srvc_question_lst *cur_qstn;
  struct name_srvc_resource_lst *cur_res;
  uint16_t i;
  unsigned char *startof_pckt, *endof_pckt, *walker;

  if ((len <= 0) ||
      (! packet))
    return 0;

  startof_pckt = (unsigned char *)packet;
  walker = startof_pckt;
  endof_pckt = startof_pckt + len;

  result = calloc(1, sizeof(struct name_srvc_packet));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->header = read_name_srvc_pckt_header(&walker, endof_pckt);
  if (! result->header) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }

  if (tid)
    *tid = result->header->transaction_id;

  i = result->header->numof_questions;
  if (i) {
    cur_qstn = malloc(sizeof(struct name_srvc_question_lst));
    if (! cur_qstn) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->questions = cur_qstn;

    while (1) {
      i--;
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
      } else {
	break;
      }
    }

    cur_qstn->next = 0;
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

    while (1) {
      i--;
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
      } else {
	break;
      }
    }

    cur_res->next = 0;
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

    while (1) {
      i--;
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
      } else {
	break;
      }
    }

    cur_res->next = 0;
  } else {
    result->authorities = 0;
  }

  i = result->header->numof_additional_recs;
  if (i) {
    cur_res = malloc(sizeof(struct name_srvc_resource_lst));
    if (! cur_res) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->aditionals = cur_res;

    while (1) {
      i--;
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
      } else {
	break;
      }
    }

    cur_res->next = 0;
  } else {
    result->aditionals = 0;
  }

  return (void *)result;
}

void *master_name_srvc_pckt_writer(void *packet_ptr,
				   unsigned int *pckt_len,
				   void *packet_field) {
  struct name_srvc_packet *packet;
  struct name_srvc_question_lst *cur_qstn;
  struct name_srvc_resource_lst *cur_res;
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

  walker = fill_name_srvc_pckt_header(packet->header, walker,
				      endof_pckt);

  cur_qstn = packet->questions;
  while (cur_qstn) {
    walker = fill_name_srvc_pckt_question(cur_qstn->qstn, walker,
					  endof_pckt, 0);
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
				     endof_pckt, 0);
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
				     endof_pckt, 0);
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
				     endof_pckt, 0);
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

  result->header = calloc(1, sizeof(struct name_srvc_pckt_header));
  if (! result->header) {
    /* TODO: errno signaling stuff */
    free(result);
    return 0;
  }
  result->header->numof_questions = qstn;
  result->header->numof_answers = answ;
  result->header->numof_authorities = auth;
  result->header->numof_additional_recs = adit;

  if (qstn) {
    cur_qstn = calloc(1, sizeof(struct name_srvc_question_lst));
    if (! cur_qstn) {
      /* TODO: errno signaling stuff */
      free(result->header);
      free(result);
      return 0;
    }
    result->questions = cur_qstn;

    qstn--;
    while (qstn) {
      cur_qstn->next = calloc(1, sizeof(struct name_srvc_question_lst));
      if (! cur_qstn->next) {
	/* TODO: errno signaling stuff */
	destroy_name_srvc_pckt(result, 1, 1);
	return 0;
      }
      cur_qstn = cur_qstn->next;
      qstn--;
    }
  }

  if (answ) {
    cur_res = calloc(1, sizeof(struct name_srvc_resource_lst));
    if (! cur_res) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->answers = cur_res;

    answ--;
    while (answ) {
      cur_res->next = calloc(1, sizeof(struct name_srvc_resource_lst));
      if (! cur_res->next) {
	/* TODO: errno signaling stuff */
	destroy_name_srvc_pckt(result, 1, 1);
	return 0;
      }
      cur_res = cur_res->next;
      answ--;
    }
  }

  if (auth) {
    cur_res = calloc(1, sizeof(struct name_srvc_resource_lst));
    if (! cur_res) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->authorities = cur_res;

    auth--;
    while (auth) {
      cur_res->next = calloc(1, sizeof(struct name_srvc_resource_lst));
      if (! cur_res->next) {
	/* TODO: errno signaling stuff */
	destroy_name_srvc_pckt(result, 1, 1);
	return 0;
      }
      cur_res = cur_res->next;
      auth--;
    }
  }

  if (adit) {
    cur_res = calloc(1, sizeof(struct name_srvc_resource_lst));
    if (! cur_res) {
      /* TODO: errno signaling stuff */
      destroy_name_srvc_pckt(result, 1, 1);
      return 0;
    }
    result->aditionals = cur_res;

    adit--;
    while (adit) {
      cur_res->next = calloc(1, sizeof(struct name_srvc_resource_lst));
      if (! cur_res->next) {
	/* TODO: errno signaling stuff */
	destroy_name_srvc_pckt(result, 1, 1);
	return 0;
      }
      cur_res = cur_res->next;
      adit--;
    }
  }

  return result;
}

struct name_srvc_question *name_srvc_make_qstn(unsigned char *label,
					       struct nbnodename_list *scope,
					       uint16_t dns_type,
					       uint16_t dns_class) {
  struct name_srvc_question *result;

  if (! label) {
    return 0;
  }

  result = malloc(sizeof(struct name_srvc_question));
  if (! result) {
    return 0;
  }
  result->name = malloc(sizeof(struct nbnodename_list));
  if (! result->name) {
    free(result);
    return 0;
  }

  result->name->name = encode_nbnodename(label, 0);
  if (! result->name->name) {
    free(result->name);
    free(result);
    return 0;
  }
  result->name->len = NETBIOS_CODED_NAME_LEN;
  result->name->next_name = clone_nbnodename(scope);
  if ((! result->name->next_name) && scope) {
    free(result->name->name);
    free(result->name);
    free(result);
    return 0;
  }

  result->qtype = dns_type;
  result->qclass = dns_class;

  return result;
}

struct name_srvc_resource *name_srvc_make_res(unsigned char *label,
					      struct nbnodename_list *scope,
					      uint16_t dns_type,
					      uint16_t dns_class,
					      uint32_t ttl,
					      enum name_srvc_rdata_type rdata_t,
					      void *rdata_content,
					      unsigned char node_type,
					      unsigned char isgroup) {
  struct name_srvc_resource *result;

  if (! label) {
    return 0;
  }

  result = malloc(sizeof(struct name_srvc_resource));
  if (! result) {
    return 0;
  }
  result->name = malloc(sizeof(struct nbnodename_list));
  if (! result->name) {
    free(result);
    return 0;
  }

  result->name->name = encode_nbnodename(label, 0);
  if (! result->name->name) {
    free(result->name);
    free(result);
    return 0;
  }
  result->name->len = NETBIOS_CODED_NAME_LEN;
  result->name->next_name = clone_nbnodename(scope);
  if ((! result->name->next_name) && scope) {
    free(result->name->name);
    free(result->name);
    free(result);
    return 0;
  }

  result->rrtype = dns_type;
  result->rrclass = dns_class;
  result->ttl = ttl;

  result->rdata_t = rdata_t;

  switch (rdata_t) {
  case nb_address_list:
  case nb_NBT_node_ip_address:
    result->rdata = make_nbaddrlst(rdata_content, &(result->rdata_len),
				   rdata_t, isgroup, node_type);
    break;

  case nb_nodename:
    result->rdata_len = nbnodenamelen(rdata_content);
    result->rdata = rdata_content;
    break;

  default:
    result->rdata_len = 0;
    result->rdata = 0;
    break;
  }

  return result;
}

struct nbaddress_list *make_nbaddrlst(struct ipv4_addr_list *ipv4_list,
				      uint16_t *finallen,
				      enum name_srvc_rdata_type type,
				      unsigned char isgroup,
				      unsigned char node_type) {
  struct nbaddress_list *nbaddrs_frst, *nbaddrs;
  uint16_t len, lenstep = 4;
  uint16_t flags = 0;

  if (! ipv4_list)
    return 0;

  switch (type) {
  case nb_address_list:
    lenstep = 6;
    if (isgroup)
      flags = NBADDRLST_GROUP_YES;
    else
      flags = NBADDRLST_GROUP_NO;
    switch (node_type) {
    case CACHE_NODEFLG_H:
      flags |= NBADDRLST_NODET_H;
      break;
    case CACHE_NODEFLG_M:
      flags |= NBADDRLST_NODET_M;
      break;
    case CACHE_NODEFLG_P:
      flags |= NBADDRLST_NODET_P;
      break;
    case CACHE_NODEFLG_B:
    default:
      flags |= NBADDRLST_NODET_B;
      break;
    }
    /* fall-through! */
  case nb_NBT_node_ip_address:
    len = 0;
    nbaddrs_frst = nbaddrs = 0;
    while (ipv4_list) {
      len = len + lenstep;
      if (nbaddrs_frst) {
	nbaddrs->next_address = malloc(sizeof(struct nbaddress_list));
	if (! nbaddrs->next_address) {
	  while (nbaddrs_frst) {
	    nbaddrs = nbaddrs_frst->next_address;
	    free(nbaddrs_frst);
	    nbaddrs_frst = nbaddrs;
	  }
	  if (finallen)
	    *finallen = 0;
	  return 0;
	}
	nbaddrs = nbaddrs->next_address;
      } else {
	nbaddrs_frst = malloc(sizeof(struct nbaddress_list));
	if (! nbaddrs_frst) {
	  if (finallen)
	    *finallen = 0;
	  return 0;
	}
	nbaddrs = nbaddrs_frst;
      }

      nbaddrs->flags = flags;
      nbaddrs->there_is_an_address = TRUE;
      nbaddrs->address = ipv4_list->ip_addr;

      ipv4_list = ipv4_list->next;
    }
    if (nbaddrs) {
      nbaddrs->next_address = 0;
      if (finallen)
	*finallen = len;
      return nbaddrs_frst;
    } else {
      return 0;
    }
    break;

  default:
    if (finallen)
      *finallen = 0;
    return 0;
    break;
  }

  return 0;
}

void destroy_name_srvc_pckt(void *packet_ptr,
			    unsigned int complete,
			    unsigned int really_complete) {
  struct name_srvc_packet *packet;
  struct name_srvc_question_lst *qstn;
  struct nbnodename_list *nbnodename;

  if (! packet_ptr)
    return;

  packet = packet_ptr;

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
	if (packet->questions->qstn->name)
	  free(packet->questions->qstn->name->name);
	free(packet->questions->qstn->name);
      }
      free(packet->questions->qstn);
    }
    free(packet->questions);
    packet->questions = qstn;
  }

  destroy_name_srvc_res_lst(packet->answers, complete, really_complete);
  destroy_name_srvc_res_lst(packet->authorities, complete, really_complete);
  destroy_name_srvc_res_lst(packet->aditionals, complete, really_complete);

  free(packet);

  /* I now understand why garbage collectors were invented. */

  return;
}

void destroy_name_srvc_res_lst(struct name_srvc_resource_lst *cur_res,
			       unsigned int complete,
			       unsigned int really_complete) {
  struct name_srvc_resource_lst *res;

  while (cur_res) {
    res = cur_res->next;
    if (cur_res->res) {
      if (complete) {
	destroy_nbnodename(cur_res->res->name);
      } else {
	if (cur_res->res->name) {
	  free(cur_res->res->name->name);
	  free(cur_res->res->name);
	}
      }

      destroy_name_srvc_res_data(cur_res->res, complete, really_complete);

      free(cur_res->res);
    }
    free(cur_res);
    cur_res = res;
  }
}

void destroy_name_srvc_res_data(struct name_srvc_resource *res,
				unsigned int complete,
				unsigned int really_complete) {
  struct name_srvc_statistics_rfc1002 *stats;
  struct nbnodename_list_backbone *nbnodename_bckbone,
    *next_nbnodename_bckbone;
  struct nbnodename_list *nbnodename;
  struct nbaddress_list *addr_list, *next_addr_list;

  switch (res->rdata_t) {
  case nb_statistics_rfc1002:
    stats = res->rdata;
    if (stats) {
      nbnodename_bckbone = stats->listof_names;
      while (nbnodename_bckbone) {
	next_nbnodename_bckbone = nbnodename_bckbone->next_nbnodename;

	if (really_complete) {
	  destroy_nbnodename(nbnodename_bckbone->nbnodename);
	} else {
	  if (nbnodename_bckbone->nbnodename) {
	    free(nbnodename_bckbone->nbnodename->name);
	    free(nbnodename_bckbone->nbnodename);
	  }
	}

	free(nbnodename_bckbone);
	nbnodename_bckbone = next_nbnodename_bckbone;
      }
      free(stats);
    }
    break;

  case nb_nodename:
    nbnodename = res->rdata;
    if (really_complete) {
      destroy_nbnodename(nbnodename);
    } else {
      if (nbnodename) {
	free(nbnodename->name);
	free(nbnodename);
      }
    }
    break;

  case nb_address_list:
  case nb_NBT_node_ip_address:
    addr_list = res->rdata;
    while (addr_list) {
      next_addr_list = addr_list->next_address;
      free(addr_list);
      addr_list = next_addr_list;
    }
    break;

  case unknown_important_resource:
  default:
    free(res->rdata);
    break;
  }

  return;
}


/* Dont forget to fill in the transaction_id of the packet! */
struct name_srvc_packet *name_srvc_Ptimer_mkpckt(struct cache_namenode *namecard,
						 struct nbnodename_list *scope,
						 uint64_t *total_lenof_nbaddrs) {
  struct name_srvc_packet *pckt;
  struct name_srvc_question_lst **qstn_ptr;
  struct name_srvc_resource_lst **adit_ptr;
  struct nbaddress_list *nbaddrs, **last_nbaddrs;
  unsigned int numof_refresh, i;
  uint64_t nbaddrs_len;
  uint16_t lenof_res, save_lenof_res;
  time_t cur_time, diff;

  if (! namecard)
    return 0;


  pckt = 0;
  numof_refresh = 0;
  qstn_ptr = 0;
  adit_ptr = 0;
  nbaddrs_len = 0;

  cur_time = time(0);
  while (namecard) {
    /* In the below if statement, a bunch of things are tested, including
     * a number of critical tests which all nodes must pass.
     * If it is found that any of the critical tests fail, the namecard is
     * scheduled for deletion by the cache pruner and jumped over by this
     * function. */
        /* is the name in a NBNS dependant mode? */
    if ((! (namecard->node_types & (CACHE_NODEFLG_P |
				    CACHE_NODEFLG_M |
				    CACHE_NODEFLG_H))) ||
	/* is there at least one group flag set? */
	((namecard->group_flg & (ISGROUP_YES | ISGROUP_NO)) ?
	   FALSE : (namecard->timeof_death = 0, TRUE)) ||
	/* is there only one group flag set? */
	((((namecard->group_flg & ISGROUP_YES) ? 1 : 0) ^
	  ((namecard->group_flg & ISGROUP_NO) ? 1 : 0)) ?
	   FALSE : (namecard->timeof_death = 0, TRUE))) {
      namecard = namecard->next;
      continue;
    }
    diff = (namecard->timeof_death) - cur_time;
    if (diff < nbworks_namsrvc_cntrl.Ptimer_refresh_margin) {
      if (! pckt) {
	pckt = alloc_name_srvc_pckt(0, 0, 0, 0);
	if (! pckt)
	  return 0;
	else {
	  qstn_ptr = &(pckt->questions);
	  adit_ptr = &(pckt->aditionals);
	}
      }

      for (i=0; i<4; i++) {
	if (namecard->addrs.recrd[i].node_type & (CACHE_NODEFLG_P |
						  CACHE_NODEFLG_M |
						  CACHE_NODEFLG_H))
	  break;
      }
      if (i>=4) {
	namecard = namecard->next;
	continue;
      }

      numof_refresh++;

      /* ---------------------------------- */
      /* question first */
      *qstn_ptr = malloc(sizeof(struct name_srvc_question_lst));
      if (! *qstn_ptr) {
	destroy_name_srvc_pckt(pckt, 1, 1);
	return 0;
      }
      (*qstn_ptr)->qstn = name_srvc_make_qstn(namecard->name, scope,
					      namecard->dns_type,
					      namecard->dns_class);
      if (! ((*qstn_ptr)->qstn)) {
	(*qstn_ptr)->next = 0;
	destroy_name_srvc_pckt(pckt, 1, 1);
	return 0;
      }
      qstn_ptr = &((*qstn_ptr)->next);

      /* ---------------------------------- */
      /* aditional second */
      *adit_ptr = malloc(sizeof(struct name_srvc_resource_lst));
      if (! *adit_ptr) {
	destroy_name_srvc_pckt(pckt, 1, 1);
	return 0;
      }
      (*adit_ptr)->res = name_srvc_make_res(namecard->name, scope,
					    namecard->dns_type,
					    namecard->dns_class,
					    namecard->refresh_ttl,
					    nb_address_list,
					    namecard->addrs.recrd[i].addr,
					    namecard->addrs.recrd[i].node_type,
					    namecard->group_flg);
      if (! ((*adit_ptr)->res)) {
	(*adit_ptr)->next = 0;
	destroy_name_srvc_pckt(pckt, 1, 1);
	return 0;
      }
      lenof_res = (*adit_ptr)->res->rdata_len;

      last_nbaddrs = (struct nbaddress_list **)&((*adit_ptr)->res->rdata);
      nbaddrs = *last_nbaddrs;
      /* continue scanning the addresses from where the last loop left off */
      for (i++; i<4; i++) {
	if (namecard->addrs.recrd[i].node_type & (CACHE_NODEFLG_P |
						  CACHE_NODEFLG_M |
						  CACHE_NODEFLG_H)) {
	  while (nbaddrs) {
	    last_nbaddrs = &(nbaddrs->next_address);
	    nbaddrs = *last_nbaddrs;
	  }
	  save_lenof_res = lenof_res;

	  *last_nbaddrs = make_nbaddrlst(namecard->addrs.recrd[i].addr,
					 &lenof_res, nb_address_list,
					 namecard->addrs.recrd[i].node_type,
					 namecard->group_flg);

	  lenof_res = save_lenof_res + lenof_res;
	}
      }

      (*adit_ptr)->res->rdata_len = lenof_res;
      nbaddrs_len = nbaddrs_len + lenof_res;
      if (nbaddrs_len < lenof_res) {
	/* Overflow! Not fatal, but must be taken into account because
	 * it means the packet must be sent via TCP. Or, if you prefer a
	 * hit-or-miss approach, by many, Many, WAY-TOO-MANY UDP packets
	 * even though there is no guarrante any single resource's datalist
	 * can fit in a UDP packet. */
	nbaddrs_len = ONES;
      }
      adit_ptr = &((*adit_ptr)->next);
    }
  }

  if (pckt) {
    *qstn_ptr = 0;
    *adit_ptr = 0;

    pckt->header->opcode = (OPCODE_REQUEST | OPCODE_REFRESH);
    pckt->header->nm_flags = FLG_RD;
    pckt->header->rcode = 0;
    pckt->header->numof_questions = numof_refresh;
    pckt->header->numof_additional_recs = numof_refresh;

    if (total_lenof_nbaddrs)
      *total_lenof_nbaddrs = nbaddrs_len;
  }

  return pckt;
}
