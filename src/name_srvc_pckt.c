#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"


struct name_srvc_pckt_header *read_name_srvc_pckt_header(void **master_packet_walker) {
  struct name_srvc_pckt_header *header;
  unsigned char *walker;

  header = malloc(sizeof(struct name_srvc_pckt_header));
  if (! header) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = (unsigned char *)*master_packet_walker;

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

  *master_packet_walker = (void *)walker;

  return header;
}

void fill_name_srvc_pckt_header(const struct name_srvc_pckt_header *header,
				void **master_packet_walker) {
  unsigned char *walker;

  walker = (unsigned char *)*master_packet_walker;

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

  *master_packet_walker = (void *)walker;

  return;
}

struct name_srvc_question *read_name_srvc_pckt_question(void **master_packet_walker,
							void *start_of_packet) {
  struct name_srvc_question *question;
  unsigned char *walker;
  void *remember_walker;

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
  walker = (unsigned char *)(*master_packet_walker +
			     ((4- ((*master_packet_walker - remember_walker) %4))) %4);

  walker = read_16field(walker, &(question->qtype));
  walker = read_16field(walker, &(question->qclass));

  *master_packet_walker = (void *)walker;

  return question;
}

void fill_name_srvc_pckt_question(struct name_srvc_question *question,
				  void **master_packet_walker) {
  unsigned char *walker;

  walker = (unsigned char *)*master_packet_walker;

  remember_walkers_position = walker;
  walker = fill_all_DNS_labels(question->name, walker);

  /* Respect the 32-bit boundary. */
  walker = (unsigned char *)(walker +
			     ((4- ((*master_packet_walker - walker) % 4)) %4));

  walker = fill_16field(question->qtype, walker);
  walker = fill_16field(question->qclass, walker);

  *master_packet_walker = (void *)walker;

  return;
}
