#include <stdlib.h>
#include <stdint.h>

#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"

struct name_srvc_pckt_header *read_name_srvc_pckt_header(const void *packet) {
  struct name_srvc_pckt_header *header;
  unsigned char *walker;

  header = malloc(sizeof(struct name_srvc_pckt_header));
  if (! header) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = (unsigned char *)packet;

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

  return header;
}

void fill_name_srvc_pckt_header(const struct name_srvc_pckt_header *header,
				void *packet) {
  unsigned char *walker;

  walker = (unsigned char *)packet;

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

  return;
}
