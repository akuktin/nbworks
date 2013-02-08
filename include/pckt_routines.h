#ifndef NBWORKS_PKCTROUTINES_H
# define NBWORKS_PKCTROUTINES_H 1

# include <stdint.h>

# include "name_srvc_pckt.h"

# ifndef MAX_UDP_PACKET_LEN
#  define MAX_UDP_PACKET_LEN 0xffff
# endif
# define MAX_DNS_LABEL_LEN 0x3f

struct state__readDNSlabels {
  struct nbnodename_list *first_label, *cur_label;
  void *pointers_visited_root;
  unsigned int name_offset;
  unsigned char *walker;
};

inline unsigned char *read_16field(unsigned char *content,
                                   uint16_t *field);
inline unsigned char *read_32field(unsigned char *content,
                                   uint32_t *field);
inline unsigned char *read_48field(unsigned char *content,
                                   uint64_t *field);
inline unsigned char *read_64field(unsigned char *content,
                                   uint64_t *field);
inline unsigned char *fill_16field(uint16_t content,
                                   unsigned char *field);
inline unsigned char *fill_32field(uint32_t content,
                                   unsigned char *field);
inline unsigned char *fill_48field(uint64_t content,
                                   unsigned char *field);
inline unsigned char *fill_64field(uint64_t content,
                                   unsigned char *field);
struct nbnodename_list *
  read_all_DNS_labels(unsigned char **start_and_end_of_walk,
                      unsigned char *start_of_packet,
                      unsigned char *end_of_packet,
                      struct state__readDNSlabels **state);
unsigned char *
  fill_all_DNS_labels(struct nbnodename_list *content,
                      unsigned char *field,
                      unsigned char *endof_pckt,
                      struct nbnodename_list **state);
unsigned char *
  fastfrwd_all_DNS_labels(unsigned char **start_and_end_of_walk,
                          unsigned char *endof_pckt);
struct nbaddress_list *
  read_nbaddress_list(unsigned char **start_and_end_of_walk,
                      uint16_t len_of_addresses,
                      unsigned char *end_of_packet);
unsigned char *
  fill_nbaddress_list(struct nbaddress_list *content,
                      unsigned char *walker,
                      unsigned char *endof_pckt);
struct nbaddress_list *
  read_ipv4_address_list(unsigned char **start_and_end_of_walk,
                         uint16_t len_of_addresses,
                         unsigned char *end_of_packet);
unsigned char *
  fill_ipv4_address_list(struct nbaddress_list *content,
                         unsigned char *walker,
                         unsigned char *endof_pckt);

#endif /* NBWORKS_PKCTROUTINES_H */
