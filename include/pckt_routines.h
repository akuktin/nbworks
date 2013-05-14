/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NBWORKS_PKCTROUTINES_H
# define NBWORKS_PKCTROUTINES_H 1

# include "name_srvc_pckt.h"

# ifndef MAX_UDP_PACKET_LEN
/* This is ment to capture ALL packets, regardless of anything.
 * The number was originally 0xffff, but then I remembered that
 * the UDP header, 8 octets wide, is also included in the length
 * field but will never be sent by the kernel to the application.
 * So, I shortened the macro. */
#  define MAX_UDP_PACKET_LEN (0xffff - 8)
# endif
# define MAX_DNS_LABEL_LEN 0x3f

/* The largest amount the intrapacket pointer can handle. */
# define MAX_PACKET_POINTER 0x3fff

# define SIZEOF_STARTBUFF 0x6000

struct state__readDNSlabels {
  struct nbworks_nbnamelst *first_label;
  struct nbworks_nbnamelst **cur_label;
  unsigned int name_offset;
  unsigned int mystery_int;
  void *mystery_pointer;
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
void
  fill_startbuff(unsigned char *startbuff_buff,
                 unsigned char **startbuff_walker,
                 unsigned char *buff,
                 unsigned char *marker);
struct nbworks_nbnamelst *
  read_all_DNS_labels(unsigned char **start_and_end_of_walk,
                      unsigned char *start_of_packet,
                      unsigned char *end_of_packet,
                      uint32_t offsetof_start,
                      struct state__readDNSlabels **state,
                      unsigned char *startblock,
                      unsigned int lenof_startblock);
unsigned char *
  fill_all_DNS_labels(struct nbworks_nbnamelst *content,
                      unsigned char *field,
                      unsigned char *endof_pckt,
                      struct nbworks_nbnamelst **state);
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
void
  destroy_nbaddress_list(struct nbaddress_list *list);
struct nbaddress_list *
  read_ipv4_address_list(unsigned char **start_and_end_of_walk,
                         uint16_t len_of_addresses,
                         unsigned char *end_of_packet);
unsigned char *
  fill_ipv4_address_list(struct nbaddress_list *content,
                         unsigned char *walker,
                         unsigned char *endof_pckt);

#endif /* NBWORKS_PKCTROUTINES_H */
