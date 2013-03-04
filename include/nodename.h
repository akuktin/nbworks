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

#ifndef NBWORKS_NODENAME_H
# define NBWORKS_NODENAME_H 1

# include <stdint.h>

# define NETBIOS_NAME_LEN 16
# define NETBIOS_CODED_NAME_LEN 32

# define NODENAMEFLG_PRM 0x0200  /* Name is permanent. */
# define NODENAMEFLG_ACT 0x0400  /* Name is active (bit is always on). */
# define NODENAMEFLG_CNF 0x0800  /* Name is in conflict. */
# define NODENAMEFLG_DRG 0x1000  /* Name is being deleted. */

# define JOKER_NAME       "*\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
# define JOKER_NAME_CODED "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

struct nbnodename_list {
  unsigned char *name;
  unsigned char len; /* Not int because the field is
                        6 bits wide in the packet. */
  struct nbnodename_list *next_name;
};

struct nbnodename_list_backbone {
  struct nbnodename_list *nbnodename;
  uint16_t name_flags;
  struct nbnodename_list_backbone *next_nbnodename;
};

unsigned char *
  decode_nbnodename(const unsigned char *coded_name,
                    unsigned char *result_buf);
unsigned char *
  encode_nbnodename(const unsigned char *decoded_name,
                    unsigned char *result_buf);

unsigned char
  unmake_nbnodename(unsigned char **coded_name);
unsigned char *
  make_nbnodename_sloppy(const unsigned char *string);
unsigned char *
  make_nbnodename(const unsigned char *string,
                  const unsigned char type_char);

void
  destroy_nbnodename(struct nbnodename_list *nbnodename);
struct nbnodename_list *
  clone_nbnodename(struct nbnodename_list *nbnodename);
int
  cmp_nbnodename(struct nbnodename_list *name_one,
                 struct nbnodename_list *name_two);
uint16_t
  nbnodenamelen(struct nbnodename_list *nbnodename);

#endif /* NBWORKS_NODENAME_H */
