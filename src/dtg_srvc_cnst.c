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
#include <string.h>
#include <stdint.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "dtg_srvc_pckt.h"


struct dtg_pckt_pyld_normal *dtg_srvc_make_pyld_normal(unsigned char *src,
						       unsigned char src_type,
						       unsigned char *dst,
						       unsigned char dst_type,
						       struct nbnodename_list *scope,
						       void *payload,
						       uint16_t lenof_pyld,
						       uint16_t offset) {
  struct dtg_pckt_pyld_normal *result;
  struct nbnodename_list *complete_src, *complete_dst;
  int lenof_names;
  unsigned char *label_src, *label_dst;

  label_src = make_nbnodename(src, src_type);
  if (! label_src) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  label_dst = make_nbnodename(dst, dst_type);
  if (! label_dst) {
    /* TODO: errno signaling stuff */
    free(label_src);
    return 0;
  }

  complete_src = malloc(sizeof(struct nbnodename_list));
  if (! complete_src) {
    /* TODO: errno signaling stuff */
    free(label_dst);
    free(label_src);
    return 0;
  }

  complete_dst = malloc(sizeof(struct nbnodename_list));
  if (! complete_dst) {
    /* TODO: errno signaling stuff */
    free(complete_src);
    free(label_dst);
    free(label_src);
    return 0;
  }

  result = malloc(sizeof(struct dtg_pckt_pyld_normal));
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_dst);
    free(complete_src);
    free(label_dst);
    free(label_src);
    return 0;
  };

  complete_src->name = label_src;
  complete_src->len = NETBIOS_CODED_NAME_LEN;
  complete_src->next_name = clone_nbnodename(scope);

  complete_dst->name = label_dst;
  complete_dst->len = NETBIOS_CODED_NAME_LEN;
  complete_dst->next_name = clone_nbnodename(scope);

  lenof_names = align_incr(0, nbnodenamelen(complete_src), 4) *2;

  result->len = lenof_names + lenof_pyld;
  result->offset = offset;
  result->src_name = complete_src;
  result->dst_name = complete_dst;
  result->payload = payload;
  result->do_del_pyldpyld = TRUE;
  result->pyldpyld_delptr = 0;

  return result;
}
