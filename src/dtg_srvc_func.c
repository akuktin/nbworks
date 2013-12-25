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

#include "c_lang_extensions.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"
#include "service_sector.h"
#include "service_sector_threads.h"


/* returns: >0=success, 0=fail */
inline uint16_t dtg_srvc_doesitmatch(struct nbworks_nbnamelst *target,
				     struct dtg_srvc_packet *shot) {
  struct nbworks_nbnamelst *gun;
  struct dtg_pckt_pyld_normal *pyld;

  if (! (target && shot))
    return 0;

  switch (shot->payload_t) {
  case normal:
    pyld = shot->payload;
    gun = pyld->dst_name;
    break;

  case nbnodename:
    gun = shot->payload;
    break;

  default:
    return FALSE;
  }

  if (! nbworks_cmp_nbnodename(target->next_name, gun->next_name))
    if (! memcmp(target->name, gun->name, NETBIOS_CODED_NAME_LEN))
      return TRUE;
  return FALSE;
}

inline struct nbworks_nbnamelst *dtg_srvc_extract_dstname(struct dtg_srvc_packet *pckt) {
  struct dtg_pckt_pyld_normal *pyld;

  if (! pckt)
    return 0;

  switch (pckt->payload_t) {
  case normal:
    pyld = pckt->payload;
    return pyld->dst_name;

  case nbnodename:
    return pckt->payload;

  default:
    return 0;
  }
}

inline struct nbworks_nbnamelst *dtg_srvc_extract_srcname(struct dtg_srvc_packet *pckt) {
  struct dtg_pckt_pyld_normal *pyld;

  if (! pckt)
    return 0;

  switch (pckt->payload_t) {
  case normal:
    pyld = pckt->payload;
    return pyld->src_name;

  case nbnodename:
    return pckt->payload;

  default:
    return 0;
  }
}

inline struct nbworks_nbnamelst *dtg_srvc_get_srcnam_recvpckt(struct dtg_srvc_recvpckt *pckt) {
  if (! pckt)
    return 0;
  else
    return pckt->dst;
}
