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

#ifndef NBWORKS_DTGSRVCFUNC_H
# define NBWORKS_DTGSRVCFUNC_H 1

# include "nodename.h"
# include "dtg_srvc_pckt.h"
# include "service_sector.h"

inline uint16_t
  dtg_srvc_doesitmatch(struct nbworks_nbnamelst *target,
                       struct dtg_srvc_packet *shot);
inline struct nbworks_nbnamelst *
  dtg_srvc_extract_dstname(struct dtg_srvc_packet *pckt);
inline struct nbworks_nbnamelst *
  dtg_srvc_extract_srcname(struct dtg_srvc_packet *pckt);
inline struct nbworks_nbnamelst *
  dtg_srvc_get_srcnam_recvpckt(struct dtg_srvc_recvpckt *pckt);

/* void dtg_srvc_send_NOTHERE_error(struct ss_unif_pckt_list *pckt); */

#endif /* NBWORKS_DTGSRVCFUNC_H */
