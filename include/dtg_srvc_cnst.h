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

#ifndef NBWORKS_DTGSRVCCNST_H
# define NBWORKS_DTGSRVCCNST_H 1

struct dtg_pckt_pyld_normal *
  dtg_srvc_make_pyld_normal(unsigned char *src,
                            unsigned char src_type,
                            unsigned char *dst,
                            unsigned char dst_type,
                            struct nbworks_nbnamelst *scope,
                            void *payload,
                            uint16_t lenof_pyld,
                            uint16_t offset);

#endif /* NBWORKS_DTGSRVCCNST_H */
