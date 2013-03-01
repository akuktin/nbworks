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

#ifndef NBWORKS_NAMESRVCFUNCFUNC_H
# define NBWORKS_NAMESRVCFUNCFUNC_H 1

# include "service_sector.h"

void
  name_srvc_do_namregreq(struct name_srvc_packet *outpckt,
                         struct sockaddr_in *addr,
                         struct ss_queue *trans,
                         uint32_t tid,
                         time_t cur_time);

void
  name_srvc_do_namqrynodestat(struct name_srvc_packet *outpckt,
                              struct sockaddr_in *addr,
                              struct ss_queue *trans,
                              uint32_t tid,
                              time_t cur_time);

void
  name_srvc_do_posnamqryresp(struct name_srvc_packet *outpckt,
                             struct sockaddr_in *addr,
                             struct ss_queue *trans,
                             uint32_t tid,
                             time_t cur_time);

#endif /* NBWORKS_NAMESRVCFUNCFUNC_H */
