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

#ifndef NBWORKS_RAILFLUSH_H
# define NBWORKS_RAILFLUSH_H 1

# include "rail-comm.h"

size_t
  rail_flushrail(size_t len,
                 int rail);
struct com_comm *
  read_railcommand(unsigned char *packet,
                   unsigned char *endof_pckt,
                   struct com_comm *field);
unsigned char *
  fill_railcommand(struct com_comm *command,
                   unsigned char *packet,
                   unsigned char *endof_packet);
struct rail_name_data *
  read_rail_name_data(unsigned char *startof_buff,
                      unsigned char *endof_buff);
unsigned char *
  fill_rail_name_data(struct rail_name_data *data,
                      unsigned char *startof_buff,
                      unsigned char *endof_buff);

#endif /* NBWORKS_RAILFLUSH_H */
