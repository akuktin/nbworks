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

#ifndef NBWORKS_NAMESRVCFUNCP_H
# define NBWORKS_NAMESRVCFUNCP_H 1

# include "name_srvc_pckt.h"

/* return: >0=success (return is ttl), 0=fail */
uint32_t
  name_srvc_P_add_name(unsigned char *name,
                       unsigned char name_type,
                       struct nbworks_nbnamelst *scope,
                       ipv4_addr_t my_ip_address,
                       unsigned char group_flg,
                       uint32_t ttl);

#endif /* NBWORKS_NAMESRVCFUNCP_H */
