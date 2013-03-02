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

#ifndef NBWORKS_NAMESRVCFUNCB_H
# define NBWORKS_NAMESRVCFUNCB_H 1

# include "name_srvc_pckt.h"

int
  name_srvc_B_add_name(unsigned char *name,
                       unsigned char name_type,
                       struct nbnodename_list *scope,
                       uint32_t my_ip_address,
                       unsigned char group_flg,
                       uint32_t ttl);
/* return: 0=success, >0=fail, -1=error */
int
  name_srvc_B_release_name(unsigned char *name,
                           unsigned char name_type,
                           struct nbnodename_list *scope,
                           uint32_t my_ip_address,
                           unsigned char group_flg);
void *
  name_srvc_B_handle_newtid(void *input);

#endif /* NBWORKS_NAMESRVCFUNCB_H */
