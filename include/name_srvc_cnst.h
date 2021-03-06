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

#ifndef NBWORKS_NAMESRVCCNST_H
# define NBWORKS_NAMESRVCCNST_H 1

# include "constdef.h"

struct name_srvc_packet *
  name_srvc_make_name_reg_big(unsigned char *name,
                              unsigned char name_type,
                              struct nbworks_nbnamelst *scope,
                              uint32_t ttl,
                              ipv4_addr_t in_address,
                              node_type_t node_type);
struct name_srvc_packet *
  name_srvc_make_name_reg_small(unsigned char *name,
                                unsigned char name_type,
                                struct nbworks_nbnamelst *scope,
                                uint32_t ttl,
                                ipv4_addr_t in_address,
                                node_type_t node_type);
struct name_srvc_resource *
  name_srvc_make_res_nbaddrlst(unsigned char *name,
                               unsigned char name_type,
                               struct nbworks_nbnamelst *scope,
                               uint32_t ttl,
                               ipv4_addr_t in_address,
                               node_type_t node_type);
struct name_srvc_packet *
  name_srvc_make_name_qry_req(unsigned char *name,
                              unsigned char name_type,
                              struct nbworks_nbnamelst *scope);
struct name_srvc_packet *
  name_srvc_make_name_qry_pos(unsigned char *name,
                              unsigned char name_type,
                              struct nbworks_nbnamelst *scope,
                              struct nbaddress_list *addresses,
                              unsigned int numof_addresses,
                              uint32_t ttl);
struct name_srvc_packet *
  name_srvc_make_name_qry_neg(unsigned char *name,
                              unsigned char name_type,
                              struct nbworks_nbnamelst *scope);
struct name_srvc_packet *
  name_srvc_make_name_qry_red(unsigned char *name,
                              unsigned char name_type,
                              struct nbworks_nbnamelst *scope,
                              struct nbworks_nbnamelst *namesrvr_name,
                              struct nbaddress_list *namesrvr_addr,
                              uint32_t ttl);
struct name_srvc_packet *
  name_srvc_make_stat_rfc1002_qry(unsigned char *name,
                                  unsigned char name_type,
                                  struct nbworks_nbnamelst *scope);
struct name_srvc_packet *
  name_srvc_make_stat_rfc1002_rsp(unsigned char *name,
                                  unsigned char name_type,
                                  struct nbworks_nbnamelst *scope,
                                  struct nbnodename_list_backbone *my_names_this_scope);
struct name_srvc_packet *
  name_srvc_make_wack(unsigned char *name,
                      unsigned char name_type,
                      struct nbworks_nbnamelst *scope,
                      uint32_t ttl,
                      uint16_t nm_flags);

#endif /* NBWORKS_NAMESRVCCNST_H */
