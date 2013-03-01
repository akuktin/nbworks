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
#include <stdint.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_cnst.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_B.h"
#include "randomness.h"
#include "service_sector.h"
#include "service_sector_threads.h"


void name_srvc_do_namregreq(struct name_srvc_packet *outpckt,
			    struct sockaddr_in *addr,
			    struct ss_queue *trans,
			    uint32_t tid,
			    time_t cur_time) {
  struct name_srvc_packet *pckt;
  struct nbaddress_list *nbaddr_list;
  struct cache_namenode *cache_namecard;
  uint32_t in_addr, i;
  unsigned char label[NETBIOS_NAME_LEN+1], decoded_name[NETBIOS_NAME_LEN+1];

  for (res = outpckt->aditionals;
       res != 0;      /* Maybe test in questions too. */
       res = res->next) {
    if ((res->res) &&
	(res->res->name) &&
	(res->res->rdata_t == nb_address_list)) {
      nbaddr_list = res->res->rdata;

      while (nbaddr_list) {
	if ((nbaddr_list->flags & NBADDRLST_GROUP_MASK) ||
	    (! nbaddr_list->there_is_an_address)) {
	  /* Jump over group addresses and empty fields. */
	  nbaddr_list = nbaddr_list->next_address;
	  continue;
	}

	cache_namecard = find_nblabel(decode_nbnodename(res->res->name->name,
							decoded_name),
				      NETBIOS_NAME_LEN,
				      ANY_NODETYPE, ISGROUP_NO,
				      res->res->rrtype,
				      res->res->rrclass,
				      res->res->name->next_name);

	/*
	 * RATIONALE: Names can be either group names or unique names. Since
	 * we jump over group names, that means we are only looking for unique
	 * names. Furthermore, we are only looking for our names. If we fail to
	 * find a record for the asked unique name, that means we have no problem.
	 * Also, if we find a record, but the name is not ours, we again have
	 * no problem.
	 */

	if (cache_namecard &&
	    (cache_namecard->token) &&
	    (cache_namecard->timeof_death > cur_time) &&
	    (! cache_namecard->isinconflict)) { /* Paired with the DOS_BUG in the
						 * POSITIVE NAME QUERY RESPONSE
						 * section, this can be abused to
						 * execute a hostile name takeover.
						 */
	  /* Someone is trying to take my name. */

	  in_addr = 0;
	  for (i=0; i<4; i++) {
	    if (cache_namecard->addrs.recrd[i].addr) {
	      in_addr = cache_namecard->addrs.recrd[i].addr->ip_addr;
	      break;
	    }
	  }

	  if (i<4) {
	    pckt = name_srvc_make_name_reg_small(decoded_name, decoded_name[NETBIOS_NAME_LEN],
						 res->res->name->next_name,
						 (cache_namecard->timeof_death
						  - cur_time),
						 in_addr, ISGROUP_NO,
						 cache_namecard->addrs.recrd[i].node_type);
	    pckt->header->transaction_id = tid;
	    pckt->header->opcode = (OPCODE_RESPONSE | OPCODE_REGISTRATION);
	    pckt->header->nm_flags = FLG_AA;
	    pckt->header->rcode = RCODE_CFT_ERR;
	    pckt->for_del = 1;
	    ss_name_send_pckt(pckt, addr, trans);
	  }

	  break;
	} else
	  break;
      } else
	  break;
    }
  }
}
