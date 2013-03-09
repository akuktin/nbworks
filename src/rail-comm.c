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
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>

#include "constdef.h"
#include "daemon_control.h"
#include "rail-comm.h"
#include "nodename.h"
#include "service_sector_threads.h"
#include "service_sector.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_func.h"
#include "name_srvc_func_B.h"
#include "dtg_srvc_pckt.h"
#include "ses_srvc_pckt.h"
#include "randomness.h"


void init_rail() {
  extern struct nbworks__rail_control_t nbworks__rail_control;

  nbworks__rail_control.all_stop = 0;
  nbworks__rail_control.poll_timeout = TP_100MS;
}


int open_rail() {
  struct sockaddr_un address;
  int result;

  memset(&address, 0, sizeof(struct sockaddr_un));

  address.sun_family = AF_UNIX;
  memcpy(address.sun_path +1, NBWORKS_SCKT_NAME, NBWORKS_SCKT_NAMELEN);

  result = socket(PF_UNIX, SOCK_STREAM, 0);
  if (result == -1) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  if (0 != fcntl(result, F_SETFL, O_NONBLOCK)) {
    /* TODO: errno signaling stuff */
    close(result);
    return -1;
  }

  if (0 != bind(result, (struct sockaddr *)&address,
		sizeof(struct sockaddr_un))) {
    /* TODO: errno signaling stuff */
    close(result);
    return -1;
  } else {
    if (0 != listen(result, SOMAXCONN)) {
      /* TODO: errno signaling stuff */
      close(result);
      return -1;
    } else
      return result;
  }
}

/* returns: !0 = success, 0 = error */
unsigned int rail_flushrail(uint32_t leng,
			    int rail) {
  unsigned char bucket[0xff];

  while (leng) {
    if (leng > 0xff) {
      if (0xff > recv(rail, bucket, 0xff, MSG_WAITALL)) {
	return FALSE;
      } else {
	leng = leng - 0xff;
      }
    } else {
      if (leng > recv(rail, bucket, leng, MSG_WAITALL)) {
	return FALSE;
      } else {
	return TRUE;
      }
    }
  }

  return TRUE;
}

void *poll_rail(void *args) {
  extern struct nbworks__rail_control_t nbworks__rail_control;
  struct rail_params params, new_params, *release_lock;
  struct pollfd pfd;
  struct sockaddr_un *address;
  struct thread_node *last_will;
  socklen_t scktlen;
  int ret_val, new_sckt;

  if (! args)
    return 0;

  memcpy(&params, args, sizeof(struct rail_params));
  release_lock = args;
  release_lock->isbusy = 0;
  new_params.isbusy = 0;

  if (params.thread_id)
    last_will = add_thread(params.thread_id);
  else
    last_will = 0;

  scktlen = sizeof(struct sockaddr_un);
  pfd.fd = params.rail_sckt;
  pfd.events = POLLIN;

  while (0xfeed) {
    if (nbworks__rail_control.all_stop) {
      if (last_will)
	last_will->dead = TRUE;
      return 0;
    }

    ret_val = poll(&pfd, 1, nbworks__rail_control.poll_timeout);

    if (ret_val == 0) {
      continue;
    }
    if (ret_val < 0) {
      /* TODO: error handling */
      continue;
    }

    address = calloc(1, sizeof(struct sockaddr_un));
    /* no calloc check */
    new_sckt = accept(params.rail_sckt, (struct sockaddr *)address,
		      &scktlen);
    if (new_sckt < 0) {
      if ((errno == EAGAIN) ||
	  (errno == EWOULDBLOCK)) {
	free(address);
      } else {
	/* TODO: error handling */
	free(address);
      }
    } else {
      while (new_params.isbusy) {
	/* busy-wait */
      }
      new_params.isbusy = 0xda;
      new_params.rail_sckt = new_sckt;
      new_params.addr = address;
      if (0 != pthread_create(&(new_params.thread_id), 0,
			      handle_rail, &new_params)) {
	new_params.isbusy = 0;
      }
    }
  }
}


void *handle_rail(void *args) {
  struct nbnodename_list *scope;
  struct rail_params params, *release_lock;
  struct com_comm command;
  struct cache_namenode *cache_namecard;
  struct thread_node *last_will;
  struct ipv4_addr_list *cur_addr, **last_addr;
  uint32_t ipv4, i;
  unsigned char buff[LEN_COMM_ONWIRE], *name_ptr;

  if (! args)
    return 0;

  memcpy(&params, args, sizeof(struct rail_params));
  release_lock = args;
  release_lock->isbusy = 0;

  if (params.thread_id)
    last_will = add_thread(params.thread_id);
  else
    last_will = 0;

  if (params.rail_sckt < 0) {
    free(params.addr);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  ipv4 = 0;

  if (LEN_COMM_ONWIRE > recv(params.rail_sckt, buff,
			     LEN_COMM_ONWIRE, MSG_WAITALL)) {
    close(params.rail_sckt);
    free(params.addr);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  if (! read_railcommand(buff, (buff+LEN_COMM_ONWIRE), &command)){
    close(params.rail_sckt);
    free(params.addr);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  switch (command.command) {
  case rail_regname:
    cache_namecard = do_rail_regname(params.rail_sckt, &command);
    if (cache_namecard) {
      command.token = cache_namecard->token;
      command.len = 0;
      command.data = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
      /* no check */
    }
    close(params.rail_sckt);
    break;

  case rail_delname:
    cache_namecard = find_namebytok(command.token, &scope);

    if (cache_namecard) {
      name_ptr = cache_namecard->name;
      ipv4 = my_ipv4_address();
      name_srvc_release_name(name_ptr, name_ptr[NETBIOS_NAME_LEN-1],
			     scope, ipv4, cache_namecard->group_flg,
			     FALSE);

      for (i=0; i<4; i++) {
	last_addr = &(cache_namecard->addrs.recrd[i].addr);
	cur_addr = *last_addr;

	while (cur_addr) {
	  if (cur_addr->ip_addr == ipv4) {
	    *last_addr = cur_addr->next;
	    free(cur_addr);
	  } else {
	    last_addr = &(cur_addr->next);
	  }

	  cur_addr = *last_addr;
	}

	if (! cache_namecard->addrs.recrd[i].addr) {
	  cache_namecard->node_types = cache_namecard->node_types &
	    (~(cache_namecard->addrs.recrd[i].node_type));
	}
      }

      if (! cache_namecard->node_types) {
	cache_namecard->timeof_death = 0;
      }

      command.len = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
    }

    close(params.rail_sckt);
    destroy_nbnodename(scope);
    break;

  case rail_send_dtg:
    if (find_namebytok(command.token, 0)) {
      if (0 == rail_senddtg(params.rail_sckt, &command)) {
	command.len = 0;
	command.data = 0;
	fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
	send(params.rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
      }
    }
    close(params.rail_sckt);
    break;

  case rail_dtg_sckt:
    if (0 == rail_add_dtg_server(params.rail_sckt,
				 &command)) {
      command.len = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
      shutdown(params.rail_sckt, SHUT_RD);
    } else {
      close(params.rail_sckt);
    }
    break;

  case rail_stream_sckt:
    if (0 == rail_add_ses_server(params.rail_sckt,
				 &command)) {
      command.len = 0;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
    } else {
      close(params.rail_sckt);
    }
    break;

  case rail_stream_take:
    rail_setup_session(params.rail_sckt,
		       command.token);
    break;

  case rail_addr_ofXuniq:
  case rail_addr_ofXgroup:
    ipv4 = rail_whatisaddrX(params.rail_sckt,
			    &command);
    if (ipv4) {
      command.len = 4;
      fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL);
      fill_32field(ipv4, buff);
      send(params.rail_sckt, buff, 4, MSG_NOSIGNAL);
    }
    close(params.rail_sckt);
    break;

  default:
    /* Unknown command. */
    close(params.rail_sckt);
    break;
  }

  free(params.addr);
  if (last_will)
    last_will->dead = TRUE;
  return 0;
}


struct com_comm *read_railcommand(unsigned char *packet,
				  unsigned char *endof_pckt,
				  struct com_comm *field) {
  struct com_comm *result;
  unsigned char *walker;

  if ((! packet) ||
      ((packet + LEN_COMM_ONWIRE) > endof_pckt))
    return 0;

  if (field)
    result = field;
  else {
    result = malloc(sizeof(struct com_comm));
    if (! result)
      return 0;
  }

  walker = packet;

  result->command = *walker;
  walker++;
  walker = read_64field(walker, &(result->token));
  walker = read_16field(walker, &(result->addr.sin_port));
  walker = read_32field(walker, &(result->addr.sin_addr.s_addr));
  result->node_type = *walker;
  walker++;
  walker = read_32field(walker, &(result->len));

  result->addr.sin_family = AF_INET;
  result->data = 0;

  return result;
}

unsigned char *fill_railcommand(struct com_comm *command,
				unsigned char *packet,
				unsigned char *endof_packet) {
  unsigned char *walker;

  if (! (command && packet))
    return packet;

  if ((packet + LEN_COMM_ONWIRE) > endof_packet) {
    /* TODO: errno signaling stuff */
    return packet;
  }

  walker = packet;

  *walker = command->command;
  walker++;
  walker = fill_64field(command->token, walker);
  walker = fill_16field(command->addr.sin_port, walker);
  walker = fill_32field(command->addr.sin_addr.s_addr, walker);
  *walker = command->node_type;
  walker++;
  walker = fill_32field(command->len, walker);

  return walker;
}

struct rail_name_data *read_rail_name_data(unsigned char *startof_buff,
					   unsigned char *endof_buff) {
  struct rail_name_data *result;
  unsigned char *walker;

  if (! startof_buff)
    return 0;

  if ((startof_buff + LEN_NAMEDT_ONWIREMIN) > endof_buff) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = startof_buff;

  result = malloc(sizeof(struct rail_name_data));
  if (! result) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  result->name = malloc(NETBIOS_NAME_LEN+1);
  if (! result->name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  memcpy(result->name, walker, NETBIOS_NAME_LEN);
  walker = walker + (NETBIOS_NAME_LEN -1);
  result->name_type = *walker;
  walker++;

  result->scope = read_all_DNS_labels(&walker, walker, endof_buff, 0, 0, 0, 0);

  result->group_flg = *walker;
  walker++;
  read_32field(walker, &(result->ttl));

  return result;
}

unsigned char *fill_rail_name_data(struct rail_name_data *data,
				   unsigned char *startof_buff,
				   unsigned char *endof_buff) {
  unsigned char *walker;

  if (! (data && startof_buff))
    return startof_buff;

  if ((startof_buff + LEN_NAMEDT_ONWIREMIN) > endof_buff) {
    /* TODO: errno signaling stuff */
    return startof_buff;
  }

  walker = mempcpy(startof_buff, data->name, NETBIOS_NAME_LEN);
  walker = fill_all_DNS_labels(data->scope, walker, endof_buff, 0);
  *walker = data->group_flg;
  walker++;
  walker = fill_32field(data->ttl, walker);

  return walker;
}


struct cache_namenode *do_rail_regname(int rail_sckt,
				       struct com_comm *command) {
  struct cache_namenode *cache_namecard, *grp_namecard;
  struct rail_name_data *namedata;
  struct ipv4_addr_list *new_addr, *cur_addr, **last_addr;
  int i;
  unsigned char *data_buff;

  /* WRONG FOR GROUPS!!! */

  if (! command)
    return 0;

  data_buff = malloc(command->len);
  if (! data_buff) {
    return 0;
  }

  if (command->len > recv(rail_sckt, data_buff,
			  command->len, MSG_WAITALL)) {
    /* TODO: error handling */
    free(data_buff);
    return 0;
  }

  namedata = read_rail_name_data(data_buff, data_buff+command->len);
  if (! namedata) {
    /* TODO: error handling */
    free(data_buff);
    return 0;
  }

#define cleanup                        \
  free(data_buff);                     \
  free(namedata->name);                \
  destroy_nbnodename(namedata->scope); \
  free(namedata);

  switch (command->node_type) {
  case 'B':
  default:
    cache_namecard = alloc_namecard(namedata->name, NETBIOS_NAME_LEN,
				    CACHE_NODEFLG_B, make_token(),
				    namedata->group_flg, QTYPE_NB, QCLASS_IN);
    if (! cache_namecard) {
      /* TODO: error handling */
      cleanup;
      return 0;
    }
    grp_namecard = find_name(cache_namecard, namedata->scope);
    if (grp_namecard) {
      destroy_namecard(cache_namecard);

      if (command->command == rail_addr_ofXgroup) {
	/* Tell the world (actually optional for B nodes). */
	if (0 == name_srvc_B_add_name(namedata->name, namedata->name_type,
				      namedata->scope,
				      my_ipv4_address(),
				      namedata->group_flg, namedata->ttl)) {
	  grp_namecard->timeof_death = time(0) + namedata->ttl;

	  for (i=0; i<4; i++) {
	    if (grp_namecard->addrs.recrd[i].node_type == CACHE_NODEFLG_B)
	      break;
	  }
	  if (i<4) {
	    new_addr = malloc(sizeof(struct ipv4_addr_list));
	    if (! new_addr) {
	      return 0;
	    }
	    new_addr->ip_addr = my_ipv4_address();
	    new_addr->next = 0;

	    while (0xd0) {
	      last_addr = &(grp_namecard->addrs.recrd[i].addr);
	      cur_addr = *last_addr;

	      while (cur_addr) {
		if (cur_addr == new_addr)
		  return grp_namecard;

		last_addr = &(cur_addr->next);
		cur_addr = *last_addr;
	      }

	      *last_addr = new_addr;
	    }
	  }
	}
      }

      cleanup;
      return 0;
    } else {
      if (0 == name_srvc_B_add_name(namedata->name, namedata->name_type,
				    namedata->scope,
				    my_ipv4_address(),
				    namedata->group_flg, namedata->ttl)) {
	if (! (add_scope(namedata->scope, cache_namecard, get_nbnsaddr()) ||
	       add_name(cache_namecard, namedata->scope))) {
	  destroy_namecard(cache_namecard);
	  cleanup;
	  return 0;
	}

	cache_namecard->addrs.recrd[0].node_type = CACHE_NODEFLG_B;
	cache_namecard->addrs.recrd[0].addr = calloc(1, sizeof(struct ipv4_addr_list));
	if (! cache_namecard->addrs.recrd[0].addr) {
	  /* TODO: error handling */
	  cache_namecard->timeof_death = 0;
	  cleanup;
	  return 0;
	}
	cache_namecard->addrs.recrd[0].addr->ip_addr = my_ipv4_address();
	cache_namecard->timeof_death = time(0) + namedata->ttl;

	cleanup;
	return cache_namecard;
      } else {
	/* TODO: error handling */
	destroy_namecard(cache_namecard);
	cleanup;
	return 0;
      }
    }
    break;
  }
#undef cleanup
}

/* returns: 0 = success, >0 = fail, <0 = error */
int rail_senddtg(int rail_sckt,
		 struct com_comm *command) {
  struct sockaddr_in dst_addr;
  struct dtg_srvc_packet *pckt;
  struct dtg_pckt_pyld_normal *normal_pyld;
  struct cache_namenode *namecard;
  struct ss_queue_storage *trans;
  struct ipv4_addr_list *group_addrs;
  struct ss_queue *queue;
  union trans_id tid;
  int i;
  unsigned short node_type, group_flg;
  unsigned char *buff, decoded_name[NETBIOS_NAME_LEN+1];

  if (! command)
    return -1;

  switch (command->node_type) {
  case 'H':
    node_type = CACHE_NODEFLG_H;
    break;
  case 'M':
    node_type = CACHE_NODEFLG_M;
    break;
  case 'P':
    node_type = CACHE_NODEFLG_P;
    break;
  case 'B':
  default:
    node_type = CACHE_NODEFLG_B;
    break;
  }
  decoded_name[NETBIOS_NAME_LEN] = 0;
  dst_addr.sin_family = AF_INET;
  /* VAXism below */
  fill_16field(138, (unsigned char *)&(dst_addr.sin_port));

  buff = malloc(command->len);
  if (! buff) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  if (command->len > recv(rail_sckt, buff, command->len, MSG_WAITALL)) {
    /* TODO: errno signaling stuff */
    free(buff);
    return 9008;
  }

  pckt = partial_dtg_srvc_pckt_reader(buff, command->len, 0);
  if (! pckt) {
    /* TODO: errno signaling stuff */
    free(buff);
    return 1;
  }

  if (pckt->type == DIR_GRP_DTG)
    group_flg = ISGROUP_YES;
  else
    group_flg = ISGROUP_NO;

  switch (pckt->payload_t) {
  case normal:
    normal_pyld = pckt->payload;
    normal_pyld->pyldpyld_delptr = buff;
    buff = 0;

    tid.name_scope = normal_pyld->src_name;

    trans = ss_find_queuestorage(&tid, DTG_SRVC);
    if (! trans) {
      queue = ss_register_dtg_tid(&tid);
      trans = ss_add_queuestorage(queue, &tid, DTG_SRVC);

      free(queue);
    }
    if (trans->last_active < ZEROONES)
      trans->last_active = time(0);


    if ((pckt->type == BRDCST_DTG) ||
	(0 == memcmp(JOKER_NAME_CODED, normal_pyld->dst_name->name,
		     NETBIOS_CODED_NAME_LEN))) {

      /* VAXism below. */
      fill_32field(get_inaddr(), (unsigned char *)&(dst_addr.sin_addr.s_addr));

      pckt->for_del = TRUE;
      ss_dtg_send_pckt(pckt, &dst_addr, &(trans->queue));

      pckt = 0;

      break;
    }

    namecard = find_nblabel(decode_nbnodename(normal_pyld->dst_name->name,
					      decoded_name),
			    NETBIOS_NAME_LEN, node_type, group_flg,
			    QTYPE_NB, QCLASS_IN, normal_pyld->dst_name->next_name);
    if (! namecard)
      namecard = name_srvc_find_name(decoded_name,
				     decoded_name[NETBIOS_NAME_LEN-1],
				     normal_pyld->dst_name->next_name,
				     node_type, group_flg, FALSE);
    if (namecard) {
      /* FIXME: sending to another name on the same host */
      for (i=0; i<4; i++) {
	if (namecard->addrs.recrd[i].node_type == node_type)
	  break;
      }
      if ((i < 4) &&
	  (namecard->addrs.recrd[i].addr)) {
	if (namecard->group_flg & ISGROUP_YES) {
	  group_addrs = namecard->addrs.recrd[i].addr;
	  while (group_addrs->next) {
	    fill_32field(group_addrs->ip_addr,
			 (unsigned char *)&(dst_addr.sin_addr.s_addr));

	    ss_dtg_send_pckt(pckt, &dst_addr, &(trans->queue));

	    group_addrs = group_addrs->next;
	  }

	  /* VAXism below */
	  fill_32field(group_addrs->ip_addr,
		       (unsigned char *)&(dst_addr.sin_addr.s_addr));
	} else {
	  /* VAXism below */
	  fill_32field(namecard->addrs.recrd[i].addr->ip_addr,
		       (unsigned char *)&(dst_addr.sin_addr.s_addr));
	}

	pckt->for_del = TRUE;
	ss_dtg_send_pckt(pckt, &dst_addr, &(trans->queue));

	pckt = 0;
      }
    } /* else
	 FU(); */
    break;

  default:
    break;
  }

  if (pckt)
    destroy_dtg_srvc_pckt(pckt, 1, 1);
  if (buff)
    free(buff);
  return 0;
}

/* returns: 0=success, >0=fail, <0=error */
int rail_add_dtg_server(int rail_sckt,
			struct com_comm *command) {
  struct ss_queue *trans;
  struct ss_queue_storage *queue;
  struct cache_namenode *namecard;
  struct nbnodename_list *nbname;
  struct rail_list *new_rail, *cur_rail, **last_rail;
  struct dtg_srv_params params;
  union trans_id tid;
  time_t cur_time;

  if (! command)
    return -1;

  new_rail = malloc(sizeof(struct rail_list));
  if (! new_rail) {
    return -1;
  }
  new_rail->rail_sckt = rail_sckt;
  new_rail->next = 0;

  nbname = malloc(sizeof(struct nbnodename_list));
  if (! nbname) {
    free(new_rail);
    return -1;
  }

  cur_time = time(0);

  namecard = find_namebytok(command->token, &(nbname->next_name));
  if ((! namecard) ||
      (namecard->timeof_death <= cur_time) ||
      (namecard->isinconflict)) {
    free(new_rail);
    free(nbname);
    return 1;
  }

  nbname->name = encode_nbnodename(namecard->name, 0);
  nbname->len = NETBIOS_CODED_NAME_LEN;

  if (command->len)
    rail_flushrail(command->len, rail_sckt);
  tid.name_scope = nbname;

  trans = ss_register_dtg_tid(&tid);
  if (! trans) {
    /* This can only mean there is already
       a registered queue with this name. */
    queue = ss_find_queuestorage(&tid, DTG_SRVC);
  } else {
    queue = ss_add_queuestorage(trans, &tid, DTG_SRVC);
  }

  if (! queue) {
    /* Dafuq!?! */
    if (trans) {
      ss_deregister_dtg_tid(&tid);
      ss__dstry_recv_queue(trans);
      free(trans);
    }
    destroy_nbnodename(nbname);
    free(new_rail);
    return 1;
  }

  while (0x101) { /* Not really 101. */
    last_rail = &(queue->rail);
    cur_rail = *last_rail;

    while (cur_rail) {
      if (cur_rail == new_rail) {
	last_rail = 0;
	break;
      } else {
	last_rail = &(cur_rail->next);
	cur_rail = *last_rail;
      }
    }

    if (last_rail)
      *last_rail = new_rail;
    else
      break;
  }

  if (trans) {
    free(trans);

    params.isbusy = 0xda;
    params.nbname = nbname;
    params.queue = queue;

    if (0 != pthread_create(&(params.thread_id), 0,
			    dtg_server, &params)) {
      ss_deregister_dtg_tid(&tid);
      ss__dstry_recv_queue(&(queue->queue));
      ss_del_queuestorage(&tid, DTG_SRVC);
      destroy_nbnodename(nbname);
      free(new_rail);

      return -1;
    }

    while (params.isbusy) {
      /* busy-wait */
    }
  }

  return 0;
}


void *dtg_server(void *arg) {
  extern struct nbworks_dtg_srv_cntrl_t nbworks_dtg_srv_cntrl;
  struct dtg_srv_params *params;
  struct thread_node *last_will;
  struct nbnodename_list *nbname;
  struct ss_queue *trans;
  struct ss_queue_storage *queue;
  struct dtg_srvc_recvpckt *pckt;
  struct rail_list *cur_rail, **last_rail;
  struct pollfd pollfd;
  union trans_id tid;
  unsigned char buff[4];

  if (! arg)
    return 0;
  else
    params = arg;
  if (params->thread_id)
    last_will = add_thread(params->thread_id);
  else
    last_will = 0;
  nbname = params->nbname;
  queue = params->queue;
  /* Release the caller. */
  params->isbusy = 0;

  trans = &(queue->queue);
  pollfd.events = POLLOUT;

#define do_close_rail          \
  *last_rail = cur_rail->next; \
  close(cur_rail->rail_sckt);  \
  free(cur_rail);              \
  cur_rail = *last_rail;

  while (! nbworks_dtg_srv_cntrl.all_stop) {
    while (438) {
      pckt = ss__recv_pckt(trans, 0);
      if (pckt) {
	if (queue->last_active < ZEROONES)
	  queue->last_active = time(0);

	fill_32field(pckt->len, buff);

	cur_rail = queue->rail;
	last_rail = &(queue->rail);
	while (cur_rail) {
	  pollfd.fd = cur_rail->rail_sckt;
	  poll(&pollfd, 1, 0);

	  if (pollfd.revents & POLLOUT) {
	    if (4 == send(cur_rail->rail_sckt, buff, 4,
			  (MSG_DONTWAIT | MSG_NOSIGNAL))) {

	      if (pckt->len > send(cur_rail->rail_sckt,
				   pckt->packetbuff, pckt->len,
				   (MSG_DONTWAIT | MSG_NOSIGNAL))) {

		do_close_rail;
		continue;
	      }

	    } else {
	      do_close_rail;
	      continue;
	    }
	  } else {
	    if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
	      do_close_rail;
	      continue;
	    }
	  }

	  last_rail = &(cur_rail->next);
	  cur_rail = *last_rail;
	}

	destroy_dtg_srvc_recvpckt(pckt, 1, 1);

	if (! queue->rail)
	  break;
      } else {
	break;
      }
    }

    cur_rail = queue->rail;
    last_rail = &(queue->rail);
    while (cur_rail) {
      pollfd.fd = cur_rail->rail_sckt;
      poll(&pollfd, 1, 0);
      if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
	do_close_rail;
      } else {
	last_rail = &(cur_rail->next);
	cur_rail = *last_rail;
      }
    }

    if (! queue->rail)
      break;

    nanosleep(&(nbworks_dtg_srv_cntrl.dtg_srv_sleeptime), 0);
  }
#undef do_close_rail

  tid.name_scope = nbname;

  ss_deregister_dtg_tid(&tid);
  ss__dstry_recv_queue(&(queue->queue));
  ss_del_queuestorage(&tid, DTG_SRVC);
  destroy_nbnodename(nbname);

  if (last_will)
    last_will->dead = 0xb00; /* said the ghost */
  return 0;
}


/* returns: 0=success, >0=fail, <0=error */
int rail_add_ses_server(int rail_sckt,
			struct com_comm *command) {
  struct cache_namenode *namecard;
  struct nbnodename_list nbname;
  time_t cur_time;

  if (! command)
    return -1;

  cur_time = time(0);

  namecard = find_namebytok(command->token, &(nbname.next_name));
  if ((! namecard) ||
      (namecard->timeof_death <= cur_time) ||
      (namecard->isinconflict)) {
    return 1;
  }

  nbname.name = encode_nbnodename(namecard->name, 0);
  nbname.len = NETBIOS_CODED_NAME_LEN;

  if (command->len)
    rail_flushrail(command->len, rail_sckt);

  if (ss__add_sessrv(&nbname, rail_sckt)) {
    return 0;
  } else {
    return 1;
  }
}

/* returns: >0 = success, 0 = failed, <0 = error */
int rail__send_ses_pending(int rail,
			   uint64_t token) {
  struct com_comm command;
  struct pollfd pfd;
  unsigned char wire_com[LEN_COMM_ONWIRE];

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_stream_pending;
  command.token = token;

  fill_railcommand(&command, wire_com, wire_com + LEN_COMM_ONWIRE);

  pfd.fd = rail;
  pfd.events = POLLOUT;
  if ((0 < poll(&pfd, 1, 0)) &&
      (pfd.revents & POLLOUT) &&
      (! (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)))) {
    if (LEN_COMM_ONWIRE == send(rail, wire_com, LEN_COMM_ONWIRE,
				MSG_NOSIGNAL))
      return 1;
  }

  return 0;
}

/* returns: >0 = success, 0 = failed, <0 = error */
int rail_setup_session(int rail,
		       uint64_t token) {
  struct ses_srv_sessions *session;
  struct ses_srvc_packet pckt;
  struct com_comm answer;
  struct stream_connector_args new_session;
  int out_sckt;
  unsigned char rail_buff[LEN_COMM_ONWIRE];
  unsigned char err[] = { NEG_SESSION_RESPONSE, 0, 0, 1, SES_ERR_UNSPEC };
  unsigned char *walker;

  session = ss__take_session(token);
  if (! session) {
    close(rail);
    return 0;
  }

  memset(&pckt, 0, sizeof(struct ses_srvc_packet));

  walker = session->first_buff;
  if (! read_ses_srvc_pckt_header(&walker, walker+SES_HEADER_LEN, &pckt)) {
    send(session->out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(session->out_sckt);
    free(session->first_buff);
    free(session);
    return -1;
  }

  if ((pckt.len+SES_HEADER_LEN) > send(rail, session->first_buff,
				       (pckt.len+SES_HEADER_LEN),
				       (MSG_NOSIGNAL | MSG_DONTWAIT))) {
    send(session->out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(session->out_sckt);
    free(session->first_buff);
    free(session);
    return -1;
  } else {
    out_sckt = session->out_sckt;
    free(session->first_buff);
  }

  if (LEN_COMM_ONWIRE > recv(rail, rail_buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
    send(session->out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    free(session);
    return 0;
  }

  if (! read_railcommand(rail_buff, (rail_buff+LEN_COMM_ONWIRE), &answer)) {
    send(session->out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    free(session);
    return -1;
  }

  if ((answer.command != rail_stream_accept) ||
      (answer.token != token)) {
    if (answer.command == rail_stream_error) {
      err[4] = answer.node_type;
    }
    send(out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    free(session);
    return -1;
  } else {
    if (answer.len)
      rail_flushrail(answer.len, rail);
  }

  if (0 != fcntl(rail, F_SETFL, O_NONBLOCK)) {
    //    send(session->out_sckt, err, 5, MSG_NOSIGNAL);

    //    close(rail);
    //    close(out_sckt);
    //    free(session);
    //    return -1;
  }
  /* The rail socket is now ready for operation. Establish a tunnel. */

  new_session.isbusy = 0xda;
  new_session.sckt_lcl = rail;
  new_session.sckt_rmt = out_sckt;

  if (0 != pthread_create(&(new_session.thread_id), 0,
			  tunnel_stream_sockets, &new_session)) {
    send(session->out_sckt, err, 5, MSG_NOSIGNAL);

    close(rail);
    close(out_sckt);
    free(session);
    return -1;
  }

  while (new_session.isbusy) {
    /* busy-wait */
  }

  free(session);

  return TRUE;
}

void *tunnel_stream_sockets(void *arg) {
  extern struct nbworks_ses_srv_cntrl_t nbworks_ses_srv_cntrl;
  struct stream_connector_args *params;
  struct thread_node *last_will;
  struct pollfd fds[2];
  ssize_t trans_len, sent_len, lastbuf_len;
  int sckt_lcl, sckt_rmt, read_sckt, write_sckt, l;
  int ret_val, i;
  unsigned char buf[DEFAULT_TUNNEL_LEN];

  if (! arg)
    return 0;

  params = arg;
  sckt_lcl = params->sckt_lcl;
  sckt_rmt = params->sckt_rmt;
  if (params->thread_id)
    last_will = add_thread(params->thread_id);
  else
    last_will = 0;
  params->isbusy = 0;

  trans_len = sent_len = 0;
  read_sckt = sckt_lcl;
  write_sckt = sckt_rmt;

  memset(buf, 0, DEFAULT_TUNNEL_LEN);
  lastbuf_len = 0;

  fds[0].fd = sckt_rmt;
  fds[0].events = (POLLIN | POLLPRI);
  fds[1].fd = sckt_lcl;
  fds[1].events = (POLLIN | POLLPRI);

  while (! nbworks_ses_srv_cntrl.all_stop) {
    ret_val = poll(fds, 2, TP_250MS);
    if (ret_val == 0) {
      continue;
    } else {
      if (ret_val < 0) {
	/* TODO: error handling */
	close(sckt_lcl);
	close(sckt_rmt);
	if (last_will)
	  last_will->dead = TRUE;
	return 0;
      }
    }

    /* A weird loop.
     * Coming in, write_sckt equals sckt_rmt. At the start of the loop,
     * write_sckt gets swaped out and is now equal to sckt_lcl. The test
     * at the end passes, loop reenters and write_sckt again gets swaped,
     * this time to sckt_rmt which causes the end test to fail and the
     * loop exits.
     * This was done because it's fun. */
    /* It was also done because I forgot that there is a deeper meaning to
     * the relationship between the socket on whose pollfd I operate and the
     * socket from which data is being read. Stupid. */
    i = 0;
    do {
      /* Swap the sockets. */
      l = write_sckt;
      write_sckt = read_sckt;
      read_sckt = l;

      if (fds[i].revents & (POLLIN | POLLPRI)) {
	if (fds[i].revents & POLLIN) {
	  trans_len = recv(read_sckt, buf, DEFAULT_TUNNEL_LEN,
			   MSG_DONTWAIT);
	  if ((trans_len <= 0) &&
	      ((errno != EAGAIN) &&
	       (errno != EWOULDBLOCK))) {
	    if (trans_len == 0) {
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    } else {
	      /* TODO: error handling */
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    }
	  }

	  if (trans_len < lastbuf_len) {
	    memset(buf+trans_len, 0, (lastbuf_len - trans_len));
	  }
	  lastbuf_len = trans_len;

	  sent_len = 0;
	  while (sent_len < trans_len) {
	    errno = 0;
	    sent_len = sent_len + send(write_sckt, (buf + sent_len),
				       (trans_len - sent_len),
				       MSG_NOSIGNAL);
	    if ((errno != 0) &&
		((errno != EAGAIN) &&
		 (errno != EWOULDBLOCK))) {
	      /* TODO: error handling */
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    }
	  }
	}
	if (fds[i].revents & POLLPRI) {
	  trans_len = recv(read_sckt, buf, DEFAULT_TUNNEL_LEN,
			   (MSG_DONTWAIT | MSG_OOB));

	  if ((trans_len <= 0) &&
	      ((errno != EAGAIN) &&
	       (errno != EWOULDBLOCK))) {
	    if (trans_len == 0) {
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    } else {
	      /* TODO: error handling */
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    }
	  }

	  if (trans_len < lastbuf_len) {
	    memset(buf+trans_len, 0, (lastbuf_len - trans_len));
	  }
	  lastbuf_len = trans_len;

	  sent_len = 0;
	  while (sent_len < trans_len) {
	    errno = 0;
	    sent_len = sent_len + send(write_sckt, (buf + sent_len),
				       (trans_len - sent_len),
				       (MSG_NOSIGNAL | MSG_OOB));

	    if ((errno != 0) &&
		((errno != EAGAIN) &&
		 (errno != EWOULDBLOCK))) {
	      /* TODO: error handling */
	      close(sckt_lcl);
	      close(sckt_rmt);
	      if (last_will)
		last_will->dead = TRUE;
	      return 0;
	    }
	  }
	}
      }

      if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) {
	if (fds[i].revents & POLLHUP) {
	  close(sckt_lcl);
	  close(sckt_rmt);
	  if (last_will)
	    last_will->dead = TRUE;
	  return 0;
	} else {
	  /* TODO: error handling */
	  close(sckt_lcl);
	  close(sckt_rmt);
	  if (last_will)
	    last_will->dead = TRUE;
	  return 0;
	}
      }

      i++;
    } while (write_sckt == sckt_lcl);
  }

  close(sckt_lcl);
  close(sckt_rmt);
  if (last_will)
    last_will->dead = TRUE;
  return 0;
}


/* WRONG FOR GROUPS! */
/* Except not really - this is only used by the session
   service which never uses more than one address. */
uint32_t rail_whatisaddrX(int rail_sckt,
			  struct com_comm *command) {
  struct cache_namenode *namecard;
  struct nbnodename_list *name;
  int i;
  unsigned char node_type;
  unsigned char *buff, *walker;

  if (! command)
    return 0;

  switch (command->node_type) {
  case 'H':
    node_type = CACHE_NODEFLG_H;
    break;
  case 'M':
    node_type = CACHE_NODEFLG_M;
    break;
  case 'P':
    node_type = CACHE_NODEFLG_P;
    break;
  case 'B':
  default:
    node_type = CACHE_NODEFLG_B;
    break;
  }

  buff = malloc(command->len);
  if (! buff) {
    return 0;
  }

  if (command->len > recv(rail_sckt, buff, command->len, MSG_WAITALL)) {
    return 0;
  }

  walker = buff;
  name = read_all_DNS_labels(&walker, buff, buff + command->len, 0, 0, 0, 0);
  free(buff);
  if (! name) {
    return 0;
  }

  namecard = find_nblabel(name->name, NETBIOS_NAME_LEN, node_type,
			  (command->command == rail_addr_ofXgroup) ?
			    ISGROUP_YES : ISGROUP_NO,
			  RRTYPE_NB, RRCLASS_IN,
			  name->next_name);

  if (! namecard) {
    namecard = name_srvc_find_name(name->name, (name->name)[NETBIOS_NAME_LEN -1],
				   name->next_name, node_type,
				   ((command->command == rail_addr_ofXgroup) ?
				    ISGROUP_YES : ISGROUP_NO), FALSE);
  }

  destroy_nbnodename(name);

  if (namecard) {
    for (i=0; i<4; i++) {
      if (namecard->addrs.recrd[i].node_type == node_type)
	return namecard->addrs.recrd[i].addr->ip_addr;
    }
  }

  return 0;
}


uint64_t make_token() {
  uint64_t result;

  do {
    result = make_weakrandom();
    result = result << (8*(sizeof(uint64_t)/2));
    result = make_weakrandom() + result;
  } while (result < 2);
  return result;
}
