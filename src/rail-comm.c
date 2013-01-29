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
#include "name_srvc_func_B.h"
#include "dtg_srvc_pckt.h"
#include "randomness.h"


void init_rail() {
  nbworks__rail_control.all_stop = 0;
  nbworks__rail_control.poll_timeout = TP_100MS;

  nbworks_dtg_srv_cntrl.all_stop = 0;
  nbworks_dtg_srv_cntrl.dtg_srv_sleeptime.tv_sec = 0;
  nbworks_dtg_srv_cntrl.dtg_srv_sleeptime.tv_nsec = T_10MS;
}


int open_rail() {
  struct sockaddr_un address;
  int i, result;
  unsigned char *deleter;

  deleter = (unsigned char *)&address;
  for (i=0; i<sizeof(struct sockaddr_un); i++) {
    *deleter = 0;
  }

  address.sun_family = AF_UNIX;
  memcpy(address.sun_path +1, NBWORKS_SCKT_NAME, NBWORKS_SCKT_NAMELEN);

  result = socket(PF_UNIX, SOCK_STREAM, 0);
  if (result == -1) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  if (0 > fcntl(result, F_SETFL, O_NONBLOCK)) {
    /* TODO: errno signaling stuff */
    close(result);
    return -1;
  }

  if (0 > bind(result, (struct sockaddr *)&address, sizeof(struct sockaddr_un))) {
    /* TODO: errno signaling stuff */
    close(result);
    return -1;
  } else {
    if (0 > listen(result, SOMAXCONN)) {
      /* TODO: errno signaling stuff */
      close(result);
      return -1;
    } else
      return result;
  }
}

void *poll_rail(void *args) {
  struct ss_queue_storage *cur_queuestor, **last_queuestor, *for_del;
  struct rail_list *for_del2, *for_del2prim;
  struct rail_params params, new_params;
  struct pollfd pfd;
  struct sockaddr_un *address;
  struct thread_node *last_will;
  time_t prunetime, prevprune;
  socklen_t scktlen;
  int ret_val, new_sckt;

  memcpy(&params, args, sizeof(struct rail_params));

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
      /* BTW, it is NOT guaranteed we will ever reach this point. */

      prunetime = time(0) - nbworks_prune_queuestorage_time;
      if (prunetime == prevprune)
	continue;
      else
	prevprune = prunetime;
      for (ret_val=0; ret_val<2; ret_val++) {
	cur_queuestor = nbworks_queue_storage[ret_val];
	last_queuestor = &(nbworks_queue_storage[ret_val]);

	while (cur_queuestor) {
	  if (cur_queuestor->last_active < prunetime) {
	    *last_queuestor = cur_queuestor->next;
	    ss_deregister_tid(&(cur_queuestor->id.tid), ret_val);
	    for_del = cur_queuestor;
	    cur_queuestor = cur_queuestor->next;
	    for_del2prim = for_del->rail;
	    while (for_del2prim) {
	      for_del2 = for_del2prim->next;
	      free(for_del2prim);
	      for_del2prim = for_del2;
	    }
	    free(for_del);
	  } else {
	    last_queuestor = &(cur_queuestor->next);
	    cur_queuestor = cur_queuestor->next;
	  }
	}
      }

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
      new_params.rail_sckt = new_sckt;
      new_params.addr = address;
      pthread_create(&(new_params.thread_id), 0,
		     handle_rail, &new_params);
    }
  }
}


void *handle_rail(void *args) {
  struct nbnodename_list *scope;
  struct rail_params params;
  struct com_comm *command;
  struct cache_namenode *cache_namecard;
  struct thread_node *last_will;
  uint32_t my_ipv4, i;
  unsigned char buff[LEN_COMM_ONWIRE], *name_ptr;

  memcpy(&params, args, sizeof(struct rail_params));

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

  if (LEN_COMM_ONWIRE > recv(params.rail_sckt, buff,
			     LEN_COMM_ONWIRE, MSG_WAITALL)) {
    close(params.rail_sckt);
    free(params.addr);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  command = read_railcommand(buff, (buff+LEN_COMM_ONWIRE));
  if (! command) {
    /* TODO: error handling */
    close(params.rail_sckt);
    free(params.addr);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }

  switch (command->command) {
  case rail_regname:
    cache_namecard = do_rail_regname(params.rail_sckt, command);
    if (cache_namecard) {
      command->token = cache_namecard->token;
      command->len = 0;
      command->data = 0;
      fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, 0);
      /* no check */
    }
    close(params.rail_sckt);
    break;

  case rail_delname:
    cache_namecard = find_namebytok(command->token, &scope);
    if (cache_namecard) {
      for (i=0; i<4; i++) {
	if (cache_namecard->addrs.recrd[i].node_type == CACHE_NODEFLG_B)
	  my_ipv4 = cache_namecard->addrs.recrd[i].addr->ip_addr;
      }

      name_ptr = cache_namecard->name;
      name_srvc_B_release_name(name_ptr, name_ptr[NETBIOS_NAME_LEN-1],
			       scope, my_ipv4, cache_namecard->isgroup);

      if (cache_namecard->isgroup) {
	cache_namecard->token = 0;
	for (i=0; i<4; i++) {
	  if (cache_namecard->addrs.recrd[i].addr)
	    break;
	}
	if (i > 3) {
	  cache_namecard->timeof_death = 0;
	}
      } else {
	cache_namecard->timeof_death = 0;
      }
      command->len = 0;
      fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, 0);
    }
    close(params.rail_sckt);
    destroy_nbnodename(scope);
    break;

  case rail_dtg_yes:
  case rail_dtg_no:
  case rail_ses_yes:
  case rail_ses_no:
    cache_namecard = find_namebytok(command->token, 0);
    if (cache_namecard) {
      switch (command->command) {
      case rail_dtg_yes:
	cache_namecard->takes = cache_namecard->takes | CACHE_TAKES_DTG;
	break;
      case rail_dtg_no:
	cache_namecard->takes = cache_namecard->takes & (~CACHE_TAKES_DTG);
	break;
      case rail_ses_yes:
	cache_namecard->takes = cache_namecard->takes | CACHE_TAKES_SES;
	break;
      case rail_ses_no:
	cache_namecard->takes = cache_namecard->takes & (~CACHE_TAKES_SES);
	break;
      default:
	break;
      }
      command->len = 0;
      fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, 0);
    }
    close(params.rail_sckt);
    break;

  case rail_send_dtg:
    if (find_namebytok(command->token, 0)) {
      if (0 == rail_senddtg(params.rail_sckt, command, &(nbworks_queue_storage[DTG_SRVC]))) {
	command->len = 0;
	command->data = 0;
	fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
	send(params.rail_sckt, buff, LEN_COMM_ONWIRE, 0);
      }
    }
    close(params.rail_sckt);
    break;

  case rail_dtg_sckt:
    if (0 == rail_add_dtg_server(params.rail_sckt,
				 command,
				 &(nbworks_queue_storage[DTG_SRVC]))) {
      command->len = 0;
      fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, 0);
      shutdown(params.rail_sckt, SHUT_RD);
    } else {
      close(params.rail_sckt);
    }
    break;

  default:
    /* Unknown command. */
    close(params.rail_sckt);
    break;
  }

  free(command);
  free(params.addr);
  if (last_will)
    last_will->dead = TRUE;
  return 0;
}


struct com_comm *read_railcommand(unsigned char *packet,
				  unsigned char *endof_pckt) {
  struct com_comm *result;
  unsigned char *walker;

  if ((packet + LEN_COMM_ONWIRE) > endof_pckt)
    return 0;

  result = malloc(sizeof(struct com_comm));
  if (! result)
    return 0;

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

  result->name = malloc(NETBIOS_NAME_LEN);
  if (! result->name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  memcpy(result->name, walker, NETBIOS_NAME_LEN);
  walker = walker + (NETBIOS_NAME_LEN -1);
  result->name_type = *walker;
  walker++;

  result->scope = read_all_DNS_labels(&walker, walker, endof_buff);

  result->isgroup = *walker;
  walker++;
  read_32field(walker, &(result->ttl));

  return result;
}

unsigned char *fill_rail_name_data(struct rail_name_data *data,
				   unsigned char *startof_buff,
				   unsigned char *endof_buff) {
  unsigned char *walker;

  if ((startof_buff + LEN_NAMEDT_ONWIREMIN) > endof_buff) {
    /* TODO: errno signaling stuff */
    return startof_buff;
  }

  walker = mempcpy(startof_buff, data->name, NETBIOS_NAME_LEN);
  walker = fill_all_DNS_labels(data->scope, walker, endof_buff);
  *walker = data->isgroup;
  walker++;
  walker = fill_32field(data->ttl, walker);

  return walker;
}


struct cache_namenode *do_rail_regname(int rail_sckt,
				       struct com_comm *command) {
  struct cache_namenode *cache_namecard;
  struct rail_name_data *namedata;
  unsigned char *data_buff;

  /* WRONG FOR GROUPS!!! */

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

  switch (command->node_type) {
  case 'B':
  default:
    cache_namecard = alloc_namecard(namedata->name, NETBIOS_NAME_LEN,
				    CACHE_NODEFLG_B, make_token(),
				    namedata->isgroup, QTYPE_NB, QCLASS_IN);
    if (! cache_namecard) {
      /* TODO: error handling */
      free(data_buff);
      free(namedata->name);
      destroy_nbnodename(namedata->scope);
      free(namedata);
      return 0;
    }
    if (find_name(cache_namecard, namedata->scope)) {
      free(data_buff);
      destroy_namecard(cache_namecard);
      free(namedata->name);
      destroy_nbnodename(namedata->scope);
      free(namedata);
      return 0;
    } else {
      if (0 == name_srvc_B_add_name(namedata->name, namedata->name_type,
				    namedata->scope,
				    command->addr.sin_addr.s_addr,
				    namedata->isgroup, namedata->ttl)) {
	add_scope(namedata->scope, cache_namecard);
	add_name(cache_namecard, namedata->scope);
	/* FIXME: I won't really bother with error detection at this time. */

	cache_namecard->addrs.recrd[0].node_type = CACHE_NODEFLG_B;
	cache_namecard->addrs.recrd[0].addr = calloc(1, sizeof(struct ipv4_addr_list));
	if (! cache_namecard->addrs.recrd[0].addr) {
	  /* TODO: error handling */
	  free(data_buff);
	  cache_namecard->timeof_death = 0;
	  free(namedata->name);
	  destroy_nbnodename(namedata->scope);
	  free(namedata);
	  return 0;
	}
	cache_namecard->addrs.recrd[0].addr->ip_addr = command->addr.sin_addr.s_addr;
	cache_namecard->timeof_death = time(0) + namedata->ttl;

	free(data_buff);
	free(namedata->name);
	destroy_nbnodename(namedata->scope);
	free(namedata);
	return cache_namecard;
      } else {
	/* TODO: error handling */
	free(data_buff);
	destroy_namecard(cache_namecard);
	free(namedata->name);
	destroy_nbnodename(namedata->scope);
	free(namedata);
	return 0;
      }
    }
    break;
  }
}

/* returns: 0 = success, >0 = fail, <0 = error */
int rail_senddtg(int rail_sckt,
		 struct com_comm *command,
		 struct ss_queue_storage **queue_stor) {
  struct dtg_srvc_packet *pckt;
  struct dtg_pckt_pyld_normal *normal_pyld;
  struct cache_namenode *namecard;
  struct ss_queue_storage *trans;
  struct sockaddr_in dst_addr;
  int isgroup, i;
  unsigned short node_type;
  uint16_t tid;
  unsigned char *buff, decoded_name[NETBIOS_NAME_LEN+1];

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

  pckt = partial_dtg_srvc_pckt_reader(buff, command->len, &tid);
  if (! pckt) {
    /* TODO: errno signaling stuff */
    free(buff);
    return 1;
  }

  if (pckt->type == DIR_GRP_DTG)
    isgroup = ISGROUP_YES;

  switch (pckt->payload_t) {
  case normal:
    normal_pyld = pckt->payload;
    normal_pyld->pyldpyld_delptr = buff;
    buff = 0;

    namecard = find_nblabel(decode_nbnodename(normal_pyld->dst_name->name,
					      (unsigned char **)&decoded_name),
			    NETBIOS_NAME_LEN, node_type, isgroup,
			    QTYPE_NB, QCLASS_IN, normal_pyld->dst_name->next_name);
    if (! namecard)
      namecard = name_srvc_B_find_name(decoded_name,
				       decoded_name[NETBIOS_NAME_LEN-1],
				       normal_pyld->dst_name->next_name,
				       node_type,
				       isgroup);
    if (namecard) {
      for (i=0; i<4; i++) {
	if (namecard->addrs.recrd[i].node_type == node_type)
	  break;
      }
      if (i<4) { /* paranoid */
	trans = ss_find_queuestorage(normal_pyld->src_name, DTG_SRVC, *queue_stor);
	while (! trans) {
	  ss_add_queuestorage(ss_register_dtg_tid(normal_pyld->src_name), normal_pyld->src_name,
			      DTG_SRVC, queue_stor);
	  trans = ss_find_queuestorage(normal_pyld->src_name, DTG_SRVC, *queue_stor);
	}
	trans->last_active = time(0);

	dst_addr.sin_addr.s_addr = namecard->addrs.recrd[i].addr->ip_addr;
	pckt->for_del = 1;

	ss_dtg_send_pckt(pckt, &dst_addr, &(trans->queue));   /* WRONG FOR GROUPS!!! */

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
			struct com_comm *command,
			struct ss_queue_storage **queue_stor) {
  struct ss_queue *trans;
  struct ss_queue_storage *queue;
  struct cache_namenode *namecard;
  struct nbnodename_list *nbname;
  struct rail_list *new_rail;
  struct dtg_srv_params *params;
  time_t cur_time;

  new_rail = malloc(sizeof(struct rail_list));
  if (! new_rail) {
    return -1;
  }
  new_rail->rail_sckt = rail_sckt;

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

  trans = ss_register_dtg_tid(nbname);
  if (! trans) {
    /* This can only mean there is already
       a registered queue with this name. */
    queue = ss_find_queuestorage(nbname, DTG_SRVC, *queue_stor);
  } else {
    queue = ss_add_queuestorage(trans, nbname, DTG_SRVC, queue_stor);
  }

  if (! queue) {
    /* Dafuq!?! */
    if (trans) {
      ss_deregister_dtg_tid(nbname);
      ss__dstry_recv_queue(trans);
      free(trans);
    }
    destroy_nbnodename(nbname);
    free(new_rail);
    return 1;
  }

  new_rail->next = queue->rail;
  queue->rail = new_rail;

  if (trans) {
    free(trans);

    params = malloc(sizeof(struct dtg_srv_params));
    if (! params) {
      ss_deregister_dtg_tid(nbname);
      ss__dstry_recv_queue(&(queue->queue));
      ss_del_queuestorage(nbname, DTG_SRVC, queue_stor);
      destroy_nbnodename(nbname);
      free(new_rail);

      return -1;
    }

    params->nbname = nbname;
    params->queue = queue;
    params->all_queues = queue_stor;

    if (0 != pthread_create(&(params->thread_id), 0,
			    dtg_server, params)) {
      ss_deregister_dtg_tid(nbname);
      ss__dstry_recv_queue(&(queue->queue));
      ss_del_queuestorage(nbname, DTG_SRVC, queue_stor);
      destroy_nbnodename(nbname);
      free(new_rail);
      free(params);

      return -1;
    }
  }

  return 0;
}


void *dtg_server(void *arg) {
  struct dtg_srv_params *params;
  struct thread_node *last_will;
  struct nbnodename_list *nbname;
  struct ss_queue *trans;
  struct ss_queue_storage *queue;
  struct ss_queue_storage **all_queues;
  struct dtg_srvc_packet *pckt;
  struct rail_list *cur_rail, **last_rail;
  struct pollfd pollfd;
  unsigned int pckt_len;
  unsigned char buff[MAX_UDP_PACKET_LEN+sizeof(uint32_t)];

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
  all_queues = params->all_queues;
  free(params);

  trans = &(queue->queue);
  pollfd.events = POLLOUT;

  while (! nbworks_dtg_srv_cntrl.all_stop) {
    while (438) {
      pckt = ss__recv_pckt(trans);
      if (pckt) {
	pckt_len = MAX_UDP_PACKET_LEN;
	master_dtg_srvc_pckt_writer(pckt, &pckt_len,
				    (buff+sizeof(uint32_t)));
	fill_32field(pckt_len, buff);

	cur_rail = queue->rail;
	last_rail = &(queue->rail);
	while (cur_rail) {
	  pollfd.fd = cur_rail->rail_sckt;
	  poll(&pollfd, 1, 0);
	  if (pollfd.revents & POLLOUT)
	    send(cur_rail->rail_sckt, buff, (pckt_len+sizeof(uint32_t)),
		 MSG_DONTWAIT);
	  else
	    if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
	      *last_rail = cur_rail->next;
	      close(cur_rail->rail_sckt);
	      free(cur_rail);
	      cur_rail = *last_rail;
	      continue;
	    }
	  cur_rail = cur_rail->next;
	}

	destroy_dtg_srvc_pckt(pckt, 1, 1);

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
	*last_rail = cur_rail->next;
	close(cur_rail->rail_sckt);
	free(cur_rail);
	cur_rail = *last_rail;
	continue;
      }
      cur_rail = cur_rail->next;
    }

    if (! queue->rail)
      break;

    nanosleep(&(nbworks_dtg_srv_cntrl.dtg_srv_sleeptime), 0);
  }

  ss_deregister_dtg_tid(nbname);
  ss__dstry_recv_queue(&(queue->queue));
  ss_del_queuestorage(nbname, DTG_SRVC, all_queues);
  destroy_nbnodename(nbname);

  if (last_will)
    last_will->dead = 0xb00; /* said the ghost */
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
