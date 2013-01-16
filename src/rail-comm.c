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
#include "pckt_routines.h"
#include "name_srvc_cache.h"
#include "name_srvc_func_B.h"
#include "randomness.h"


void init_rail() {
  nbworks__rail_control.all_stop = 0;
  nbworks__rail_control.poll_timeout = TP_100MS;
}


# define NBWORKS_SCKT_NAME "NBWORKS_MULTIPLEX_DAEMON"
# define NBWORKS_SCKT_NAMELEN (7+1+9+1+6)

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
  if (result == -1)
    /* TODO: errno signaling stuff */
    return -1;

  if (0 > fcntl(result, F_SETFL, O_NONBLOCK)) {
    /* TODO: errno signaling stuff */
    close(result);
    return -1;
  }

  if (0 > bind(result, (struct sockaddr *)&address, sizeof(struct sockaddr_un)))
    /* TODO: errno signaling stuff */
    return -1;
  else 
    if (0 > listen(result, SOMAXCONN))
      /* TODO: errno signaling stuff */
      return -1;
    else
      return result;
}

void *poll_rail(void *args) {
  struct rail_params params, new_params;
  struct pollfd pfd;
  struct sockaddr_un *address;
  struct thread_node *last_will;
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

    if (ret_val == 0)
      continue;
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
  struct rail_params params;
  struct com_comm *command;
  struct cache_namenode *cache_namecard;
  struct thread_node *last_will;
  unsigned char buff[LEN_COMM_ONWIRE];

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
      free(command);
      close(params.rail_sckt);
    }
    free(params.addr);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
    break;

  case rail_delname:
    cache_namecard = find_namebytok(command->token);
    if (cache_namecard) {
      /*      if (cache_namecard->isgroup) {

	      } else {*/
      cache_namecard->timeof_death = 0;    /* WRONG!!! */
	/*      }*/
      command->len = 0;
      fill_railcommand(command, buff, (buff+LEN_COMM_ONWIRE));
      send(params.rail_sckt, buff, LEN_COMM_ONWIRE, 0);
    }
    close(params.rail_sckt);
    free(command);
    free(params.addr);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
    break;

  default:
    /* Unknown command. */
    close(params.rail_sckt);
    free(command);
    free(params.addr);
    if (last_will)
      last_will->dead = TRUE;
    return 0;
  }
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
  walker = fill_32field(command->len, walker);

  return walker;
}

struct rail_name_data *read_rail_name_data(unsigned char *startof_buff,
					   unsigned char *endof_buff) {
  struct rail_name_data *result;
  unsigned char *walker;

  if ((startof_buff + LEN_NAMEDT_ONWIREMIN) < endof_buff) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  walker = startof_buff;

  result = malloc(sizeof(struct rail_name_data));
  if (! result)
    /* TODO: errno signaling stuff */
    return 0;

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
  result->node_type = *walker;
  walker++;
  read_32field(walker, &(result->ttl));

  return result;
}


struct cache_namenode *do_rail_regname(int rail_sckt,
				       struct com_comm *command) {
  struct cache_namenode *cache_namecard;
  struct rail_name_data *namedata;
  ssize_t ret_val;
  unsigned char *data_buff;

  /* WRONG FOR GROUPS!!! */

  data_buff = malloc(command->len);
  if (! data_buff) {
    close(rail_sckt);
    free(command);
    return 0;
  }

  ret_val = recv(rail_sckt, data_buff,
		 MAX_UDP_PACKET_LEN, MSG_DONTWAIT);
  if (ret_val < 1) {
    if ((errno == EAGAIN) ||
	(errno == EWOULDBLOCK)) {
      /* What do I do now? */
    } else {
      /* TODO: error handling */
      close(rail_sckt);
      free(data_buff);
      free(command);
      return 0;
    }
  }
  command->data = read_rail_name_data(data_buff, data_buff+ret_val);
  if (! command->data) {
    /* TODO: error handling */
    close(rail_sckt);
    free(data_buff);
    free(command);
    return 0;
  } else
    namedata = command->data;

  switch (namedata->node_type) {
  case 'B':
  default:
    cache_namecard = alloc_namecard(namedata->name, NETBIOS_NAME_LEN,
				    CACHE_NODEFLG_B, make_token(),
				    namedata->isgroup, QTYPE_NB, QCLASS_IN);
    if (! cache_namecard) {
      /* TODO: error handling */
      close(rail_sckt);
      free(data_buff);
      free(command);
      free(namedata->name);
      destroy_nbnodename(namedata->scope);
      free(namedata);
      return 0;
    }
    if (find_name(cache_namecard, namedata->scope)) {
      close(rail_sckt);
      destroy_namecard(cache_namecard);
      free(data_buff);
      free(command);
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
	/* TODO: I won't really bother with error detection at this time. */

	cache_namecard->timeof_death = time(0) + namedata->ttl;
	cache_namecard->addrs.recrd[0].node_type = CACHE_NODEFLG_B;
	cache_namecard->addrs.recrd[0].addr = calloc(1, sizeof(struct ipv4_addr_list));
	if (! cache_namecard->addrs.recrd[0].addr) {
	  /* TODO: error handling */
	  close(rail_sckt);
	  free(data_buff);
	  free(command);
	  free(namedata->name);
	  destroy_nbnodename(namedata->scope);
	  free(namedata);
	  cache_namecard->timeof_death = 0;
	  return 0;
	}
	cache_namecard->addrs.recrd[0].addr->ip_addr = command->addr.sin_addr.s_addr;

	free(data_buff);
	free(namedata->name);
	destroy_nbnodename(namedata->scope);
	free(namedata);
	return cache_namecard;
      } else {
	/* TODO: error handling */
	close(rail_sckt);
	free(data_buff);
	free(command);
	free(namedata->name);
	destroy_nbnodename(namedata->scope);
	free(namedata);
	return 0;
      }
    }
    break;
  }
}



uint64_t make_token() {
  uint64_t result;

  result = 0;
  while (result < 2) {
    /* BUG: the below line causes GCC to emit a warning. */
    result = make_weakrandom() << (8*(sizeof(uint64_t)/2));
    result = make_weakrandom() + result;
  }
  return result;
}
