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

#ifndef NBWORKS_RAILCOMM_H
# define NBWORKS_RAILCOMM_H 1

# include "nodename.h"
# include "service_sector.h"

# define NBWORKS_SCKT_NAME "NBWORKS_MULTIPLEX_DAEMON"
# define NBWORKS_SCKT_NAMELEN (7+1+9+1+6)

enum rail_commands {
  rail_readcom,        /* daemon tells library it read the whole command */

  rail_regname,        /* library wants to register a name in the scope */
  rail_delname,        /* library wants to delete a name from the scope */

  rail_make_stream,    /* library wants to establist a session with port 139 */
  rail_stream_sckt,    /* library informs the daemon it wants to be a server */
  rail_stream_pending, /* inform library there is a new session request */
  rail_stream_take,    /* library requests forwarding the session request */
  rail_stream_accept,  /* library accepts the new session */
  rail_stream_error,   /* library wants us to send an error and disconnect */

  rail_send_dtg,       /* library wants to send a datagram with port 138 */
  rail_dtg_sckt,       /* library informs the daemon it wants to be a server */

  rail_addr_ofXuniq,   /* what is the address of X (unique)? */
  rail_addr_ofXgroup   /* what is the address of X (group)? */
};

# define LEN_COMM_ONWIRE (1+8+(2+4)+1+4+4)
/* The below structure is used to ferry information between the multiplexing
 * daemon (and later nbworks NS) on one side and the library on the other side.
 * Fields are used only as they are needed. If a field is not needed, it is
 * ignored. */
struct com_comm {
  unsigned char command;
  token_t token;
  struct sockaddr_in addr; /* on wire: uint16_t port, uint32_t ip_addr */
  unsigned char node_type; /* one of {B, P, M, H, b, p, m, h},
                            * flags are used internally */
  uint32_t nbworks_errno;
  uint32_t len;
  void *data;
};

# define LEN_NAMEDT_ONWIREMIN ((NETBIOS_NAME_LEN+1)+4)
struct rail_name_data {
  unsigned char *name; /* whole name, the entire NETBIOS_NAME_LEN */
  unsigned char name_type;
  struct nbworks_nbnamelst *scope;
  uint32_t ttl;
};

/* For the session tunnel. */
#define DEFAULT_TUNNEL_LEN (1600*32) /* The point with this is to figure
				      * out a number which equals maximum
				      * transmission unit times the number
				      * of TCP packets we will receive in
				      * the time it takes us to send the
				      * data down the tunnel. */

struct rail_params {
  unsigned char isbusy;
  pthread_t thread_id;
  int rail_sckt;
};

struct stream_connector_args {
  unsigned char isbusy;
  pthread_t thread_id;
  int sckt_lcl;
  int sckt_rmt;
};

struct dtg_srv_params {
  unsigned char isbusy;
  pthread_t thread_id;
  struct nbworks_nbnamelst *nbname;
  struct ss_queue_storage *queue;
};

void
  init_rail(void);

int
  open_rail(void);
void *
  poll_rail(void *args);

void *
  handle_rail(void *args);

struct cache_namenode *
  do_rail_regname(int rail_sckt,
                  struct com_comm *command,
                  unsigned int *rail_isreusable);
int
  do_rail_delname(int rail_sckt,
                  struct com_comm *command,
                  unsigned int *rail_isreusable);

int
  rail_senddtg(int rail_sckt,
               struct com_comm *command);
/* returns: 0=success, >0=fail, <0=error */
int
  rail_add_dtg_server(int rail_sckt,
                      struct com_comm *command);

void *
  dtg_server(void *arg);

/* returns: 0=success, >0=fail, <0=error */
int
  rail_add_ses_server(int rail_sckt,
                      struct com_comm *command);
/* returns: >0 = success, 0 = failed, <0 = error */
int
  rail__send_ses_pending(int rail,
                         token_t token);
/* returns: >0 = success, 0 = failed, <0 = error */
int
  rail_setup_session(int rail,
                     token_t token);
void *
  tunnel_stream_sockets(void *arg);

ipv4_addr_t
  rail_whatisaddrX(int rail_sckt,
                   struct com_comm *command,
                   unsigned int *rail_isreusable);

token_t
  make_token(void);

#endif /* NBWORKS_RAILCOMM_H */
