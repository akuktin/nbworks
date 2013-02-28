#ifndef NBWORKS_RAILCOMM_H
# define NBWORKS_RAILCOMM_H 1

# include "nodename.h"
# include "service_sector.h"

# include <stdint.h>
# include <pthread.h>

# include <sys/socket.h>
# include <sys/un.h>
# include <netinet/in.h>
# include <netinet/ip.h>

# define NBWORKS_SCKT_NAME "NBWORKS_MULTIPLEX_DAEMON"
# define NBWORKS_SCKT_NAMELEN (7+1+9+1+6)

enum rail_commands {
  rail_regname = 1,    /* library wants to register a name in the scope */
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

# define LEN_COMM_ONWIRE (1+8+(2+4)+1+4)
struct com_comm {
  unsigned char command;
  uint64_t token;
  struct sockaddr_in addr; /* on wire: uint16_t port, uint32_t ip_addr */
  unsigned char node_type; /* one of {B, P, M, H}, flags are used internally */
  uint32_t len;
  void *data;
};

# define LEN_NAMEDT_ONWIREMIN ((NETBIOS_NAME_LEN+1)+1+4)
struct rail_name_data {
  unsigned char *name; /* whole name, the entire NETBIOS_NAME_LEN */
  unsigned char name_type;
  struct nbnodename_list *scope;
  unsigned char group_flg;
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
  struct sockaddr_un *addr;
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
  struct nbnodename_list *nbname;
  struct ss_queue_storage *queue;
};

void
  init_rail();

int
  open_rail();
/* returns: >=0 = success, <0 = error */
unsigned int
  rail_flushrail(uint32_t len,
                 int rail);
void *
  poll_rail(void *args);

void *
  handle_rail(void *args);

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

struct cache_namenode *
  do_rail_regname(int rail_sckt,
                  struct com_comm *command);

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
                         uint64_t token);
/* returns: >0 = success, 0 = failed, <0 = error */
int
  rail_setup_session(int rail,
                     uint64_t token);
void *
  tunnel_stream_sockets(void *arg);

uint32_t
  rail_whatisaddrX(int rail_sckt,
                   struct com_comm *command);

uint64_t
  make_token();

#endif /* NBWORKS_RAILCOMM_H */
