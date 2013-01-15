#ifndef NBWORKS_RAILCOMM_H
# define NBWORKS_RAILCOMM_H 1

# include "nodename.h"

# include <stdint.h>
# include <pthread.h>

# include <sys/socket.h>
# include <sys/un.h>

enum rail_commands {
  rail_regname = 1,
  rail_delname,

  rail_dtg_yes,
  rail_dtg_no,      /* default */
  rail_ses_yes,
  rail_ses_no,      /* default */

  rail_make_stream,
  rail_stream_sckt, /* for the server */
  rail_send_dtg,
  rail_dtg_sckt,    /* for the server */

  rail_ask_X_dtgp,  /* does X accept datagrams? */
  rail_addr_ofX     /* what is the address of X? */
};

# define LEN_COMM_ONWIRE (1+8+(2+4)+4)
struct com_comm {
  unsigned char command;
  uint64_t token;
  struct sockaddr_in addr; /* on wire: uint16_t port, uint32_t ip_addr */
  uint32_t len;
  void *data;
};

struct rail_params {
  pthread_t tid;
  int rail_sckt;
  struct sockaddr_un *addr;
};

# define LEN_NAMEDT_ONWIREMIN ((NETBIOS_NAME_LEN+1)+1+1+4)
struct rail_name_data {
  unsigned char *name; /* whole name, the entire NETBIOS_NAME_LEN */
  unsigned char name_type;
  struct nbnodename_list *scope;
  unsigned char isgroup;
  unsigned char node_type; /* one of {B, P, M, H}, flags are used internally */
  uint32_t ttl;
};

#endif /* NBWORKS_RAILCOMM_H */
