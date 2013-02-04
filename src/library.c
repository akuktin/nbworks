#include "c_lang_extensions.h"

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "nodename.h"
#include "library.h"
#include "rail-comm.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"
#include "randomness.h"

// temporary
#include "service_sector.h"


int lib_daemon_socket() {
  struct sockaddr_un address;
  int daemon;

  memset(&address, 0, sizeof(struct sockaddr_un));

  address.sun_family = AF_UNIX;
  memcpy(address.sun_path +1, NBWORKS_SCKT_NAME, NBWORKS_SCKT_NAMELEN);

  daemon = socket(PF_UNIX, SOCK_STREAM, 0);
  if (daemon < 0) {
    /* TODO: errno signaling stuff */
    return -1;
  }

  if (0 != fcntl(daemon, F_SETFL, O_NONBLOCK)) {
    /* TODO: errno signaling stuff */
    close(daemon);
    return -1;
  }

  if (0 != connect(daemon, &address, sizeof(struct sockaddr_un))) {
    /* TODO: errno signaling stuff */
    close(daemon);
    return -1;
  }

  return daemon;
}


/* returns: <0 = error, 0 or >0 = something was sent */
int lib_senddtg_138(struct name_state *handle,
		    unsigned char *recepient,
		    unsigned char recepient_type,
		    void *data,
		    unsigned int len,
		    unsigned char isgroup,
		    unsigned char isbroadcast) {
  struct dtg_srvc_packet *pckt;
  struct com_comm command;
  int daemon_sckt;
  unsigned int pckt_len;
  unsigned char readycommand[LEN_COMM_ONWIRE];
  void *readypacket;

  if ((! (handle && recepient)) ||
      (len > 0xff00)) { /* A bit shorter because I have not yet
			   implemented a start-stop datagram writer. */
    /* FIXME: errno signaling stuff */
    return -1;
  }

  pckt = malloc(sizeof(struct dtg_srvc_packet));
  if (! pckt) {
    /* FIXME: errno signaling stuff */
    return -1;
  }

  pckt->for_del = 0;
  pckt->type = 0;
  //  pckt->flags = DTG_FIRST_FLAG; /* stub */
  switch (handle->node_type) {
  case CACHE_NODEFLG_B:
    pckt->flags = (DTG_FIRST_FLAG | DTG_NODE_TYPE_B);
    command.node_type = 'B';
    break;
  case CACHE_NODEFLG_P:
    pckt->flags = (DTG_FIRST_FLAG | DTG_NODE_TYPE_P);
    command.node_type = 'P';
    break;
  case CACHE_NODEFLG_M:
    pckt->flags = (DTG_FIRST_FLAG | DTG_NODE_TYPE_M);
    command.node_type = 'M';
    break;
  case CACHE_NODEFLG_H:
  default:
    pckt->flags = (DTG_FIRST_FLAG | DTG_NODE_TYPE_M);
    command.node_type = 'H';
    break;
  }
  pckt->id = make_weakrandom() & 0xffff;
  pckt->src_address = my_ipv4_address();
  pckt->src_port = 138;

  pckt->payload_t = normal;
  /* FIXME: the below is a stub. I have to implement datagram fragmentation. */
  pckt->payload = dtg_srvc_make_pyld_normal(handle->name->name, handle->label_type,
					    recepient, recepient_type, handle->scope,
					    data, len, 0);
  if (! pckt->payload) {
    /* FIXME: errno signaling stuff */
    free(pckt);
    return -1;
  }
  pckt->error_code = 0;

  pckt_len = DTG_HDR_LEN + 2 + 2 +
    ((1+NETBIOS_CODED_NAME_LEN) *2) + (handle->lenof_scope *2) +
    (2 * 4) /* extra space for name alignment, if performed */ + len;

  readypacket = master_dtg_srvc_pckt_writer(pckt, &pckt_len, 0);
  if (! readypacket) {
    /* FIXME: errno signaling stuff */
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  daemon_sckt = lib_daemon_socket();
  if (daemon_sckt == -1) {
    /* FIXME: errno signaling stuff */
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  command.command = rail_send_dtg;
  command.token = handle->token;
  memset(&(command.addr), 0, sizeof(struct sockaddr_in));
  command.len = pckt_len;
  command.data = readypacket;

  fill_railcommand(&command, readycommand, (readycommand + LEN_COMM_ONWIRE));

  if (LEN_COMM_ONWIRE > send(daemon_sckt, readycommand, LEN_COMM_ONWIRE,
			     MSG_NOSIGNAL)) {
    /* FIXME: errno signaling stuff */
    close(daemon_sckt);
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  if (pckt_len > send(daemon_sckt, readypacket, pckt_len, MSG_NOSIGNAL)) {
    /* FIXME: errno signaling stuff */
    close(daemon_sckt);
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(daemon_sckt, readycommand, LEN_COMM_ONWIRE,
			     MSG_WAITALL)) {
    /* FIXME: errno signaling stuff */
    close(daemon_sckt);
    free(readypacket);
    destroy_dtg_srvc_pckt(pckt, 1, 1);
    return -1;
  }

  close(daemon_sckt);
  free(readypacket);
  destroy_dtg_srvc_pckt(pckt, 1, 1);

  return len;
}
