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

#include "c_lang_extensions.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "nbworks.h"
#include "constdef.h"
#include "nodename.h"
#include "library.h"
#include "rail-comm.h"
#include "pckt_routines.h"
#include "ses_srvc_pckt.h"
#include "dtg_srvc_pckt.h"
#include "dtg_srvc_cnst.h"
#include "rail-flush.h"
#include "portability.h"


void nbworks_libinit(void) {
  nbworks_libcntl.stop_alldtg_srv = 0;
  nbworks_libcntl.stop_allses_srv = 0;

  nbworks_libcntl.dtg_srv_polltimeout = TP_100MS;
  nbworks_libcntl.ses_srv_polltimeout = TP_100MS;

  nbworks_libcntl.max_ses_retarget_retries = SSN_RETRY_COUNT;
  nbworks_libcntl.close_timeout = SSN_CLOSE_TIMEOUT;
  nbworks_libcntl.keepalive_interval = SSN_KEEP_ALIVE_TIMEOUT;

  nbworks_libcntl.dtg_frag_keeptime = FRAGMENT_TO;

  /* It's a little sad to write an algorithm that can
   * handle hell and heaven and then cripple it like this. */
  nbworks_libcntl.dtg_max_wholefrag_len = MAX_DATAGRAM_LENGTH;

  nbworks_libcntl.emergencyfix_long1 = 0;
  nbworks_libcntl.emergencyfix_long2 = 0;
  nbworks_libcntl.emergencyfix_long3 = 0;
  nbworks_libcntl.emergencyfix_long4 = 0;
  nbworks_libcntl.emergencyfix_voidp1 = 0;
  nbworks_libcntl.emergencyfix_voidp2 = 0;
  nbworks_libcntl.emergencyfix_voidp3 = 0;
  nbworks_libcntl.emergencyfix_voidp4 = 0;

  init_my_ip4_address();
}

void nbworks_reinit_myIP4address(void) {
  init_my_ip4_address();
}


unsigned long nbworks_maxdtglen(nbworks_namestate_p handle,
				unsigned int withfrag) {
  struct name_state *name;
  long result;

  result = nbworks_libcntl.dtg_max_wholefrag_len -
    (DTG_HDR_LEN + (2 + 2));

  name = handle;
  if (name)
    result = result - (2 * align(0, (1 + NETBIOS_CODED_NAME_LEN +
				     name->lenof_scope),
				 4));
  else
    result = result - (2 * align(0, (1 + NETBIOS_CODED_NAME_LEN +
				     1),
				 4));

  if (result > 0) {
    if (withfrag)
      result = result + DTG_MAXOFFSET;

    return result;
  } else
    return 0;
}


nbworks_namestate_p nbworks_regname(unsigned char *name,
				    unsigned char name_type,
				    struct nbworks_nbnamelst *scope,
				    unsigned char isgroup,
				    unsigned char node_type, /* only one type */
				    unsigned long ttl,
				    unsigned int withguard) {
  struct name_state *result;
  struct com_comm command;
  struct rail_name_data namedt;
  int daemon;
  node_type_t real_node_type;
  unsigned int lenof_scope, lenof_name;
  unsigned char commbuff[LEN_COMM_ONWIRE], *namedtbuff;

  if (! name) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  lenof_scope = nbworks_nbnodenamelen(scope);
  if ((lenof_scope + (1+NETBIOS_CODED_NAME_LEN)) >
      ARBITRARY_MAXIMUM_LENOF_NAME) {
    nbworks_errno = EINVAL;
    return 0;
  }
  if (*name == '*') {
    nbworks_errno = EINVAL;
  }

  result = nbw_calloc(1, sizeof(struct name_state));
  if (! result) {
    nbworks_errno = ENOMEM;
    return 0;
  }

  if (pthread_mutex_init(&(result->dtg_srv_work_inprog), 0)) {
    free(result);
    nbworks_errno = ENOMEM;
    return 0;
  }

  if (pthread_mutex_init(&(result->ses_srv_work_inprog), 0))  {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    free(result);
    nbworks_errno = ENOMEM;
    return 0;
  }

  result->name = malloc(sizeof(struct nbworks_nbnamelst) +
			NETBIOS_NAME_LEN +1);
  if (! result->name) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    free(result);
    nbworks_errno = ENOMEM;
    return 0;
  }
  result->name->next_name = 0;
  result->name->len = NETBIOS_NAME_LEN;
  lenof_name = strlen((char *)name);
  if (lenof_name > (NETBIOS_NAME_LEN -1))
    lenof_name = NETBIOS_NAME_LEN -1;
  memcpy(result->name->name, name, lenof_name);
  if (lenof_name < (NETBIOS_NAME_LEN-1))
    memset((result->name->name+lenof_name), ' ',
	   ((NETBIOS_NAME_LEN-1) - lenof_name));
  result->name->name[NETBIOS_NAME_LEN-1] = name_type;
  /* Tramp stamp. */
  result->name->name[NETBIOS_NAME_LEN] = 0;

  result->scope = nbworks_clone_nbnodename(scope);
  if ((! result->scope) &&
      scope) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    nbworks_dstr_nbnodename(result->name);
    free(result);
    nbworks_errno = ENOMEM;
    return 0;
  }

  result->lenof_scope = lenof_scope;
  result->label_type = name_type;
  result->isinconflict = FALSE;
  if (0 != pthread_mutex_init(&(result->guard_mutex), 0)) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    nbworks_dstr_nbnodename(result->name);
    free(result);
    nbworks_errno = ENOMEM;
    return 0;
  }
  if (0 != pthread_mutex_init(&(result->dtg_recv_mutex), 0)) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    pthread_mutex_destroy(&(result->guard_mutex));
    nbworks_dstr_nbnodename(result->name);
    free(result);
    nbworks_errno = ENOMEM;
    return 0;
  }
  result->guard_rail = -1;

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_regname;
  switch (node_type) {
  case NBWORKS_NODE_B:
    if (isgroup) {
      real_node_type = CACHE_NODEGRPFLG_B;
      command.node_type = RAIL_NODET_BGRP;
    } else {
      real_node_type = CACHE_NODEFLG_B;
      command.node_type = RAIL_NODET_BUNQ;
    }
    break;
  case NBWORKS_NODE_P:
    if (isgroup) {
      real_node_type = CACHE_NODEGRPFLG_P;
      command.node_type = RAIL_NODET_PGRP;
    } else {
      real_node_type = CACHE_NODEFLG_P;
      command.node_type = RAIL_NODET_PUNQ;
    }
    break;
  case NBWORKS_NODE_M:
    if (isgroup) {
      real_node_type = CACHE_NODEGRPFLG_M;
      command.node_type = RAIL_NODET_MGRP;
    } else {
      real_node_type = CACHE_NODEFLG_M;
      command.node_type = RAIL_NODET_MUNQ;
    }
    break;
  case NBWORKS_NODE_H:
    if (isgroup) {
      real_node_type = CACHE_NODEGRPFLG_H;
      command.node_type = RAIL_NODET_HGRP;
    } else {
      real_node_type = CACHE_NODEFLG_H;
      command.node_type = RAIL_NODET_HUNQ;
    }
    break;

  default:
    nbworks_errno = EINVAL;
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    pthread_mutex_destroy(&(result->guard_mutex));
    pthread_mutex_destroy(&(result->dtg_recv_mutex));
    nbworks_dstr_nbnodename(result->name);
    free(result);
    return 0;
  }
  result->node_type = real_node_type;


  command.len = (LEN_NAMEDT_ONWIREMIN -1) + lenof_scope;
  namedt.name = result->name->name;
  namedt.name_type = name_type;
  namedt.scope = scope;
  namedt.ttl = ttl;

  fill_railcommand(&command, commbuff, (commbuff + LEN_COMM_ONWIRE));
  namedtbuff = malloc(command.len);
  if (! namedtbuff) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    pthread_mutex_destroy(&(result->guard_mutex));
    pthread_mutex_destroy(&(result->dtg_recv_mutex));
    nbworks_errno = ENOBUFS;
    nbworks_dstr_nbnodename(result->name);
    free(result);
    return 0;
  }
  fill_rail_name_data(&namedt, namedtbuff, (namedtbuff + command.len));

  /* ----------------------- */

  daemon = lib_daemon_socket();
  if (daemon < 0) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    pthread_mutex_destroy(&(result->guard_mutex));
    pthread_mutex_destroy(&(result->dtg_recv_mutex));
    nbworks_dstr_nbnodename(result->scope);
    nbworks_dstr_nbnodename(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = ECONNREFUSED;
    return 0;
  }

  if (LEN_COMM_ONWIRE > send(daemon, &commbuff, LEN_COMM_ONWIRE,
			     MSG_NOSIGNAL)) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    pthread_mutex_destroy(&(result->guard_mutex));
    pthread_mutex_destroy(&(result->dtg_recv_mutex));
    close(daemon);
    nbworks_dstr_nbnodename(result->scope);
    nbworks_dstr_nbnodename(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = errno;
    return 0;
  }
  if (command.len > send(daemon, namedtbuff, command.len,
			 MSG_NOSIGNAL)) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    pthread_mutex_destroy(&(result->guard_mutex));
    pthread_mutex_destroy(&(result->dtg_recv_mutex));
    close(daemon);
    nbworks_dstr_nbnodename(result->scope);
    nbworks_dstr_nbnodename(result->name);
    free(result);
    free(namedtbuff);
    nbworks_errno = errno;
    return 0;
  }

  free(namedtbuff);

  if (LEN_COMM_ONWIRE > recv(daemon, &commbuff, LEN_COMM_ONWIRE,
			     MSG_WAITALL)) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    pthread_mutex_destroy(&(result->guard_mutex));
    pthread_mutex_destroy(&(result->dtg_recv_mutex));
    close(daemon);
    nbworks_dstr_nbnodename(result->scope);
    nbworks_dstr_nbnodename(result->name);
    free(result);
    nbworks_errno = EPERM;
    return 0;
  }
  close(daemon);
  read_railcommand(commbuff, (commbuff + LEN_COMM_ONWIRE), &command);

  if ((command.command != rail_regname) ||
      (command.token < 2) ||
      (command.nbworks_errno)) {
    pthread_mutex_destroy(&(result->dtg_srv_work_inprog));
    pthread_mutex_destroy(&(result->ses_srv_work_inprog));
    pthread_mutex_destroy(&(result->guard_mutex));
    pthread_mutex_destroy(&(result->dtg_recv_mutex));
    nbworks_dstr_nbnodename(result->scope);
    nbworks_dstr_nbnodename(result->name);
    free(result);
    if (command.nbworks_errno)
      nbworks_errno = command.nbworks_errno;
    else
      nbworks_errno = EPERM;
    return 0;
  }

  result->token = command.token;

  if (withguard)
    nbworks_grab_railguard(result);

  return result;
}

/* returns: >0 = success, 0 = fail, <0 = error */
int nbworks_delname(nbworks_namestate_p namehandle) {
  struct com_comm command;
  struct name_state *handle;
  int daemon, guarded;
  unsigned char combuff[LEN_COMM_ONWIRE];

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  }

  if (handle->guard_rail < 0) {
    guarded = FALSE;
    daemon = lib_daemon_socket();
    if (daemon < 0) {
      nbworks_errno = EPIPE;
      return -1;
    }
  } else {
    guarded = TRUE;
    pthread_mutex_lock(&(handle->guard_mutex));
    daemon = handle->guard_rail;
  }

  memset(&command, 0, sizeof(struct com_comm));

  command.command = rail_delname;
  command.token = handle->token;
  switch (handle->node_type) {
  case CACHE_NODEFLG_B:
    command.node_type = RAIL_NODET_BUNQ;
    break;
  case CACHE_NODEGRPFLG_B:
    command.node_type = RAIL_NODET_BGRP;
    break;

  case CACHE_NODEFLG_P:
    command.node_type = RAIL_NODET_PUNQ;
    break;
  case CACHE_NODEGRPFLG_P:
    command.node_type = RAIL_NODET_PGRP;
    break;

  case CACHE_NODEFLG_M:
    command.node_type = RAIL_NODET_MUNQ;
    break;
  case CACHE_NODEGRPFLG_M:
    command.node_type = RAIL_NODET_MGRP;
    break;

  case CACHE_NODEFLG_H:
    command.node_type = RAIL_NODET_HUNQ;
    break;
  case CACHE_NODEGRPFLG_H:
    command.node_type = RAIL_NODET_HGRP;
    break;

  default:
    nbworks_errno = EINVAL;
    if (! guarded)
      close(daemon);
    else
      pthread_mutex_unlock(&(handle->guard_mutex));
    return -1;
  }

  fill_railcommand(&command, combuff, (combuff + LEN_COMM_ONWIRE));
  if (LEN_COMM_ONWIRE > send(daemon, combuff, LEN_COMM_ONWIRE,
			     MSG_NOSIGNAL)) {
    if (guarded) {
      close(daemon);
      goto do_delete_everything;
    } else {
      close(daemon);
      return 0;
    }
  }

  /* Wait on the daemon, so our day does not get screwed up. */
  if (LEN_COMM_ONWIRE > recv(daemon, combuff, LEN_COMM_ONWIRE, 0)) {
    close(daemon);
    if (guarded) {
      goto do_delete_everything;
    } else {
      return 0;
    }
  }
  close(daemon);

  if (! read_railcommand(combuff, (combuff + LEN_COMM_ONWIRE),
			 &command)) {
    goto do_delete_everything;
  }

  if ((! ((command.command == rail_delname) ||
	  (command.command == rail_readcom))) ||
      (command.token != handle->token)) {
    if (guarded)
      goto do_delete_everything;
    else
      return 0;
  }

 do_delete_everything:
  if (handle->dtg_srv_tid) {
    handle->dtg_srv_stop = TRUE;

    pthread_join(handle->dtg_srv_tid, 0);
  }

  if (handle->ses_srv_tid) {
    handle->ses_srv_stop = TRUE;

    pthread_join(handle->ses_srv_tid, 0);
  }

  nbworks_dstr_nbnodename(handle->name);
  if (handle->scope)
    nbworks_dstr_nbnodename(handle->scope);

  if (handle->dtg_listento)
    nbworks_dstr_nbnodename(handle->dtg_listento);
  if (handle->dtg_frags)
    lib_destroy_allfragbckbone(handle->dtg_frags);
  if (handle->in_library)
    lib_dstry_packets(handle->in_library);

  if (handle->ses_listento)
    nbworks_dstr_nbnodename(handle->ses_listento);
  if (handle->sesin_library)
    lib_dstry_sesslist(handle->sesin_library);

  pthread_mutex_destroy(&(handle->dtg_srv_work_inprog));
  pthread_mutex_destroy(&(handle->ses_srv_work_inprog));
  pthread_mutex_destroy(&(handle->guard_mutex));
  pthread_mutex_destroy(&(handle->dtg_recv_mutex));

  free(handle); /* Bye-bye. */

  return TRUE;
}

/* returns: >0 = success; 0 = fail; <0 = error */
int nbworks_grab_railguard(nbworks_namestate_p namehandle) {
  struct com_comm command;
  struct name_state *handle;
  int rail;
  unsigned char buff[LEN_COMM_ONWIRE];

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  memset(&command, 0, sizeof(command));
  command.command = rail_isguard;
  command.token = handle->token;
  switch (handle->node_type) {
  case CACHE_NODEFLG_B:
    command.node_type = RAIL_NODET_BUNQ;
    break;
  case CACHE_NODEGRPFLG_B:
    command.node_type = RAIL_NODET_BGRP;
    break;

  case CACHE_NODEFLG_P:
    command.node_type = RAIL_NODET_PUNQ;
    break;
  case CACHE_NODEGRPFLG_P:
    command.node_type = RAIL_NODET_PGRP;
    break;

  case CACHE_NODEFLG_M:
    command.node_type = RAIL_NODET_MUNQ;
    break;
  case CACHE_NODEGRPFLG_M:
    command.node_type = RAIL_NODET_MGRP;
    break;

  case CACHE_NODEFLG_H:
    command.node_type = RAIL_NODET_HUNQ;
    break;
  case CACHE_NODEGRPFLG_H:
    command.node_type = RAIL_NODET_HGRP;
    break;

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
  if (buff == fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE))) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  if (handle->guard_rail > -1) {
    if (0 <= nbworks_release_railguard(handle)) {
      return 0;
    }
  }

  rail = lib_daemon_socket();
  if (rail < 0) {
    nbworks_errno = EPIPE;
    return -1;
  }

  if (LEN_COMM_ONWIRE > send(rail, buff, LEN_COMM_ONWIRE,
			     MSG_NOSIGNAL)) {
    close(rail);
    nbworks_errno = EPIPE;
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(rail, buff, LEN_COMM_ONWIRE,
			     MSG_WAITALL)) {
    close(rail); /* This could lead us to losing the name. */
    nbworks_errno = EREMOTEIO;
    return -1;
  }

  if (! read_railcommand(buff, (buff+LEN_COMM_ONWIRE), &command)) {
    close(rail); /* This COULD lead us to losing the name. */
    nbworks_errno = EREMOTEIO;
    return -1;
  }

  if (!((command.command == rail_isguard) &&
	(command.token == handle->token) &&
	(command.nbworks_errno == 0))) {
    close(rail); /* This COULD lead us to losing the name. */
    nbworks_errno = EREMOTEIO;
    return -1;
  }

  if (command.len)
    rail_flushrail(command.len, rail);
  handle->guard_rail = rail;

  return 1;
}

/* returns: >0 = success; 0 = fail; <0 = error */
int nbworks_release_railguard(nbworks_namestate_p namehandle) {
  struct com_comm command;
  struct name_state *handle;
  int rail;
  unsigned char buff[LEN_COMM_ONWIRE];

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  if (handle->guard_rail < 0) {
    return 1;
  } else {
    if (0 == pthread_mutex_trylock(&(handle->guard_mutex)))
      rail = handle->guard_rail;
    else {
      nbworks_errno = EDEADLK;
      return 0;
    }
  }

  memset(&command, 0, sizeof(command));
  command.command = rail_isnotguard;
  command.token = handle->token;
  switch (handle->node_type) {
  case CACHE_NODEFLG_B:
    command.node_type = RAIL_NODET_BUNQ;
    break;
  case CACHE_NODEGRPFLG_B:
    command.node_type = RAIL_NODET_BGRP;
    break;

  case CACHE_NODEFLG_P:
    command.node_type = RAIL_NODET_PUNQ;
    break;
  case CACHE_NODEGRPFLG_P:
    command.node_type = RAIL_NODET_PGRP;
    break;

  case CACHE_NODEFLG_M:
    command.node_type = RAIL_NODET_MUNQ;
    break;
  case CACHE_NODEGRPFLG_M:
    command.node_type = RAIL_NODET_MGRP;
    break;

  case CACHE_NODEFLG_H:
    command.node_type = RAIL_NODET_HUNQ;
    break;
  case CACHE_NODEGRPFLG_H:
    command.node_type = RAIL_NODET_HGRP;
    break;

  default:
    nbworks_errno = EINVAL;
    pthread_mutex_unlock(&(handle->guard_mutex));
    return -1;
  }
  if (buff == fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE))) {
    nbworks_errno = ENOBUFS;
    pthread_mutex_unlock(&(handle->guard_mutex));
    return -1;
  }

  if (LEN_COMM_ONWIRE > send(rail, buff, LEN_COMM_ONWIRE,
			     MSG_NOSIGNAL)) {
    nbworks_errno = EREMOTEIO;
    pthread_mutex_unlock(&(handle->guard_mutex));
    return 0;
  }

  if (LEN_COMM_ONWIRE > recv(rail, buff, LEN_COMM_ONWIRE,
			     MSG_WAITALL)) {
    nbworks_errno = EREMOTEIO;
    pthread_mutex_unlock(&(handle->guard_mutex));
    return 0;
  }

  if (! read_railcommand(buff, (buff+LEN_COMM_ONWIRE), &command)) {
    nbworks_errno = EREMOTEIO;
    pthread_mutex_unlock(&(handle->guard_mutex));
    return 0;
  }

  if (!((command.command == rail_isnotguard) &&
	(command.token == handle->token) &&
	(command.nbworks_errno == 0))) {
    nbworks_errno = EREMOTEIO;
    pthread_mutex_unlock(&(handle->guard_mutex));
    return 0;
  }

  close(rail);
  handle->guard_rail = -1;

  pthread_mutex_unlock(&(handle->guard_mutex));
  return 1;
}


nbworks_session_p nbworks_castdtgsession(nbworks_namestate_p namehandle,
					 struct nbworks_nbnamelst *defaultpeer) {
  nbworks_session_p new_ses;
  struct name_state *handle;
  struct nbworks_nbnamelst *peer;

  handle = namehandle;
  if (! namehandle) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  /* FIXME: speed this up */

  if (defaultpeer) {
    if (defaultpeer->len < NETBIOS_NAME_LEN) {
      peer = malloc(sizeof(struct nbworks_nbnamelst) +
		    NETBIOS_NAME_LEN +1);
      if (! peer) {
	nbworks_errno = ENOBUFS;
	return 0;
      }
      memcpy(peer->name, defaultpeer->name, defaultpeer->len);
      memset((peer->name + defaultpeer->len), ' ',
	     (NETBIOS_NAME_LEN - defaultpeer->len));
      peer->len = NETBIOS_NAME_LEN;
    } else {
      peer = nbworks_clone_nbnodename(defaultpeer);
      if (peer->next_name)
	nbworks_dstr_nbnodename(peer->next_name);
    }
    peer->next_name = nbworks_clone_nbnodename(handle->scope);
    if ((! peer->next_name) &&
	handle->scope) {
      nbworks_dstr_nbnodename(peer);
      nbworks_errno = ENOBUFS;
      return 0;
    }
  } else
    peer = 0;

  new_ses = lib_make_session(-1, peer, namehandle, FALSE);
  nbworks_dstr_nbnodename(peer);
  return new_ses;
}


/* returns: >0 = success, 0 = fail, <0 = error */
int nbworks_listen_dtg(nbworks_namestate_p namehandle,
		       unsigned char takes_field,
		       struct nbworks_nbnamelst *listento) {
  struct com_comm command;
  struct name_state *handle;
  int daemon;
  unsigned char buff[LEN_COMM_ONWIRE], real_takes;

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  if ((! handle->token) ||
      (handle->isinconflict)) {
    nbworks_errno = EPERM;
    return 0;
  }

  if (! (listento || takes_field)) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    switch (takes_field) {
    case NBWORKS_TAKES_ALL:
      real_takes = HANDLE_TAKES_ALL;
      break;
    case NBWORKS_TAKES_BRDCST:
      real_takes = HANDLE_TAKES_ALLBRDCST;
      break;
    case NBWORKS_TAKES_UNQCST:
      real_takes = HANDLE_TAKES_ALLUNCST;
      break;
    case 0:
      real_takes = 0;
      break;
    default:
      nbworks_errno = EINVAL;
      return -1;
    }
  }

  if (pthread_mutex_lock(&(handle->dtg_srv_work_inprog))) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  if (handle->dtg_srv_tid) {
    handle->dtg_srv_stop = TRUE;

    pthread_join(handle->dtg_srv_tid, 0);
  }

  daemon = lib_daemon_socket();
  if (daemon < 0) {
    pthread_mutex_unlock(&(handle->dtg_srv_work_inprog));
    nbworks_errno = EPIPE;
    return -1;
  }

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_dtg_sckt;
  command.token = handle->token;

  fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));

  if (LEN_COMM_ONWIRE > send(daemon, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
    close(daemon);
    pthread_mutex_unlock(&(handle->dtg_srv_work_inprog));
    nbworks_errno = EPIPE;
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(daemon, buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
    close(daemon);
    pthread_mutex_unlock(&(handle->dtg_srv_work_inprog));
    nbworks_errno = EPIPE;
    return 0;
  }

  if (0 == read_railcommand(buff, (buff + LEN_COMM_ONWIRE), &command)) {
    close(daemon);
    pthread_mutex_unlock(&(handle->dtg_srv_work_inprog));
    nbworks_errno = EPIPE;
    return -1;
  }

  if (!((command.command == rail_dtg_sckt) &&
	(command.token == handle->token) &&
	(command.nbworks_errno == 0))) {
    close(daemon);

    if ((command.command == rail_dtg_sckt) &&
	(command.token == handle->token) &&
	(command.nbworks_errno == EADDRINUSE)) {
      nbworks_errno = EADDRINUSE;
      handle->isinconflict = TRUE;
    }

    pthread_mutex_unlock(&(handle->dtg_srv_work_inprog));
    nbworks_errno = EPIPE;
    return -1;
  }

  if (command.len)
    rail_flushrail(command.len, daemon);

  handle->dtg_srv_sckt = daemon;

  if (handle->dtg_listento)
    nbworks_dstr_nbnodename(handle->dtg_listento);
  handle->dtg_listento = nbworks_clone_nbnodename(listento);
  handle->dtg_takes = real_takes;
  if (handle->dtg_frags) {
    lib_destroy_allfragbckbone(handle->dtg_frags);
    handle->dtg_frags = 0;
  }
  handle->in_server = 0;
  if (handle->in_library) {
    lib_dstry_packets(handle->in_library);
    handle->in_library = 0;
  }
  handle->dtg_srv_stop = FALSE;

  if (0 != pthread_create(&(handle->dtg_srv_tid), 0,
			  lib_dtgserver, handle)) {
    nbworks_errno = errno;
    handle->dtg_srv_tid = 0;

    close(daemon);
    handle->dtg_srv_sckt = -1;
    nbworks_dstr_nbnodename(handle->dtg_listento);
    handle->dtg_listento = 0;

    handle->in_library = 0;
    handle->dtg_srv_tid = 0;

    pthread_mutex_unlock(&(handle->dtg_srv_work_inprog));
    nbworks_errno = ENOBUFS;
    return -1;
  }

  pthread_mutex_unlock(&(handle->dtg_srv_work_inprog));
  return 1;
}

/* returns: >0 = success, 0 = fail, <0 = error */
int nbworks_listen_ses(nbworks_namestate_p namehandle,
		       unsigned char takes_field,
		       struct nbworks_nbnamelst *listento) {
  struct com_comm command;
  struct name_state *handle;
  int daemon;
  unsigned char buff[LEN_COMM_ONWIRE];

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  if ((! handle->token) ||
      (handle->isinconflict)) {
    nbworks_errno = EPERM;
    return 0;
  }

  if (! (listento || takes_field)) {
    nbworks_errno = EINVAL;
    return -1;
  }

  if (pthread_mutex_lock(&(handle->ses_srv_work_inprog))) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  if (handle->ses_srv_tid) {
    handle->ses_srv_stop = TRUE;

    pthread_join(handle->ses_srv_tid, 0);
  }

  daemon = lib_daemon_socket();
  if (daemon < 0) {
    pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
    nbworks_errno = EPIPE;
    return -1;
  }

  memset(&command, 0, sizeof(struct com_comm));
  command.command = rail_stream_sckt;
  command.token = handle->token;

  fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));

  if (LEN_COMM_ONWIRE > send(daemon, buff, LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
    close(daemon);
    pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
    nbworks_errno = EPIPE;
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(daemon, buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
    close(daemon);
    pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
    nbworks_errno = EPIPE;
    return 0;
  }

  if (0 == read_railcommand(buff, (buff + LEN_COMM_ONWIRE), &command)) {
    close(daemon);
    pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
    nbworks_errno = EPIPE;
    return -1;
  }

  if (!((command.command == rail_stream_sckt) &&
	(command.token == handle->token) &&
	(command.nbworks_errno == 0))) {
    close(daemon);

    if ((command.command == rail_stream_sckt) &&
	(command.token == handle->token) &&
	(command.nbworks_errno == EADDRINUSE)) {
      nbworks_errno = EADDRINUSE;
      handle->isinconflict = TRUE;
    }
    pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
    nbworks_errno = EPIPE;
    return -1;
  }

  if (command.len)
    rail_flushrail(command.len, daemon);

  handle->ses_srv_sckt = daemon;

  if (handle->ses_listento)
    nbworks_dstr_nbnodename(handle->ses_listento);
  handle->ses_listento = nbworks_clone_nbnodename(listento);
  if (takes_field)
    handle->ses_takes = HANDLE_TAKES_ALL;
  else
    handle->ses_takes = 0;
  handle->sesin_server = 0;
  if (handle->sesin_library) {
    lib_dstry_sesslist(handle->sesin_library);
    handle->sesin_library = 0;
  }
  handle->ses_srv_stop = FALSE;

  if (0 != pthread_create(&(handle->ses_srv_tid), 0,
			  lib_ses_srv, handle)) {
    nbworks_errno = errno;
    close(daemon);
    handle->ses_srv_sckt = -1;

    nbworks_dstr_nbnodename(handle->ses_listento);
    handle->ses_listento = 0;

    handle->sesin_library = 0;

    handle->ses_srv_tid = 0;

    pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
    nbworks_errno = ENOBUFS;
    return -1;
  }

  pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
  return TRUE;
}

/* returns: >0 = success; 0 = fail; <0 = error */
int nbworks_update_listentos(unsigned char service,
			     nbworks_namestate_p namehandle,
			     unsigned char newtakes_field,
			     struct nbworks_nbnamelst *newlistento) {
  struct name_state *handle;
  struct nbworks_nbnamelst *new, *old;

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else
    nbworks_errno = 0;

  new = nbworks_clone_nbnodename(newlistento);
  if (newlistento && (! new)) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  switch (service) {
  case NBWORKS_DTG_SRVC:
    old = handle->dtg_listento;
    handle->dtg_listento = new;
    switch (newtakes_field) {
    case NBWORKS_TAKES_ALL:
      handle->dtg_takes = HANDLE_TAKES_ALL;
      break;
    case NBWORKS_TAKES_BRDCST:
      handle->dtg_takes = HANDLE_TAKES_ALLBRDCST;
      break;
    case NBWORKS_TAKES_UNQCST:
      handle->dtg_takes = HANDLE_TAKES_ALLUNCST;
      break;
    case 0:
      handle->dtg_takes = 0;
      break;
    default:
      handle->dtg_listento = old;
      nbworks_dstr_nbnodename(new);
      nbworks_errno = EINVAL;
      return -1;
    }
    break;
  case NBWORKS_SES_SRVC:
    old = handle->ses_listento;
    handle->ses_listento = new;
    if (newtakes_field)
      handle->ses_takes = HANDLE_TAKES_ALL;
    else
      handle->ses_takes = 0;
    break;
  default:
    nbworks_errno = EINVAL;
    return -1;
  }

  nbworks_dstr_nbnodename(old);

  return 1;
}

nbworks_session_p nbworks_accept_ses(nbworks_namestate_p namehandle,
				     int timeout) {
  struct timespec sleeptime;
  struct name_state *handle;
  struct nbworks_session *result, *clone;
  int waits;

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  sleeptime.tv_sec = 0;
  sleeptime.tv_nsec = T_12MS;
  if (timeout <= 0) {
    if (timeout < 0)
      waits = -1;
    else
      waits = 0;
  } else {
    waits = timeout / 12;
    if (timeout % 12) {
      waits++;
      timeout = timeout - (timeout % 12);
      timeout = timeout + 12;
      if (timeout < 12) {
        /* Safety first. */
        timeout = (int)ZEROONES;
      }
    }
  }

  if (pthread_mutex_lock(&(handle->ses_srv_work_inprog))) {
    nbworks_errno = ENOBUFS;
    return 0;
  }

  do {
    if (handle->sesin_library) {
      result = handle->sesin_library;

      if ((! result->peer) ||
	  (result->socket < 0)) {
	if (result->next) {
	  handle->sesin_library = result->next;
	  nbworks_hangup_ses(result);

	  if (timeout > 0) {
	    timeout = timeout - (waits * 12);
	    if (timeout < 0) {
              timeout = 0;
	    }
	  }
          pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
	  return nbworks_accept_ses(handle, timeout);
	} else {
          goto do_wait;
	}
      }

      if (result->next) {
	handle->sesin_library = result->next;
	result->next = 0;
      } else {
	clone = malloc(sizeof(struct nbworks_session));
	if (! clone) {
          pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
	  nbworks_errno = ENOBUFS;
	  return 0;
	}

	memcpy(clone, result, sizeof(struct nbworks_session));

	result->peer = 0;
	result->socket = -1;

	pthread_mutex_init(&(clone->mutex), 0);
	pthread_mutex_init(&(clone->receive_mutex), 0);

	result = clone;
      }

      if ((result->keepalive) &&
	  (! result->caretaker_tid)) {
	if (0 != pthread_create(&(result->caretaker_tid), 0,
				lib_caretaker, handle)) {
	  result->caretaker_tid = 0;
	}
      } else {
	result->caretaker_tid = 0;
      }

      pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
      return result;
    }

   do_wait:
    if (waits != 0) {
      nanosleep(&sleeptime, 0);
      if (waits > 0)
        waits--;
    } else
      break;
  } while (404);

  pthread_mutex_unlock(&(handle->ses_srv_work_inprog));
  nbworks_errno = EAGAIN;
  return 0;
}

nbworks_session_p nbworks_sescall(nbworks_namestate_p namehandle,
				  struct nbworks_nbnamelst *dst,
				  unsigned char keepalive) {
  struct name_state *handle;
  int this_is_a_socket;

  handle = namehandle;
  if (! (handle && dst)) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  if (handle->isinconflict) {
    nbworks_errno = EPERM;
    return 0;
  }

  this_is_a_socket = lib_open_session(handle, dst);

  if (this_is_a_socket < 0) {
    /* nbworks_errno is already set */
    return 0;
  } else {
    return lib_make_session(this_is_a_socket, dst, handle, keepalive);
  }
}

nbworks_session_p nbworks_dtgconnect(nbworks_session_p session,
				     struct nbworks_nbnamelst *dst) {
  struct nbworks_session *ses;

  ses = session;
  if (! ses) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  if (ses->peer)
    nbworks_dstr_nbnodename(ses->peer);

  if (dst) {
    if (dst->len < NBWORKS_NBNAME_LEN) {
      ses->peer = malloc(sizeof(struct nbworks_nbnamelst) +
			 NBWORKS_NBNAME_LEN +1);
      if (! ses->peer) {
	return 0;
      }
      memcpy(ses->peer->name, dst->name, dst->len);
      if (dst->len < (NBWORKS_NBNAME_LEN-1))
	memset((ses->peer->name + dst->len), ' ',
	       ((NBWORKS_NBNAME_LEN-1) - dst->len ));
      /* Default to name_type of 0x00. */
      ses->peer->name[NBWORKS_NBNAME_LEN] = 0;
      ses->peer->len = NBWORKS_NBNAME_LEN;
      if (dst->next_name) {
	ses->peer->next_name = nbworks_clone_nbnodename(dst->next_name);
      } else {
	ses->peer->next_name = 0;
      }
    } else {
      ses->peer = nbworks_clone_nbnodename(dst);
    }
  } else {
    ses->peer = 0;
  }

  return ses;
}


int nbworks_poll(unsigned char service,
		 struct nbworks_pollfd *handles,
		 int numof_pfd,
		 int timeout) {
  struct pollfd *pfd;
  struct timespec sleeptime;
  struct packet_cooked *trgt;
  struct nbworks_session *session;
  struct name_state *nstate;
  int i, count, ret_val;

  if ((! handles) ||
      (numof_pfd <= 0)) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  switch (service) {
  case NBWORKS_DTG_SRVC:
    sleeptime.tv_sec = 0;
    sleeptime.tv_nsec = T_12MS;

    ret_val = 0;
    for (i=0; i<numof_pfd; i++) {
      session = handles[i].session;
      if (session) {
	nstate = session->handle;
	if (nstate) {
	  trgt = nstate->in_library;
	  if (! trgt) {
	    handles[i].revents = POLLOUT;
	    continue;
	  }
	} else {
	  nbworks_errno = EINVAL;
	  return -1;
	}
      } else {
	nbworks_errno = EINVAL;
	return -1;
      }

      /* If trgt[i].data is non-NULL, then this particular packet
       * has an unread payload and we do not need to check for the
       * presence of other packets. However, it is possible the packet
       * was read, thus making trgt[i].data equal NULL, but a new
       * packet has arrived. In this case, move trgt[i] down the list,
       * then evaluate it. The maneuvre is done for it's side effect,
       * changing the contents of trgt[i]. The same thing can also be
       * done without the comma, but this is way sexier, IMHO. :)
       * One other thing: I am not using the "logical or" operator because
       * I want to exercise total control over memory contents.
       * After all - that is the reason I use C and not PHP. */
      if ((trgt->data) ? trgt :
	  ((trgt = trgt->next), trgt)) {
	ret_val++;

	/* Do not report a POLLIN event if the application has not
	 * asked for it. */
	handles[i].revents = ((handles[i].events & POLLIN) | POLLOUT);
      } else {
	handles[i].revents = POLLOUT;
      }
    }

    if (ret_val) {
      return ret_val;
    }

    if (timeout < 0) {
      while (0xce0) {

	for (i=0; i<numof_pfd; i++) {
	  session = handles[i].session;
	  if (session) {
	    nstate = session->handle;
	    if (nstate) {
	      trgt = nstate->in_library;
	      if (! trgt) {
		continue;
	      }
	    } else {
	      nbworks_errno = EINVAL;
	      return -1;
	    }
	  } else {
	    nbworks_errno = EINVAL;
	    return -1;
	  }

	  /* Same as above. */
	  if ((trgt->data) ? trgt :
	      ((trgt = trgt->next), trgt)) {
	    ret_val++;

	    handles[i].revents = ((handles[i].events & POLLIN) | POLLOUT);
	  }
	}

	if (ret_val)
	  break;

	if (-1 == nanosleep(&sleeptime, 0)) {
	  nbworks_errno = errno;
	  for (i=0; i<numof_pfd; i++) {
	    handles[i].revents = POLLERR;
	  }
	  return -1;
	}
      }
    } else {
      count = timeout / 12;
      if (timeout % 12)
	count++;
      for (; count > 0; count--) {

	for (i=0; i<numof_pfd; i++) {
	  session = handles[i].session;
	  if (session) {
	    nstate = session->handle;
	    if (nstate) {
	      trgt = nstate->in_library;
	      if (! trgt) {
		continue;
	      }
	    } else {
	      nbworks_errno = EINVAL;
	      return -1;
	    }
	  } else {
	    nbworks_errno = EINVAL;
	    return -1;
	  }

	  /* Same as above. */
	  if ((trgt->data) ? trgt :
	      ((trgt = trgt->next), trgt)) {
	    ret_val++;

	    handles[i].revents = ((handles[i].events & POLLIN) | POLLOUT);
	  }
	}

	if (ret_val)
	  break;

	if (-1 == nanosleep(&sleeptime, 0)) {
	  nbworks_errno = errno;
	  for (i=0; i<numof_pfd; i++) {
	    handles[i].revents = POLLERR;
	  }
	  return -1;
	}
      }
    }

    return ret_val;


  case NBWORKS_SES_SRVC:
    pfd = malloc(numof_pfd * sizeof(struct pollfd));
    if (! pfd) {
      nbworks_errno = ENOBUFS;
      for (i=0; i<numof_pfd; i++) {
	handles[i].revents = POLLERR;
      }
      return -1;
    }

    for (i=0; i<numof_pfd; i++) {
      session = handles[i].session;
      pfd[i].fd = session->socket;
      pfd[i].events = handles[i].events;
    }

    ret_val = poll(pfd, numof_pfd, timeout);
    nbworks_errno = errno;

    for (i=0; i<numof_pfd; i++) {
      handles[i].revents = pfd[i].revents;
    }

    free(pfd);

    return ret_val;

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
}


ssize_t nbworks_sendto(unsigned char service,
		       nbworks_session_p sesp,
		       void *buff_ptr,
		       size_t len,
		       int callflags,
		       struct nbworks_nbnamelst *dst) {
  struct nbworks_nbnamelst *peer;
  struct ses_srvc_packet pckt;
  struct nbworks_session *ses;
  time_t start_time, end_times;
  ssize_t ret_val, sent, notsent;
  int flags;
  unsigned char pcktbuff[SES_HEADER_LEN], *buff;

  /* Fun fact: since ssize_t is signed, and size_t is not,
   *           ssize_t has one bit less than size_t.
   *           The implication of this is that it is possible
   *           for an application to request sending of a
   *           larger number of octets than we can report back
   *           as being sent.
   *           max(ssize_t) < max(size_t) */

  ses = sesp;
  if ((! (ses && buff_ptr)) ||
      (len <= 0) ||
      (len >= (SIZE_MAX / 2))) { /* This hack may not work everywhere. */
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    sent = 0;
    /* Turn off MSG_EOR in the flags we send to the socket. */
    flags = callflags & (ONES ^ (MSG_EOR | MSG_DONTROUTE));
    buff = buff_ptr;
  }

  switch (service) {
  case NBWORKS_DTG_SRVC:
    /* FEATURE_REQUEST: for now, we only support sending
                        via the multiplexing daemon */
    if (! ses->handle) {
      nbworks_errno = EINVAL;
      return -1;
    }

    if (ses->handle->isinconflict) {
      nbworks_errno = EPERM;
      return -1;
    }

    if (len > DTG_MAXLEN) {
      nbworks_errno = EMSGSIZE;
      return -1;
    }

    if (dst) {
      if (dst->len == NETBIOS_NAME_LEN)
	peer = dst;
      else {
	nbworks_errno = EINVAL;
	return -1;
      }
    } else
      if (ses->peer) {
	peer = ses->peer;
      } else {
	nbworks_errno = ENOTCONN;
	return -1;
      }

    if (callflags & MSG_BRDCAST) {
      flags = DTGIS_BRDCST;
    } else {
      if (callflags & MSG_GROUP)
	flags = DTGIS_GRPCST;
      else
	flags = DTGIS_UNQCST;
    }

    ret_val = lib_senddtg_138(ses->handle, peer->name,
			      (peer->name)[NETBIOS_NAME_LEN-1],
			      buff, len, flags);

    if (ret_val < len) {
      /* nbworks_errno is already set */
      return -1;
    } else
      return ret_val;

  case NBWORKS_SES_SRVC:
#define handle_cancel				\
    if (ses->cancel_send) {			\
      ses->cancel_send = 0;			\
      close(ses->socket);			\
      ses->socket = -1;				\
      nbworks_errno = ECANCELED;		\
      return -1;				\
    }
#define handle_timeout							\
    end_times = start_time + nbworks_libcntl.close_timeout;		\
    if (end_times < start_time)						\
      end_times = INFINITY; /* A statement laden with meaning */	\
    if (end_times < time(0)) {						\
      close(ses->socket);						\
      ses->socket = -1;							\
      nbworks_errno = ETIME;						\
      return -1;							\
    }

    start_time = time(0);
    pckt.type = SESSION_MESSAGE;
    pckt.flags = 0;

    /* --> begin setup */
    if ((ses->nonblocking) ||
	(flags & MSG_DONTWAIT)) {
      if (0 != pthread_mutex_trylock(&(ses->mutex))) {
	if (errno == EBUSY) {
	  nbworks_errno = EBUSY;
	  return -1;
	} else {
	  nbworks_errno = errno;
	  return -1;
	}
      }
    } else {
      if (0 != pthread_mutex_lock(&(ses->mutex))) {
	nbworks_errno = errno;
	return -1;
      }
    }
    /* --> end setup */

    /* --> begin send overweight stuff */
    while (len > SES_MAXLEN) {
      pckt.len = SES_MAXLEN;
      if (pcktbuff == fill_ses_packet_header(&pckt, pcktbuff,
					     (pcktbuff + SES_HEADER_LEN))) {
	pthread_mutex_unlock(&(ses->mutex));
	if (sent)
	  return sent;
	else {
	  nbworks_errno = ENOBUFS;
	  return -1;
	}
      }

      /* send header */
      notsent = SES_HEADER_LEN;
      while (notsent) {
	ret_val = send(ses->socket, (pcktbuff + (SES_HEADER_LEN - notsent)),
		       notsent, flags);
	if (ret_val <= 0) {
	  pthread_mutex_unlock(&(ses->mutex));
	  if (ret_val == 0) {
	    return sent;
	  } else {
	    if (((errno == EAGAIN) ||
		 (errno == EWOULDBLOCK)) &&
		sent) {
	      return sent;
	    } else {
	      nbworks_errno = errno;
	      return ret_val;
	    }
	  }
	} else {
	  notsent = notsent - ret_val;
	}

	handle_timeout;
	handle_cancel;
      }

      /* send data */
      notsent = SES_MAXLEN;
      while (notsent) {
	ret_val = send(ses->socket, (buff + (SES_MAXLEN - notsent)),
		       notsent, (flags & (ONES ^ MSG_DONTWAIT)));
	if (ret_val <= 0) {
	  /* So, basically, once you commit to a packet, you HAVE to send
	   * the whole thing because failure to do so would desync the stream. */

	  if (ret_val == 0) {
	    pthread_mutex_unlock(&(ses->mutex));

	    nbworks_errno = EREMOTEIO;
	    return -1;
	  } else {
	    if ((errno == EAGAIN) ||
		(errno == EWOULDBLOCK)) {
	      handle_timeout;
	      handle_cancel else continue;
	    }
	    pthread_mutex_unlock(&(ses->mutex));

	    nbworks_errno = errno;
	    return ret_val;
	  }
	} else {
	  notsent = notsent - ret_val;
	}

	handle_timeout;
	handle_cancel;
      }

      sent = sent + SES_MAXLEN;

      if (callflags & MSG_EOR) {
	pthread_mutex_unlock(&(ses->mutex));
	return sent;
      } else {
	buff = buff + SES_MAXLEN;
	len = len - SES_MAXLEN;
      }
    }

    if (len == 0) {
      pthread_mutex_unlock(&(ses->mutex));
      return sent;
    }
    /* --> end send overweight stuff */

    /* --> begin send normal stuff */
    pckt.len = len;
    if (pcktbuff == fill_ses_packet_header(&pckt, pcktbuff,
					   (pcktbuff + SES_HEADER_LEN))) {
      pthread_mutex_unlock(&(ses->mutex));
      if (sent)
	return sent;
      else {
	nbworks_errno = ENOBUFS;
	return -1;
      }
    }

    /* send header */
    notsent = SES_HEADER_LEN;
    while (notsent) {
      ret_val = send(ses->socket, (pcktbuff + (SES_HEADER_LEN - notsent)),
		     notsent, flags);
      if (ret_val <= 0) {
	pthread_mutex_unlock(&(ses->mutex));
	if (ret_val == 0) {
	  return sent;
	} else {
	  if (((errno == EAGAIN) ||
	       (errno == EWOULDBLOCK)) &&
	      sent) {
	    return sent;
	  } else {
	    nbworks_errno = errno;
	    return ret_val;
	  }
	}
      } else {
	notsent = notsent - ret_val;
      }

      handle_timeout;
      handle_cancel;
    }

    /* send data */
    notsent = len;
    while (notsent) {
      ret_val = send(ses->socket, (buff + (len - notsent)),
		     notsent, (flags & (ONES ^ MSG_DONTWAIT)));
      if (ret_val <= 0) {
	/* So, basically, once you commit to a packet, you HAVE to send
	 * the whole thing because failure to do so would desync the stream. */

	if (ret_val == 0) {
	  pthread_mutex_unlock(&(ses->mutex));

	  nbworks_errno = EREMOTEIO;
	  return -1;
	} else {
	  if ((errno == EAGAIN) ||
	      (errno == EWOULDBLOCK)) {
	    handle_timeout;
	    handle_cancel else continue;
	  }
	  pthread_mutex_unlock(&(ses->mutex));

	  nbworks_errno = errno;
	  return ret_val;
	}
      } else {
	notsent = notsent - ret_val;
      }

      handle_timeout;
      handle_cancel;
    }
    /* --> end sending normal stuff */

    pthread_mutex_unlock(&(ses->mutex));
    sent = sent + len;

    return sent;
#undef handle_timeout
#undef handle_cancel

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
}

ssize_t nbworks_recvfrom(unsigned char service,
			 nbworks_session_p sesp,
			 void **buff_pptr,
			 size_t len,
			 int callflags,
			 struct nbworks_nbnamelst **src) {
  struct timespec sleeptime;
  struct packet_cooked *in_lib;
  struct ses_srvc_packet hdr;
  struct nbworks_session *ses;
  time_t start_time, end_time;
  ssize_t recved, notrecved, ret_val, torecv;
  size_t *hndllen_left, len_left;
  int flags, kill_name;
  unsigned char hdrbuff[SES_HEADER_LEN], *walker, *buff;

  ses = sesp;
  if ((! (ses && buff_pptr)) ||
      (len <= 0) ||
      (len >= (SIZE_MAX / 2))) { /* This hack may not work everywhere. */
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    ret_val = 0;

    /* Turn off some flags. */
    flags = callflags & (ONES ^ (MSG_EOR | MSG_PEEK | MSG_ERRQUEUE));
  }

  switch (service) {
  case NBWORKS_DTG_SRVC:
#define handle_dtg_cancel					\
    if (ses->cancel_recv) {					\
      ses->cancel_recv = 0;					\
      nbworks_errno = ECANCELED;				\
      pthread_mutex_unlock(&(ses->handle->dtg_recv_mutex));	\
      return -1;						\
    }
#define handle_dtg_timeout						\
    end_time = start_time + nbworks_libcntl.close_timeout;		\
    if (end_time < start_time)						\
      end_time = INFINITY;						\
    if (end_time < time(0)) {						\
      nbworks_errno = ETIME;						\
      pthread_mutex_unlock(&(ses->handle->dtg_recv_mutex));		\
      return -1;							\
    }

    if (! ses->handle) {
      nbworks_errno = EINVAL;
      return -1;
    } else {
      ret_val = 0;
      sleeptime.tv_sec = 0;
      sleeptime.tv_nsec = T_50MS;
      kill_name = FALSE;
    }

    if ((!(flags & MSG_WAITALL)) &&
	((ses->nonblocking) ||
	 (flags & MSG_DONTWAIT))) {
      if (0 != pthread_mutex_trylock(&(ses->handle->dtg_recv_mutex))) {
	if (errno == EBUSY) {
	  nbworks_errno = EBUSY;
	  return -1;
	} else {
	  nbworks_errno = errno;
	  return -1;
	}
      }
    } else {
      if (0 != pthread_mutex_lock(&(ses->handle->dtg_recv_mutex))) {
	nbworks_errno = errno;
	return -1;
      }
    }
    start_time = time(0);


    in_lib = ses->handle->in_library;
    do {
      if (in_lib) {
	if (in_lib->src) {
	  if (src) {
	    if (*src) {
	      if (0 == nbworks_cmp_nbnodename(*src,
					      in_lib->src)) {
		nbworks_dstr_nbnodename(in_lib->src);
	      } else {
		goto jump_to_next_datagram;
	      }
	    } else {
	      if (ses->peer) {
		if (0 != nbworks_cmp_nbnodename(ses->peer,
						in_lib->src)) {
		  goto jump_to_next_datagram;
		}
	      }
	      if (kill_name)
		nbworks_dstr_nbnodename(*src); /* Plug a memory leak. */
	      *src = in_lib->src;
	      kill_name = TRUE;
	    }
	  } else {
	    /* From now on, we are enforcing multiplexing. */
	    if (ses->peer) {
	      if (0 != nbworks_cmp_nbnodename(ses->peer,
					      in_lib->src)) {
		goto jump_to_next_datagram;
	      }
	    }
	    nbworks_dstr_nbnodename(in_lib->src);
	  }
	  in_lib->src = 0;
	}

	if (in_lib->data) {
	  if (*buff_pptr) {
	    if (len < in_lib->len) {
	      if (flags & MSG_TRUNC) {
		ret_val = in_lib->len;
	      } else {
		ret_val = len;
	      }
	    } else {
	      ret_val = in_lib->len;
	      len = ret_val;
	    }

	    memcpy(*buff_pptr, in_lib->data, len);
	    free(in_lib->data);

	  } else {
	    ret_val = in_lib->len;

	    if (ret_val)
	      *buff_pptr = in_lib->data;
	    else
	      free(in_lib->data);
	  }
	  in_lib->data = 0;
	}

      jump_to_next_datagram:
	if (in_lib->next) {
	  if ((ses->handle->in_library == in_lib) &&
	      (! (in_lib->data &&
		  in_lib->src))) {
	    /* Only move the queue if this datagram has already
	     * been disemboweled. */
	    ses->handle->in_library = in_lib->next;
	    free(in_lib);
	    in_lib = ses->handle->in_library;
	  } else {
	    in_lib = in_lib->next;
	  }
	} else {
	  if (ret_val)
	    break;
	  if (((flags & MSG_DONTWAIT) ||
	       (ses->nonblocking)) &&
	      (! (flags & MSG_WAITALL))) {
	    if (kill_name)
	      nbworks_dstr_nbnodename(*src); /* Plug a leak. */
	    nbworks_errno = EAGAIN;
	    ret_val = -1;
	    break;
	  } else {
	    if (ses->handle->isinconflict) {
	      if (kill_name)
		nbworks_dstr_nbnodename(*src); /* Plug a leak. */
	      nbworks_errno = EPERM;
	      ret_val = -1;
	      break;
	    } else {
	      handle_dtg_timeout;
	      handle_dtg_cancel;
	      nanosleep(&sleeptime, 0);
	      /* don't break */
	    }
	  }
	}
      } else {
	if (((flags & MSG_DONTWAIT) ||
	     (ses->nonblocking)) &&
	    (! (flags & MSG_WAITALL))) {
	  nbworks_errno = EAGAIN;
	  ret_val = -1;
	  break;
	} else {
	  if (ses->handle->isinconflict) {
	    nbworks_errno = EPERM;
	    ret_val = -1;
	    break;
	  } else {
	    handle_dtg_timeout;
	    handle_dtg_cancel;
	    nanosleep(&sleeptime, 0);
	    in_lib = ses->handle->in_library;
	    /* don't break */
	  }
	}
      }
    } while (! ret_val);

    pthread_mutex_unlock(&(ses->handle->dtg_recv_mutex));
    return ret_val;

  case NBWORKS_SES_SRVC:
#define handle_cancel					\
    if (ses->cancel_recv) {				\
      ses->cancel_recv = 0;				\
      close(ses->socket);				\
      ses->socket = -1;					\
      nbworks_errno = ECANCELED;			\
      pthread_mutex_unlock(&(ses->receive_mutex));	\
      return -1;					\
    }
#define handle_timeout							\
    end_time = start_time + nbworks_libcntl.close_timeout;		\
    if (end_time < start_time)						\
      end_time = INFINITY;						\
    if (end_time < time(0)) {						\
      *hndllen_left = *hndllen_left + len_left;				\
      nbworks_errno = ETIME;						\
      pthread_mutex_unlock(&(ses->receive_mutex));			\
      return recved;							\
    }

    /* --> begin setup */
    if (! *buff_pptr) {
      *buff_pptr = malloc(len);
      if (! *buff_pptr) {
	nbworks_errno = ENOMEM;
	return -1;
      }
    }
    buff = *buff_pptr;

    if ((!(flags & MSG_WAITALL)) &&
	((ses->nonblocking) ||
	 (flags & MSG_DONTWAIT))) {
      if (0 != pthread_mutex_trylock(&(ses->receive_mutex))) {
	if (errno == EBUSY) {
	  nbworks_errno = EBUSY;
	  return -1;
	} else {
	  nbworks_errno = errno;
	  return -1;
	}
      }
    } else {
      if (0 != pthread_mutex_lock(&(ses->receive_mutex))) {
	nbworks_errno = errno;
	return -1;
      }
    }

    if (src)
      *src = nbworks_clone_nbnodename(ses->peer);
    start_time = time(0);

    recved = 0;
    notrecved = len;
    if (flags & MSG_OOB) {
      hndllen_left = &(ses->ooblen_left);
    } else {
      hndllen_left = &(ses->len_left);
    }
    len_left = *hndllen_left;
    /* --> end setup */

    while (notrecved) {
      if (len_left) {
	if (*hndllen_left >= notrecved) {
	  len_left = notrecved;
	  *hndllen_left = *hndllen_left - notrecved;
	} else {
	  /* len_left is already set */
	  *hndllen_left = 0;
	}

	if (flags & MSG_OOB) {
	  if (! ses->oob_tmpstor) {
	    nbworks_errno = ENOBUFS;
	    *hndllen_left = 0;
	    pthread_mutex_unlock(&(ses->receive_mutex));
	    return -1;
	  }

	  memcpy(*buff_pptr, (ses->oob_tmpstor + ses->ooblen_offset), len_left);

	  if (*hndllen_left) {
	    ses->ooblen_offset = ses->ooblen_offset + len_left;
	  } else {
	    ses->ooblen_offset = 0;

	    free(ses->oob_tmpstor);
	    ses->oob_tmpstor = 0;
	  }

	  notrecved = notrecved - len_left;
	  len_left = 0;
	} else {
	  do {
	    ret_val = recv(ses->socket, (char *)(buff + (len - notrecved)),
			   len_left, flags);

	    if (ret_val <= 0) {
	      pthread_mutex_unlock(&(ses->receive_mutex));
	      if (ret_val == 0) {
		return recved;
	      } else {
		*hndllen_left = *hndllen_left + len_left;
		if ((errno == EAGAIN) ||
		    (errno == EWOULDBLOCK)) {
		  if (recved)
		    return recved;
		  else {
		    nbworks_errno = EAGAIN;
		    return -1;
		  }
		} else {
		  nbworks_errno = errno;
		  return -1;
		}
	      }
	    }
	    notrecved = notrecved - ret_val;
	    recved = recved + ret_val;
	    len_left = len_left - ret_val;

	    handle_timeout;
	    handle_cancel;
	  } while (len_left);
	}

	if ((callflags & MSG_EOR) ||
	    (! notrecved)) {
	  pthread_mutex_unlock(&(ses->receive_mutex));
	  if (recved)
	    return recved;
	  else {
	    nbworks_errno = EAGAIN;
	    return -1;
	  }
	}
      }

      /* Headers MUST be read en-block. */
      ret_val = recv(ses->socket, hdrbuff, SES_HEADER_LEN,
		     ((flags & (ONES ^ MSG_DONTWAIT)) | MSG_WAITALL));
      if (ret_val < SES_HEADER_LEN) {
	pthread_mutex_unlock(&(ses->receive_mutex));
	if (ret_val == 0) {
	  return recved;
	} else {
	  if ((ret_val == -1) &&
	      ((errno == EAGAIN) ||
	       (errno == EWOULDBLOCK))) {
	    if (recved)
	      return recved;
	    else {
	      nbworks_errno = EAGAIN;
	      return -1;
	    }
	  } else {
	    nbworks_errno = EREMOTEIO;
	    return -1;
	  }
	}
      }
      walker = hdrbuff;
      if (0 == read_ses_srvc_pckt_header(&walker, (hdrbuff + SES_HEADER_LEN),
					 &hdr)) {
	nbworks_errno = EREMOTEIO;
	pthread_mutex_unlock(&(ses->receive_mutex));
	return -1;
      }

      if (hdr.type != SESSION_MESSAGE) {
	if (! ((hdr.type == SESSION_KEEP_ALIVE) ||
	       (hdr.type == POS_SESSION_RESPONSE))) {
	  close(ses->socket);
	  ses->socket = -1;
	  ses->kill_caretaker = TRUE;
	  pthread_mutex_unlock(&(ses->mutex));
	  nbworks_errno = EPROTO;
	  pthread_mutex_unlock(&(ses->receive_mutex));
	  if (recved) {
	    return recved;
	  } else {
	    return -1;
	  }
	}
	if (hdr.len) {
	  ret_val = lib_flushsckt(ses->socket, hdr.len, flags);
	  if (ret_val <= 0) {
	    /* nbworks_errno is set */
	    pthread_mutex_unlock(&(ses->receive_mutex));
	    return ret_val;
	  }
	}
	/* no timeouts here */
	handle_cancel else continue;
      }
      if (hdr.len > notrecved) {
	*hndllen_left = hdr.len - notrecved;
	len_left = notrecved;
      } else {
	len_left = hdr.len;
	if (len_left == 0) {
	  if ((! (flags & MSG_WAITALL)) &&
	      ((ses->nonblocking) ||
	       (flags & MSG_DONTWAIT))) {
	    pthread_mutex_unlock(&(ses->receive_mutex));
	    if (recved)
	      return recved;
	    else {
	      nbworks_errno = EAGAIN;
	      return -1;
	    }
	  } else {
	    handle_timeout;
	    handle_cancel;
	  }
	}
      }
      while (len_left) {
	ret_val = recv(ses->socket, (char *)(buff + (len - notrecved)),
		       len_left, flags);
	if (ret_val <= 0) {
	  if (ret_val == 0) {
	    pthread_mutex_unlock(&(ses->receive_mutex));
	    return recved;
	  } else {
	    *hndllen_left = *hndllen_left + len_left;
	    if ((errno == EAGAIN) ||
		(errno == EWOULDBLOCK)) {
	      if (flags & MSG_OOB)
		break; /* and enter the below if block */
	      pthread_mutex_unlock(&(ses->receive_mutex));
	      if (recved)
		return recved;
	      else {
		nbworks_errno = EAGAIN;
		return -1;
	      }
	    } else {
	      nbworks_errno = errno;
	      pthread_mutex_unlock(&(ses->receive_mutex));
	      return -1;
	    }
	  }
	}

	len_left = len_left - ret_val;
	notrecved = notrecved - ret_val;
	recved = recved + ret_val;

	if (! (flags & MSG_OOB)) {
	  handle_timeout;
	} else {
	  end_time = start_time + nbworks_libcntl.close_timeout;
	  if (end_time < start_time)
	    end_time = INFINITY;
	  if (end_time < time(0)) {
	    *hndllen_left = *hndllen_left + len_left;
	    break; /* and enter the below if block */
	  }
	}
	handle_cancel;
      }

      if ((flags & MSG_OOB) &&
	  (*hndllen_left)) {
	len_left = *hndllen_left;
	torecv = len_left;

	ses->oob_tmpstor = malloc(len_left);
	if (! ses->oob_tmpstor) {
	  /* Emergency! The stream is about to get desynced. */
	  nbworks_errno = ENOBUFS;
	  pthread_mutex_unlock(&(ses->receive_mutex));
	  return recved;
	}
	ses->ooblen_offset = 0;

	while (len_left) {
	  ret_val = recv(ses->socket, (ses->oob_tmpstor +(torecv - len_left)),
			 len_left, flags);
	  if (ret_val <= 0) {
	    if (ret_val == 0) {
	      pthread_mutex_unlock(&(ses->receive_mutex));
	      return recved;
	    } else {
	      if ((errno == EAGAIN) ||
		  (errno == EWOULDBLOCK)) {
		/* no timeouts here */
		handle_cancel else continue;
	      } else {
		nbworks_errno = errno;
		pthread_mutex_unlock(&(ses->receive_mutex));
		return -1;
	      }
	    }
	  }

	  len_left = len_left - ret_val;
	  torecv = torecv - ret_val;

	  /* no timeouts here */
	  handle_cancel;
	}
      }

      if (callflags & MSG_EOR) {
	pthread_mutex_unlock(&(ses->receive_mutex));
	if (recved)
	  return recved;
	else {
	  nbworks_errno = EAGAIN;
	  return -1;
	}
      }

    }

    pthread_mutex_unlock(&(ses->receive_mutex));
    return recved;
#undef handle_timeout
#undef handle_cancel

  default:
    nbworks_errno = EINVAL;
    return -1;
  }
}

ssize_t nbworks_recvwait(nbworks_session_p session,
			 void **buff_pptr,
			 size_t len,
			 int callflags,
			 int timeout,
			 struct nbworks_nbnamelst **src) {
  struct timespec sleeptime;
  struct nbworks_session *ses;
  ssize_t ret_val;
  long waitsteps;
  int flags, kill_name;
  time_t start_time, end_time;
  struct packet_cooked *in_lib;

  ses = session;
  if ((! (session && buff_pptr)) ||
      (len <= 0) ||
      (len >= (SIZE_MAX / 2))) { /* This hack may not work everywhere. */
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
    ret_val = 0;
    kill_name = FALSE;

    /* Turn off some flags. */
    flags = callflags & (ONES ^ (MSG_EOR | MSG_PEEK | MSG_ERRQUEUE));
  }

#define handle_dtg_cancel					\
  if (ses->cancel_recv) {					\
    ses->cancel_recv = 0;					\
    nbworks_errno = ECANCELED;					\
    pthread_mutex_unlock(&(ses->handle->dtg_recv_mutex));	\
    return -1;							\
  }
#define handle_dtg_timeout						\
  end_time = start_time + nbworks_libcntl.close_timeout;		\
  if (end_time < start_time)						\
    end_time = INFINITY;						\
  if (end_time < time(0)) {						\
    nbworks_errno = ETIME;						\
    pthread_mutex_unlock(&(ses->handle->dtg_recv_mutex));		\
    return -1;							\
  }

  if (! ses->handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    sleeptime.tv_sec = 0;
    sleeptime.tv_nsec = T_12MS;
  }
  if (timeout > 0) {
    waitsteps = timeout / 12;
    if (timeout % 12) {
      waitsteps++;
    }
  } else {
    if (timeout == 0) {
      waitsteps = 0;
    } else {
      waitsteps = -1;
    }
  }

  if ((!(flags & MSG_WAITALL)) &&
      ((ses->nonblocking) ||
       (flags & MSG_DONTWAIT))) {
    if (0 != pthread_mutex_trylock(&(ses->handle->dtg_recv_mutex))) {
      if (errno == EBUSY) {
	nbworks_errno = EBUSY;
	return -1;
      } else {
	nbworks_errno = errno;
	return -1;
      }
    }
  } else {
    if (0 != pthread_mutex_lock(&(ses->handle->dtg_recv_mutex))) {
      nbworks_errno = errno;
      return -1;
    }
  }
  start_time = time(0);

  in_lib = ses->handle->in_library;
  do {
    if (in_lib) {
      if (in_lib->src) {
	if (src) {
	  if (*src) {
	    if (0 == nbworks_cmp_nbnodename(*src,
					    in_lib->src)) {
	      nbworks_dstr_nbnodename(in_lib->src);
	    } else {
	      goto jump_to_next_datagram;
	    }
	  } else {
	    if (ses->peer) {
	      if (0 != nbworks_cmp_nbnodename(ses->peer,
					      in_lib->src)) {
		goto jump_to_next_datagram;
	      }
	    }
	    if (kill_name)
	      nbworks_dstr_nbnodename(*src); /* Plug a memory leak. */
	    *src = in_lib->src;
	    kill_name = TRUE;
	  }
	} else {
	  /* From now on, we are enforcing multiplexing. */
	  if (ses->peer) {
	    if (0 != nbworks_cmp_nbnodename(ses->peer,
					    in_lib->src)) {
	      goto jump_to_next_datagram;
	    }
	  }
	  nbworks_dstr_nbnodename(in_lib->src);
	}
	in_lib->src = 0;
      }

      if (in_lib->data) {
	if (*buff_pptr) {
	  if (len < in_lib->len) {
	    if (flags & MSG_TRUNC) {
	      ret_val = in_lib->len;
	    } else {
	      ret_val = len;
	    }
	  } else {
	    ret_val = in_lib->len;
	    len = ret_val;
	  }

	  memcpy(*buff_pptr, in_lib->data, len);
	  free(in_lib->data);

	} else {
	  ret_val = in_lib->len;

	  if (ret_val)
	    *buff_pptr = in_lib->data;
	  else
	    free(in_lib->data);
	}
	in_lib->data = 0;
      }

    jump_to_next_datagram:
      if (in_lib->next) {
	if ((ses->handle->in_library == in_lib) &&
	    (! (in_lib->data &&
		in_lib->src))) {
	  /* Only move the queue if this datagram has already
	   * been disemboweled. */
	  ses->handle->in_library = in_lib->next;
	  free(in_lib);
	  in_lib = ses->handle->in_library;
	} else {
	  in_lib = in_lib->next;
	}
      } else {
	if (ret_val)
	  break;
	if ((! (flags & MSG_WAITALL)) &&
	    (flags & MSG_DONTWAIT)) {
	  nbworks_errno = EAGAIN;
	  ret_val = -1;
	  if (kill_name)
	    nbworks_dstr_nbnodename(*src); /* Plug a leak. */
	  break;
	} else {
	  if (ses->handle->isinconflict) {
	    nbworks_errno = EPERM;
	    ret_val = -1;
	    if (kill_name)
	      nbworks_dstr_nbnodename(*src); /* Plug a leak. */
	    break;
	  } else {
	    handle_dtg_timeout;
	    handle_dtg_cancel;
	    nanosleep(&sleeptime, 0);

	    if (waitsteps > 0) {
	      waitsteps--;
	    }
	    /* don't break */
	  }
	}
      }
    } else {
      if ((! (flags & MSG_WAITALL)) &&
	  (flags & MSG_DONTWAIT)) {
	nbworks_errno = EAGAIN;
	ret_val = -1;
	break;
      } else {
	if (ses->handle->isinconflict) {
	  nbworks_errno = EPERM;
	  ret_val = -1;
	  break;
	} else {
	  handle_dtg_timeout;
	  handle_dtg_cancel;
	  nanosleep(&sleeptime, 0);

	  if (waitsteps > 0) {
	    waitsteps--;
	  }
	  in_lib = ses->handle->in_library;
	  /* don't break */
	}
      }
    }
  } while ((! ret_val) &&
	   (waitsteps != 0));

  pthread_mutex_unlock(&(ses->handle->dtg_recv_mutex));
  if ((ret_val == 0) &&
      (waitsteps == 0) &&
      (kill_name == FALSE)) {
    /* Entering this means nothing happened. EXCEPT! That an empty
     * datagram will look just like this too. And because it is
     * indistiguishable from an empty exit, I need to do things
     * like this. Also: I *HATE* that kill_name kludge! */
    ret_val = -1;
    nbworks_errno = EAGAIN;
  }
  return ret_val;
}

void nbworks_cancel(nbworks_session_p sesp,
		    unsigned char what) {
  struct nbworks_session *ses;

  ses = sesp;
  if (! ses) {
    nbworks_errno = EINVAL;
    return;
  } else {
    nbworks_errno = 0;
  }

  if (what & NBWORKS_CANCEL_SEND) {
    ses->cancel_send = TRUE;
  }
  if (what & NBWORKS_CANCEL_RECV) {
    ses->cancel_recv = TRUE;
  }

  return;
}


/* returns: >0 = success, 0 = fail, <0 = error */
int nbworks_haltsrv(unsigned int service,
		    nbworks_namestate_p namehandle) {
  struct name_state *handle;

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  } else {
    nbworks_errno = 0;
  }

  switch (service) {
  case NBWORKS_DTG_SRVC:
    handle->dtg_srv_stop = TRUE;
    pthread_join(handle->dtg_srv_tid, 0);
    handle->dtg_srv_tid = 0;
    break;

  case NBWORKS_SES_SRVC:
    handle->ses_srv_stop = TRUE;
    pthread_join(handle->ses_srv_tid, 0);
    handle->ses_srv_tid = 0;
    break;

  default:
    nbworks_errno = EINVAL;
    return -1;
  }

  return 1;
}

void nbworks_hangup_ses(nbworks_session_p sesp) {
  struct nbworks_session *ses;

  ses = sesp;
  if (! ses)
    return;

  if (ses->socket >= 0)
    close(ses->socket);

  if (ses->caretaker_tid) {
    ses->kill_caretaker = TRUE;

    pthread_join(ses->caretaker_tid, 0);
  }

  pthread_mutex_destroy(&(ses->mutex));
  pthread_mutex_destroy(&(ses->receive_mutex));

  if (ses->peer)
    nbworks_dstr_nbnodename(ses->peer);
  if (ses->oob_tmpstor)
    free(ses->oob_tmpstor);
  free(ses);

  return;
}


#define NUMOF_NODETYPES 8
const node_type_t nbworks_nodetype_templates[NUMOF_NODETYPES][2] = {
  {CACHE_NODEFLG_B, RAIL_NODET_BUNQ}, {CACHE_NODEFLG_P, RAIL_NODET_PUNQ},
  {CACHE_NODEFLG_M, RAIL_NODET_MUNQ}, {CACHE_NODEFLG_H, RAIL_NODET_HUNQ},
  {CACHE_NODEGRPFLG_B, RAIL_NODET_BGRP}, {CACHE_NODEGRPFLG_P, RAIL_NODET_PGRP},
  {CACHE_NODEGRPFLG_M, RAIL_NODET_MGRP}, {CACHE_NODEGRPFLG_H, RAIL_NODET_HGRP}};

unsigned long nbworks_whatisIP4addrX(struct nbworks_nbnamelst *X,
				     unsigned char node_types,
				     unsigned char isgroup,
				     unsigned long len) {
  struct com_comm command, answer;
  ipv4_addr_t result;
  int daemon_sckt;
  enum rail_commands cur_command;
  node_type_t real_node_types, node_type_walker, bullshit;
  unsigned char combuff[LEN_COMM_ONWIRE], *buff, cur_node_type;

  if ((! (X && node_types)) ||
      (X->len != NETBIOS_NAME_LEN)) {
    nbworks_errno = EINVAL;
    return 0;
  } else {
    nbworks_errno = 0;
  }

  result = 0;
  node_type_walker = 0;
  cur_node_type = 0;

  memset(&command, 0, sizeof(struct com_comm));

  real_node_types = 0;
  if (node_types & NBWORKS_NODE_B)
    real_node_types |= CACHE_NODEFLG_B;
  if (node_types & NBWORKS_NODE_P)
    real_node_types |= CACHE_NODEFLG_P;
  if (node_types & NBWORKS_NODE_M)
    real_node_types |= CACHE_NODEFLG_M;
  if (node_types & NBWORKS_NODE_H)
    real_node_types |= CACHE_NODEFLG_H;

  if (isgroup) {
    real_node_types = real_node_types << GROUP_SHIFT;
    cur_command = rail_addr_ofXgroup;
  } else {
    cur_command = rail_addr_ofXuniq;
  }
  command.command = cur_command;

  if ((len < (1+NETBIOS_NAME_LEN+1)) ||
      (len > (uint32_t)ONES)) {
  no_bullshit_please:
    len = nbworks_nbnodenamelen(X);
    bullshit = FALSE;
  } else {
    bullshit = TRUE;
  }
  command.len = len;

  buff = malloc(len);
  if (! buff) {
    nbworks_errno = ENOBUFS;
    return 0;
  }

  if (buff == fill_all_DNS_labels(X, buff, (buff +len), 0)) {
    free(buff);

    if (bullshit) {
      goto no_bullshit_please;
    } else {
      nbworks_errno = ENOBUFS;
      return 0;
    }
  }

  daemon_sckt = lib_daemon_socket();
  if (daemon_sckt == -1) {
    free(buff);
    nbworks_errno = EPIPE;
    return 0;
  }

  while (real_node_types) {
    for (; node_type_walker < NUMOF_NODETYPES; node_type_walker++) {
      if (real_node_types &
	  (nbworks_nodetype_templates[node_type_walker][0])) {

	cur_node_type = nbworks_nodetype_templates[node_type_walker][1];

	real_node_types = real_node_types &
	  (~nbworks_nodetype_templates[node_type_walker][0]);

	break;
      }
    }
    if (! (node_type_walker < NUMOF_NODETYPES)) {
      break;
    } else {
      node_type_walker++; /* To speed up for-loop walking. */
    }
    command.node_type = cur_node_type;

    fill_railcommand(&command, combuff, (combuff +LEN_COMM_ONWIRE));

    if (LEN_COMM_ONWIRE > send(daemon_sckt, combuff,
			       LEN_COMM_ONWIRE, MSG_NOSIGNAL)) {
      close(daemon_sckt);
      free(buff);
      nbworks_errno = EPIPE;
      return 0;
    }

    if (len > send(daemon_sckt, buff, len, MSG_NOSIGNAL)) {
      close(daemon_sckt);
      free(buff);
      nbworks_errno = EPIPE;
      return 0;
    }


    if (LEN_COMM_ONWIRE > recv(daemon_sckt, combuff,
			       LEN_COMM_ONWIRE, MSG_WAITALL)) {
      close(daemon_sckt);
      free(buff);
      nbworks_errno = EPIPE;
      return 0;
    }

    if (0 == read_railcommand(combuff, (combuff +LEN_COMM_ONWIRE),
			      &answer)) {
      close(daemon_sckt);
      free(buff);
      nbworks_errno = ENOBUFS;
      return 0;
    }

    if (answer.command != cur_command) {
      close(daemon_sckt);
      free(buff);
      nbworks_errno = EPIPE; /* What do I put here? */
      return 0;
    }

    if (answer.nbworks_errno)
      continue;

    if ((answer.len < 4) ||
	(answer.node_type != cur_node_type)) {
      close(daemon_sckt);
      free(buff);
      nbworks_errno = EPIPE; /* What do I put here? */
      return 0;
    }

    if (4 > recv(daemon_sckt, combuff, 4, MSG_WAITALL)) {
      close(daemon_sckt);
      free(buff);
      nbworks_errno = EPIPE;
      return 0;
    } else {
      read_32field(combuff, &result);
      break;
    }
  }

  close(daemon_sckt);
  free(buff);

  return result;
}
#undef NUMOF_NODETYPES

/* returns: >0 = yes; 0 = no; <0 = error */
int nbworks_isinconflict(nbworks_namestate_p namehandle) {
  struct com_comm command;
  struct name_state *handle;
  int daemon, guarded;
  unsigned char buff[LEN_COMM_ONWIRE];

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  }

  if (handle->guard_rail < 0) {
  open_unguarded_rail:
    guarded = FALSE;
    daemon = lib_daemon_socket();
    if (daemon < 0) {
      nbworks_errno = EPIPE;
      return -1;
    }
  } else {
    if (0 != pthread_mutex_trylock(&(handle->guard_mutex)))
      goto open_unguarded_rail;
    guarded = TRUE;
    daemon = handle->guard_rail;
  }

  memset(&command, 0, sizeof(command));
  command.command = rail_isinconflict;
  command.token = handle->token;

  fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE));
  if (LEN_COMM_ONWIRE > send(daemon, buff, LEN_COMM_ONWIRE,
			     MSG_NOSIGNAL)) {
    if (! guarded)
      close(daemon);
    else
      pthread_mutex_unlock(&(handle->guard_mutex));
    nbworks_errno = EPIPE;
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(daemon, buff, LEN_COMM_ONWIRE,
			     MSG_WAITALL)) {
    if (! guarded)
      close(daemon);
    else
      pthread_mutex_unlock(&(handle->guard_mutex));
    nbworks_errno = EPIPE;
    return -1;
  }

  if (! read_railcommand(buff, (buff + LEN_COMM_ONWIRE), &command)) {
    if (! guarded)
      close(daemon);
    else
      pthread_mutex_unlock(&(handle->guard_mutex));
    nbworks_errno = ENOBUFS;
    return -1;
  }

  if (! guarded)
    close(daemon);
  else {
    if (command.len)
      rail_flushrail(command.len, daemon);
    pthread_mutex_unlock(&(handle->guard_mutex));
  }

  if (!((command.command == rail_isinconflict) &&
	(command.token == handle->token))) {
    nbworks_errno = EPROTO;
    return -1;
  }

  if (command.nbworks_errno) {
    handle->isinconflict = TRUE;
    return 1;
  } else {
    handle->isinconflict = FALSE;
    return 0;
  }
}


/* returns: >0 = success, 0 = fail, <0 = error */
int nbworks_setsignal(nbworks_namestate_p namehandle,
		      int signal) {
  struct com_comm command;
  struct name_state *handle;
  int64_t transit;
  pid_t pid;
  int rail, isguarded;
  unsigned char buff[LEN_COMM_ONWIRE+(8*2)];

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  }

  memset(&command, 0, sizeof(struct com_comm));

  command.command = rail_setsignal;
  command.token = handle->token;
  command.len = (8*2);
  if (buff >= fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE))) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  pid = getpid();
  transit = pid;
  fill_64field((uint64_t)transit, (buff + LEN_COMM_ONWIRE));
  transit = signal;
  fill_64field((uint64_t)transit, (buff + LEN_COMM_ONWIRE+8));

  if (!(handle->guard_rail < 0)) {
    if (0 != pthread_mutex_trylock(&(handle->guard_mutex))) {
      goto regular_socket;
    } else {
      isguarded = TRUE;
      rail = handle->guard_rail;
    }
  } else {
  regular_socket:
    isguarded = FALSE;
    rail = lib_daemon_socket();
    if (rail < 0) {
      nbworks_errno = EPIPE;
      return -1;
    }
  }

  if ((LEN_COMM_ONWIRE+(8*2)) > send(rail, buff,
				     (LEN_COMM_ONWIRE+(8*2)), 0)) {
    if (isguarded) {
      pthread_mutex_unlock(&(handle->guard_mutex));
    } else {
      close(rail);
    }
    nbworks_errno = EPIPE;
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(rail, buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
    if (isguarded) {
      pthread_mutex_unlock(&(handle->guard_mutex));
    } else {
      close(rail);
    }
    nbworks_errno = EPIPE;
    return -1;
  }

  if (! read_railcommand(buff, (buff + LEN_COMM_ONWIRE), &command)) { 
    if (isguarded) {
      pthread_mutex_unlock(&(handle->guard_mutex));
    } else {
      close(rail);
    }
    nbworks_errno = ENOBUFS;
    return -1;
  }

  if (isguarded) {
    if (command.len)
      rail_flushrail(command.len, rail);
    pthread_mutex_unlock(&(handle->guard_mutex));
  } else {
    close(rail);
  }

  if ((command.command != rail_setsignal) ||
      (command.token != handle->token)) {
    nbworks_errno = EPROTO;
    return -1;
  }

  if (command.nbworks_errno) {
    nbworks_errno = command.nbworks_errno;
    return 0;
  } else {
    nbworks_errno = 0;
    return 1;
  }
}

/* returns: >0 = success, 0 = fail, <0 = error */
int nbworks_rmsignal(nbworks_namestate_p namehandle) {
  struct com_comm command;
  struct name_state *handle;
  int rail, isguarded;
  unsigned char buff[LEN_COMM_ONWIRE];

  handle = namehandle;
  if (! handle) {
    nbworks_errno = EINVAL;
    return -1;
  }

  memset(&command, 0, sizeof(struct com_comm));

  command.command = rail_rmsignal;
  command.token = handle->token;
  if (buff >= fill_railcommand(&command, buff, (buff+LEN_COMM_ONWIRE))) {
    nbworks_errno = ENOBUFS;
    return -1;
  }

  if (!(handle->guard_rail < 0)) {
    if (0 != pthread_mutex_trylock(&(handle->guard_mutex))) {
      goto regular_socket;
    } else {
      isguarded = TRUE;
      rail = handle->guard_rail;
    }
  } else {
  regular_socket:
    isguarded = FALSE;
    rail = lib_daemon_socket();
    if (rail < 0) {
      nbworks_errno = EPIPE;
      return -1;
    }
  }

  if (LEN_COMM_ONWIRE > send(rail, buff, LEN_COMM_ONWIRE, 0)) {
    if (isguarded) {
      pthread_mutex_unlock(&(handle->guard_mutex));
    } else {
      close(rail);
    }
    nbworks_errno = EPIPE;
    return -1;
  }

  if (LEN_COMM_ONWIRE > recv(rail, buff, LEN_COMM_ONWIRE, MSG_WAITALL)) {
    if (isguarded) {
      pthread_mutex_unlock(&(handle->guard_mutex));
    } else {
      close(rail);
    }
    nbworks_errno = EPIPE;
    return -1;
  }

  if (! read_railcommand(buff, (buff + LEN_COMM_ONWIRE), &command)) { 
    if (isguarded) {
      pthread_mutex_unlock(&(handle->guard_mutex));
    } else {
      close(rail);
    }
    nbworks_errno = ENOBUFS;
    return -1;
  }

  if (isguarded) {
    if (command.len)
      rail_flushrail(command.len, rail);
    pthread_mutex_unlock(&(handle->guard_mutex));
  } else {
    close(rail);
  }

  if ((command.command != rail_rmsignal) ||
      (command.token != handle->token)) {
    nbworks_errno = EPROTO;
    return -1;
  }

  if (command.nbworks_errno) {
    nbworks_errno = command.nbworks_errno;
    return 0;
  } else {
    nbworks_errno = 0;
    return 1;
  }
}


void *nbworks_emergencyfix_func1(void *arg) {
  return arg;
}

void *nbworks_emergencyfix_func2(void *arg) {
  return arg;
}

void *nbworks_emergencyfix_func3(void *arg) {
  return arg;
}

void *nbworks_emergencyfix_func4(void *arg) {
  return arg;
}
