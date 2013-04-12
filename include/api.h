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

#ifndef NBWORKS_API_H
# define NBWORKS_API_H 1

# define NBWORKS_CANCEL_SEND 1
# define NBWORKS_CANCEL_RECV 2

struct nbworks_pollfd {
  struct name_state *handle;
  struct nbworks_session *session;
  short int events;
  short int revents;
};

void nbworks_libinit(void);

struct name_state *
  nbworks_regname(unsigned char *name,
                  unsigned char name_type,
                  struct nbnodename_list *scope,
                  unsigned char group_flg,
                  unsigned char node_type, /* only one type */
                  uint32_t ttl);
/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_delname(struct name_state *handle);

/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_listen_dtg(struct name_state *handle,
                     unsigned char takes_field,
                     struct nbnodename_list *listento);
/* returns: >0 = success, 0 = fail, <0 = error */
int
  nbworks_listen_ses(struct name_state *handle,
                     unsigned char takes_field,
                     struct nbnodename_list *listento);
struct nbworks_session *
  nbworks_accept_ses(struct name_state *handle);
struct nbworks_session *
  nbworks_sescall(struct name_state *handle,
                  struct nbnodename_list *dst,
                  unsigned char keepalive);

int
  nbworks_poll(unsigned char service,
               struct nbworks_pollfd *handles,
               int numof_sess,
               int timeout);

ssize_t
  nbworks_sendto(unsigned char service,
                 struct nbworks_session *ses,
                 void *buff,
                 size_t len,
                 int flags,
                 struct nbnodename_list *dst);
# define nbworks_send(a, b, c, d, e) nbworks_sendto(a, b, c, d, e, 0)
ssize_t
  nbworks_recvfrom(unsigned char service,
                   struct nbworks_session *ses,
                   void **buff,
                   size_t len,
                   int callflags,
                   struct nbnodename_list **src);
# define nbworks_recv(a, b, c, d, e) nbworks_recvfrom(a, b, c, d, e, 0)
void
  nbworks_cancel(struct nbworks_session *ses,
                 unsigned char what);

void
  nbworks_hangup_ses(struct nbworks_session *ses);
# define nbworks_destroy_ses(a) nbworks_hangup_ses(a)

uint32_t
  nbworks_whatisaddrX(struct nbnodename_list *X,
                      unsigned int len);


#endif /* NBWORKS_API_H */
