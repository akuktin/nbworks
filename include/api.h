#ifndef NBWORKS_API_H
# define NBWORKS_API_H 1

struct nbworks_pollfd {
  struct name_state *handle;
  struct nbworks_session *session;
  short int events;
  short int revents;
};

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

#endif /* NBWORKS_API_H */
