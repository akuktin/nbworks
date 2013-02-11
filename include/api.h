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
  nbworks_send(unsigned char service,
               struct nbworks_session *ses,
               void *buff,
               size_t len,
               int flags);

ssize_t
  nbworks_recv(unsigned char service,
               struct nbworks_session *ses,
               void **buff,
               size_t len,
               int callflags);

#endif /* NBWORKS_API_H */
