#ifndef NBWORKS_API_H
# define NBWORKS_API_H 1

int nbworks_errno;

struct nbworks_pollfd {
  struct name_state *handle;
  struct nbworks_session *session;
  short int events;
  short int revents;
};

int
  nbworks_sespoll(struct nbworks_pollfd *sessions,
                  int numof_sess,
                  int timeout);
int
  nbworks_dtgpoll(struct nbworks_pollfd *handles,
                  int numof_dtgs,
                  int timeout);

ssize_t
  nbworks_send(unsigned char service,
               void *handle,
               void *buff,
               size_t len,
               int flags);

#endif /* NBWORKS_API_H */
