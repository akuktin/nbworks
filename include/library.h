#ifndef NBWORKS_LIBRARY_H
# define NBWORKS_LIBRARY_H 1

# include "nodename.h"
# include "name_srvc_cache.h"

struct name_state {
  uint64_t token;
  struct nbnodename_list *name;
  struct nbnodename_list *scope;
  int dtg_srv_sckt;
  int ses_srv_sckt;
  short lenof_scope; /* the amount of octets the encoded scope takes,
                      * incl. the terminating NULL in the packet */
  unsigned char label_type; /* the type octet of the name */
  unsigned char node_type;  /* flag field */
};

int
  lib_daemon_socket();

int
  lib_senddtg_138(struct name_state *handle,
                  unsigned char *recepient,
                  unsigned char recepient_type,
                  void *data,
                  unsigned int len,
                  unsigned char isgroup,
                  unsigned char isbroadcast);

#endif /* NBWORKS_LIBRARY_H */
