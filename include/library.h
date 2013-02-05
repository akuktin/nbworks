#ifndef NBWORKS_LIBRARY_H
# define NBWORKS_LIBRARY_H 1

# include <pthread.h>

# include "nodename.h"
# include "name_srvc_cache.h"
# include "dtg_srvc_pckt.h"

# define HANDLE_TAKES_ALLBRDCST 0x01
# define HANDLE_TAKES_ALLUNCST  0x02
# define HANDLE_TAKES_ALL       0x03

struct packet_cooked {
  void *data;
  uint32_t len;
  struct nbnodename_list *src;
  struct packet_cooked *next;
};

struct name_state {
  uint64_t token;
  struct nbnodename_list *name;
  struct nbnodename_list *scope;

  pthread_t dtg_srv_tid;
  int dtg_srv_sckt;
  struct nbnodename_list *dtg_listento;
  unsigned char dtg_takes;  /* flag field */
  unsigned char dtg_srv_stop;
  struct dtg_frag_bckbone *dtg_frags;
  struct packet_cooked *in_server;
  struct packet_cooked *in_library;

  pthread_t ses_srv_tid;
  int ses_srv_sckt;
  struct nbnodename_list *ses_listento;
  unsigned char ses_takes;  /* flag field */
  unsigned char ses_srv_stop;

  short lenof_scope; /* the amount of octets the encoded scope takes,
                      * incl. the terminating NULL in the packet */
  unsigned char label_type; /* the type octet of the name */
  unsigned char node_type;  /* flag field */
  struct name_state *next;
};


void
  lib_init();

int
  lib_start_dtg_srv(struct name_state *handle,
                    unsigned char takes_field,
                    struct nbnodename_list *listento);

void
  lib_destroy_frag(struct dtg_frag *flesh);
void
  lib_destroy_fragbckbone(struct dtg_frag_bckbone *bone);
struct dtg_frag_bckbone *
  lib_add_fragbckbone(uint16_t id,
                      struct nbnodename_list *src,
                      uint16_t offsetof_first,
                      uint16_t lenof_first,
                      void *first_data,
                      struct dtg_frag_bckbone **frags);
struct dtg_frag_bckbone *
  lib_find_fragbckbone(uint16_t id,
                       struct nbnodename_list *src,
                       struct dtg_frag_bckbone *frags);
struct dtg_frag_bckbone *
  lib_take_fragbckbone(uint16_t id,
                       struct nbnodename_list *src,
                       struct dtg_frag_bckbone **frags);
void
  lib_del_fragbckbone(uint16_t id,
                      struct nbnodename_list *src,
                      struct dtg_frag_bckbone **frags);
struct dtg_frag_bckbone *
  lib_add_frag_tobone(uint16_t id,
                      struct nbnodename_list *src,
                      uint16_t offset,
                      uint16_t len,
                      void *data,
                      struct dtg_frag_bckbone *frags);
struct dtg_frag *
  lib_order_frags(struct dtg_frag *frags,
                  uint32_t *len);

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

int
  lib_recvdtg(struct name_state *handle,
              void *buff,
              int lenof_buff);

void
  lib_dstry_packets(struct packet_cooked *forkill);

void *
  lib_dtgserver(void *arg);

#endif /* NBWORKS_LIBRARY_H */
