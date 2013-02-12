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

struct dtg_frag {
  uint32_t offset;
  uint32_t len;
  void *data;
  struct dtg_frag *next;
};

struct dtg_frag_bckbone {
  uint16_t id;
  time_t last_active;
  struct nbnodename_list *src;
  struct dtg_frag *frags;
  struct dtg_frag_bckbone *next;
};

struct name_state {
/* identification */
  uint64_t token;
  struct nbnodename_list *name;
  struct nbnodename_list *scope;

/* datagram server */
  pthread_t dtg_srv_tid;
  int dtg_srv_sckt;
  struct nbnodename_list *dtg_listento;
  unsigned char dtg_takes;  /* flag field */
  unsigned char dtg_srv_stop;
  struct dtg_frag_bckbone *dtg_frags;
  struct packet_cooked *in_server;
  struct packet_cooked *in_library;

/* session taker server */
  pthread_t ses_srv_tid;
  int ses_srv_sckt;
  struct nbnodename_list *ses_listento;
  unsigned char ses_takes;  /* flag field */
  unsigned char ses_srv_stop;
  struct nbworks_session *sesin_server;
  struct nbworks_session *sesin_library;

/* metadata for the name and scope */
  short lenof_scope; /* the amount of octets the encoded scope takes,
                      * incl. the terminating NULL in the packet */
  unsigned char label_type; /* the type octet of the name */
  unsigned char node_type;  /* flag field */
  unsigned char isgroup;

/* maybe we will daysie-chain them */
  struct name_state *next;
};

struct nbworks_session {
  struct nbnodename_list *peer; /* name + scope */
  struct name_state *handle;    /* pointer back to the whole name_handle */
  unsigned char kill_caretaker;
  unsigned char keepalive;
  unsigned char nonblocking;    /* TRUE by default */
  int socket;
  size_t len_left;
  size_t ooblen_left;
  size_t ooblen_offset;
  void *oob_tmpstor;
  pthread_mutex_t mutex;
  pthread_t caretaker_tid;
  struct nbworks_session *next;
};

union nbworks_handle {
  struct name_state *dtg;
  struct nbworks_session *ses;
};

void
  lib_init();

/* returns: >0 = success, 0 = fail, <0 = error */
int
  lib_start_dtg_srv(struct name_state *handle,
                    unsigned char takes_field,
                    struct nbnodename_list *listento);
/* returns: >0 = success, 0 = fail, <0 = error */
int
  lib_start_ses_srv(struct name_state *handle,
                    unsigned char takes_field,
                    struct nbnodename_list *listento);

void
  lib_dstry_packets(struct packet_cooked *forkill);

void
  lib_destroy_frags(struct dtg_frag *flesh);
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
void *
  lib_assemble_frags(struct dtg_frag *frags,
                     uint32_t len);

/* returns: TRUE (AKA 1) = YES, listens to,
            FALSE (AKA 0) = NO, doesn't listen to */
unsigned int
  lib_doeslistento(struct nbnodename_list *query,
                   struct nbnodename_list *answerlist);

uint32_t
  lib_whatisaddrX(struct nbnodename_list *X,
                  unsigned int len);
int
  lib_daemon_socket();

ssize_t
  lib_senddtg_138(struct name_state *handle,
                  unsigned char *recepient,
                  unsigned char recepient_type,
                  void *data,
                  size_t len,
                  unsigned char isgroup,
                  unsigned char isbroadcast);

void *
  lib_dtgserver(void *arg);

int
  lib_open_session(struct name_state *handle,
                   struct nbnodename_list *dst);
void *
  lib_ses_srv(void *arg);

void *
  lib_caretaker(void *arg);
struct nbworks_session *
  lib_make_session(int socket,
                   struct nbnodename_list *caller,
                   struct name_state *handle,
                   unsigned char keepalive);
void
  lib_dstry_sesslist(struct nbworks_session *ses);
void
  lib_dstry_session(struct nbworks_session *ses);

ssize_t
  lib_flushsckt(int socket,
                ssize_t len,
                int flags);

#endif /* NBWORKS_LIBRARY_H */
