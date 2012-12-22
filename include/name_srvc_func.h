#ifndef NBWORKS_NAMESRVCFUNC_H
# define NBWORKS_NAMESRVCFUNC_H 1

struct name_srvc_packet *
  name_srvc_make_name_registration(unsigned char *name,
                                   unsigned char name_type,
                                   struct nbnodename_list *scope,
                                   uint32_t ttl,
                                   uint32_t in_address,
                                   int isgroup,
                                   unsigned char node_type);

#endif /* NBWORKS_NAMESRVCFUNC_H */
