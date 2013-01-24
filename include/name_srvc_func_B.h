#ifndef NBWORKS_NAMESRVCFUNCB_H
# define NBWORKS_NAMESRVCFUNCB_H 1

# include "name_srvc_pckt.h"

int
  name_srvc_B_add_name(unsigned char *name,
                       unsigned char name_type,
                       struct nbnodename_list *scope,
                       uint32_t my_ip_address,
                       int isgroup,
                       uint32_t ttl);
/* return: 0=success, >0=fail, -1=error */
int
  name_srvc_B_release_name(unsigned char *name,
                           unsigned char name_type,
                           struct nbnodename_list *scope,
                           uint32_t my_ip_address,
                           int isgroup);
struct name_srvc_resource_lst *
  name_srvc_B_callout_name(unsigned char *name,
                           unsigned char name_type,
                           struct nbnodename_list *scope);
struct cache_namenode *
  name_srvc_B_find_name(unsigned char *name,
                        unsigned char name_type,
                        struct nbnodename_list *scope,
                        unsigned short nodetype, /* Only one node type! */
                        int isgroup);
void *
  name_srvc_B_handle_newtid(void *input);

#endif /* NBWORKS_NAMESRVCFUNCB_H */
