#ifndef NBWORKS_NAMESRVCFUNC_H
# define NBWORKS_NAMESRVCFUNC_H 1

int
  name_srvc_B_add_name(unsigned char *name,
                       unsigned char name_type,
                       struct nbnodename_list *scope,
                       uint32_t my_ip_address,
                       int isgroup);
/* return: 0=success, >0=fail, -1=error */
int
  name_srvc_B_release_name(unsigned char *name,
                           unsigned char name_type,
                           struct nbnodename_list *scope,
                           uint32_t my_ip_address,
                           int isgroup);
struct name_srvc_resource *
  name_srvc_B_callout_name(unsigned char *name,
                           unsigned char name_type,
                           struct nbnodename_list *scope);
void *
  name_srvc_B_handle_newtid(void *input);

#endif /* NBWORKS_NAMESRVCFUNC_H */
