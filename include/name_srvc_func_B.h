#ifndef NBWORKS_NAMESRVCFUNC_H
# define NBWORKS_NAMESRVCFUNC_H 1

int name_srvc_B_add_name(unsigned char *name,
                         unsigned char name_type,
                         struct nbnodename_list *scope,
                         uint32_t my_ip_address,
                         int isgroup);

#endif /* NBWORKS_NAMESRVCFUNC_H */
