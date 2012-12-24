#ifndef NBWORKS_NAMESRVCFUNC_H
# define NBWORKS_NAMESRVCFUNC_H 1

struct name_srvc_packet *
  name_srvc_make_name_reg_big(unsigned char *name,
                              unsigned char name_type,
                              struct nbnodename_list *scope,
                              uint32_t ttl,
                              uint32_t in_address,
                              int isgroup,
                              unsigned char node_type);
struct name_srvc_packet *
  name_srvc_make_name_reg_small(unsigned char *name,
                               unsigned char name_type,
                               struct nbnodename_list *scope,
                               uint32_t ttl,
                               uint32_t in_address,
                               int isgroup,
                               unsigned char node_type);
struct name_srvc_packet *
  name_srvc_make_name_qry_req(unsigned char *name,
                              unsigned char name_type,
                              struct nbnodename_list *scope);
struct name_srvc_packet *
  name_srvc_make_name_qry_pos(unsigned char *name,
                              unsigned char name_type,
                              struct nbnodename_list *scope,
                              struct nbaddress_list *addresses,
                              unsigned int numof_addresses,
                              uint32_t ttl);
struct name_srvc_packet *
  name_srvc_make_name_qry_neg(unsigned char *name,
                              unsigned char name_type,
                              struct nbnodename_list *scope);
struct name_srvc_packet *
  name_srvc_make_name_qry_red(unsigned char *name,
                              unsigned char name_type,
                              struct nbnodename_list *scope,
                              struct nbnodename_list *namesrvr_name,
                              struct nbaddress_list *namesrvr_addr,
                              uint32_t ttl);
struct name_srvc_packet *
  name_srvc_make_name_stat_rfc1002_qry(unsigned char *name,
                                       unsigned char name_type,
                                       struct nbnodename_list *scope);
struct name_srvc_packet *
  name_srvc_make_name_stat_rfc1002_rsp(unsigned char *name,
                                       unsigned char name_type,
                                       struct nbnodename_list *scope,
                                       struct nbnodename_list_backbone *my_names_this_scope);

#endif /* NBWORKS_NAMESRVCFUNC_H */
