#ifndef NBWORKS_DTGSRVCCNST_H
# define NBWORKS_DTGSRVCCNST_H 1

struct dtg_pckt_pyld_normal *
  dtg_srvc_make_pyld_normal(unsigned char *src,
                            unsigned char src_type,
                            unsigned char *dst,
                            unsigned char dst_type,
                            struct nbnodename_list *scope,
                            void *payload,
                            uint16_t lenof_pyld,
                            uint16_t offset);

#endif /* NBWORKS_DTGSRVCCNST_H */
