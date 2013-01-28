#ifndef NBWORKS_DTGSRVCFUNC_H
# define NBWORKS_DTGSRVCFUNC_H 1

# include "nodename.h"
# include "dtg_srvc_pckt.h"

inline uint16_t
  dtg_srvc_doesitmatch(struct nbnodename_list *target,
                       struct dtg_srvc_packet *shot);
inline struct nbnodename_list *
  dtg_srvc_extract_dstname(struct dtg_srvc_packet *pckt);
inline struct nbnodename_list *
  dtg_srvc_extract_srcname(struct dtg_srvc_packet *pckt);

#endif /* NBWORKS_DTGSRVCFUNC_H */
