#include "c_lang_extensions.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "constdef.h"
#include "nodename.h"
#include "pckt_routines.h"
#include "dtg_srvc_pckt.h"


struct dtg_pckt_pyld_normal *dtg_srvc_make_pyld_normal(unsigned char *src,
						       unsigned char src_type,
						       unsigned char *dst,
						       unsigned char dst_type,
						       struct nbnodename_list *scope,
						       void *payload,
						       uint16_t lenof_pyld,
						       uint16_t offset) {
  struct dtg_pckt_pyld_normal *result;
  struct nbnodename_list *complete_src, *complete_dst;
  unsigned char *label_src, *label_dst;
  int lenof_names;

  label_src = make_nbnodename(src, src_type);
  if (! label_src) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  label_dst = make_nbnodename(dst, dst_type);
  if (! label_dst) {
    /* TODO: errno signaling stuff */
    free(label_src);
    return 0;
  }

  complete_src = malloc(sizeof(struct nbnodename_list));
  if (! complete_src) {
    /* TODO: errno signaling stuff */
    free(label_dst);
    free(label_src);
    return 0;
  }

  complete_dst = malloc(sizeof(struct nbnodename_list));
  if (! complete_dst) {
    /* TODO: errno signaling stuff */
    free(complete_src);
    free(label_dst);
    free(label_src);
    return 0;
  }

  result = malloc(sizeof(struct dtg_pckt_pyld_normal));
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_src);
    free(complete_dst);
    free(label_dst);
    free(label_src);
    return 0;
  };

  complete_src->name = label_src;
  complete_src->len = NETBIOS_CODED_NAME_LEN;
  complete_src->next_name = clone_nbnodename(scope);

  complete_dst->name = label_dst;
  complete_dst->len = NETBIOS_CODED_NAME_LEN;
  complete_dst->next_name = clone_nbnodename(scope);

  lenof_names = align_incr(0, nbnodenamelen(complete_src), 4) *2;

  result->len = lenof_names + lenof_pyld;
  result->offset = offset;
  result->src_name = complete_src;
  result->dst_name = complete_dst;
  result->payload = payload;
  result->do_del_pyldpyld = TRUE;

  return result;
}
