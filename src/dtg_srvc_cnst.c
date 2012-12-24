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
  int lenof_names;

  complete_src = make_nbnodename(src, src_type);
  if (! complete_src) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  complete_dst = make_nbnodename(dst, dst_type);
  if (! complete_dst) {
    /* TODO: errno signaling stuff */
    free(complete_src);
    return 0;
  }

  result = malloc(sizeof(struct dtg_pckt_pyld_normal));
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_src);
    free(complete_dst);
    return 0;
  };

  lenof_names = ((4- (nbnodenamelen(complete_src) %4)) %4) *2;

  result->len = lenof_names + lenof_pyld;
  result->offset = offset;
  result->src_name = complete_src;
  result->dst_name = complete_dst;
  result->payload = payload;

  return result;
}
