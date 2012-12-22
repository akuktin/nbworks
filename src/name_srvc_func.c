#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "nodename.h"
#include "pckt_routines.h"
#include "name_srvc_pckt.h"
#include "name_srvc_func.h"


/* Returns a half-baked packet which must be finished:
     1. transaction_id
     2. nm_flags must be set, regarding (a) broadcast and (b) name server
*/
struct name_srvc_packet *name_srvc_make_name_reg_req(unsigned char *name,
						     unsigned char name_type,
						     struct nbnodename_list *scope,
						     uint32_t ttl,
						     uint32_t in_address,
						     int isgroup,
						     unsigned char node_type) {
  struct name_srvc_packet *result;
  struct nbnodename_list *complete_name;
  struct nbaddress_list *addr;

  complete_name = malloc(sizeof(struct nbnodename_list));
  if (! complete_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  complete_name->name = make_nbnodename(name, name_type);
  if (! complete_name->name) {
    /* TODO: errno signaling stuff */
    free(complete_name);
    return 0;
  }
  complete_name->len = NETBIOS_CODED_NAME_LEN;
  complete_name->next_name = scope;

  addr = malloc(sizeof(struct nbaddress_list));
  if (! addr) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    return 0;
  }
  addr->next_address = 0;
  addr->there_is_an_address = 1;
  addr->address = in_address;
  if (isgroup) {
    addr->flags = 0x80;
  } else {
    addr->flags = 0;
  }
  switch (node_type) {
  case 'H':
    addr->flags = addr->flags | 0x60;
    break;

  case 'M':
    addr->flags = addr->flags | 0x40;
    break;

  case 'P':
    addr->flags = addr->flags | 0x20;
    break;

  case 'B':
  default:
    break;
  }


  result = alloc_name_srvc_pckt(1, 0, 0, 1);
  if (! result) {
    /* TODO: errno signaling stuff */
    free(complete_name->name);
    free(complete_name);
    free(addr);
    return 0;
  }

  result->questions->next = 0;
  result->questions->qstn = malloc(sizeof(struct name_srvc_question));
  if (! result->questions->qstn) {
    /* TODO: errno signaling stuff */
    free(addr);
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 0, 1);
    return 0;
  }

  result->aditionals->next = 0;
  result->aditionals->res = malloc(sizeof(struct name_srvc_resource));
  if (! result->aditionals->res) {
    /* TODO: errno signaling stuff */
    free(addr);
    free(complete_name->name);
    free(complete_name);
    destroy_name_srvc_pckt(result, 0, 1);
    return 0;
  }

  result->questions->qstn->name = complete_name;
  result->questions->qstn->qtype = QTYPE_NB;
  result->questions->qstn->qclass = QCLASS_IN;

  result->aditionals->res->name = complete_name;
  result->aditionals->res->rrtype = RRTYPE_NB;
  result->aditionals->res->rrclass = RRCLASS_IN;
  result->aditionals->res->ttl = ttl;
  result->aditionals->res->rdata_len = 6;
  result->aditionals->res->rdata_t = nb_address_list;
  result->aditionals->res->rdata = addr;

  result->header->opcode = 0x5;
  result->header->rcode = 0;

  return result;
}
