#ifndef NBWORKS_NODENAME_H
# define NBWORKS_NODENAME_H 1

# include <stdint.h>

# define NETBIOS_NAME_LEN 16
# define NETBIOS_CODED_NAME_LEN 32

struct nbnodename_list {
  unsigned char *name;
  unsigned char len; /* Not int because the field is
                        6 bits wide in the packet. */
  struct nbnodename_list *next_name;
};

struct nbnodename_list_backbone {
  struct nbnodename_list *nbnodename;
  uint16_t name_flags;
  struct nbnodename_list_backbone *next_nbnodename;
};

unsigned char *
  decode_nbnodename(const unsigned char *coded_name);
unsigned char *
  encode_nbnodename(const unsigned char *decoded_name);

unsigned char
  unmake_nbnodename(unsigned char **coded_name);
unsigned char *
  make_nbnodename_sloppy(const unsigned char *string);
unsigned char *
  make_nbnodename(const unsigned char *string,
                  const unsigned char type_char);

void
  destroy_nbnodename(struct nbnodename_list *nbnodename);
struct nbnodename_list *
  clone_nbnodename(struct nbnodename_list *nbnodename);
int
  cmp_nbnodename(struct nbnodename_list *name_one,
                 struct nbnodename_list *name_two);
uint16_t
  nbnodenamelen(struct nbnodename_list *nbnodename);

#endif /* NBWORKS_NODENAME_H */
