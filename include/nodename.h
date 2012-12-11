#ifndef NBWORKS_NODENAME_H
# define NBWORKS_NODENAME_H 1

# define NETBIOS_NAME_LEN 16
# define NETBIOS_CODED_NAME_LEN 32

unsigned char *decode_nbnodename(const unsigned char *coded_name);
unsigned char *encode_nbnodename(const unsigned char *decoded_name);
unsigned char *make_nbnodename_sloppy(const unsigned char *string);
unsigned char *make_nbnodename(const unsigned char *string,
                               const unsigned char type_char);

#endif /* NBWORKS_NODENAME_H */
