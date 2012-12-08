#define NETBIOS_NAME_LEN 16
#define NETBIOS_CODED_NAME_LEN 32

unsigned char *decode_nbnodename(unsigned char *coded_name);
unsigned char *encode_nbnodename(unsigned char *decoded_name);
