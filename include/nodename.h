#define NETBIOS_NAME_LEN 16
#define NETBIOS_CODED_NAME_LEN 32

char *decode_nbnodename(char *coded_name);
char *encode_nbnodename(char *decoded_name);
