#include <stdlib.h>

#include "nodename.h"

unsigned char *decode_nbnodename(unsigned char *coded_name) {
  int coded_name_cntr, decoded_name_cntr;
  int coded_name_len;
  unsigned char *decoded_name;
  unsigned char nibble_reactor;

  coded_name_len = strnlen(coded_name, NETBIOS_CODED_NAME_LEN +1);
  if (coded_name_len != NETBIOS_CODED_NAME_LEN) {
    /* FIXME: have to make it use ERRNO signaling */
    return 0;
  }
  decoded_name = malloc(NETBIOS_NAME_LEN +1);
  if (! decoded_name) {
    return 0;
  }
  decoded_name[NETBIOS_NAME_LEN] = '\0'; /* tramp stamp */

  decoded_name_cntr = 0;
  for (coded_name_cntr = 0; coded_name_cntr < NETBIOS_CODED_NAME_LEN;
       coded_name_cntr++) {
    nibble_reactor = coded_name[coded_name_cntr] - 'A';
    decoded_name[decoded_name_cntr] = nibble_reactor << 4;

    coded_name_cntr++;
    nibble_reactor = coded_name[coded_name_cntr] - 'A';
    decoded_name[decoded_name_cntr] =
      decoded_name[decoded_name_cntr] + nibble_reactor;

    decoded_name_cntr++;

    /* The +1 below is because when the very last char is done,
       the counter will be (NETBIOS_NAME_LEN + 1) and will be dangling
       above the terminating NULL character in the string. */
    if (decoded_name_cntr > (NETBIOS_NAME_LEN +1) ||
	coded_name_cntr > NETBIOS_CODED_NAME_LEN) {
      abort();
    }
  }

  return decoded_name;
}

unsigned char *encode_nbnodename(unsigned char *decoded_name) {
  int coded_name_cntr, decoded_name_cntr;
  int decoded_name_len;
  unsigned char *coded_name;
  unsigned char nibble_reactor;

  decoded_name_len = strnlen(decoded_name, NETBIOS_NAME_LEN +1);
  if (decoded_name_len != NETBIOS_NAME_LEN ||
      decoded_name[0] == '*') {
    /* FIXME: have to make it use ERRNO signaling */
    return 0;
  }
  coded_name = malloc(NETBIOS_CODED_NAME_LEN +1);
  if (! coded_name) {
    return 0;
  }
  coded_name[NETBIOS_CODED_NAME_LEN] = '\0';

  coded_name_cntr = 0;
  for (decoded_name_cntr = 0; decoded_name_cntr < NETBIOS_NAME_LEN;
       decoded_name_cntr++) {
    nibble_reactor = decoded_name[decoded_name_cntr] & 0xf0;
    nibble_reactor = nibble_reactor >> 4;
    coded_name[coded_name_cntr] = nibble_reactor + 'A';
    coded_name_cntr++;

    nibble_reactor = decoded_name[decoded_name_cntr] & 0x0f;
    coded_name[coded_name_cntr] = nibble_reactor + 'A';
    coded_name_cntr++;

    /* The +1 below is because when the very last char is done,
       the counter will be (NETBIOS_CODED_NAME_LEN + 1) and will be
       dangling above the terminating NULL character in the string. */
    if (decoded_name_cntr > NETBIOS_NAME_LEN ||
	coded_name_cntr > (NETBIOS_CODED_NAME_LEN +1)) {
      abort();
    }
  }

  return coded_name;
}
