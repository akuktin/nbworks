#include "c_lang_extensions.h"

#include <stdlib.h>
#include <string.h>

#include "nodename.h"


unsigned char *decode_nbnodename(const unsigned char *coded_name) {
  int coded_name_cntr, decoded_name_cntr;
  int coded_name_len;
  unsigned char *decoded_name;
  unsigned char nibble_reactor;

  if (! coded_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  coded_name_len = strnlen(coded_name, NETBIOS_CODED_NAME_LEN +1);
  if (coded_name_len != NETBIOS_CODED_NAME_LEN) {
    /* TODO: have to make it use ERRNO signaling */
    return 0;
  }
  decoded_name = malloc(NETBIOS_NAME_LEN +1);
  if (! decoded_name) {
    return 0;
  }

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

  decoded_name[NETBIOS_NAME_LEN] = '\0'; /* tramp stamp */

  return decoded_name;
}

unsigned char *encode_nbnodename(const unsigned char *decoded_name) {
  int coded_name_cntr, decoded_name_cntr;
  int decoded_name_len;
  unsigned char *coded_name;
  unsigned char nibble_reactor;

  if (! decoded_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  decoded_name_len = strnlen(decoded_name, NETBIOS_NAME_LEN +1);
  if (decoded_name_len != NETBIOS_NAME_LEN) {
    /* TODO: have to make it use ERRNO signaling */
    return 0;
  }
  coded_name = malloc(NETBIOS_CODED_NAME_LEN +1);
  if (! coded_name) {
    return 0;
  }

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

  coded_name[NETBIOS_CODED_NAME_LEN] = '\0';

  return coded_name;
}

unsigned char *make_nbnodename_sloppy(const unsigned char *string) {
  int j, len;
  /* Array below is to save a call to malloc()
     and give us a wonderfull pleasure of not having to
     free() stuff. */
  unsigned char prepared_name[NETBIOS_NAME_LEN +1];
  unsigned char *coded_name;

  if (! string) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  len = strnlen(string, NETBIOS_NAME_LEN +1);
  if (len > NETBIOS_NAME_LEN) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  strncpy(prepared_name, string, NETBIOS_NAME_LEN);

  for (j = len; j < NETBIOS_NAME_LEN; j++) {
    prepared_name[j] = ' '; /* a space character */
  }

  for (j = 0; j < NETBIOS_NAME_LEN; j++) {
    prepared_name[j] = toupper(prepared_name[j]);
  }

  prepared_name[NETBIOS_NAME_LEN] = '\0';

  return(encode_nbnodename(prepared_name));
}

unsigned char *make_nbnodename(const unsigned char *string,
			       const unsigned char type_char) {
  int j, len;
  /* Array below is to save a call to malloc()
     and give us a wonderfull pleasure of not having to
     free() stuff. */
  unsigned char prepared_name[NETBIOS_NAME_LEN +1];
  unsigned char *coded_name;

  if (! string) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  len = strnlen(string, ((NETBIOS_NAME_LEN +1) -1));
  if (len > NETBIOS_NAME_LEN) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  strncpy(prepared_name, string, NETBIOS_NAME_LEN -1);

  for (j = len; j < NETBIOS_NAME_LEN; j++) {
    prepared_name[j] = ' '; /* a space character */
  }

  for (j = 0; j < NETBIOS_NAME_LEN; j++) {
    prepared_name[j] = toupper(prepared_name[j]);
  }

  prepared_name[NETBIOS_NAME_LEN -1] = type_char;
  prepared_name[NETBIOS_NAME_LEN] = '\0';

  return(encode_nbnodename(prepared_name));
}
