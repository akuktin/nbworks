#include "c_lang_extensions.h"

#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "nodename.h"


unsigned char *decode_nbnodename(const unsigned char *coded_name,
				 unsigned char *result_buf) {
  int coded_name_cntr, decoded_name_cntr;
  int coded_name_len;
  unsigned char *decoded_name;
  unsigned char nibble_reactor;

  if (! coded_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  coded_name_len = strnlen((char *)coded_name, NETBIOS_CODED_NAME_LEN +1);
  if (coded_name_len != NETBIOS_CODED_NAME_LEN) {
    /* TODO: have to make it use ERRNO signaling */
    return 0;
  }
  if (result_buf) {
    decoded_name = result_buf;
  } else {
    decoded_name = malloc(NETBIOS_NAME_LEN +1);
    if (! decoded_name) {
      return 0;
    }
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
      if (! result_buf)
        free(decoded_name);
      return 0;
    }
  }

  decoded_name[NETBIOS_NAME_LEN] = '\0'; /* tramp stamp */

  return decoded_name;
}

unsigned char *encode_nbnodename(const unsigned char *decoded_name,
				 unsigned char *result_buf) {
  int coded_name_cntr, decoded_name_cntr;
  unsigned char *coded_name;
  unsigned char nibble_reactor;

  if (! decoded_name) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /*
   * Instead of checking the len of the string, I will put my
   * faith in the caller. The caller MUST call with a string
   * (that is, an array of uchars with any content) whose length
   * is at least NETBIOS_NAME_LEN.
   * If the length were checked, two problems would arise.
   * Number one: labels with embeded NULLs would not be encoded
   * as they were supposed to. And number two: labels which end
   * with the type char 0x00 (that is, ALL of the labels) would
   * crash the function.
   */

  if (result_buf) {
    coded_name = result_buf;
  } else {
    coded_name = malloc(NETBIOS_CODED_NAME_LEN +1);
    if (! coded_name) {
      return 0;
    }
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
      if (! result_buf)
        free(coded_name);
      return 0;
    }
  }

  coded_name[NETBIOS_CODED_NAME_LEN] = '\0';

  return coded_name;
}


unsigned char unmake_nbnodename(unsigned char **coded_name) {
  int i;
  unsigned char result, *decoded_name, *label;

  decoded_name = decode_nbnodename(*coded_name, 0);

  result = decoded_name[NETBIOS_NAME_LEN -1];

  for (i=(NETBIOS_NAME_LEN-2); i >= 0; i--) {
    if (decoded_name[i] != ' ') /* a space character */
      break;
  }

  if (i >= 0) {
    label = malloc(i+2);
    memcpy(label, decoded_name, i+1);
    label[i+2] = '\0';

    *coded_name = label;
  } else {
    *coded_name = 0;
  }

  free(decoded_name);
  return result;
}

unsigned char *make_nbnodename_sloppy(const unsigned char *string) {
  int j, len;
  /* Array below is to save a call to malloc()
     and give us a wonderfull pleasure of not having to
     free() stuff. */
  unsigned char prepared_name[NETBIOS_NAME_LEN +1];

  if (! string) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  len = strnlen((char *)string, NETBIOS_NAME_LEN +1);
  if (len > NETBIOS_NAME_LEN) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  strncpy((char *)prepared_name, (char *)string, NETBIOS_NAME_LEN);

  for (j = len; j < NETBIOS_NAME_LEN; j++) {
    prepared_name[j] = ' '; /* a space character */
  }

  for (j = 0; j < NETBIOS_NAME_LEN; j++) {
    prepared_name[j] = toupper(prepared_name[j]);
  }

  prepared_name[NETBIOS_NAME_LEN] = '\0';

  return(encode_nbnodename(prepared_name, 0));
}

unsigned char *make_nbnodename(const unsigned char *string,
			       const unsigned char type_char) {
  int j, len;
  /* Array below is to save a call to malloc()
     and give us a wonderfull pleasure of not having to
     free() stuff. */
  unsigned char prepared_name[NETBIOS_NAME_LEN +1];

  if (! string) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  len = strnlen((char *)string, ((NETBIOS_NAME_LEN +1) -1));
  if (len >= NETBIOS_NAME_LEN) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  strncpy((char *)prepared_name, (char *)string, NETBIOS_NAME_LEN -1);

  for (j = len; j < (NETBIOS_NAME_LEN -1); j++) {
    prepared_name[j] = ' '; /* a space character */
  }

  for (j = 0; j < len; j++) {
    prepared_name[j] = toupper(prepared_name[j]);
  }

  prepared_name[NETBIOS_NAME_LEN -1] = type_char;
  prepared_name[NETBIOS_NAME_LEN] = '\0';

  return(encode_nbnodename(prepared_name, 0));
}


void destroy_nbnodename(struct nbnodename_list *nbnodename) {
  struct nbnodename_list *next;

  while (nbnodename) {
    next = nbnodename->next_name;
    free(nbnodename->name);
    free(nbnodename);
    nbnodename = next;
  }

  return;
}

struct nbnodename_list *clone_nbnodename(struct nbnodename_list *nbnodename) {
  struct nbnodename_list *original, *clone, *first_clone;

  original = nbnodename;

  if (original) {
    clone = malloc(sizeof(struct nbnodename_list));
    if (! clone) {
      /* TODO: errno signaling stuff */
      return 0;
    }
    first_clone = clone;
    clone->name = 0;
    clone->next_name = 0;

    while (1) {
      clone->len = original->len;
      clone->name = malloc(clone->len);
      if (! clone->name) {
	/* TODO: errno signaling stuff */
	destroy_nbnodename(first_clone);
	return 0;
      }
      memcpy(clone->name, original->name, clone->len);
      if (original->next_name) {
	original = original->next_name;
	clone->next_name = malloc(sizeof(struct nbnodename_list));
	if (! clone->next_name) {
	  /* TODO: errno signaling stuff */
	  destroy_nbnodename(first_clone);
	  return 0;
	}
	clone = clone->next_name;
	clone->next_name = 0;
	clone->name = 0;
      } else
	break;
    }
    return first_clone;
  } else
    return 0;
}

/* return: 0=equal, 1=not equal, -1=error */
int cmp_nbnodename(struct nbnodename_list *name_one,
		   struct nbnodename_list *name_two) {
  while (name_one) {
    if (name_two) {
      if (name_one->len == name_two->len) {
	if (0 == memcmp(name_one->name, name_two->name,
			name_one->len)) {
	  name_one = name_one->next_name;
	  name_two = name_two->next_name;
	} else
	  return 1;
      } else
	return 1;
    } else
      return 1;
  }
  if (name_two)
    return 1;
  else
    return 0;
}

uint16_t nbnodenamelen(struct nbnodename_list *nbnodename) {
  struct nbnodename_list *cur_name;
  uint16_t result;

  cur_name = nbnodename;
  result = 1; /* To account for the terminating NULL. */

  /* No overflow checks. */

  while (cur_name) {
    result = result + cur_name->len +1;
    cur_name = cur_name->next_name;
  }

  return result;
}
