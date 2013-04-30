/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "c_lang_extensions.h"

#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

#include "constdef.h"
#include "nodename.h"


unsigned char *decode_nbnodename(const unsigned char *coded_name,
				 unsigned char *result_buf) {
  int coded_name_cntr, decoded_name_cntr;
  int coded_name_len;
  unsigned char *decoded_name;
  unsigned char nibble_reactor;

  if (! coded_name) {
    nbworks_errno = EINVAL;
    return 0;
  }

  /* DON'T check the length of coded_name. This way,
   * we don't have to use the tramp stamp. */

  if (result_buf) {
    decoded_name = result_buf;
  } else {
    decoded_name = malloc(NETBIOS_NAME_LEN);
    if (! decoded_name) {
      nbworks_errno = ENOBUFS;
      return 0;
    }
  }

  decoded_name_cntr = 0;
  for (coded_name_cntr = 0; coded_name_cntr < NETBIOS_CODED_NAME_LEN;
       coded_name_cntr++) {
    nibble_reactor = (coded_name[coded_name_cntr] - 'A') << 4;
    coded_name_cntr++;

    nibble_reactor |= coded_name[coded_name_cntr] - 'A';
    decoded_name[decoded_name_cntr] = nibble_reactor;

    decoded_name_cntr++;
  }

  return decoded_name;
}

unsigned char *encode_nbnodename(const unsigned char *decoded_name,
				 unsigned char *result_buf) {
  int coded_name_cntr, decoded_name_cntr;
  unsigned char *coded_name;
  unsigned char nibble_reactor;

  if (! decoded_name) {
    nbworks_errno = EINVAL;
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
    coded_name = malloc(NETBIOS_CODED_NAME_LEN);
    if (! coded_name) {
      nbworks_errno = ENOBUFS;
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
  }

  return coded_name;
}


unsigned char *nbworks_make_nbnodename(const unsigned char *string,
				       const unsigned char type_char,
				       unsigned char *field) {
  int j, len;
  /* Array below is to save a call to malloc()
   * and give us a wonderfull pleasure of not having to
   * free() stuff. */
  unsigned char prepared_name[NETBIOS_NAME_LEN +1];

  if (! string) {
    nbworks_errno = EINVAL;
    return 0;
  }

  len = strlen((char *)string);
  if (len > NETBIOS_NAME_LEN) {
    nbworks_errno = EINVAL;
    return 0;
  }

  strncpy((char *)prepared_name, (char *)string, NETBIOS_NAME_LEN -1);

  for (j = 0; j < len; j++) {
    prepared_name[j] = toupper(prepared_name[j]);
  }

  /* j is inherited from the previous loop */
  for (; j < (NETBIOS_NAME_LEN -1); j++) {
    prepared_name[j] = ' '; /* a space character */
  }

  prepared_name[NETBIOS_NAME_LEN -1] = type_char;
  prepared_name[NETBIOS_NAME_LEN] = '\0';

  return(encode_nbnodename(prepared_name, field));
}

unsigned char *nbworks_create_nbnodename(const unsigned char *string,
				         const unsigned char type_char,
				         unsigned char *field) {
  int j, len;
  unsigned char *result;

  if (! string) {
    nbworks_errno = EINVAL;
    return 0;
  }

  len = strlen((char *)string);
  if (len > NETBIOS_NAME_LEN) {
    nbworks_errno = EINVAL;
    return 0;
  }

  if (! field) {
    result = malloc(NETBIOS_NAME_LEN);
    if (! result) {
      nbworks_errno = ENOMEM;
      return 0;
    }
  } else {
    result = field;
  }

  strncpy((char *)result, (char *)string, NETBIOS_NAME_LEN -1);

  for (j = 0; j < len; j++) {
    result[j] = toupper(result[j]);
  }

  /* j is inherited from the previous loop */
  for (; j < (NETBIOS_NAME_LEN -1); j++) {
    result[j] = ' '; /* a space character */
  }

  result[NETBIOS_NAME_LEN -1] = type_char;

  return result;
}


void nbworks_dstr_nbnodename(struct nbworks_nbnamelst *nbnodename) {
  struct nbworks_nbnamelst *next;

  while (nbnodename) {
    next = nbnodename->next_name;
    free(nbnodename->name);
    free(nbnodename);
    nbnodename = next;
  }

  return;
}

struct nbworks_nbnamelst *nbworks_clone_nbnodename(struct nbworks_nbnamelst *nbnodename) {
  struct nbworks_nbnamelst *original, *clone, *first_clone;

  original = nbnodename;

  if (original) {
    clone = malloc(sizeof(struct nbworks_nbnamelst));
    if (! clone) {
      /* TODO: errno signaling stuff */
      return 0;
    }
    first_clone = clone;
    clone->name = 0;
    clone->next_name = 0;

    while (1) {
      clone->len = original->len;
      if (original->name) {
        clone->name = malloc(clone->len +1);
        if (! clone->name) {
	  /* TODO: errno signaling stuff */
	  nbworks_dstr_nbnodename(first_clone);
	  return 0;
        }
        memcpy(clone->name, original->name, clone->len);
	clone->name[clone->len] = 0;
      } else {
        clone->name = 0;
      }
      if (original->next_name) {
	original = original->next_name;
	clone->next_name = malloc(sizeof(struct nbworks_nbnamelst));
	if (! clone->next_name) {
	  /* TODO: errno signaling stuff */
	  nbworks_dstr_nbnodename(first_clone);
	  return 0;
	}
	clone = clone->next_name;
      } else {
	clone->next_name = 0;
	break;
      }
    }
    return first_clone;
  } else
    return 0;
}

/* return: 0=equal, 1=not equal, -1=error */
int nbworks_cmp_nbnodename(struct nbworks_nbnamelst *name_one,
			   struct nbworks_nbnamelst *name_two) {
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

unsigned int nbworks_nbnodenamelen(struct nbworks_nbnamelst *nbnodename) {
  struct nbworks_nbnamelst *cur_name;
  unsigned int result;

  cur_name = nbnodename;
  result = 1; /* To account for the terminating NULL. */

  /* No overflow checks. */

  while (cur_name) {
    result = result + cur_name->len +1;
    cur_name = cur_name->next_name;
  }

  return result;
}


struct nbworks_nbnamelst *nbworks_buff2nbname(unsigned char *buff,
					      unsigned long lenof_string) {
  struct nbworks_nbnamelst *result;

  if (! buff) {
    nbworks_errno = EINVAL;
    return 0;
  } else
    nbworks_errno = 0;

  result = malloc(sizeof(struct nbworks_nbnamelst));
  if (! result) {
    nbworks_errno = ENOMEM;
    return 0;
  }

  result->next_name = 0;

  if (! lenof_string)
    lenof_string = strlen((char *)buff);
  result->len = lenof_string;

  result->name = malloc(lenof_string+1);
  if (! result->name) {
    free(result);
    nbworks_errno = ENOMEM;
    return 0;
  }

  memcpy(result->name, buff, lenof_string);
  result->name[lenof_string] = 0;

  return result;
}

unsigned long nbworks_nbname2buff(unsigned char **destination,
				  struct nbworks_nbnamelst *name) {
  unsigned char *result, *walker;
  unsigned long len;

  if (! (name && destination)) {
    nbworks_errno = EINVAL;
    return 0;
  } else
    nbworks_errno = 0;

  len = nbworks_nbnodenamelen(name);
  len--;

  if (! (*destination)) {
    *destination = malloc(len);
    if (! *destination) {
      nbworks_errno = ENOMEM;
      return 0;
    }
  }

  result = *destination;

  walker = result;
  while (0xe5) {
    walker = mempcpy(walker, name->name, name->len);
    name = name->next_name;
    if (name)
      *walker = '.';
    else
      break;
  }

  *walker = 0;

  return len;
}


struct nbworks_nbnamelst *nbworks_makescope(unsigned char *buff) {
  struct nbworks_nbnamelst **result, *first, *cur;
  unsigned long name_len;
  char *walker, *point;

  if (! buff) {
    nbworks_errno = EINVAL;
    return 0;
  } else
    nbworks_errno = 0;

  result = &first;

  walker = (char *)buff;
  while (*walker) {
    point = strchrnul(walker, '.');
    name_len = point - walker;

    *result = malloc(sizeof(struct nbworks_nbnamelst));
    if (! *result) {
      nbworks_dstr_nbnodename(first);
      nbworks_errno = ENOMEM;
      return 0;
    }
    cur = *result;
    result = &(cur->next_name);

    cur->len = name_len;
    cur->name = malloc(name_len +1);
    if (! cur->name) {
      *result = 0;
      nbworks_dstr_nbnodename(first);
      nbworks_errno = ENOMEM;
      return 0;
    }

    memcpy(cur->name, walker, name_len);
    cur->name[name_len] = 0;

    walker = point;
  }

  *result = 0;
  return first;
}
