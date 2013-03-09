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
#include <stdint.h>
#include <string.h>

#include "constdef.h"
#include "nodename.h"
#include "name_srvc_pckt.h"
#include "pckt_routines.h"


inline unsigned char *read_16field(unsigned char *content,
				   uint16_t *field) {
  *field = 0;
  *field = (*field | *content) << 8;
  content++;
  *field = (*field | *content);
  content++;

  return content;
}
inline unsigned char *read_32field(unsigned char *content,
                                   uint32_t *field) {
  int i;

  *field = 0;
  for (i = 2; i >= 0; i--) {
    *field = (*field | *content) << 8;
    content++;
  }
  *field = (*field | *content);
  content++;

  return content;
}

inline unsigned char *read_48field(unsigned char *content,
                                   uint64_t *field) {
  int i;

  *field = 0;
  for (i = 4; i >= 0; i--) {
    *field = (*field | *content) << 8;
    content++;
  }
  *field = (*field | *content);
  content++;

  return content;
}

inline unsigned char *read_64field(unsigned char *content,
                                   uint64_t *field) {
  int i;

  *field = 0;
  for (i = 6; i >= 0; i--) {
    *field = (*field | *content) << 8;
    content++;
  }
  *field = (*field | *content);
  content++;

  return content;
}

inline unsigned char *fill_16field(uint16_t content,
				   unsigned char *field) {
  int i;
  uint16_t flags;

  flags = 0xff00;

  for (i = 1; i >= 0; i--) {
    *field = (unsigned char)((content & flags) >> (8 * i));
    field++;
    flags = flags >> 8;
  }

  return field;
}

inline unsigned char *fill_32field(uint32_t content,
				   unsigned char *field) {
  int i;
  uint32_t flags;

  flags = 0xff000000;

  for (i = 3; i >= 0; i--) {
    *field = (unsigned char)((content & flags) >> (8 * i));
    field++;
    flags = flags >> 8;
  }

  return field;
}

inline unsigned char *fill_48field(uint64_t content,
				   unsigned char *field) {
  int i;
  uint64_t flags;

  flags = 0xff0000000000;

  for (i = 5; i >= 0; i--) {
    *field = (unsigned char)((content & flags) >> (8 * i));
    field++;
    flags = flags >> 8;
  }

  return field;
}

inline unsigned char *fill_64field(uint64_t content,
				   unsigned char *field) {
  int i;
  uint64_t flags;

  flags = 0xff00000000000000;

  for (i = 7; i >= 0; i--) {
    *field = (unsigned char)((content & flags) >> (8 * i));
    field++;
    flags = flags >> 8;
  }

  return field;
}

struct nbnodename_list *read_all_DNS_labels(unsigned char **start_and_end_of_walk,
					    unsigned char *startof_packet,
					    unsigned char *end_of_packet,
					    uint32_t offsetof_start,
					    struct state__readDNSlabels **state,
					    unsigned char *startblock,
					    unsigned int lenof_startblock) {
  /* The first member of this list exists on the stack because I do not deem it
   * worthwile to use malloc. Here's the thing: in normal operation, it is
   * perfectly understandable and expected that the name will have one pointer.
   * Having more that one pointer is not likely. If I were to not have one struct
   * on the stack, I would have to malloc a pointer_clip very often - at least
   * once per all non-query packets. Using the stack, however, eliminates that
   * problem. It does, however, expose us to failure on architectures where one
   * is not allowed to use pointers will-nilly, for example, in cases where an
   * architecture prevents the function to use a single pointer type for objects
   * on the stack an objects on the heap. */
  struct pointer_clip {
    unsigned int offset;
    struct pointer_clip *next;
  } clip1, *clip_ptr, **clip_pptr;

  struct nbnodename_list *label, *first_label, **cur_label;
  int name_len;
  uint32_t name_offset;
  unsigned char *walker, *weighted_companion_buf, *end;

  /* The author assures you that weighted_companion_buf will never
   * bite your ass when you are not careful with pointers and that it,
   * infact, does not exist as an entity. */

  /* --- sanity check --- */
  if (start_and_end_of_walk &&
      (*start_and_end_of_walk < startof_packet ||
       *start_and_end_of_walk >= end_of_packet)) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  /* --- sanity check --- */

  /* @@ MACROS BEGIN @------------------------------------------- */
  /* This is the point where C stops being sleak and sexy. */

#define del_clip					\
  clip_ptr = clip1.next;				\
  while (clip_ptr) {					\
    clip1.next = clip_ptr->next;			\
    free(clip_ptr);					\
    clip_ptr = clip1.next;				\
  }

#define kill_yourself					\
  if (state) {						\
    free(*state);					\
    *state = 0;						\
  }							\
							\
  del_clip;						\
							\
  *cur_label = 0;					\
  destroy_nbnodename(first_label);			\
  return 0;

#define handle_abort						\
  if (state) {							\
    if (! *state) {						\
      *state = malloc(sizeof(struct state__readDNSlabels));	\
      if (! *state) {						\
	kill_yourself;						\
      }								\
    }								\
    (*state)->first_label = first_label;			\
    (*state)->cur_label = cur_label;				\
    (*state)->name_offset = name_offset;			\
    (*state)->mystery_int = clip1.offset;			\
    (*state)->mystery_pointer = clip1.next;			\
								\
    if (name_offset == ONES)					\
      *start_and_end_of_walk = walker;				\
    return 0;							\
  } else {							\
    /* TODO: errno signaling stuff */				\
    *cur_label = 0;						\
    destroy_nbnodename(first_label);				\
    return 0;							\
  }

  /* @@ MACROS END @--------------------------------------------- */

  /* -XX--   BEGIN INIT   --XX- */

  if ((state && *state)) {
    first_label = (*state)->first_label;
    if (first_label) {
      cur_label = (*state)->cur_label;
    } else {
      cur_label = &first_label;
    }
    name_offset = (*state)->name_offset;
    clip1.offset = (*state)->mystery_int;
    clip1.next = (*state)->mystery_pointer;
  } else {
    first_label = 0;
    cur_label = &first_label;
    name_offset = ONES;
    clip1.offset = ONES;
    clip1.next = 0;
  }

  /* ------------- */

  walker = *start_and_end_of_walk;
  clip_pptr = 0; /* Only to prevent compilation warnings. */

  /* -XX--   END INIT   --XX- */

  /* Read RFC 1002 and RFC 883 for
     details and understanding of
     what exactly is going on here. */
  /* Not counting the start-stop system, ofcourse. */

  while (*walker != 0) {
    if (*walker <= MAX_DNS_LABEL_LEN) {
      name_len = *walker;
      if ((walker + name_len +1) >= end_of_packet) {
	/* OUT_OF_BOUNDS */
	handle_abort;
      }

      *cur_label = malloc(sizeof(struct nbnodename_list));
      label = *cur_label;
      if (! label) {
	kill_yourself;
      }
      cur_label = &(label->next_name);

      label->name = malloc(name_len +1);
      if (! label->name) {
	/* TODO: errno signaling stuff */
	kill_yourself;
      }
      walker++;
      for (weighted_companion_buf = label->name, end = walker + name_len;
	   walker < end; weighted_companion_buf++, walker++) {
	*weighted_companion_buf = *walker;
      }
      *weighted_companion_buf = 0;
      /* You should now incinirate the weighted_companion_buf. */

      label->len = name_len;
      /* walker is updated by the for loop. */

    } else { /* that is, *walker > MAX_DNS_LABEL_LEN */
      if ((walker +1) >= end_of_packet) {
	/* OUT_OF_BOUNDS */
	handle_abort;
      }

      if (name_offset == ONES) {
	/* Because of the way name_offset is filled (look below),
	   the two top bits are guaranteed to be empty if we have
	   encountered at least one pointer. If those two bits are
	   set, then that can only mean this is the first pointer
	   and we should record its position to enable us to read
	   the rest of the packet. */
	*start_and_end_of_walk = walker +2;
      }
      name_offset = *walker & 0x3f;
      name_offset = name_offset << 8;
      walker++;
      name_offset = name_offset | *walker;

      clip_ptr = &clip1;
      do {
	if (clip_ptr->offset == name_offset) {
	  /* Infinite loop. */
	  kill_yourself;
	}

	if (clip_ptr->offset == ONES) {
	  break;
	}

	clip_pptr = &(clip_ptr->next);
	clip_ptr = *clip_pptr;
      } while (clip_ptr);
      if (! clip_ptr) {
	*clip_pptr = malloc(sizeof(struct pointer_clip));
	clip_ptr = *clip_pptr;
	if (! clip_ptr) {
	  kill_yourself;
	}
	clip_ptr->next = 0;
      }
      clip_ptr->offset = name_offset;

      if (offsetof_start <= name_offset) {
	walker = startof_packet + (name_offset - offsetof_start);
      } else {
	if (startblock) {
	  walker = startblock + name_offset;
	  if (walker >= (startblock + lenof_startblock)) {
	    handle_abort;
	  }
	} else {
	  kill_yourself;
	}
      }
    }
  }
  *cur_label = 0;

  if (name_offset == ONES) {
    /* Read the fourth comment up.
       If this test has succeded, then we have not encountered
       a single pointer, *start_and_end_of_walk has not been
       updated, so we update it now. */
    *start_and_end_of_walk = walker +1;
  }

  if (state)
    free(*state);

  del_clip;

#undef handle_abort
#undef kill_yourself
#undef del_clip

  return first_label;
}

unsigned char *fill_all_DNS_labels(struct nbnodename_list *content,
				   unsigned char *walker,
				   unsigned char *endof_pckt,
				   struct nbnodename_list **state) {
  struct nbnodename_list *iterator;
  unsigned char *field;

  /* I have to check if I can fit the terminating 0 into
     the packet here because content may be NULL. */
  if ((walker +1) > endof_pckt) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return walker;
  }

  field = walker;

  if (state) {
    if (*state) {
      iterator = *state;
    } else {
      iterator = content;
    }
  } else {
    iterator = content;
  }

  while (iterator) {
    /* field + 1 octet for the len + 1 octet for the
       terminating 0 + the len of the label */
    if ((field + 2 + iterator->len) > endof_pckt) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      if (state) {
	*state = iterator;
	return field;
      } else {
	memset(walker, 0, (field-walker));
	return walker;
      }
    }
    *field = iterator->len;
    field++;
    field = mempcpy(field, iterator->name, iterator->len);
    iterator = iterator->next_name;
  }

  *field = '\0';
  field++;

  return field;
}

unsigned char *fastfrwd_all_DNS_labels(unsigned char **start_and_end_of_walk,
				       unsigned char *endof_pckt) {
  unsigned char *walker;
  unsigned char step;

  if (! start_and_end_of_walk) {
    return 0;
  } else {
    if (*start_and_end_of_walk >= endof_pckt) {
      return 0;
    }
  }

  walker = *start_and_end_of_walk;
  while (0xb0b0) {
    step = *walker;
    if (step > MAX_DNS_LABEL_LEN) {
      step = 1;
      break;
    } else {
      if (step)
	walker = (walker + step +1);
      else
	break;
    }

    if (walker >= endof_pckt)
      return 0;
  }

  walker = walker + step + 1;

  *start_and_end_of_walk = walker;

  return walker;
}

struct nbaddress_list *read_nbaddress_list(unsigned char **start_and_end_of_walk,
					   uint16_t len_of_addresses,
					   unsigned char *end_of_packet) {
  struct nbaddress_list *result, *return_result;
  unsigned char *walker;

  if ((*start_and_end_of_walk + len_of_addresses) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    *start_and_end_of_walk = end_of_packet;
    return 0;
  }

  if (len_of_addresses < 2) {
    *start_and_end_of_walk = *start_and_end_of_walk +len_of_addresses;
    return 0;
  }
  walker = *start_and_end_of_walk;

  return_result = malloc(sizeof(struct nbaddress_list));
  if (! return_result) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  return_result->next_address = 0;
  result = return_result;

  while (0xdead101) {
    walker = read_16field(walker, &(result->flags));
    len_of_addresses = len_of_addresses - 2;

    if (len_of_addresses >= 4) {
      result->there_is_an_address = TRUE;
      walker = read_32field(walker, &(result->address));
      len_of_addresses = len_of_addresses - 4;

    } else {
      result->there_is_an_address = FALSE;
      /* Presumably, this is the end of the list. */
      /* Master packet walker is updated before the return. */
      result->next_address = 0;
      break;
    }

    if (len_of_addresses >= 2) {
      result->next_address = malloc(sizeof(struct nbaddress_list));
      if (! result->next_address) {
	/* TODO: errno signaling stuff */
	while (return_result) {
	  result = return_result->next_address;
	  free(return_result);
	  return_result = result;
	}
	return 0;
      }
      result = result->next_address;
    } else {
      result->next_address = 0;
      break;
    }

  }

  *start_and_end_of_walk = walker + len_of_addresses;

  return return_result;
}

unsigned char *fill_nbaddress_list(struct nbaddress_list *content,
				   unsigned char *walker,
				   unsigned char *endof_pckt) {
  while (content) {
    if (content->there_is_an_address == TRUE) {
      if ((walker +6) > endof_pckt) {
	/* OUT_OF_BOUNDS */
	/* TODO: errno signaling stuff */
	return walker;
      }
      walker = fill_16field(content->flags, walker);
      walker = fill_32field(content->address, walker);
    } else {
      if ((walker +2) > endof_pckt) {
	/* OUT_OF_BOUNDS */
	/* TODO: errno signaling stuff */
	return walker;
      }
      walker = fill_16field(content->flags, walker);
    }
    content = content->next_address;
  }

  return walker;
}

struct nbaddress_list *read_ipv4_address_list(unsigned char **start_and_end_of_walk,
					      uint16_t len_of_addresses,
					      unsigned char *end_of_packet) {
  struct nbaddress_list *result, *return_result;
  unsigned char *walker;

  if ((*start_and_end_of_walk + len_of_addresses) > end_of_packet) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    *start_and_end_of_walk = end_of_packet;
    return 0;
  }

  if (len_of_addresses < 4) {
    *start_and_end_of_walk = *start_and_end_of_walk +len_of_addresses;
    return 0;
  }
  walker = *start_and_end_of_walk;

  return_result = malloc(sizeof(struct nbaddress_list));
  if (! return_result) {
    /* TODO: errno signaling stuff */
    *start_and_end_of_walk = *start_and_end_of_walk +len_of_addresses;
    return 0;
  }
  return_result->next_address = 0;
  result = return_result;

  while (0xbeef101) {
    walker = read_32field(walker, &(result->address));
    len_of_addresses = len_of_addresses - 4;

    if (len_of_addresses >= 4) {
      result->next_address = malloc(sizeof(struct nbaddress_list));
      if (! result->next_address) {
	/* TODO: errno signaling stuff */
	while (return_result) {
	  result = return_result->next_address;
	  free(return_result);
	  return_result = result;
	}
        *start_and_end_of_walk = *start_and_end_of_walk +len_of_addresses;
	return 0;
      }
      result = result->next_address;
      result->next_address = 0;
    } else {
      break;
    }
  }

  *start_and_end_of_walk = walker + len_of_addresses;

  return return_result;
}

unsigned char *fill_ipv4_address_list(struct nbaddress_list *content,
				      unsigned char *walker,
				      unsigned char *endof_pckt) {
  while (content) {
    if ((walker +4) > endof_pckt) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      return walker;
    }
    walker = fill_32field(content->address, walker);
    content = content->next_address;
  }

  return walker;
}
