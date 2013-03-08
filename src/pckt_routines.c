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

void destroy_namepointer(struct DNS_label_pointer_list *first) {
  struct DNS_label_pointer_list *next;

  while (first) {
    next = first->next;
    free(first->label);
    free(first);
    first = next;
  }

  return;
}

struct nbnodename_list *read_all_DNS_labels(unsigned char **start_and_end_of_walk,
					    unsigned char *start_of_packet,
					    unsigned char *end_of_packet,
					    struct state__readDNSlabels **state,
					    struct DNS_label_pointer_block **pointer_blck,
					    uint32_t offsetof_start) {
  struct nbnodename_list *first_label, *cur_label;
  struct DNS_label_pointer_list *pointer_root, *pointer,
    **pointer_nxt, **pointer_lbl;
  int name_len, weighted_companion_pointer;
  uint32_t name_offset, pckt_offset;
  unsigned char *walker, **label_ptr;
  unsigned char *startblock, *endof_startblock;
  unsigned char buf[MAX_DNS_LABEL_LEN +1]; /* saves us calls to
					      malloc() and free() */

  if (*start_and_end_of_walk < start_of_packet ||
      *start_and_end_of_walk >= end_of_packet) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  /* @@ MACROS BEGIN @------------------------------------------- */
  /* This is the point where C stops being sleak and sexy. */

#define alloc_stateless_labels					\
  first_label = calloc(1, sizeof(struct nbnodename_list));	\
  if (! first_label) {						\
    /* TODO: errno signaling stuff */				\
    return 0;							\
  }								\
  cur_label = first_label;					\
  								\
  name_offset = ONES;


#define handle_abort					\
  *pointer_nxt = 0;					\
  if (pointer_lbl)					\
    *pointer_lbl = 0;					\
  if (pointer_blck) {					\
    (*pointer_blck)->pointer_root = pointer_root;	\
    if (pointer_root) {					\
      (*pointer_blck)->pointer_next = pointer_nxt;	\
    } else {						\
      (*pointer_blck)->pointer_next = 0;		\
    }							\
    (*pointer_blck)->pointer_brokenlbl = pointer_lbl;	\
  } else {						\
    destroy_namepointer(pointer_root);			\
  }							\
							\
  if (state) {						\
    (*state)->first_label = first_label;		\
    (*state)->cur_label = cur_label;			\
    (*state)->name_offset = name_offset;		\
							\
    if (name_offset == ONES)				\
      *start_and_end_of_walk = walker;			\
    return 0;						\
  } else {						\
    /* TODO: errno signaling stuff */			\
    cur_label->name = 0;				\
    cur_label->next_name = 0;				\
    destroy_nbnodename(first_label);			\
    *start_and_end_of_walk = end_of_packet;		\
    return 0;						\
  }

  /* MEMMAN_NOTES: be carefull about this one. cur_label->name
   *               is not touched, but destroy_nbnodename() IS
   *               called on cur_label. If cur_label->name is
   *               not initialized, you will crash, or worse.
   *               Therefore: pay attention and if cur_label->name
   *               is not set before kill_yourself is called,
   *               you have to NULL it. */
#define kill_yourself					\
  *pointer_nxt = 0;					\
  if (pointer_lbl)					\
    *pointer_lbl = 0;					\
  if (state) {						\
    free(*state);					\
    *state = 0;						\
  }							\
  cur_label->next_name = 0;				\
  destroy_nbnodename(first_label);			\
  if (pointer_blck) {					\
    free(*pointer_blck);				\
    *pointer_blck = 0;					\
  }							\
  destroy_namepointer(pointer_root);			\
  *start_and_end_of_walk = end_of_packet;		\
  return 0;

  /* MEMMAN_NOTES: 1. After the macro exits in the first branch case,
   *               a new pointer structure has been added with the
   *               previous one's links set to point to this one.
   *               The new pointer structure has position and labellen
   *               filled, label is either malloced or is NULL and
   *               next_label and next are undefined. The label_ptr
   *               has been updated to either point to the malloced
   *               label buffer or NULL and is thus safe for use.
   *               2. After the macro exits in the second branch case,
   *               no new pointer structures are added, and the previous
   *               structures' forward links are terminated. The
   *               label_ptr has been NULLed and is thus safe for use. 
   *          Conclusion:
   *               The pointer structures' internal values are never
   *               manipulated directly by the code. There are exactly
   *               three pointer pointers that are used as handles to
   *               internal value fields. All three are properly
   *               initialized and are thus safe. */
#define move_pointer							\
  if ((pckt_offset <= MAX_PACKET_POINTER) || pointer_lbl) {		\
    pointer = malloc(sizeof(struct DNS_label_pointer_list));		\
    if (! pointer) {							\
      cur_label->name = 0;						\
      kill_yourself;							\
    }									\
    pointer->position = pckt_offset;					\
    if (name_len) {							\
      /* IMPORTANT: pckt_offset is updated by this macro! */		\
      pckt_offset = pckt_offset + name_len +1;				\
      if (pckt_offset < name_len) {					\
	pckt_offset = ONES;						\
      }									\
									\
      pointer->label = malloc(name_len+1);				\
      if (! pointer->label) {						\
	cur_label->name = 0;						\
	kill_yourself;							\
      }									\
      label_ptr = &(pointer->label);					\
    } else {								\
      pointer->label = 0;						\
      label_ptr = 0;							\
    }									\
    pointer->labellen = name_len;					\
									\
    if (pointer_lbl)							\
      *pointer_lbl = pointer;						\
    pointer_lbl = &(pointer->next_label);				\
									\
    *pointer_nxt = pointer;						\
    pointer_nxt = &(pointer->next);					\
  } else {								\
    *pointer_nxt = 0;							\
    if (pointer_lbl) {							\
      *pointer_lbl = 0;							\
      pointer_lbl = 0;							\
    }									\
  }
  /* I don't have to NULL out label_ptr because it is non-NULL only
   * in a short span of time between allocing a new pointer structure
   * and cloning the label into it. */

  /* @@ MACROS END @--------------------------------------------- */

  if (pointer_blck) {
    if (*pointer_blck) {
      pointer_root = (*pointer_blck)->pointer_root;
      pointer_nxt = (*pointer_blck)->pointer_next;
      if (! pointer_nxt) {
	pointer_nxt = &(pointer_root);
	pointer = *pointer_nxt;
	while (pointer) {
	  pointer_nxt = &(pointer->next);
	  pointer = *pointer_nxt;
	}
      }
      pointer_lbl = (*pointer_blck)->pointer_brokenlbl;
      startblock = (*pointer_blck)->startblock;
      endof_startblock = (*pointer_blck)->endof_startblock;
    } else {
      *pointer_blck = malloc(sizeof(struct DNS_label_pointer_block));
      if (! (*pointer_blck)) {
	return 0;
      }
      (*pointer_blck)->startblock = 0;
      (*pointer_blck)->endof_startblock = 0;

      pointer_root = 0;
      pointer_nxt = &pointer_root;
      pointer_lbl = 0;
      startblock = 0;
      endof_startblock = 0;
    }
  } else {
    pointer_root = 0;
    pointer_nxt = &pointer_root;
    pointer_lbl = 0;
    startblock = 0;
    endof_startblock = 0;
  }
  label_ptr = 0;


  if (state) {
    if (*state) {
      first_label = (*state)->first_label;
      cur_label = (*state)->cur_label;
      name_offset = (*state)->name_offset;

    } else {
      *state = malloc(sizeof(struct state__readDNSlabels));
      if (! (*state)) {
	/* TODO: errno signaling stuff */
	return 0;
      }

      alloc_stateless_labels;
    }
  } else {
    alloc_stateless_labels;
  }

  if (startblock > endof_startblock) {
    cur_label->name = 0;
    kill_yourself;
  }

  /* ------------- */

  walker = *start_and_end_of_walk;
  pckt_offset = offsetof_start + (walker - start_of_packet);
  if (offsetof_start > MAX_PACKET_POINTER) {
    offsetof_start = ONES;
    pckt_offset = ONES;
  }
  buf[MAX_DNS_LABEL_LEN] = '\0';

  /* -XX--   END INIT   --XX- */
  /* BEGIN TEXT */

  /* Read RFC 1002 and RFC 883 for
     details and understanding of
     what exactly is going on here. */
  /* Not counting the start-stop system, ofcourse. */

  /* MEMMAN_NOTES: at the start of every label processing, whether
   *               pointer or not, cur_label's contents are well
   *               defined: they are totaly undefined. */

  while (*walker != 0) {
    if (*walker <= MAX_DNS_LABEL_LEN) {
      while (0xf0e4) { /* while 0xf0r_ev4! */
	name_len = *walker;
	if ((walker + name_len +1) >= end_of_packet) {
	  /* OUT_OF_BOUNDS */
	  handle_abort;
	}

	/* ------------------------ */
	move_pointer;
	/* ------------------------ */

	cur_label->len = name_len;
	walker++;
	for (weighted_companion_pointer = 0;
	     weighted_companion_pointer < name_len;
	     weighted_companion_pointer++) {
	  buf[weighted_companion_pointer] = *walker;
	  walker++;
	}
	/* buf[weighted_companion_pointer] is now
	 * pointing to the slot after the last
	 * character. So we terminate it. */
	/* weighted_companion_pointer == name_len */
	buf[weighted_companion_pointer] = '\0';

	cur_label->name = malloc(weighted_companion_pointer +1);
	if (! cur_label->name) {
	  /* TODO: errno signaling stuff */
	  kill_yourself;
	}

	/* Also copy the terminating NULL. */
	memcpy((void *)cur_label->name, (void *)buf,
	       weighted_companion_pointer +1);
	if (label_ptr) {
	  memcpy(*label_ptr, buf, weighted_companion_pointer +1);
	  label_ptr = 0;
	}

	/* see the for loop above if you are wondering about walker */
	if (*walker <= MAX_DNS_LABEL_LEN &&
	    *walker != 0) {
	  cur_label->next_name = malloc(sizeof(struct nbnodename_list));
	  if (! cur_label->next_name) {
	    kill_yourself;
	  }
	  cur_label = cur_label->next_name;
	} else
	  break;
	/* This would be impossible in Perl. */
      }
    } else { /* that is, *walker > MAX_DNS_LABEL_LEN */
      /* pckt_pointer points to the first octet of the pointer. */
      if ((walker +1) >= end_of_packet) {
	/* OUT_OF_BOUNDS */
	handle_abort;
      }

      /* ------------------------ */
      name_len = 0;
      move_pointer;
      /* ------------------------ */

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

      /* ------------------------ */

      *pointer_nxt = 0;

      pointer = pointer_root;
      while (pointer) {
	if (pointer->position == name_offset)
	  break;
	else
	  pointer = pointer->next;
      }

      if (pointer) {
	/* pointer_lbl is set in the move_pointer macro */
	*pointer_lbl = pointer;
	name_offset = ONES -1;

	while (0x69) {
	  if (pointer->position == pckt_offset) {
	    *pointer_lbl = 0;
	    cur_label->name = 0;
	    cur_label->next_name = 0;
	    destroy_nbnodename(first_label);

	    break;
	  }
	  if (pointer->labellen == 0) {
	    pointer = pointer->next_label;
	    continue;
	  }

	  name_len = pointer->labellen;
	  cur_label->name = malloc(name_len);
	  memcpy(cur_label->name, pointer->label, name_len);
	  cur_label->len = name_len;

	  pointer = pointer->next_label;
	  if (pointer) {
	    cur_label->next_name = malloc(sizeof(struct nbnodename_list));
	    if (! cur_label->next_name) {
	      kill_yourself;
	    }
	    cur_label = cur_label->next_name;
	  } else {
	    cur_label->next_name = 0;
	    break;
	  }
	}

	break;
      } else {
	pckt_offset = name_offset;

	if (offsetof_start <= name_offset) {
	  walker = start_of_packet + (name_offset - offsetof_start);
	  if (walker >= end_of_packet) {
	    handle_abort;
	  }
	} else {
	  if (startblock) {
	    walker = startblock + name_offset;
	    if (walker >= endof_startblock) {
	      cur_label->name = 0;
	      kill_yourself;
	    }
	  } else {
	    cur_label->name = 0;
	    kill_yourself;
	  }
	}
      }

    }
  }

  cur_label->next_name = 0;
  if (first_label->name == 0) {
    /* This means we have been only been fed the root label,
       which is NULL, which is imposibble to parse and should
       never happen (I think).
       Please be a good routine and get ready to puke for us. */
    destroy_nbnodename(first_label);
    first_label = 0;
  }

  if (name_offset == ONES) {
    /* Read the fourth comment up.
       If this test has succeded, then we have not encountered
       a single pointer, *start_and_end_of_walk has not been
       updated, so we update it now. */
    *start_and_end_of_walk = walker +1;
  }

  if (state)
    free(*state);

  if (pointer_blck) {
    if (*pointer_blck) {
      (*pointer_blck)->pointer_root = pointer_root;
      (*pointer_blck)->pointer_next = pointer_nxt;
      (*pointer_blck)->pointer_brokenlbl = 0;
    } else {
      *pointer_blck = calloc(1, sizeof(struct DNS_label_pointer_block));
      if (*pointer_blck) {
	(*pointer_blck)->pointer_root = pointer_root;
	(*pointer_blck)->pointer_next = pointer_nxt;
      } else {
	*pointer_nxt = 0;
	destroy_namepointer(pointer_root);
      }
    }
  } else {
    *pointer_nxt = 0;
    destroy_namepointer(pointer_root);
  }

#undef move_pointer
#undef kill_yourself
#undef handle_abort
#undef alloc_stateless_labels

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
