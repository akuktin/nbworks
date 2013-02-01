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
					    unsigned char *start_of_packet,
					    unsigned char *end_of_packet,
					    struct state__readDNSlabels **state) {
  struct DNS_label_pointer_list {
    uint16_t pointer;
    struct DNS_label_pointer_list *next_pointer;
  };

  struct nbnodename_list *first_label, *cur_label;
  struct DNS_label_pointer_list *pointers_visited,
    *pointers_visited_root, *pointers_visited_last;
  int name_len, weighted_companion_pointer;
  unsigned int name_offset;
  unsigned char *walker;
  unsigned char buf[MAX_DNS_LABEL_LEN +1]; /* saves us calls to
					      malloc() and free() */

  if (*start_and_end_of_walk < start_of_packet ||
      *start_and_end_of_walk >= end_of_packet) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  if (state) {
    if (*state) {
      first_label = (*state)->first_label;
      cur_label = (*state)->cur_label;
      pointers_visited_root = (*state)->pointers_visited_root;
      name_offset = (*state)->name_offset;
      walker = (*state)->walker;

      if (walker >= end_of_packet ||
	  walker < start_of_packet)
	return 0;
    } else {
      *state = malloc(sizeof(struct state__readDNSlabels));
      if (! (*state)) {
	/* TODO: errno signaling stuff */
	return 0;
      }

      first_label = malloc(sizeof(struct nbnodename_list));
      if (! first_label) {
	/* TODO: errno signaling stuff */
	return 0;
      }
      first_label->name = 0;
      first_label->next_name = 0;
      cur_label = first_label;

      pointers_visited_root = 0;
      name_offset = ONES;
      walker = *start_and_end_of_walk;
    }
  } else {
    first_label = malloc(sizeof(struct nbnodename_list));
    if (! first_label) {
      /* TODO: errno signaling stuff */
      return 0;
    }
    first_label->name = 0;
    first_label->next_name = 0;
    cur_label = first_label;

    pointers_visited_root = 0;
    name_offset = ONES;
    walker = *start_and_end_of_walk;
  }
  buf[MAX_DNS_LABEL_LEN] = '\0';
  pointers_visited = pointers_visited_last = 0;

  /* Read RFC 1002 and RFC 883 for
     details and understanding of
     what exactly is going on here. */
  /* Not counting the start-stop system, ofcourse. */

  while (*walker != 0) {
    if (*walker <= MAX_DNS_LABEL_LEN) {
      while (0xf0e4) { /* while 0xf0r_ev4! */
	name_len = *walker;
	if ((walker + name_len +1) >= end_of_packet) {
	  /* OUT_OF_BOUNDS */
	  if (state) {
	    (*state)->first_label = first_label;
	    (*state)->cur_label = cur_label;
	    (*state)->pointers_visited_root = pointers_visited_root;
	    (*state)->name_offset = name_offset;
	    (*state)->walker = walker;

	    if (name_offset == ONES)
	      *start_and_end_of_walk = walker;
	    return 0;
	  } else {
	    /* TODO: errno signaling stuff */
	    while (first_label) {
	      cur_label = first_label->next_name;
	      free(first_label->name);
	      free(first_label);
	      first_label = cur_label;
	    }
	    while (pointers_visited_root) {
	      pointers_visited = pointers_visited_root->next_pointer;
	      free(pointers_visited_root);
	      pointers_visited_root = pointers_visited;
	    }
	    *start_and_end_of_walk = end_of_packet;
	    return 0;
	  }
	}
	cur_label->len = name_len;
	walker++;
	for (weighted_companion_pointer = 0;
	     weighted_companion_pointer < name_len;
	     weighted_companion_pointer++) {
	  buf[weighted_companion_pointer] = *walker;
	  walker++;
	}
	/* buf[weighted_companion_pointer] is now
	   pointing to the slot after the last
	   character. So we terminate it. */
	buf[weighted_companion_pointer] = '\0';

	cur_label->name = malloc(weighted_companion_pointer +1);
	if (! cur_label->name) {
	  /* TODO: errno signaling stuff */
	  while (first_label) {
	    cur_label = first_label->next_name;
	    free(first_label->name);
	    free(first_label);
	    first_label = cur_label;
	  }
	  while (pointers_visited_root) {
	    pointers_visited = pointers_visited_root->next_pointer;
	    free(pointers_visited_root);
	    pointers_visited_root = pointers_visited;
	  }
	  return 0;
	}
	/* I know what I am doing. */
	/* Note to self: also copy the terminating NULL. */
	memcpy((void *)cur_label->name, (void *)buf,
	       weighted_companion_pointer +1);

	/* see the for loop above if you are wondering about walker */
	if (*walker <= MAX_DNS_LABEL_LEN &&
	    *walker != 0) {
	  cur_label->next_name = malloc(sizeof(struct nbnodename_list));
	  cur_label = cur_label->next_name;
	} else
	  break;
	/* So far in my life, this is the only case in which
	   I have found perl and its perky loops to be superior
	   to C. */
	/* Although, now that I am error-checking my work, seems
	   C is still superior. Imagine error-checking all this
	   crap in perl! Juck (and borderline impossible). */
      }
    } else { /* that is, *walker > MAX_DNS_LABEL_LEN */
      if ((walker +1) >= end_of_packet) {
	/* OUT_OF_BOUNDS */
	if (state) {
	  (*state)->first_label = first_label;
	  (*state)->cur_label = cur_label;
	  (*state)->pointers_visited_root = pointers_visited_root;
	  (*state)->name_offset = name_offset;
	  (*state)->walker = walker;

	  if (name_offset == ONES)
	    *start_and_end_of_walk = walker;
	  return 0;
	} else {
	  /* TODO: errno signaling stuff */
	  while (first_label) {
	    cur_label = first_label->next_name;
	    free(first_label->name);
	    free(first_label);
	    first_label = cur_label;
	  }
	  while (pointers_visited_root) {
	    pointers_visited = pointers_visited_root->next_pointer;
	    free(pointers_visited_root);
	    pointers_visited_root = pointers_visited;
	  }
	  *start_and_end_of_walk = end_of_packet;
	  return 0;
	}
      };
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
      walker = (start_of_packet + name_offset);
      if (walker >= end_of_packet) {
	/* OUT_OF_BOUNDS */
	if (state) {
	  (*state)->first_label = first_label;
	  (*state)->cur_label = cur_label;
	  (*state)->pointers_visited_root = pointers_visited_root;
	  (*state)->name_offset = name_offset;
	  (*state)->walker = walker;

	  if (name_offset == ONES)
	    *start_and_end_of_walk = walker;
	  return 0;
	} else {
	  /* TODO: errno signaling stuff */
	  while (first_label) {
	    cur_label = first_label->next_name;
	    free(first_label->name);
	    free(first_label);
	    first_label = cur_label;
	  }
	  while (pointers_visited_root) {
	    pointers_visited = pointers_visited_root->next_pointer;
	    free(pointers_visited_root);
	    pointers_visited_root = pointers_visited;
	  }
	  *start_and_end_of_walk = end_of_packet;
	  return 0;
	}
      }

      /* ------------------------ */
      /* The walker has now been updated. The "pointers_visited" code
	 Below is for detecting infinite loops. */

      /* Now, I COULD have been civilized and just followed the
         RFC 883 which specifies that pointers can only point
         backward, to parts of the packet which were already
         parsed. But, realistically, (a) I'm a jackass and, more
         importantly, (b) this is done for practice, meaning it
         has to be as complete as possible, but it is also done
         to provide a solution which works as advertised come
         hell or high water. */
      pointers_visited = pointers_visited_root;
      while (pointers_visited) {
	if (pointers_visited->pointer == name_offset) {
	  /* INFINITE_LOOP */
	  /* TODO: errno signaling stuff */
	  while (first_label) {
	    cur_label = first_label->next_name;
	    free(first_label->name);
	    free(first_label);
	    first_label = cur_label;
	  }
	  while (pointers_visited_root) {
	    pointers_visited = pointers_visited_root->next_pointer;
	    free(pointers_visited_root);
	    pointers_visited_root = pointers_visited;
	  }
	  return 0;
	}
	pointers_visited_last = pointers_visited;
	pointers_visited = pointers_visited->next_pointer;
      }
      pointers_visited = malloc(sizeof(struct DNS_label_pointer_list));
      if (! pointers_visited) {
	/* TODO: errno signaling stuff */
	while (first_label) {
	  cur_label = first_label->next_name;
	  free(first_label->name);
	  free(first_label);
	  first_label = cur_label;
	}
	while (pointers_visited_root) {
	  pointers_visited = pointers_visited_root->next_pointer;
	  free(pointers_visited_root);
	  pointers_visited_root = pointers_visited;
	}
	return 0;
      }
      pointers_visited->next_pointer = 0;
      if (pointers_visited_root)
	pointers_visited_last->next_pointer = pointers_visited;
      else
	pointers_visited_root = pointers_visited;
    }
  }
  if (first_label->name == 0) {
    /* This means we have been only been fed the root label,
       which is NULL, which is imposibble to parse and should
       never happen (I think).
       Please be a good routine and get ready to puke for us. */
    while (first_label) {
      cur_label = first_label->next_name;
      free(first_label->name);
      free(first_label);
      first_label = cur_label;
    }
    while (pointers_visited_root) {
      pointers_visited = pointers_visited_root->next_pointer;
      free(pointers_visited_root);
      pointers_visited_root = pointers_visited;
    }
  } else {
    cur_label->next_name = 0;
  }

  if (name_offset == ONES) {
    /* Read the third comment up.
       If this test has succeded, then we have not encountered
       a single pointer, *start_and_end_of_walk has not been
       updated, so we update it now. */
    *start_and_end_of_walk = walker +1;
  }

  if (state)
    free(*state);

  return first_label;
}

unsigned char *fill_all_DNS_labels(struct nbnodename_list *content,
				   unsigned char *field,
				   unsigned char *endof_pckt,
				   struct nbnodename_list **state) {
  struct nbnodename_list *iterator;

  /* I have to check if I can fit the terminating 0 into
     the packet here because content may be NULL. */
  if ((field +1) > endof_pckt) {
    /* OUT_OF_BOUNDS */
    /* TODO: errno signaling stuff */
    return field;
  }

  if (state) {
    if (*state) {
      iterator = *state;
    }
  } else {
    iterator = content;
  }

  while (iterator) {
    /* field + 1 octet for the len + 1 octet for the
       terminating 0 + the len of the label */
    if ((field + 2 + content->len) > endof_pckt) {
      /* OUT_OF_BOUNDS */
      /* TODO: errno signaling stuff */
      if (state)
	*state = iterator;
      return field;
    }
    *field = content->len;
    field++;
    field = mempcpy(field, content->name, content->len);
    iterator = content->next_name;
  }

  *field = '\0';
  field++;

  return field;
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
