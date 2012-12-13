#include "c_lang_extensions.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "constdef.h"
#include "name_srvc_pckt.h"


inline unsigned char *read_16field(unsigned char *content,
				   uint16_t *field) {
  int i;

  *field = 0;
  for (i = 1; i >= 0; i--) {
    *field = (*field | *content) << (8 * i);
    content++;
  }

  return content;
}
inline unsigned char *read_32field(unsigned char *content,
                                   uint32_t *field) {
  int i;

  *field = 0;
  for (i = 3; i >= 0; i--) {
    *field = (*field | *content) << (8 * i);
    content++;
  }

  return content;
}

inline unsigned char *read_64field(unsigned char *content,
                                   uint64_t *field) {
  int i;

  *field = 0;
  for (i = 7; i >= 0; i--) {
    *field = (*field | *content) << (8 * i);
    content++;
  }

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

struct nbnodename_list *read_all_DNS_labels(void **start_and_end_of_walk,
					    void *start_of_packet) {
  struct nbnodename_list *first_label, *cur_label;
  int name_len, weighted_companion_pointer;
  unsigned int name_offset;
  unsigned char *walker;
  unsigned char buf[MAX_DNS_LABEL_LEN +1]; /* saves us calls to
					      malloc() and free() */

  if (start_of_packet >= *start_and_end_of_walk) {
    /* TODO: errno signaling stuff */
    return 0;
  }

  first_label = malloc(sizeof(struct nbnodename_list));
  if (! first_label) {
    /* TODO: errno signaling stuff */
    return 0;
  }
  first_label->name = 0;
  cur_label = first_label;

  walker = (unsigned char *)*start_and_end_of_walk;
  name_offset = ONES;
  buf[MAX_DNS_LABEL_LEN] = '\0';

  /* Read RFC 1002 and RFC 883 for
     details and understanding of
     what exactly is going on here. */

  while (*walker != 0) {
    if (*walker <= MAX_DNS_LABEL_LEN) {
      while (0xf0e4) { /* while 0xf0r_ev4! */
	cur_label->len = *walker;
	name_len = *walker;
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
	    if (first_label->name) {
	      free(first_label->name);
	    }
	    free(first_label);
	    first_label = cur_label;
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
	  continue;
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
      walker = (unsigned char *)(start_of_packet + name_offset);
    }
  }
  if (first_label->name == 0) {
    /* This means we have been only been fed the root label,
       which is NULL, which is imposibble to parse and should
       never happen (I think).
       Please be a good routine and get ready to puke for us. */
    while (first_label) {
      cur_label = first_label->next_name;
      if (first_label->name) {
	free(first_label->name);
      }
      free(first_label);
      first_label = cur_label;
    }
  } else {
    cur_label->next_name = 0;
  }

  if (name_offset == ONES) {
    /* Read the pre-previous comment.
       If this test has succeded, then we have not encountered
       a single pointer, *start_and_end_of_walk has not been
       updated, so we update it now. */
    *start_and_end_of_walk = walker +1;
  }

  return first_label;
}

unsigned char *fill_all_DNS_labels(struct nbnodename_list *content,
				   unsigned char *field) {
  struct nbnodename_list *iterator;

  iterator = content;

  while (iterator) {
    *field = content->len;
    field++;
    field = mempcpy(field, content->name, content->len);
    iterator = content->next_name;
  }

  field = '\0';
  field++;

  return field;
}
