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

#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "constdef.h"
#include "portability.h"
#include "daemon_control.h"
#include "config.h"
#include "pckt_routines.h"

#define LENOF_BUF 0xff

struct option_match all_options[] = {{option_default_nbns,
				      "default_nbns"},
				     {option_nooption,
				      0}};


/* FIXME: make this Unicode compliant. */
struct option *parse_config(char *path) {
  struct option *result, **last_option, *cur_opt;
  struct option_match *option_selector;
  ssize_t ret_val;
  unsigned long lenof_data;
  int fd;
  unsigned int in_comment, in_word, in_equal, in_data;
  char buf[LENOF_BUF], *walker, *end_walk;
  char command_buf[LENOF_BUF+1], *comwalker, *com_endof;
  enum config_option option;

  if (! path)
    return 0;
  fd = open_configfile(path);
  if (fd < 0) {
    return 0;
  }

  last_option = &result;
  in_comment = FALSE;
  in_word = FALSE;
  in_equal = FALSE;
  in_data = FALSE;
  option = option_nooption;
  lenof_data = 0;
  walker = end_walk = comwalker = 0;

  com_endof = command_buf + LENOF_BUF;
  command_buf[LENOF_BUF] = 0;

  while (LENOF_BUF) {
    ret_val = read(fd, buf, LENOF_BUF);
    if (ret_val <= 0) {
      close(fd);
      if (ret_val == 0) {
	if (in_data)
	  goto do_save_option;
	else
	  break;
      } else {
	*last_option = 0;
	cur_opt = result;
	while (cur_opt) {
	  free(cur_opt->data);
	  result = cur_opt->next;
	  free(cur_opt);
	  cur_opt = result;
	}
	return 0;
      }
    }

    walker = buf;
    end_walk = walker + ret_val;

    if (in_comment)
      goto do_keep_walking;
    if (in_word)
      goto do_read_word;
    if (in_equal)
      goto do_jumpover_equal;
    if (in_data)
      goto do_read_data;

  start_reading_line:
    while ((*walker == ' ') ||
	   (*walker == '\t') ||
	   (*walker == SYSTEMS_NEWLINE) ||
	   (*walker == SYSTEMS_STRINGSTOP)) {
      /* This can create some REALLY weird effects on certain systems
       * under very exact conditions. One of those conditions is that
       * the option name begins with the \r character. */
      walker++;
      if (walker >= end_walk)
	break;
    }

    if (walker >= end_walk) {
      continue;
    }

    if (*walker == '#') {
    do_keep_walking:
      in_comment = FALSE;
      while (*walker != SYSTEMS_NEWLINE) {
	walker++;
	if (walker >= end_walk) {
	  in_comment = TRUE;
	  break;
	}
      }
      walker++; /* Move to the next character.
		 * Resiliant to an end-of-buffer error condition. */
      if (walker >= end_walk)
	continue;
      goto start_reading_line;
    }

    in_word = TRUE;
    comwalker = command_buf;
  do_read_word:
    while (comwalker < com_endof) {
      if (walker < end_walk) {
	if ((*walker != ' ') &&
	    (*walker != '\t') &&
	    (*walker != '=') &&
	    (*walker != SYSTEMS_NEWLINE)) {
	  *comwalker = *walker;
	  comwalker++;
	  walker++;
	} else {
#ifdef SYSTEM_IS_WINDOWS
	  /* This, too, can create weird effect on some systems under very specific
	   * conditions. */
	  if (*walker == SYSTEMS_NEWLINE) {
	    comwalker--;
	    if (comwalker < command_buf) {
	      comwalker = command_buf;
	    }
	  }
#endif
	  break;
	}
      } else {
	break;
      }
    }
    if (walker >= end_walk)
      continue;
    in_word = FALSE;
    *comwalker = 0;

    /* Parse the option label. */
    for (option_selector = all_options;
	 option_selector->option != option_nooption;
	 option_selector++) {
      if (0 == strcmp(option_selector->option_text, command_buf)) {
	option = option_selector->option;
	in_equal = TRUE;
	break;
      }
    }

    if (! in_equal)
      goto do_keep_walking;

  do_jumpover_equal:
    while ((*walker == ' ') ||
	   (*walker == '\t') ||
	   (*walker == '=')) {
      walker++;
      if (walker >= end_walk) {
	break;
      }
    }
    if (walker >= end_walk)
      continue;
    in_equal = FALSE;

    lenof_data = 0;
    in_data = TRUE;
    comwalker = command_buf;
  do_read_data:
    while (*walker != SYSTEMS_NEWLINE) {
      if (comwalker < com_endof) {
	lenof_data++;
	*comwalker = *walker;
	comwalker++;
	walker++;
	if (walker >= end_walk)
	  break;
      } else {
	in_data = FALSE;
	goto do_keep_walking;
      }
    }
    if (walker >= end_walk)
      continue;
#ifdef SYSTEM_IS_WINDOWS
    /* Yet another instance where it becomes painfully obvious
     * that you should not use more than one character to signify
     * the end of the line. */
    if (lenof_data) {
      lenof_data--;
    }
#endif
    in_data = FALSE;

  do_save_option:
    cur_opt = malloc(sizeof(struct option));
    if (! cur_opt) {
      goto do_keep_walking;
    }
    cur_opt->option = option;
    cur_opt->lenof_data = lenof_data;
    if (lenof_data) {
      cur_opt->data = malloc(lenof_data);
      if (! cur_opt->data) {
	free(cur_opt);
	goto do_keep_walking;
      }
      memcpy(cur_opt, command_buf, lenof_data);
    } else {
      cur_opt->data = 0;
    }
    *last_option = cur_opt;
    last_option = &(cur_opt->next);

    if (ret_val) {
      option = option_nooption;
      goto do_keep_walking;
    } else
      break;
  }

  *last_option = 0;

  return result;
}

/* returns: >0 = success; 0 = failure; <0 = error */
int do_configure(void) {
  struct option *options, *cur_opt;
  char **file_selector;

  options = 0;
  file_selector = (config_files -1);
  do {
    file_selector++;
    if (! *file_selector)
      return 0;
    else
      if (*file_selector == ENVIRONMENT_CONFIG_FILE_PLACEHOLDER)
	continue;
    options = parse_config(*file_selector);
  } while (! options);

  cur_opt = options;
  while (cur_opt) {
    switch (cur_opt->option) {
    case option_default_nbns:
      nbworks__default_nbns = read_ipv4_addr_conf(cur_opt->data,
						  cur_opt->lenof_data);
      break;

    default:
      /* Nothing. Just ignore unknown options. */
      break;
    }

    cur_opt = cur_opt->next;
  }

  while (options) {
    cur_opt = options->next;
    if (options->data)
      free(options->data);
    free(options);
    options = cur_opt;
  }

  return 1;
}


/* FIXME: make this Unicode compliant. */
ipv4_addr_t read_ipv4_addr_conf(unsigned char *field,
				unsigned int len) {
  ipv4_addr_t result;
  unsigned int i;
  unsigned char *walker, *endof_walk, block[4];

  if ((! field) ||
      (len < (1+1 + 1+1 + 1+1 +1))) {
    return 0;
  }

  endof_walk = field + len;
  walker = field;

  i = 0;
  block[0] = block[1] = block[2] = block[3] = 0;
  while (walker < endof_walk) {
    if ((*walker >= '0') &&
	(*walker <= '9')) {
      block[i] = (block[i] * 10) + (*walker - '0');
    } else {
      if (*walker == '.') {
	i++;
	if (i>3)
	  break;
      } else {
	if (i != 3)
	  return 0;
	else
	  break;
      }
    }

    walker++;
  }

  if (i != 3)
    return 0;

  /* I will burn in hell. */
  read_32field(block, &result);

  return result;
}
