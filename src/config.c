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

#define LENOF_BUF 0xff

char option_default_nbns[] = "default_nbns";


/* FIXME: make this Unicode compliant. */
struct option *parse_config(char *path) {
  struct option *result, **last_option, *cur_opt;
  ssize_t ret_val;
  unsigned long lenof_data;
  int fd;
  unsigned int in_comment, in_word, in_equal, in_data;
  char buf[LENOF_BUF], *walker, *end_walk;
  char command_buf[LENOF_BUF+1], *comwalker, *com_endof;
  char *option;

  fd = open_configfile(path);
  if (fd < 0) {
    return 0;
  }

  last_option = &result;
  in_comment = FALSE;
  in_word = FALSE;
  in_equal = FALSE;
  in_data = FALSE;
  option = 0;
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
	  if (*walker == SYSTEMS_NEWLINE) {
	    comwalker--;
	    if (comwalker < command_buf) {
	      comwalker = command_buf;
	    }
	    *comwalker = 0;
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

    /* Test all options. In reality, this should be done by using
     * some black magic, but I will think about that later on. */

    if (0 == strcmp(option_default_nbns, command_buf)) {
      option = option_default_nbns;
      in_equal = TRUE;
      goto do_jumpover_equal;
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
    comwalker--;
    if (comwalker < command_buf) {
      comwalker = command_buf;
    }
    *comwalker = 0;
#endif
    in_data = FALSE;

  do_save_option:
    cur_opt = malloc(sizeof(struct option));
    if (! cur_opt) {
      goto do_keep_walking;
    }
    cur_opt->nameof_option = option;
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

    if (ret_val)
      goto do_keep_walking;
    else
      break;
  }

  *last_option = 0;

  return result;
}
