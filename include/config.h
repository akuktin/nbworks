/*
 *  This file is part of nbworks, an implementation of NetBIOS.
 *  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NBWORKS_CONFIG_H
# define NBWORKS_CONFIG_H 1

enum config_option {
  option_nooption = 0,
  option_default_nbns
};

struct option_match {
  enum config_option option;
  char *option_text;
};

struct option {
  enum config_option option;
  unsigned long lenof_data;
  unsigned char *data;
  struct option *next;
};


struct option *
  parse_config(char *path);
int
  do_configure(void);

ipv4_addr_t
  read_ipv4_addr_conf(unsigned char *field,
                      unsigned int len);

#endif /* NBWORKS_CONFIG_H */
