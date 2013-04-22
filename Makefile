#
#  This file is part of nbworks, an implementation of NetBIOS.
#  Copyright (C) 2013 Aleksandar Kuktin <akuktin@gmail.com>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

CFLAGS ?= -O3 -g -Wall
CC ?= gcc
MKDIR ?= mkdir
RM ?= rm
RF ?= -rf

SYSTEM_IS_MACRO = -DSYSTEM_IS_LINUX

FILES_FOR_DAEMON = config.c daemon.c daemon_externals.c dtg_srvc_func.c     \
                   dtg_srvc_pckt.c name_srvc_cache.c name_srvc_cnst.c       \
                   name_srvc_func_B.c name_srvc_func_P.c                    \
                   name_srvc_func_func.c name_srvc_pckt.c nodename.c        \
                   pckt_routines.c portability.c rail-comm.c rail-flush.c   \
                   randomness.c service_sector.c service_sector_threads.c   \
                   ses_srvc_pckt.c

FILES_FOR_LIBRARY = api.c dtg_srvc_cnst.c dtg_srvc_pckt.c library.c         \
                    library_externals.c nodename.c pckt_routines.c          \
                    portability.c rail-flush.c randomness.c ses_srvc_pckt.c

DAEMON_STARTER = daemon_main.c
NBNS_STARTER = nbns_main.c

SRCDIR = src

OBJDIR_NBNS = obj-nbns
OBJDIR_DAEMON = obj-daemon
OBJDIR_LIBRARY = obj-library

OBJS_FOR_NBNS = $(addprefix $(OBJDIR_NBNS)/,$(FILES_FOR_DAEMON:.c=.o) \
                                            $(NBNS_STARTER:.c=.o))
OBJS_FOR_DAEMON = $(addprefix $(OBJDIR_DAEMON)/,$(FILES_FOR_DAEMON:.c=.o) \
                                                $(DAEMON_STARTER:.c=.o))
OBJS_FOR_LIBRARY = $(addprefix $(OBJDIR_LIBRARY)/,$(FILES_FOR_LIBRARY:.c=.o))

.PHONY all: nbworksd libnbworks.so.0.0 nbworksnbnsd

.PHONY clean:
	$(RM) $(RF) $(OBJDIR_NBNS) $(OBJDIR_DAEMON) $(OBJDIR_LIBRARY) \
	      nbworksd libnbworks.* nbworksnbnsd

nbworksd: $(OBJS_FOR_DAEMON)
	$(CC) $(CFLAGS) $+ -o $@ -lpthread

libnbworks.so.0.0: $(OBJS_FOR_LIBRARY)
	$(CC) $(CFLAGS) $+ -o $@ -lpthread

nbworksnbnsd: $(OBJS_FOR_NBNS)
	$(CC) $(CFLAGS) $+ -o $@ -lpthread


$(OBJDIR_NBNS)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -DCOMPILING_NBNS $(SYSTEM_IS_MACRO) -Iinclude -c -o $@ $<

$(OBJDIR_DAEMON)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -DCOMPILING_DAEMON $(SYSTEM_IS_MACRO) -Iinclude -c -o $@ $<

$(OBJDIR_LIBRARY)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(SYSTEM_IS_MACRO) -Iinclude -c -o $@ $<

$(OBJS_FOR_NBNS): | $(OBJDIR_NBNS)

$(OBJS_FOR_DAEMON): | $(OBJDIR_DAEMON)

$(OBJS_FOR_LIBRARY): | $(OBJDIR_LIBRARY)

$(OBJDIR_NBNS):
	$(MKDIR) $(OBJDIR_NBNS)

$(OBJDIR_DAEMON):
	$(MKDIR) $(OBJDIR_DAEMON)

$(OBJDIR_LIBRARY):
	$(MKDIR) $(OBJDIR_LIBRARY)
