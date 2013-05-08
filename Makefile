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

ETCDIR ?= /etc
PREFIX ?= /usr/local
EPREFIX ?= $(PREFIX)

####################

BINDIR = $(EPREFIX)/bin
LIBDIR = $(EPREFIX)/lib
INCLUDEDIR = $(PREFIX)/include

DATAROOTDIR = $(PREFIX)/share
MANDIR = $(DATAROOTDIR)/man
#DOCDIR = $(DATAROOTDIR)/doc/nbworks

INSTALL_DIRS = $(ETCDIR) $(PREFIX) $(EPREFIX) $(BINDIR) $(LIBDIR)       \
               $(INCLUDEDIR) $(DATAROOTDIR) $(MANDIR) $(MANDIR)/man3    \
               $(MANDIR)/man7 $(MANDIR)/man8 $(DOCDIR)


CFLAGS ?= -g -Wall
CC ?= gcc
MKDIR ?= mkdir -p
RM_RF ?= rm -rf
LN_SV ?= ln -s
INSTALL ?= install

SYSTEM_IS_MACRO = -DSYSTEM_IS_LINUX

FILES_FOR_DAEMON = config.c daemon.c daemon_externals.c dtg_srvc_func.c     \
                   dtg_srvc_pckt.c name_srvc_cache.c name_srvc_cnst.c       \
                   name_srvc_func_B.c name_srvc_func_P.c                    \
                   name_srvc_func_func.c name_srvc_pckt.c nodename.c        \
                   pckt_routines.c portability.c rail-comm.c rail-flush.c   \
                   randomness.c service_sector.c service_sector_threads.c   \
                   ses_srvc_pckt.c c-lib.c

FILES_FOR_LIBRARY = api.c dtg_srvc_cnst.c dtg_srvc_pckt.c library.c         \
                    library_externals.c nodename.c pckt_routines.c          \
                    portability.c rail-flush.c randomness.c ses_srvc_pckt.c \
                    c-lib.c

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

.PHONY : all lib clean install

all: nbworksd libnbworks.so.0.0 # nbworksnbnsd

lib: libnbworks.so.0.0

clean:
	$(RM_RF) $(OBJDIR_NBNS) $(OBJDIR_DAEMON) $(OBJDIR_LIBRARY) \
	    nbworksd libnbworks.* nbworksnbnsd

install: all | $(sort $(INSTALL_DIRS))
	$(INSTALL) nbworksd $(BINDIR)
	$(INSTALL) libnbworks.so.0.0 $(LIBDIR)
	if [ -e $(LIBDIR)/libnbworks.so.0 ]; then $(RM_RF) $(LIBDIR)/libnbworks.so.0; fi
	$(LN_SV) libnbworks.so.0.0 $(LIBDIR)/libnbworks.so.0
	if [ -e $(LIBDIR)/libnbworks.so ]; then $(RM_RF) $(LIBDIR)/libnbworks.so; fi
	$(LN_SV) libnbworks.so.0 $(LIBDIR)/libnbworks.so
	$(INSTALL) include/nbworks.h $(INCLUDEDIR)
	$(INSTALL) nbworks.conf.SAMPLE $(ETCDIR)/nbworks.conf
	$(INSTALL) doc/*.3 $(MANDIR)/man3
	$(INSTALL) doc/*.7 $(MANDIR)/man7
	$(INSTALL) doc/*.8 $(MANDIR)/man8

nbworksd: $(OBJS_FOR_DAEMON)
	$(CC) $(CFLAGS)  $+ -o $@ -lpthread

libnbworks.so.0.0: $(OBJS_FOR_LIBRARY)
	$(CC) $(CFLAGS) -fpic -fPIC $+ -shared -o $@ -lpthread

nbworksnbnsd: $(OBJS_FOR_NBNS)
	$(CC) $(CFLAGS)  $+ -o $@ -lpthread


$(OBJDIR_NBNS)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -DCOMPILING_NBNS $(SYSTEM_IS_MACRO)  -Iinclude -c -o $@ $<

$(OBJDIR_DAEMON)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -DCOMPILING_DAEMON $(SYSTEM_IS_MACRO)  -Iinclude -c -o $@ $<

$(OBJDIR_LIBRARY)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) $(SYSTEM_IS_MACRO) -fpic -fPIC -Iinclude -c -o $@ $<

$(OBJS_FOR_NBNS): | $(OBJDIR_NBNS)

$(OBJS_FOR_DAEMON): | $(OBJDIR_DAEMON)

$(OBJS_FOR_LIBRARY): | $(OBJDIR_LIBRARY)

$(OBJDIR_NBNS):
	$(MKDIR) $(OBJDIR_NBNS)

$(OBJDIR_DAEMON):
	$(MKDIR) $(OBJDIR_DAEMON)

$(OBJDIR_LIBRARY):
	$(MKDIR) $(OBJDIR_LIBRARY)

$(ETCDIR) $(PREFIX) $(PREFIX)/%:
	$(MKDIR) $@
