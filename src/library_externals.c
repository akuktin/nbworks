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

#include "c_lang_extensions.h"

#include "nbworks.h"
#include "constdef.h"
#include "nodename.h"

nbworks_errno_t nbworks_errno;

#ifdef DO_ALIGN_FIELDS
nbworks_do_align_t nbworks_do_align = 1;
#else
nbworks_do_align_t nbworks_do_align = 0;
#endif

ipv4_addr_t nbworks__myip4addr;

const char nbworks_jokername[] = JOKER_NAME;
const char nbworks_jokernamecoded[] = JOKER_NAME_CODED;

struct nbworks_libcntl_t nbworks_libcntl;
