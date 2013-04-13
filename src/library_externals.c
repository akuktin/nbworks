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

#include <stdint.h>

#include "library_control.h"
#include "constdef.h"

nbworks_errno_t nbworks_errno;

#ifdef DO_ALIGN_FIELDS
nbworks_do_align_t nbworks_do_align = 1;
#else
nbworks_do_align_t nbworks_do_align = 0;
#endif

uint32_t brdcst_addr;
uint32_t my_ip4_address;

struct nbworks_libcntl_t nbworks_libcntl;
