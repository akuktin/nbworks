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

#include "daemon_control.h"
#include "library_control.h"
#include "constdef.h"

#ifdef COMPILING_NBNS
# include "service_sector.h"

struct ss__NBNStrans ss_alltrans[MAXNUMOF_TIDS];
#endif

nbworks_do_align_t nbworks_do_align;
nbworks_errno_t nbworks_errno;
struct nbworks_all_port_cntl_t nbworks_all_port_cntl;
struct nbworks__rail_control_t nbworks__rail_control;
struct nbworks_namsrvc_cntrl_t nbworks_namsrvc_cntrl;
struct nbworks_dtg_srv_cntrl_t nbworks_dtg_srv_cntrl;
struct nbworks_ses_srv_cntrl_t nbworks_ses_srv_cntrl;
struct nbworks_pruners_cntrl_t nbworks_pruners_cntrl;
struct nbworks_libcntl_t nbworks_libcntl;
uint32_t nbworks__default_nbns;
struct cache_scopenode *nbworks_rootscope;
