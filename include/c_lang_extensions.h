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

#ifndef NBWORKS_CLANGEXTENSIONS_H
# define NBWORKS_CLANGEXTENSIONS_H 1

# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif

# ifndef _POSIX_C_SOURCE
#  define _POSIX_C_SOURCE 199309
# endif

# ifdef SYSTEM_DOES_NOT_HAVE_MEMPCPY
#  define mempcpy(a, b, c) (memcpy(a, b, c), (a+c))
# endif

#endif /* NBWORKS_CLANGEXTENSIONS_H */
