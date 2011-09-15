/*
   Kerberos 5 migration module
   Version 0.0.3.
   PAM authentication module to transparently add passwords to a Kerberos 5
   database.

   Copyright (C) Steve Langasek 2000-2001
   Copyright (C) Jelmer Vernooij 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef _PAM_KRB5_MIGRATE_H
#define _PAM_KRB5_MIGRATE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syslog.h>
#include <pwd.h>
#include <krb5.h>
#include <kadm5/admin.h>
#include <kadm5/kadm5_err.h>

#ifndef LINUX

/* This is only used in the Sun implementation. */
#include <security/pam_appl.h>

#endif  /* LINUX */

#include <security/pam_modules.h>

#endif /* _PAM_KRB5_MIGRATE_H */
