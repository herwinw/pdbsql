/*
 * Common PDB SQL backend functions
 * Copyright (C) Jelmer Vernooij 2003-2004
 *
 * This program is free software; you can redistribute it and/or modify 
it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your 
option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License 
for
 * more details.
 *
 * You should have received a copy of the GNU General Public License 
along with
 * this program; if not, write to the Free Software Foundation, Inc., 
675
 * Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

#ifndef _PDB_SQL_H
#define _PDB_SQL_H

enum sql_search_field { SQL_SEARCH_NONE = 0, SQL_SEARCH_USER_SID = 1, SQL_SEARCH_USER_NAME = 2};

char *sql_escape_string(TALLOC_CTX *mem_ctx, const char *unesc);
char *sql_account_query_select(TALLOC_CTX *mem_ctx, const char *data, BOOL update, enum sql_search_field field, const char *value);
char *sql_account_query_delete(TALLOC_CTX *mem_ctx, const char *data, const char *esc) ;
char *sql_account_query_update(TALLOC_CTX *mem_ctx, const char *location, const SAM_ACCOUNT *newpwd, char isupdate);
BOOL sql_account_config_valid(const char *data);

#endif /* _PDB_SQL_H */

