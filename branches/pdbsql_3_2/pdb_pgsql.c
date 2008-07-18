/*
 * PostgresSQL password backend for samba
 * Copyright (C) Hamish Friedlander 2003
 * Copyright (C) Jelmer Vernooij 2004-2006
 * Copyright (C) Wilco Baan Hofman 2006
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 675
 * Mass Ave, Cambridge, MA 02139, USA.
 *
 * TODO
 * * Volker commited Trust domain passwords to be included in the pdb.
 *   These need to be added here:
 *   bool get_trusteddom_pw(struct pdb_methods *methods, const char *domain, char **pwd, DOM_SID *sid, time_t *pass_last_set_time)
 *   bool set_trusteddom_pw(struct pdb_methods *methods, const char *domain, const char *pwd, const DOM_SID *sid)
 *   bool del_trusteddom_pw(struct pdb_methods *methods, const char *domain)
 *   NTSTATUS enum_trusteddoms(struct pdb_methods *methods, TALLOC_CTX *mem_ctx, uint32 *num_domains, struct trustdom_info ***domains)
 */

#include "pdb_sql.h"
#include <libpq-fe.h>

/* To prevent duplicate defines */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_VERSION
#undef PACKAGE_TARNAME
#include <pg_config.h>

#define CONFIG_HOST_DEFAULT				"localhost"
#define CONFIG_USER_DEFAULT				"samba"
#define CONFIG_PASS_DEFAULT				""
#define CONFIG_PORT_DEFAULT				DEF_PGPORT_STR
#define CONFIG_DB_DEFAULT				"samba"

static int pgsqlsam_debug_level = DBGC_ALL;

#undef DBGC_CLASS
#define DBGC_CLASS pgsqlsam_debug_level

/* handles for doing db transactions */
typedef struct pdb_pgsql_data {
	PGconn     *master_handle;
	PGconn     *handle;

	PGresult   *pwent;
	long        currow;
	const char *db;
	const char *host;
	const char *port;
	const char *user;
	const char *pass;

	const char *location;
} pdb_pgsql_data;

/* Store the data needed for the _search_next_entry iterator */
typedef struct pdb_pgsql_search_state {
	uint32_t acct_flags;

	PGresult *pwent;
	long currow;
} pdb_pgsql_search_state;

#define SET_DATA(data,methods) { \
	if(!methods){ \
		DEBUG(0, ("invalid methods!\n")); \
			return NT_STATUS_INVALID_PARAMETER; \
	} \
	data = (struct pdb_pgsql_data *)methods->private_data; \
}


#define SET_DATA_QUIET(data,methods) { \
	if(!methods){ \
		DEBUG(0, ("invalid methods!\n")); \
			return; \
	} \
	data = (struct pdb_pgsql_data *)methods->private_data; \
}


#define config_value(data, name, default_value) \
	lp_parm_const_string(GLOBAL_SECTION_SNUM, (data)->location, name, default_value)

static PGconn *pgsqlsam_connect(struct pdb_pgsql_data *data)
{
	PGconn *handle;
  
	DEBUG(1, ("Connecting to database server, host: %s, user: %s, password: XXXXXX, database: %s, port: %s\n",
				data->host, data->user, data->db, data->port));
  
	/* Do the pgsql initialization */
	handle = PQsetdbLogin(
			data->host,
			data->port,
			NULL,
			NULL,
			data->db,
			data->user,
			data->pass);
  
	if (handle != NULL && PQstatus(handle) != CONNECTION_OK) {
		DEBUG(0, ("Failed to connect to pgsql database: error: %s\n",
				(handle != NULL ? PQerrorMessage(handle) : "")));
		return NULL;
	}
  
	DEBUG(5, ("Connected to pgsql database\n"));
	return handle;
}

/* The assumption here is that the master process will get connection 0,
 * and all the renaining ones just one connection for their etire life span.
 */
static PGconn *choose_connection(struct pdb_pgsql_data *data)
{
	if (data->master_handle == NULL) {
		data->master_handle = pgsqlsam_connect(data);
		return data->master_handle;
	}

	/* Master connection != NULL, so we are just another process. */

	/* If we didn't connect yet, do it now. */
	if (data->handle == NULL) {
		data->handle = pgsqlsam_connect(data);
	}

	return data->handle;
}

static long PQgetlong(PGresult *r, long row, long col)
{
	if (PQgetisnull(r, row, col)) {
		return 0;
	}
  
	return atol(PQgetvalue(r, row, col));
}

static NTSTATUS row_to_sam_account (PGresult *r, long row, struct samu *u)
{
	unsigned char temp[16];
	DOM_SID sid;
	unsigned char *hours;
	size_t hours_len = 0;
  
	if (row >= PQntuples(r)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	pdb_set_logon_time           (u, PQgetlong (r, row,  0), PDB_SET);
	pdb_set_logoff_time          (u, PQgetlong (r, row,  1), PDB_SET);
	pdb_set_kickoff_time         (u, PQgetlong (r, row,  2), PDB_SET);
	pdb_set_pass_last_set_time   (u, PQgetlong (r, row,  3), PDB_SET);
	pdb_set_pass_can_change_time (u, PQgetlong (r, row,  4), PDB_SET);
	pdb_set_pass_must_change_time(u, PQgetlong (r, row,  5), PDB_SET);
	pdb_set_username             (u, PQgetvalue(r, row,  6), PDB_SET);
	pdb_set_domain               (u, PQgetvalue(r, row,  7), PDB_SET);
	pdb_set_nt_username          (u, PQgetvalue(r, row,  8), PDB_SET);
	pdb_set_fullname             (u, PQgetvalue(r, row,  9), PDB_SET);
	pdb_set_homedir              (u, PQgetvalue(r, row, 10), PDB_SET);
	pdb_set_dir_drive            (u, PQgetvalue(r, row, 11), PDB_SET);
	pdb_set_logon_script         (u, PQgetvalue(r, row, 12), PDB_SET);
	pdb_set_profile_path         (u, PQgetvalue(r, row, 13), PDB_SET);
	pdb_set_acct_desc            (u, PQgetvalue(r, row, 14), PDB_SET);
	pdb_set_workstations         (u, PQgetvalue(r, row, 15), PDB_SET);
	pdb_set_comment              (u, PQgetvalue(r, row, 16), PDB_SET);
	pdb_set_munged_dial          (u, PQgetvalue(r, row, 17), PDB_SET);
 
	pdb_set_acct_ctrl            (u, PQgetlong (r, row, 23), PDB_SET);
	pdb_set_logon_divs           (u, PQgetlong (r, row, 24), PDB_SET);
	pdb_set_hours_len            (u, PQgetlong (r, row, 25), PDB_SET);
	pdb_set_bad_password_count   (u, PQgetlong (r, row, 26), PDB_SET);
	pdb_set_logon_count          (u, PQgetlong (r, row, 27), PDB_SET);
	pdb_set_unknown_6            (u, PQgetlong (r, row, 28), PDB_SET);
	
	hours = (unsigned char *) PQgetvalue (r, row,  29);
	if (hours != NULL) {
		hours = PQunescapeBytea(hours, &hours_len);
		if (hours_len > 0) {
			pdb_set_hours(u, hours, PDB_SET);
		}
	}
  
  
	if (!PQgetisnull(r, row, 18)) {
		string_to_sid(&sid, PQgetvalue(r, row, 18));
		pdb_set_user_sid(u, &sid, PDB_SET);
	}

	if (!PQgetisnull(r, row, 19)) {
		string_to_sid(&sid, PQgetvalue(r, row, 19));
		pdb_set_group_sid(u, &sid, PDB_SET);
	}
  
	if (pdb_gethexpwd(PQgetvalue(r, row, 20), temp)) {
		pdb_set_lanman_passwd(u, temp, PDB_SET);
	}
	if (pdb_gethexpwd(PQgetvalue(r, row, 21), temp)) {
		pdb_set_nt_passwd(u, temp, PDB_SET);
	}
	/* Set password history field */
	if (!PQgetisnull(r, row, 30)) {
		uint8 pwhist[MAX_PW_HISTORY_LEN * PW_HISTORY_ENTRY_LEN];
		int i;
		char *history_string = PQgetvalue(r, row, 30);
		
		memset(&pwhist, 0, MAX_PW_HISTORY_LEN * PW_HISTORY_ENTRY_LEN);
		for (i = 0; i < MAX_PW_HISTORY_LEN && i < strlen(history_string)/64; i++) {
			pdb_gethexpwd(&(history_string)[i*64], &pwhist[i*PW_HISTORY_ENTRY_LEN]);
			pdb_gethexpwd(&(history_string)[i*64+32], 
					&pwhist[i*PW_HISTORY_ENTRY_LEN+PW_HISTORY_SALT_LEN]);
		}
		pdb_set_pw_history(u, pwhist, strlen(history_string)/64, PDB_SET);
	}

  
	/* Only use plaintext password storage when lanman and nt are NOT used */
	if (PQgetisnull(r, row, 20) || PQgetisnull(r, row, 21)) {
		pdb_set_plaintext_passwd(u, PQgetvalue(r, row, 22));
	}
  
	return NT_STATUS_OK;
}

static NTSTATUS pgsqlsam_select_by_field(struct pdb_methods *methods, struct samu *user, enum sql_search_field field, const char *sname)
{
	struct pdb_pgsql_data *data;
	PGconn *handle;
  
	char *esc;
	char *query;
  
	PGresult *result;
	NTSTATUS retval;

	SET_DATA(data, methods);

	if (user == NULL) {
		DEBUG(0, ("pdb_getsampwnam: struct samu is NULL.\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
  
	DEBUG(5, ("pgsqlsam_select_by_field: getting data where %d = %s(nonescaped)\n", field, sname));
  
	/* Escape sname */
	esc = talloc_array(NULL, char, strlen(sname) * 2 + 1);
	if (!esc) {
		DEBUG(0, ("Can't allocate memory to store escaped name\n"));
		return NT_STATUS_NO_MEMORY; 
	}
  
	/* tmp_sname = smb_xstrdup(sname); */
	PQescapeString(esc, sname, strlen(sname));

	/* Connect to the DB. */
	handle = choose_connection(data);
	if (handle == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}
  
	query = sql_account_query_select(NULL, data->location, True, field, esc);
  
	/* Execute query */
	DEBUG(5, ("Executing query %s\n", query));
	result = PQexec(handle, query);
  
	/* Result? */
	if (result == NULL) {
		DEBUG(0, ("Error executing %s, %s\n", query, PQerrorMessage(handle)));
		retval = NT_STATUS_UNSUCCESSFUL;
	} else if (PQresultStatus(result) != PGRES_TUPLES_OK) {
		DEBUG(0, ("Error executing %s, %s\n", query, PQresultErrorMessage(result)));
		retval = NT_STATUS_UNSUCCESSFUL;
	} else {
		retval = row_to_sam_account(result, 0, user);
	}
  
	talloc_free(esc);
	talloc_free(query);
 
	if (result != NULL) {
		PQclear(result);
	}
	
	return retval;
}

/******************************************************************
  Lookup a name in the SAM database
 ******************************************************************/

static NTSTATUS pgsqlsam_getsampwnam(struct pdb_methods *methods, struct samu *user, const char *sname)
{
	struct pdb_pgsql_data *data;
	size_t i, l;
	char *lowercasename;
	NTSTATUS result;
  
	SET_DATA(data, methods);
  
	if (!sname) {
		DEBUG(0, ("invalid name specified"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	lowercasename = smb_xstrdup(sname);
	l = strlen(lowercasename);
	for(i = 0; i < l; i++) {
		lowercasename[i] = tolower_ascii(lowercasename[i]);
	}
  
	result = pgsqlsam_select_by_field(methods, user, SQL_SEARCH_USER_NAME, lowercasename);

	SAFE_FREE(lowercasename);

	return result;
}


/***************************************************************************
  Search by sid
 **************************************************************************/

static NTSTATUS pgsqlsam_getsampwsid(struct pdb_methods *methods, struct samu *user, const DOM_SID *sid)
{
	struct pdb_pgsql_data *data;
	fstring sid_str;
  
	SET_DATA(data, methods);
  
	sid_to_fstring(sid_str, sid);
  
	return pgsqlsam_select_by_field(methods, user, SQL_SEARCH_USER_SID, sid_str);
}

/***************************************************************************
  Delete a struct samu
 ****************************************************************************/

static NTSTATUS pgsqlsam_delete_sam_account(struct pdb_methods *methods, struct samu *sam_pass)
{
	struct pdb_pgsql_data *data;
	PGconn *handle;
  
	const char *sname = pdb_get_username(sam_pass);
	char *esc;
	char *query;
  
	PGresult *result;
	NTSTATUS retval;
 
	SET_DATA(data, methods);
  
	if (!sname) {
		DEBUG(0, ("invalid name specified\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
  
	/* Escape sname */
	esc = talloc_array(NULL, char, strlen(sname) * 2 + 1);
	if (!esc) {
		DEBUG(0, ("Can't allocate memory to store escaped name\n"));
		return NT_STATUS_NO_MEMORY;
	}
  
	PQescapeString(esc, sname, strlen(sname));

	/* Connect to the DB. */
	handle = choose_connection(data);
	if (handle == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
  	}
	query = sql_account_query_delete(NULL, data->location, esc);
  
	/* Execute query */
	result = PQexec(handle, query);
  
	if (result == NULL) {
		DEBUG(0, ("Error executing %s, %s\n", query, PQerrorMessage(handle)));
		retval = NT_STATUS_UNSUCCESSFUL;
	} else if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		DEBUG(0, ("Error executing %s, %s\n", query, PQresultErrorMessage(result)));
		retval = NT_STATUS_UNSUCCESSFUL;
	} else {
		DEBUG(5, ("User '%s' deleted\n", sname));
		retval = NT_STATUS_OK;
	}
  
	if (result != NULL) {
		    PQclear(result);
	}
	talloc_free(esc);
	talloc_free(query);
  
	return retval;
}

static NTSTATUS pgsqlsam_replace_sam_account(struct pdb_methods *methods, struct samu *newpwd, char isupdate)
{
	struct pdb_pgsql_data *data;
	PGconn *handle;
	char *query;
	PGresult *result;
	NTSTATUS retval;
  
	if (!methods) {
		DEBUG(0, ("invalid methods!\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}
  
	data = (struct pdb_pgsql_data *) methods->private_data;
  
	if (data == NULL) {
		DEBUG(0, ("invalid handle!\n"));
		return NT_STATUS_INVALID_HANDLE;
	}

	query = sql_account_query_update(NULL, data->location, newpwd, isupdate);
	if (query == NULL) {
		/* Nothing to update. */
		return NT_STATUS_OK;
	}
	/* Connect to the DB. */
	handle = choose_connection(data);
	if (handle == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Execute the query */
	result = PQexec(handle, query);
  
	if (result == NULL) {
		DEBUG(0, ("Error executing %s, %s\n", query, PQerrorMessage(handle)));
		retval = NT_STATUS_INVALID_PARAMETER;
	} else if (PQresultStatus(result) != PGRES_COMMAND_OK) {
		DEBUG(0, ("Error executing %s, %s\n", query, PQresultErrorMessage(result)));
		retval = NT_STATUS_INVALID_PARAMETER;
	} else {
		retval = NT_STATUS_OK;
	}
	
	if (result != NULL) {
		PQclear(result);
	}
	talloc_free(query);
  
	return retval;
}

static NTSTATUS pgsqlsam_add_sam_account(struct pdb_methods *methods, struct samu *newpwd)
{
	return pgsqlsam_replace_sam_account(methods, newpwd, 0);
}

static NTSTATUS pgsqlsam_update_sam_account(struct pdb_methods *methods, struct samu *newpwd)
{
	return pgsqlsam_replace_sam_account(methods, newpwd, 1);
}

static bool pgsqlsam_rid_algorithm(struct pdb_methods *pdb_methods) 
{
	return True;
}
static bool pgsqlsam_new_rid(struct pdb_methods *pdb_methods, uint32 *rid) 
{
	return False;
}

/* Iterate through search results, if a new entry is available: store in
 * entry and return True. Otherwise: return False
 */
static bool pgsqlsam_search_next_entry(struct pdb_search *search,
		struct samr_displayentry *entry)
{
	struct pdb_pgsql_search_state *search_state;
	DOM_SID sid;
	PGresult *r;
	long row;

	search_state = (struct pdb_pgsql_search_state *)search->private_data;
	r = search_state->pwent;
	row = search_state->currow;

	if (r == NULL) {
		DEBUG(0, ("invalid query result pointer\n"));
		return False;
	}

	if (row >= PQntuples(r)) {
		/* We've reached the end */
		return False;
	}
	
	/* Now why do we need to fill entry as rid is enough? Okay, it is a bit
	 * of a hack, but I don't see the point in filling everything when we
	 * never read it.
	 */ 
	if (!PQgetisnull(r, row, 18)) {
		string_to_sid(&sid, PQgetvalue(r, row, 18));
		entry->rid = sid.sub_auths[4];
	}

	entry->acct_flags = atoi(PQgetvalue(r, row, 23));
	entry->account_name = talloc_strdup(search->mem_ctx, PQgetvalue(r, row, 6));
	entry->fullname = talloc_strdup(search->mem_ctx, PQgetvalue(r, row, 9));
	entry->description = talloc_strdup(search->mem_ctx, PQgetvalue(r, row, 14));

	search_state->currow++;

	if ((entry->account_name == NULL)) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return False;
	}

	if (!(entry->acct_flags & search_state->acct_flags)) {
		return pgsqlsam_search_next_entry(search, entry);
 
	}

	return True;
}

/* Free the memory after a search, reset some default values */
static void pgsqlsam_search_end(struct pdb_search *search)
{
	struct pdb_pgsql_search_state *search_state;

	search_state = (struct pdb_pgsql_search_state *)search->private_data;

	if (search_state->pwent != NULL) {
		PQclear(search_state->pwent);
	}

	search_state->pwent = NULL;
	search_state->currow = 0;

	talloc_free(search);

	DEBUG(5, ("pgsqlsam_search_end called\n"));
}

/* Prepare a search object for iterating through the users */
static bool pgsqlsam_search_users(struct pdb_methods *pdb_methods,
		struct pdb_search *search, uint32_t acct_flags)
{
	struct pdb_pgsql_data *data;
	struct pdb_pgsql_search_state *search_state;
	PGconn *handle;
	char *query;

	data = (struct pdb_pgsql_data *) pdb_methods->private_data;
  
	search_state = TALLOC_ZERO_P(search->mem_ctx, struct pdb_pgsql_search_state);
	if (search_state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return False;
	}
	search_state->acct_flags = acct_flags;

	if (!pdb_methods) {
		DEBUG(0, ("invalid methods!\n"));
		return False;
	}

	handle = choose_connection(data);
	if (handle == NULL) {
		DEBUG(0, ("Unable to obtain handle\n"));
		return False;
	}

	/* The query to select all the users */
	query = sql_account_query_select(NULL, data->location, False, SQL_SEARCH_NONE, NULL);

	DEBUG(5, ("Executing query: %s\n", query));
	search_state->pwent = PQexec(handle, query);
	search_state->currow = 0;
	talloc_free(query);

	/* Check results */
	if (search_state->pwent == NULL) {
		DEBUG(0, ("Error executing %s, %s\n", query, PQerrorMessage(handle)));
		return False;
	} else if (PQresultStatus(search_state->pwent) != PGRES_TUPLES_OK) {
		DEBUG(0, ("Error executing %s, %s\n", query, PQresultErrorMessage(search_state->pwent)));
		return False;
	} else {
		DEBUG(5, ("pgsqlsam_search_users succeeded(%d results)!\n", PQntuples(search_state->pwent)));
	}
	search->private_data = search_state;
	search->next_entry = pgsqlsam_search_next_entry;
	search->search_end = pgsqlsam_search_end;
  
	return True;
}

static NTSTATUS pgsqlsam_init (struct pdb_methods **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	  
	struct pdb_pgsql_data *data;

	pgsqlsam_debug_level = debug_add_class("pgsqlsam");
	if (pgsqlsam_debug_level == -1) {
		pgsqlsam_debug_level = DBGC_ALL;
		DEBUG(0,
			  ("pgsqlsam: Couldn't register custom debugging class!\n"));
	}

        if ( !NT_STATUS_IS_OK(nt_status = make_pdb_method( pdb_method )) ) {
		return nt_status;
        }
  
  
	(*pdb_method)->name               = "pgsqlsam";
  
	(*pdb_method)->search_users       = pgsqlsam_search_users;
	(*pdb_method)->getsampwnam        = pgsqlsam_getsampwnam;
	(*pdb_method)->getsampwsid        = pgsqlsam_getsampwsid;
	(*pdb_method)->add_sam_account    = pgsqlsam_add_sam_account;
	(*pdb_method)->update_sam_account = pgsqlsam_update_sam_account;
	(*pdb_method)->delete_sam_account = pgsqlsam_delete_sam_account;
	(*pdb_method)->rid_algorithm      = pgsqlsam_rid_algorithm;
	(*pdb_method)->new_rid            = pgsqlsam_new_rid;

	data = talloc(*pdb_method, struct pdb_pgsql_data);
	(*pdb_method)->private_data = data;

	data->master_handle = NULL;
	data->handle = NULL;
	data->pwent  = NULL;

	if (!location) {
		DEBUG(0, ("No identifier specified. Check the Samba HOWTO Collection for details\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data->location = smb_xstrdup(location);

	if(!sql_account_config_valid(data->location)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(1, ("Database server parameters: host: %s, user: %s, password: XXXX, database: %s, port: %s\n",
			config_value(data, "pgsql host"    , CONFIG_HOST_DEFAULT),
			config_value(data, "pgsql user"    , CONFIG_USER_DEFAULT),
			config_value(data, "pgsql database", CONFIG_DB_DEFAULT  ),
			config_value(data, "pgsql port"    , CONFIG_PORT_DEFAULT)));

	/* Save the parameters. */
	data->db   = config_value(data, "pgsql database", CONFIG_DB_DEFAULT  );
	data->host = config_value(data, "pgsql host"    , CONFIG_HOST_DEFAULT);
	data->port = config_value(data, "pgsql port"    , CONFIG_PORT_DEFAULT);
	data->user = config_value(data, "pgsql user"    , CONFIG_USER_DEFAULT);
	data->pass = config_value(data, "pgsql password", CONFIG_PASS_DEFAULT);

	DEBUG(5, ("Pgsql module initialized\n"));
	return NT_STATUS_OK;
}

NTSTATUS init_samba_module(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "pgsql", pgsqlsam_init);
}

/* For backwards compatibility with either 3.2.0~r2 or Debian */
NTSTATUS init_module(void)
{
	return init_samba_module();
}

