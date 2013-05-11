/*
 * Support for multiple password databases
 * Copyright (C) Jelmer Vernooij 2006
 * Copyright (C) Wilco Baan Hofman 2006
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
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
 *   bool get_trusteddom_pw(struct pdb_methods *methods, const char *domain, char **pwd, struct dom_sid *sid, time_t *pass_last_set_time)
 *   bool set_trusteddom_pw(struct pdb_methods *methods, const char *domain, const char *pwd, const struct dom_sid *sid)
 *   bool del_trusteddom_pw(struct pdb_methods *methods, const char *domain)
 *   NTSTATUS enum_trusteddoms(struct pdb_methods *methods, TALLOC_CTX *mem_ctx, uint32 *num_domains, struct trustdom_info ***domains)
 */

#include "includes.h"
#include "passdb.h"

static int multisam_debug_level = DBGC_ALL;

#undef DBGC_CLASS
#define DBGC_CLASS multisam_debug_level

typedef struct multisam_data {
	const char *location;
	int num_backends;
	char **names;
	char **locations;
	struct pdb_methods **methods;
	struct pdb_methods *default_methods;
} multisam_data;

struct multisam_search_state {
	uint32_t acct_flags;
	int current;
	struct pdb_search **search;
	int num_backends;
};

static bool multisam_search_next_entry(struct pdb_search *search,
		struct samr_displayentry *entry)
{
	int i;
	struct multisam_search_state *state;

	state = talloc_get_type_abort(search->private_data, struct multisam_search_state);
	for (i = 0; i < state->num_backends; i++)
	{
		bool res;
		struct pdb_search *s = state->search[i];

		res = s->next_entry(s, entry);
		if (res == true)
			return true;
	}

	return false;
}

static void multisam_search_end(struct pdb_search *search)
{
	int i;
	struct multisam_search_state *state;

	state = talloc_get_type_abort(search->private_data, struct multisam_search_state);
	for (i = 0; i < state->num_backends; i++)
	{
		struct pdb_search *s = state->search[i];
		s->search_end(s);
	}

	talloc_free(search);
}

static bool multisam_search_users(struct pdb_methods *methods,
		struct pdb_search *search,
		uint32 acct_flags)
{
	struct multisam_search_state *state;
	struct multisam_data *data;
	int i;

	data = (struct multisam_data *) methods->private_data;
	state = talloc_zero(search, struct multisam_search_state);
	if (state == NULL)
	{
		DEBUG(0, ("Talloc failed\n"));
		return false;
	}

	state->acct_flags = acct_flags;
	state->current = 0;
	state->num_backends = data->num_backends;

	/* Initialize all backends, take care of the search structs */
	state->search = talloc_array(data, struct pdb_search *, data->num_backends);
	for (i = 0; i < data->num_backends; i++)
	{
		struct pdb_search *search2 = TALLOC_ZERO_P(data, struct pdb_search);
		memcpy(search2, search, sizeof(struct pdb_search));
		data->methods[i]->search_users(data->methods[i], search2, acct_flags);
		state->search[i] = search2;
	}

	search->private_data = state;
	search->next_entry = multisam_search_next_entry;
	search->search_end = multisam_search_end;
	return true;
}


#define SET_DATA(data,methods) { \
	if(!methods){ \
		DEBUG(0, ("invalid methods!\n")); \
		return NT_STATUS_INVALID_PARAMETER; \
	} \
	data = (struct multisam_data *)methods->private_data; \
	if(!data){ \
		return NT_STATUS_INVALID_HANDLE; \
	} \
}
#define IS_DEFAULT(methods, function) ((*(data->default_methods)->function) == (*(methods)->function))

static bool multisam_new_rid(struct pdb_methods *methods,
				uint32 *rid,
				short backend)
{
	short i;
	struct multisam_data *data;

	if (!methods) return false;
	data = (struct multisam_data *)methods->private_data;
	if (!data) return false;


	/* 250 tries.. Andrew Bartlett picked the number. */
	for (i = 0; *rid == 0 && i < 250; i++) {
		if (!data->methods[backend]->new_rid(data->methods[backend], rid)) {
			return false;
		}
		/* FIXME We need a function to check if a rid is used.
		if () {
			*rid = 0;
		} */
	}

	if (*rid == 0) {
		return false;
	}

	return true;
}

static bool multisam_search_groups(struct pdb_methods *methods,
		struct pdb_search *search)
{
	talloc_set_destructor(search, NULL);
	return false;
}

static bool multisam_search_aliases(struct pdb_methods *methods,
		struct pdb_search *search,
		const struct dom_sid *sid)
{
	talloc_set_destructor(search, NULL);
	return false;
}

static NTSTATUS multisam_get_account_policy(struct pdb_methods *methods, enum pdb_policy_type type, uint32 *value)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_set_account_policy(struct pdb_methods *methods, enum pdb_policy_type type, uint32 value)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_get_seq_num(struct pdb_methods *methods, time_t *seq_num)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* Tries gid_to_sid on every backend until one succeeds, returns true on success */
static bool multisam_gid_to_sid(struct pdb_methods *methods, gid_t gid,
		struct dom_sid *sid)
{
	short i;
	struct multisam_data *data;
	bool rv;

	if (!methods) return false;
	data = (struct multisam_data *)methods->private_data;
	if (!data) return false;

	for (i = 0; i < data->num_backends; i++) {
		rv = data->methods[i]->gid_to_sid(data->methods[i], gid, sid);
		if (rv == true) {
			return true;
		}
	}

	return false;
}

/* Tries sid_to_id on every backend until one succeeds, returns true on success */
static bool multisam_sid_to_id(struct pdb_methods *methods,
		const struct dom_sid *sid,
		union unid_t *id, enum lsa_SidType *type)
{
	short i;
	struct multisam_data *data;
	bool rv;

	if (!methods) return false;
	data = (struct multisam_data *)methods->private_data;
	if (!data) return false;

	for (i = 0; i < data->num_backends; i++) {
		rv = data->methods[i]->sid_to_id(data->methods[i], sid, id, type);
		if (rv == true) {
			return true;
		}
	}

	return false;
}

static NTSTATUS multisam_create_user(struct pdb_methods *methods,
					TALLOC_CTX *tmp_ctx, const char *name,
					uint32 acb_info, uint32 *rid)
{
	struct multisam_data *data;

	SET_DATA(data, methods);

	DEBUG(0, ("Creating user in first multisam backend\n"));

	/* XXX Might be nice to allow separations of machine accounts here? */


	/* Get a new free rid if necessary */
	if (data->methods[0]->capabilities(data->methods[0])) {
		multisam_new_rid(methods, rid, 0);
	}

	return data->methods[0]->create_user(data->methods[0], tmp_ctx, name, acb_info, rid);
}

static NTSTATUS multisam_delete_user(struct pdb_methods *methods,
					TALLOC_CTX *mem_ctx,
					struct samu *sam_acct)
{
	short i;
	struct multisam_data *data;

	SET_DATA(data, methods);

	for (i = 0; i < data->num_backends; i++) {
		if (NT_STATUS_IS_OK(data->methods[i]->delete_user(data->methods[i], mem_ctx, sam_acct))) {
			return NT_STATUS_OK;
		}
	}
	DEBUG(1, ("Could not find user in multisam backends\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS multisam_enum_group_memberships(struct pdb_methods *methods,
		TALLOC_CTX *mem_ctx,
		struct samu *user,
		struct dom_sid **pp_sids,
		gid_t **pp_gids,
		size_t *p_num_groups)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_enum_group_members(struct pdb_methods *methods,
					TALLOC_CTX *mem_ctx,
					const struct dom_sid *group,
					uint32 **pp_member_rids,
					size_t *p_num_members)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_delete_dom_group(struct pdb_methods *methods,
		TALLOC_CTX *mem_ctx,
		uint32 rid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_update_login_attempts (struct pdb_methods *methods, struct samu *newpwd, bool success)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
		struct dom_sid sid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
		gid_t gid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
		const char *name)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map)
{
	short i;
	struct multisam_data *data;

	SET_DATA(data, methods);

	DEBUG(1, ("Adding group map entry\n"));
	for (i = 0; i < data->num_backends; i++) {
		if (!IS_DEFAULT(data->methods[i], add_group_mapping_entry)) {
			return data->methods[i]->add_group_mapping_entry(data->methods[i], map);
		}
	}

	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_update_group_mapping_entry(struct pdb_methods *methods,
		GROUP_MAP *map)
{
	short i;
	struct multisam_data *data;
	NTSTATUS ret;

	SET_DATA(data, methods);

	for (i = 0; i < data->num_backends; i++) {
		if (!IS_DEFAULT(data->methods[i], update_group_mapping_entry)) {
			ret = data->methods[i]->update_group_mapping_entry(data->methods[i], map);
			if (NT_STATUS_IS_OK(ret)) {
				return ret;
			}
		}
	}
	return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS multisam_delete_group_mapping_entry(struct pdb_methods *methods,
		struct dom_sid sid)
{
	short i;
	struct multisam_data *data;
	NTSTATUS ret;

	SET_DATA(data, methods);

	for (i = 0; i < data->num_backends; i++) {
		if (!IS_DEFAULT(data->methods[i], delete_group_mapping_entry)) {
			ret = data->methods[i]->delete_group_mapping_entry(data->methods[i], sid);
			if (NT_STATUS_IS_OK(ret)) {
				return ret;
			}
		}
	}
	return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS multisam_enum_group_mapping(struct pdb_methods *methods,
		const struct dom_sid *sid, enum lsa_SidType sid_name_use,
		GROUP_MAP **pp_rmap, size_t *p_num_entries,
		bool unix_only)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

#if 0
static NTSTATUS multisam_find_alias(struct pdb_methods *methods,
				const char *name, struct dom_sid *sid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}
#endif

static NTSTATUS multisam_create_alias(struct pdb_methods *methods,
		const char *name, uint32 *rid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_delete_alias(struct pdb_methods *methods,
		const struct dom_sid *sid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_get_aliasinfo(struct pdb_methods *methods,
		const struct dom_sid *sid,
		struct acct_info *info)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_set_aliasinfo(struct pdb_methods *methods,
		const struct dom_sid *sid,
		struct acct_info *info)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_add_aliasmem(struct pdb_methods *methods,
		const struct dom_sid *alias, const struct dom_sid *member)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_del_aliasmem(struct pdb_methods *methods,
		const struct dom_sid *alias, const struct dom_sid *member)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS multisam_enum_aliasmem(struct pdb_methods *methods,
		const struct dom_sid *alias, TALLOC_CTX *mem_ctx,
		struct dom_sid **pp_members, size_t *p_num_members)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_alias_memberships(struct pdb_methods *methods,
		TALLOC_CTX *mem_ctx,
		const struct dom_sid *domain_sid,
		const struct dom_sid *members,
		size_t num_members,
		uint32 **pp_alias_rids,
		size_t *p_num_alias_rids)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* Creates user list in every backend */
#if 0
static NTSTATUS multisam_setsampwent(struct pdb_methods *methods, bool update, uint32 acb_mask)
{
	short i;
	struct multisam_data *data;
	NTSTATUS ret;

	SET_DATA(data, methods);

	DEBUG(1, ("Setsampwent executing..\n"));

	for (i = 0; i < data->num_backends; i++) {
		ret = data->methods[i]->setsampwent(data->methods[i], update, acb_mask);
		if (!NT_STATUS_IS_OK(ret)) {
			return ret;
		}
	}

	return NT_STATUS_OK;
}

/***************************************************************
  End enumeration of the passwd list.
 ****************************************************************/
/* Runs endsampwent on every backend */
static void multisam_endsampwent(struct pdb_methods *methods)
{
	short i;
	struct multisam_data *data;

	if (!methods) return;
	data = (struct multisam_data *)methods->private_data;
	if (!data) return;

	DEBUG(1, ("Freeing pwent results on multisam backends\n"));

	for (i = 0; i < data->num_backends; i++) {
		data->methods[i]->endsampwent(data->methods[i]);
	}
}

/*****************************************************************
  Get one struct samu from the list (next in line)
 *****************************************************************/
/* Reads every user from backend 0, then 1.. etc (returns one) */
static NTSTATUS multisam_getsampwent(struct pdb_methods *methods, struct samu * user)
{
	short i;
	struct multisam_data *data;
	NTSTATUS ret;

	SET_DATA(data, methods);

	for (i = 0; i < data->num_backends; i++) {
		ret = data->methods[i]->getsampwent(data->methods[i], user);
		if (NT_STATUS_IS_OK(ret)) {
			return ret;
		}
	}

	return NT_STATUS_INVALID_PARAMETER;
}
#endif

/******************************************************************
  Lookup a name in the SAM database
 ******************************************************************/
/* Tries to find the account in all backends until it succeeds or runs out of backends */
static NTSTATUS multisam_getsampwnam(struct pdb_methods *methods, struct samu * user,
		const char *sname)
{
	short i;
	struct multisam_data *data;
	NTSTATUS ret;

	SET_DATA(data, methods);

	for (i = 0; i < data->num_backends; i++) {
		DEBUG(5, ("Looking for user in %s\n", data->names[i]));
		if (NT_STATUS_IS_OK(ret = data->methods[i]->getsampwnam(data->methods[i], user, sname))) {
			DEBUG(3, ("Found user in %s\n", data->names[i]));
			return ret;
		}
	}
	return NT_STATUS_UNSUCCESSFUL;
}


/***************************************************************************
  Search by sid
 **************************************************************************/
/* Tries to find the account in all backends until it succeeds or runs out of backends */
static NTSTATUS multisam_getsampwsid(struct pdb_methods *methods, struct samu * user,
		const struct dom_sid * sid)
{
	short i;
	struct multisam_data *data;
	NTSTATUS ret;

	SET_DATA(data, methods);

	for (i = 0; i < data->num_backends; i++) {
		DEBUG(5, ("Looking for user in %s\n", data->names[i]));
		if (NT_STATUS_IS_OK(ret = data->methods[i]->getsampwsid(data->methods[i], user, sid))) {
			DEBUG(3, ("Found user in %s\n", data->names[i]));
			return ret;
		}
	}
	return NT_STATUS_UNSUCCESSFUL;
}

/***************************************************************************
  Delete a sam account
 ****************************************************************************/
/* Tries to delete the user from all backends, if one succeeds we're happy */
static NTSTATUS multisam_delete_sam_account(struct pdb_methods *methods,
							struct samu * sam_pass)
{
	short i;
	struct multisam_data *data;

	SET_DATA(data, methods);

	for (i = 0; i < data->num_backends; i++) {
		if (NT_STATUS_IS_OK(data->methods[i]->delete_sam_account(data->methods[i], sam_pass))) {
			return NT_STATUS_OK;
		}
	}
	DEBUG(1, ("Could not find SAM account in multisam backends\n"));
	return NT_STATUS_UNSUCCESSFUL;
}

/* Creates sam account in the first backend */
static NTSTATUS multisam_add_sam_account(struct pdb_methods *methods, struct samu * newpwd)
{
	struct multisam_data *data;

	SET_DATA(data, methods);

	DEBUG(0, ("Creating sam account in first multisam backend\n"));
	return data->methods[0]->add_sam_account(data->methods[0], newpwd);
}

/* Tries update in every backend, if one succeeds we're happy. */
static NTSTATUS multisam_update_sam_account(struct pdb_methods *methods,
							struct samu * newpwd)
{
	short i;
	struct multisam_data *data;
	NTSTATUS ret;

	SET_DATA(data, methods);
	DEBUG(5, ("Updating sam account.\n"));
	for (i = 0; i < data->num_backends; i++) {
		ret = data->methods[i]->update_sam_account(data->methods[i], newpwd);
		if (NT_STATUS_IS_OK(ret)) {
			return ret;
		}
	}
	return NT_STATUS_UNSUCCESSFUL;
}
static NTSTATUS multisam_rename_sam_account (struct pdb_methods *methods, struct samu *pwd, const char *newname)
{
	short i;
	struct multisam_data *data;
	NTSTATUS ret;

	SET_DATA(data, methods);
	DEBUG(5, ("Renaming sam account.\n"));
	for (i = 0; i < data->num_backends; i++) {
		ret = data->methods[i]->rename_sam_account(data->methods[i], pwd, newname);
		if (NT_STATUS_IS_OK(ret)) {
			return ret;
		}
	}
	return NT_STATUS_UNSUCCESSFUL;
}


static NTSTATUS multisam_lookup_rids(struct pdb_methods *methods,
		const struct dom_sid *domain_sid,
		int num_rids,
		uint32 *rids,
		const char **names,
		uint32 *attrs)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_create_dom_group(struct pdb_methods *methods,
		TALLOC_CTX *mem_ctx,
		const char *name,
		uint32 *rid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_add_groupmem(struct pdb_methods *methods,
		TALLOC_CTX *mem_ctx,
		uint32 group_rid,
		uint32 member_rid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_del_groupmem(struct pdb_methods *methods,
		TALLOC_CTX *mem_ctx,
		uint32 group_rid,
		uint32 member_rid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* The capabilities of the first backend is used. */
/* FIXME This should combine the capabilities from all the backends */
static uint32_t multisam_capabilities (struct pdb_methods *methods)
{
	return PDB_CAP_STORE_RIDS | PDB_CAP_ADS;
}

/* This function is a fallback for errors */
static bool multisam_dummy_new_rid (struct pdb_methods *methods, uint32 *rid)
{
	DEBUG(0, ("This function should not be used!\n"));
	return false;
}

static NTSTATUS multisam_init(struct pdb_methods **pdb_method, const char *location)
{
	NTSTATUS nt_status;
	int i;
	struct multisam_data *data;

	multisam_debug_level = debug_add_class("multisam");
	if (multisam_debug_level == -1) {
		multisam_debug_level = DBGC_ALL;
		DEBUG(0,
				("multisam: Couldn't register custom debugging class!\n"));
	}

	if ( !NT_STATUS_IS_OK(nt_status = make_pdb_method( pdb_method )) ) {
		return nt_status;
	}

	data = talloc(*pdb_method, struct multisam_data);
	(*pdb_method)->private_data = data;

	/* Create default_methods with default functions (as in pdb_interface.c) */
	if (!NT_STATUS_IS_OK(nt_status = make_pdb_method( &(data->default_methods)))) {
		DEBUG(0, ("Could not create default pdb_method\n"));
		return nt_status;
	}

	(*pdb_method)->name = "multisam";

	/* Mandatory implementation */
	/* (*pdb_method)->setsampwent = multisam_setsampwent; */
	/* (*pdb_method)->endsampwent = multisam_endsampwent; */
	/* (*pdb_method)->getsampwent = multisam_getsampwent; */
	(*pdb_method)->search_users = multisam_search_users;
	(*pdb_method)->getsampwnam = multisam_getsampwnam;
	(*pdb_method)->getsampwsid = multisam_getsampwsid;
	(*pdb_method)->add_sam_account = multisam_add_sam_account;
	(*pdb_method)->update_sam_account = multisam_update_sam_account;
	(*pdb_method)->delete_sam_account = multisam_delete_sam_account;
	(*pdb_method)->rename_sam_account = multisam_rename_sam_account;
	(*pdb_method)->capabilities = multisam_capabilities;
	(*pdb_method)->new_rid = multisam_dummy_new_rid;

	(*pdb_method)->create_user = multisam_create_user;
	(*pdb_method)->delete_user = multisam_delete_user;
	(*pdb_method)->gid_to_sid = multisam_gid_to_sid;
	(*pdb_method)->sid_to_id = multisam_sid_to_id;


	(*pdb_method)->update_login_attempts = multisam_update_login_attempts;
	(*pdb_method)->getgrsid = multisam_getgrsid;
	(*pdb_method)->getgrgid = multisam_getgrgid;
	(*pdb_method)->getgrnam = multisam_getgrnam;
	(*pdb_method)->create_dom_group = multisam_create_dom_group;
	(*pdb_method)->delete_dom_group = multisam_delete_dom_group;
	(*pdb_method)->enum_group_mapping = multisam_enum_group_mapping;
	(*pdb_method)->enum_group_members = multisam_enum_group_members;
	(*pdb_method)->enum_group_memberships = multisam_enum_group_memberships;
	(*pdb_method)->add_groupmem = multisam_add_groupmem;
	(*pdb_method)->del_groupmem = multisam_del_groupmem;
	(*pdb_method)->create_alias = multisam_create_alias;
	(*pdb_method)->delete_alias = multisam_delete_alias;
	(*pdb_method)->get_aliasinfo = multisam_get_aliasinfo;
	(*pdb_method)->set_aliasinfo = multisam_set_aliasinfo;
	(*pdb_method)->add_aliasmem = multisam_add_aliasmem;
	(*pdb_method)->del_aliasmem = multisam_del_aliasmem;
	(*pdb_method)->enum_aliasmem = multisam_enum_aliasmem;
	(*pdb_method)->enum_alias_memberships = multisam_alias_memberships;
	(*pdb_method)->lookup_rids = multisam_lookup_rids;
	(*pdb_method)->get_account_policy = multisam_get_account_policy;
	(*pdb_method)->set_account_policy = multisam_set_account_policy;
	(*pdb_method)->get_seq_num = multisam_get_seq_num;
	(*pdb_method)->search_users = multisam_search_users;
	(*pdb_method)->search_groups = multisam_search_groups;
	(*pdb_method)->search_aliases = multisam_search_aliases;
	/* Not yet implemented here */
#if 0
	(*pdb_method)->find_alias = multisam_find_alias;
#endif

	if (!location) {
		DEBUG(0, ("No identifier specified. Check the Samba HOWTO Collection for details\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data->location = talloc_strdup(data, location);
	data->names = str_list_make(data, data->location, NULL);
	data->num_backends = str_list_length((const char **)data->names);
	data->locations = talloc_array(data, char *, data->num_backends);
	data->methods = talloc_array(data, struct pdb_methods *, data->num_backends);

	for (i = 0; i < data->num_backends; i++) {
		struct pdb_init_function_entry *entry = NULL;

		data->locations[i] = strchr(data->names[i], ':');
		if (data->locations[i]) {
			*(data->locations[i]) = '\0';
			data->locations[i]++;
		}

		entry = pdb_find_backend_entry(data->names[i]);
		if (!entry) {
			DEBUG(2,("No builtin backend found, trying to load plugin\n"));
			if(NT_STATUS_IS_OK(smb_probe_module("pdb", data->names[i])) && !(entry = pdb_find_backend_entry(data->names[i]))) {
				DEBUG(0,("Plugin is available, but doesn't register passdb backend %s\n", data->names[i]));
				return NT_STATUS_UNSUCCESSFUL;
			}
		}
		if (!entry) {
			DEBUG(0, ("Unable to find multisam backend %d: %s\n", i, data->names[i]));
			return NT_STATUS_UNSUCCESSFUL;
		}

		DEBUG(2, ("Found entry point. Loading multisam backend %d: %s\n", i, data->names[i]));
		nt_status = entry->init(&data->methods[i], data->locations[i]);

		if (NT_STATUS_IS_ERR(nt_status)) {
			return nt_status;
		}
		/* These functions are only used on LDAP now.. */
		if (!IS_DEFAULT(data->methods[i], add_group_mapping_entry))
			(*pdb_method)->add_group_mapping_entry = multisam_add_group_mapping_entry;
		if (!IS_DEFAULT(data->methods[i], update_group_mapping_entry))
			(*pdb_method)->update_group_mapping_entry = multisam_update_group_mapping_entry;
		if (!IS_DEFAULT(data->methods[i], delete_group_mapping_entry))
			(*pdb_method)->delete_group_mapping_entry = multisam_delete_group_mapping_entry;
	}
	return NT_STATUS_OK;
}

NTSTATUS init_samba_module(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "multi", multisam_init);
}

NTSTATUS init_module(void)
{
	return init_samba_module();
}

