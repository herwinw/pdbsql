/*
 * Support for multiple password databases
 * Copyright (C) Jelmer Vernooij 2006
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
 */

#include "includes.h"

static int multisam_debug_level = DBGC_ALL;

#undef DBGC_CLASS
#define DBGC_CLASS multisam_debug_level

typedef struct multisam_data {
	const char *location;
	int num_backends;
	char **names;
	char **locations;
	struct pdb_methods **methods;
} multisam_data;

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

static BOOL multisam_search_groups(struct pdb_methods *methods,
				      struct pdb_search *search)
{
	return False;
}

static BOOL multisam_search_aliases(struct pdb_methods *methods,
				       struct pdb_search *search,
				       const DOM_SID *sid)
{
	return False;
}

static BOOL multisam_search_users(struct pdb_methods *methods,
				     struct pdb_search *search,
				     uint32 acct_flags)
{
	return False;
}


static NTSTATUS multisam_get_account_policy(struct pdb_methods *methods, int policy_index, uint32 *value)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_set_account_policy(struct pdb_methods *methods, int policy_index, uint32 value)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_get_seq_num(struct pdb_methods *methods, time_t *seq_num)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static BOOL multisam_uid_to_rid(struct pdb_methods *methods, uid_t uid,
				   uint32 *rid)
{
	return False;
}

static BOOL multisam_gid_to_sid(struct pdb_methods *methods, gid_t gid,
				   DOM_SID *sid)
{
	return False;
}

static BOOL multisam_sid_to_id(struct pdb_methods *methods,
				  const DOM_SID *sid,
				  union unid_t *id, enum SID_NAME_USE *type)
{
	return False;
}


static NTSTATUS multisam_set_unix_primary_group(struct pdb_methods *methods,
						   TALLOC_CTX *mem_ctx,
						   struct samu *sampass)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_create_user(struct pdb_methods *methods,
					TALLOC_CTX *tmp_ctx, const char *name,
					uint32 acb_info, uint32 *rid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_delete_user(struct pdb_methods *methods,
					TALLOC_CTX *mem_ctx,
					struct samu *sam_acct)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_enum_group_memberships(struct pdb_methods *methods,
					    TALLOC_CTX *mem_ctx,
					    struct samu *user,
					    DOM_SID **pp_sids,
					    gid_t **pp_gids,
					    size_t *p_num_groups)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_enum_group_members(struct pdb_methods *methods,
					TALLOC_CTX *mem_ctx,
					const DOM_SID *group,
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


static NTSTATUS multisam_rename_sam_account (struct pdb_methods *methods, struct samu *pwd, const char *newname)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_update_login_attempts (struct pdb_methods *methods, struct samu *newpwd, BOOL success)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid)
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
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_enum_group_mapping(struct pdb_methods *methods,
					   const DOM_SID *sid, enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **pp_rmap, size_t *p_num_entries,
					   BOOL unix_only)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_find_alias(struct pdb_methods *methods,
				const char *name, DOM_SID *sid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_create_alias(struct pdb_methods *methods,
				  const char *name, uint32 *rid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_delete_alias(struct pdb_methods *methods,
				  const DOM_SID *sid)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_get_aliasinfo(struct pdb_methods *methods,
				   const DOM_SID *sid,
				   struct acct_info *info)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_set_aliasinfo(struct pdb_methods *methods,
				   const DOM_SID *sid,
				   struct acct_info *info)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_add_aliasmem(struct pdb_methods *methods,
				  const DOM_SID *alias, const DOM_SID *member)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_del_aliasmem(struct pdb_methods *methods,
				  const DOM_SID *alias, const DOM_SID *member)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS multisam_enum_aliasmem(struct pdb_methods *methods,
				   const DOM_SID *alias, DOM_SID **pp_members,
				   size_t *p_num_members)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_alias_memberships(struct pdb_methods *methods,
				       TALLOC_CTX *mem_ctx,
				       const DOM_SID *domain_sid,
				       const DOM_SID *members,
				       size_t num_members,
				       uint32 **pp_alias_rids,
				       size_t *p_num_alias_rids)
{
	DEBUG(1, ("This function is not implemented yet\n"));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_setsampwent(struct pdb_methods *methods, BOOL update, uint32 acb_mask)
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

/******************************************************************
  Lookup a name in the SAM database
 ******************************************************************/

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

static NTSTATUS multisam_getsampwsid(struct pdb_methods *methods, struct samu * user,
					 const DOM_SID * sid)
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

static NTSTATUS multisam_add_sam_account(struct pdb_methods *methods, struct samu * newpwd)
{
	struct multisam_data *data;
	
	SET_DATA(data, methods);
	
	DEBUG(0, ("Creating user in first multisam backend\n"));
	return data->methods[0]->add_sam_account(data->methods[0], newpwd);
}

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

static NTSTATUS multisam_lookup_rids(struct pdb_methods *methods,
				 const DOM_SID *domain_sid,
				 int num_rids,
				 uint32 *rids,
				 const char **names,
				 uint32 *attrs)
{
	DEBUG(1, ("This function is not implemented yet\n"));
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

static BOOL multisam_rid_algorithm (struct pdb_methods *methods)
{
	return False;
}
static BOOL multisam_new_rid (struct pdb_methods *methods, uint32 *rid)
{
	*rid = 0;
	return True;
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
	
	(*pdb_method)->name = "multisam";

	/* Mandatory implementation */
	(*pdb_method)->setsampwent = multisam_setsampwent;
	(*pdb_method)->endsampwent = multisam_endsampwent;
	(*pdb_method)->getsampwent = multisam_getsampwent;
	(*pdb_method)->getsampwnam = multisam_getsampwnam;
	(*pdb_method)->getsampwsid = multisam_getsampwsid;
	(*pdb_method)->add_sam_account = multisam_add_sam_account;
	(*pdb_method)->update_sam_account = multisam_update_sam_account;
	(*pdb_method)->delete_sam_account = multisam_delete_sam_account;
	(*pdb_method)->rename_sam_account = multisam_rename_sam_account;
	(*pdb_method)->rid_algorithm = multisam_rid_algorithm;
	(*pdb_method)->new_rid = multisam_new_rid;


	data = talloc(*pdb_method, struct multisam_data);
	(*pdb_method)->private_data = data;

	if (!location) {
		DEBUG(0, ("No identifier specified. Check the Samba HOWTO Collection for details\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data->location = talloc_strdup(data, location);
	data->names = str_list_make_talloc(data, data->location, NULL);
	data->num_backends = str_list_count((const char **)data->names);
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
		
		/* Optional.. only set if implemented */
		if (*(data->methods[i])->update_login_attempts != (*pdb_method)->update_login_attempts)
			(*pdb_method)->update_login_attempts = multisam_update_login_attempts;
		if (*(data->methods[i])->create_user != (*pdb_method)->create_user)
			(*pdb_method)->create_user = multisam_create_user;
		if (*(data->methods[i])->delete_user != (*pdb_method)->delete_user)
			(*pdb_method)->delete_user = multisam_delete_user;
		if (*(data->methods[i])->getgrsid != (*pdb_method)->getgrsid)
			(*pdb_method)->getgrsid = multisam_getgrsid;
		if (*(data->methods[i])->getgrgid != (*pdb_method)->getgrgid)
			(*pdb_method)->getgrgid = multisam_getgrgid;
		if (*(data->methods[i])->getgrnam != (*pdb_method)->getgrnam)
			(*pdb_method)->getgrnam = multisam_getgrnam;
		if (*(data->methods[i])->create_dom_group != (*pdb_method)->create_dom_group)
			(*pdb_method)->create_dom_group = multisam_create_dom_group;
		if (*(data->methods[i])->delete_dom_group != (*pdb_method)->delete_dom_group)
			(*pdb_method)->delete_dom_group = multisam_delete_dom_group;
		if (*(data->methods[i])->add_group_mapping_entry != (*pdb_method)->add_group_mapping_entry)
			(*pdb_method)->add_group_mapping_entry = multisam_add_group_mapping_entry;
		if (*(data->methods[i])->update_group_mapping_entry != (*pdb_method)->update_group_mapping_entry)
			(*pdb_method)->update_group_mapping_entry = multisam_update_group_mapping_entry;
		if (*(data->methods[i])->delete_group_mapping_entry != (*pdb_method)->delete_group_mapping_entry)
			(*pdb_method)->delete_group_mapping_entry = multisam_delete_group_mapping_entry;
		if (*(data->methods[i])->enum_group_mapping != (*pdb_method)->enum_group_mapping)
			(*pdb_method)->enum_group_mapping = multisam_enum_group_mapping;
		if (*(data->methods[i])->enum_group_members != (*pdb_method)->enum_group_members)
			(*pdb_method)->enum_group_members = multisam_enum_group_members;
		if (*(data->methods[i])->enum_group_memberships != (*pdb_method)->enum_group_memberships)
			(*pdb_method)->enum_group_memberships = multisam_enum_group_memberships;
		if (*(data->methods[i])->set_unix_primary_group != (*pdb_method)->set_unix_primary_group)
			(*pdb_method)->set_unix_primary_group = multisam_set_unix_primary_group;
		if (*(data->methods[i])->add_groupmem != (*pdb_method)->add_groupmem)
			(*pdb_method)->add_groupmem = multisam_add_groupmem;
		if (*(data->methods[i])->del_groupmem != (*pdb_method)->del_groupmem)
			(*pdb_method)->del_groupmem = multisam_del_groupmem;
		if (*(data->methods[i])->find_alias != (*pdb_method)->find_alias)
			(*pdb_method)->find_alias = multisam_find_alias;
		if (*(data->methods[i])->create_alias != (*pdb_method)->create_alias)
			(*pdb_method)->create_alias = multisam_create_alias;
		if (*(data->methods[i])->delete_alias != (*pdb_method)->delete_alias)
			(*pdb_method)->delete_alias = multisam_delete_alias;
		if (*(data->methods[i])->get_aliasinfo != (*pdb_method)->get_aliasinfo)
			(*pdb_method)->get_aliasinfo = multisam_get_aliasinfo;
		if (*(data->methods[i])->set_aliasinfo != (*pdb_method)->set_aliasinfo)
			(*pdb_method)->set_aliasinfo = multisam_set_aliasinfo;
		if (*(data->methods[i])->add_aliasmem != (*pdb_method)->add_aliasmem)
			(*pdb_method)->add_aliasmem = multisam_add_aliasmem;
		if (*(data->methods[i])->del_aliasmem != (*pdb_method)->del_aliasmem)
			(*pdb_method)->del_aliasmem = multisam_del_aliasmem;
		if (*(data->methods[i])->enum_aliasmem != (*pdb_method)->enum_aliasmem)
			(*pdb_method)->enum_aliasmem = multisam_enum_aliasmem;
		if (*(data->methods[i])->enum_alias_memberships != (*pdb_method)->enum_alias_memberships)
			(*pdb_method)->enum_alias_memberships = multisam_alias_memberships;
		if (*(data->methods[i])->lookup_rids != (*pdb_method)->lookup_rids)
			(*pdb_method)->lookup_rids = multisam_lookup_rids;
		if (*(data->methods[i])->get_account_policy != (*pdb_method)->get_account_policy)
			(*pdb_method)->get_account_policy = multisam_get_account_policy;
		if (*(data->methods[i])->set_account_policy != (*pdb_method)->set_account_policy)
			(*pdb_method)->set_account_policy = multisam_set_account_policy;
		if (*(data->methods[i])->get_seq_num != (*pdb_method)->get_seq_num)
			(*pdb_method)->get_seq_num = multisam_get_seq_num;
		if (*(data->methods[i])->uid_to_rid != (*pdb_method)->uid_to_rid)
			(*pdb_method)->uid_to_rid = multisam_uid_to_rid;
		if (*(data->methods[i])->gid_to_sid != (*pdb_method)->gid_to_sid)
			(*pdb_method)->gid_to_sid = multisam_gid_to_sid;
		if (*(data->methods[i])->sid_to_id != (*pdb_method)->sid_to_id)
			(*pdb_method)->sid_to_id = multisam_sid_to_id;
		if (*(data->methods[i])->search_users != (*pdb_method)->search_users)
			(*pdb_method)->search_users = multisam_search_users;
		if (*(data->methods[i])->search_groups != (*pdb_method)->search_groups)
			(*pdb_method)->search_groups = multisam_search_groups;
		if (*(data->methods[i])->search_aliases != (*pdb_method)->search_aliases)
			(*pdb_method)->search_aliases = multisam_search_aliases;
	}
	return NT_STATUS_OK;
}

NTSTATUS init_module(void) 
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "multi", multisam_init);
}
