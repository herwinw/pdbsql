/*
 * Support for multiple password databases
 * Copyright (C) Jelmer Vernooij 2006
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
	struct multisam_backend {
		const char *location;
		struct pdb_methods *methods;
	} *backends;
} multisam_data;

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
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_set_account_policy(struct pdb_methods *methods, int policy_index, uint32 value)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_get_seq_num(struct pdb_methods *methods, time_t *seq_num)
{
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
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_create_user(struct pdb_methods *methods,
					TALLOC_CTX *tmp_ctx, const char *name,
					uint32 acb_info, uint32 *rid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_delete_user(struct pdb_methods *methods,
					TALLOC_CTX *mem_ctx,
					struct samu *sam_acct)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_enum_group_memberships(struct pdb_methods *methods,
					    TALLOC_CTX *mem_ctx,
					    struct samu *user,
					    DOM_SID **pp_sids,
					    gid_t **pp_gids,
					    size_t *p_num_groups)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_enum_group_members(struct pdb_methods *methods,
					TALLOC_CTX *mem_ctx,
					const DOM_SID *group,
					uint32 **pp_member_rids,
					size_t *p_num_members)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_delete_dom_group(struct pdb_methods *methods,
					     TALLOC_CTX *mem_ctx,
					     uint32 rid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_rename_sam_account (struct pdb_methods *methods, struct samu *pwd, const char *newname)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_update_login_attempts (struct pdb_methods *methods, struct samu *newpwd, BOOL success)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_getgrsid(struct pdb_methods *methods, GROUP_MAP *map,
				 DOM_SID sid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_getgrgid(struct pdb_methods *methods, GROUP_MAP *map,
				 gid_t gid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_getgrnam(struct pdb_methods *methods, GROUP_MAP *map,
				 const char *name)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_add_group_mapping_entry(struct pdb_methods *methods,
						GROUP_MAP *map)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_update_group_mapping_entry(struct pdb_methods *methods,
						   GROUP_MAP *map)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_delete_group_mapping_entry(struct pdb_methods *methods,
						   DOM_SID sid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_enum_group_mapping(struct pdb_methods *methods,
					   const DOM_SID *sid, enum SID_NAME_USE sid_name_use,
					   GROUP_MAP **pp_rmap, size_t *p_num_entries,
					   BOOL unix_only)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_find_alias(struct pdb_methods *methods,
				const char *name, DOM_SID *sid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_create_alias(struct pdb_methods *methods,
				  const char *name, uint32 *rid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_delete_alias(struct pdb_methods *methods,
				  const DOM_SID *sid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_get_aliasinfo(struct pdb_methods *methods,
				   const DOM_SID *sid,
				   struct acct_info *info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_set_aliasinfo(struct pdb_methods *methods,
				   const DOM_SID *sid,
				   struct acct_info *info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_add_aliasmem(struct pdb_methods *methods,
				  const DOM_SID *alias, const DOM_SID *member)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_del_aliasmem(struct pdb_methods *methods,
				  const DOM_SID *alias, const DOM_SID *member)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS multisam_enum_aliasmem(struct pdb_methods *methods,
				   const DOM_SID *alias, DOM_SID **pp_members,
				   size_t *p_num_members)
{
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
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_setsampwent(struct pdb_methods *methods, BOOL update, uint32 acb_mask)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/***************************************************************
  End enumeration of the passwd list.
 ****************************************************************/

static void multisam_endsampwent(struct pdb_methods *methods)
{

}

/*****************************************************************
  Get one struct samu from the list (next in line)
 *****************************************************************/

static NTSTATUS multisam_getsampwent(struct pdb_methods *methods, struct samu * user)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/******************************************************************
  Lookup a name in the SAM database
 ******************************************************************/

static NTSTATUS multisam_getsampwnam(struct pdb_methods *methods, struct samu * user,
					 const char *sname)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/***************************************************************************
  Search by sid
 **************************************************************************/

static NTSTATUS multisam_getsampwsid(struct pdb_methods *methods, struct samu * user,
					 const DOM_SID * sid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/***************************************************************************
  Delete a sam account 
 ****************************************************************************/

static NTSTATUS multisam_delete_sam_account(struct pdb_methods *methods,
							struct samu * sam_pass)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_replace_sam_account(struct pdb_methods *methods,
							 struct samu * newpwd, char isupdate)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_add_sam_account(struct pdb_methods *methods, struct samu * newpwd)
{
	return multisam_replace_sam_account(methods, newpwd, 0);
}

static NTSTATUS multisam_update_sam_account(struct pdb_methods *methods,
							struct samu * newpwd)
{
	return multisam_replace_sam_account(methods, newpwd, 1);
}

static NTSTATUS multisam_lookup_rids(struct pdb_methods *methods,
				 const DOM_SID *domain_sid,
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
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_add_groupmem(struct pdb_methods *methods,
					 TALLOC_CTX *mem_ctx,
					 uint32 group_rid,
					 uint32 member_rid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS multisam_del_groupmem(struct pdb_methods *methods,
					 TALLOC_CTX *mem_ctx,
					 uint32 group_rid,
					 uint32 member_rid)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS multisam_init(struct pdb_methods **pdb_method, const char *location)
{
	NTSTATUS nt_status;
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

	(*pdb_method)->setsampwent = multisam_setsampwent;
	(*pdb_method)->endsampwent = multisam_endsampwent;
	(*pdb_method)->getsampwent = multisam_getsampwent;
	(*pdb_method)->getsampwnam = multisam_getsampwnam;
	(*pdb_method)->getsampwsid = multisam_getsampwsid;
	(*pdb_method)->create_user = multisam_create_user;
	(*pdb_method)->delete_user = multisam_delete_user;
	(*pdb_method)->add_sam_account = multisam_add_sam_account;
	(*pdb_method)->update_sam_account = multisam_update_sam_account;
	(*pdb_method)->delete_sam_account = multisam_delete_sam_account;
	(*pdb_method)->rename_sam_account = multisam_rename_sam_account;
	(*pdb_method)->update_login_attempts = multisam_update_login_attempts;

	(*pdb_method)->getgrsid = multisam_getgrsid;
	(*pdb_method)->getgrgid = multisam_getgrgid;
	(*pdb_method)->getgrnam = multisam_getgrnam;
	(*pdb_method)->create_dom_group = multisam_create_dom_group;
	(*pdb_method)->delete_dom_group = multisam_delete_dom_group;
	(*pdb_method)->add_group_mapping_entry = multisam_add_group_mapping_entry;
	(*pdb_method)->update_group_mapping_entry = multisam_update_group_mapping_entry;
	(*pdb_method)->delete_group_mapping_entry = multisam_delete_group_mapping_entry;
	(*pdb_method)->enum_group_mapping = multisam_enum_group_mapping;
	(*pdb_method)->enum_group_members = multisam_enum_group_members;
	(*pdb_method)->enum_group_memberships = multisam_enum_group_memberships;
	(*pdb_method)->set_unix_primary_group = multisam_set_unix_primary_group;
	(*pdb_method)->add_groupmem = multisam_add_groupmem;
	(*pdb_method)->del_groupmem = multisam_del_groupmem;
	(*pdb_method)->find_alias = multisam_find_alias;
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
	(*pdb_method)->uid_to_rid = multisam_uid_to_rid;
	(*pdb_method)->gid_to_sid = multisam_gid_to_sid;
	(*pdb_method)->sid_to_id = multisam_sid_to_id;

	(*pdb_method)->search_users = multisam_search_users;
	(*pdb_method)->search_groups = multisam_search_groups;
	(*pdb_method)->search_aliases = multisam_search_aliases;

	data = talloc(*pdb_method, struct multisam_data);
	(*pdb_method)->private_data = data;

	if (!location) {
		DEBUG(0, ("No identifier specified. Check the Samba HOWTO Collection for details\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	data->location = talloc_strdup(data, location);
	/* FIXME: parse location */

	return NT_STATUS_OK;
}

NTSTATUS init_module(void) 
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "multi", multisam_init);
}
