/* Prevents opers from /kill'ing admins and netadmins.
 * Prevents admins from /kill'ing netadmins.
 *
 * Must be loaded on all servers to be effective.
 *
 * NOTE: The name of the module may be somewhat misleading
 *    as oper powers are based on flags, not levels.  However,
 *    privsets are often configured being inclusive of lower
 *    privsets, making this module effective.
 *
 * Copyright (C) 2015-2016 - ChatLounge IRC Network Development Team
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "hash.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "privilege.h"
#include "s_newconf.h"

static void block_higher_oper_kill(void *data);

mapi_hfn_list_av1 m_nokillhigheropers_hfnlist[] = {
	{ "can_kill", (hookfn) block_higher_oper_kill },
	{ NULL, NULL }
};

static void
block_higher_oper_kill(void *vdata)
{
	hook_data_client_approval *data = (hook_data_client_approval *) vdata;

	if(!MyClient(data->client))
		return;

	if(!data->approved)
		return;
	
	// Net admins have no restrictions, nor do services (for /ns ghost to function)
	if(IsNetAdmin(data->client) || IsService(data->client))
		data->approved = 1;
	/* If the source is *not* a net admin (so an admin or oper) and the target
	 * is.  Check the source first since (hopefully) most opers are not net
	 * admins.
	 */
	else if(!IsNetAdmin(data->client) && IsNetAdmin(data->target))
	{
		sendto_one_numeric(data->client, ERR_ISCHANSERVICE,
			"KILL %s :Cannot kill, %s",
			data->target->name, GlobalSetOptions.netadminstring);
		data->approved = 0;
	}
	/* If here, the target is *not* a net admin (so an admin or oper).  Check
	 * if the target is an admin, and if the source is an oper (not an admin
	 * or net admin).  IsOper returns true for all oper types, making it
	 * inappropriate here.  IsAdmin returns true for admins and netadmins.
	 *
	 */
	else if(IsAdmin(data->target) && (!IsAdmin(data->client)))
	{
		sendto_one_numeric(data->client, ERR_ISCHANSERVICE,
			"KILL %s :Cannot kill, %s",
			data->target->name, GlobalSetOptions.adminstring);
		data->approved = 0;
	}
	else
		data->approved = 1;
}
DECLARE_MODULE_AV1(m_no_kill_higher_opers, NULL, NULL, NULL, NULL,
	m_nokillhigheropers_hfnlist, "Prevent kills on higher level opers from lower level opers.");