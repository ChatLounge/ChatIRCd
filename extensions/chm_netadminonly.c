/*
 *  Module that provides usermode +N.  When set, only
 *  Network Administrators (NetAdmins) may join the
 *  channel.
 *
 *  Copyright 2015 - The Chat Lounge IRC Network
 *		     Development Team
 *
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_serv.h"
#include "numeric.h"
#include "chmode.h"

static void h_can_join(hook_data_channel *);

mapi_hfn_list_av1 netadminonly_hfnlist[] = {
	{ "can_join", (hookfn) h_can_join },
	{ NULL, NULL }
};

static unsigned int mymode;

static int
_modinit(void)
{
	mymode = cflag_add('N', chm_staff);
	if (mymode == 0)
		return -1;

	return 0;
}

static void
_moddeinit(void)
{
	cflag_orphan('N');
}

DECLARE_MODULE_AV1(chm_netadminonly, _modinit, _moddeinit, NULL, NULL, netadminonly_hfnlist, "$Revision$");

static void
h_can_join(hook_data_channel *data)
{
	struct Client *source_p = data->client;
	struct Channel *chptr = data->chptr;

	if((chptr->mode.mode & mymode) && !IsNetAdmin(source_p)) {
		sendto_one_numeric(source_p, 519, "%s :Cannot join channel (+N) - you are not an IRC network administrator", chptr->chname);
		data->approved = ERR_CUSTOM;
	}
}

