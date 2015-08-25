/*
 * Prevents opers from setting umode +B unless the oper has the oper:cansetbot
 * priv.
 *
 * - Ben
 *
 * Copyright (C) 2015 Chat Lounge IRC Network Development
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_newconf.h"
//#include "s_user.h"

static void h_nobotmodeoper_umode_changed(hook_data_umode_changed *);

mapi_hfn_list_av1 nobotmodeoper_list[] = {
	{ "umode_changed", (hookfn) h_nobotmodeoper_umode_changed },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(no_oper_bot_mode, NULL, NULL, NULL, NULL, nobotmodeoper_list, "Prevent opers from using umode +B without oper:cansetbot.");

static void
h_nobotmodeoper_umode_changed(hook_data_umode_changed *hdata)
{
	struct Client *source_p = hdata->client;
	
	if(MyClient(source_p) && IsOper(source_p) && !IsOperCanSetBot(source_p) &&
		IsSetBot(source_p))
	{
		//const char *parv[4] = {source_p, source_p, "-B", NULL};
		//user_mode(source_p, source_p, 3, parv);
		ClearBot(source_p);
		/* Complain only if the user is opered up and attempts to set umode +B. */
		if(hdata->oldumodes & UMODE_OPER)
			sendto_one_notice(source_p, ":*** Opers may not set themselves in bot mode without the correct permission.");
	}
}