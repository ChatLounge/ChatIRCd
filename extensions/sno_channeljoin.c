/*
 * +j snomask: Channel join/part notices.
 *
 * Original by nenolod, extended by Ben to support remote channel join notices.
 *
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"

static void
show_channeljoin(hook_data_channel_activity *info)
{
	sendto_realops_snomask(snomask_modes['j'], L_ALL,
		"%s (%s@%s) has joined channel %s", info->client->name,
		info->client->username, info->client->host, info->chptr->chname);
}

static void
show_remotechanneljoin(hook_data_channel_activity *info)
{
	sendto_realops_snomask(snomask_modes['J'], L_ALL,
		"%s (%s@%s) has joined channel %s", info->client->name,
		info->client->username, info->client->host, info->chptr->chname);
}

mapi_hfn_list_av1 channeljoin_hfnlist[] = {
        {"channel_join", (hookfn) show_channeljoin},
		{"remote_channel_join", (hookfn) show_remotechanneljoin},
        {NULL, NULL}
};

static int
init(void)
{
	snomask_modes['j'] = find_snomask_slot();
	snomask_modes['J'] = find_snomask_slot();

	return 0;
}

static void
fini(void)
{
	snomask_modes['j'] = 0;
	snomask_modes['J'] = 0;
}

DECLARE_MODULE_AV1(sno_channeljoin, init, fini, NULL, NULL, channeljoin_hfnlist, "SporksIRCD development team");

