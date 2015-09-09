/* Borrowed from Ircd-seven, adapted to use umode +y in lieu of cmode +M.
 *
 * - Ben
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "numeric.h"
#include "chmode.h"
#include "s_newconf.h"
#include "s_user.h"

#define CanSetNoKick(x)     (HasPrivilege((x), "oper:cansetnokick"))

static void can_kick(hook_data_channel_approval *);
static void can_set_umode_y(void *vdata);

mapi_hfn_list_av1 nooperkick_hfnlist[] = {
	{ "can_kick", (hookfn) can_kick },
	{ "umode_changed", (hookfn) can_set_umode_y },
	{ NULL, NULL }
};

static int
_modinit(void)
{
	/* Add the +y user mode. */
	user_modes['y'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	user_modes['y'] = 0;
	construct_umodebuf();
}

static void
can_set_umode_y(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if(MyClient(source_p) && source_p->umodes & user_modes['y'] && !CanSetNoKick(source_p))
	{
		source_p->umodes &= ~user_modes['y'];
		sendto_one_notice(source_p, ":*** -- You may not set user mode +y.");
	}

	return;
};

static void
can_kick(hook_data_channel_approval *data)
{
	struct Client *source_p = data->client;
	struct Client *target_p = data->target;
	struct Channel *chptr = data->chptr;

	if (target_p->umodes & user_modes['y'] && data->approved &&
		!IsService(source_p) && !(source_p->umodes & UMODE_OVERRIDE))
	{
		sendto_one_numeric(source_p, ERR_ISCHANSERVICE,
				"%s %s :User is immune from kick.",
				target_p->name, chptr->chname);
		sendto_one_notice(target_p, ":*** Notice -- %s (%s@%s) tried to kick you from %s",
				source_p->name, source_p->username, source_p->orighost,
				chptr->chname);
		data->approved = 0;
	}
}

DECLARE_MODULE_AV1(chm_no_oper_kick, _modinit, _moddeinit, NULL, NULL, nooperkick_hfnlist, "$Revision$");