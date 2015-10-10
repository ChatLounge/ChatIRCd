/*
 *  Copyright (c) 2015 - Chat Lounge IRC Network Development
 *
 *      "LISTINVITE"/"LISTINVITES" command
 *
 *      When executed without an argument, lists all channels you have been
 *  invited to.
 *
 *      When executed with a nick that's not your own, lists all channels the
 *  target has been invited to.  This requires IRC operator status.
 *
 *  Syntax:
 *    /listinvites
 *    /listinvites SomeNickHere
 *
 *    - Ben
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "modules.h"
#include "numeric.h"
#include "send.h"

static int m_listinvites(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[]);
static int me_listinvites(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[]);

struct Message listinvite_msgtab = {
	"LISTINVITE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_listinvites, 1}, mg_ignore, mg_ignore, {me_listinvites, 1}, {m_listinvites, 1}}
};

struct Message listinvites_msgtab = {
	"LISTINVITES", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_listinvites, 1}, mg_ignore, mg_ignore, mg_ignore, {m_listinvites, 1}}
};

mapi_clist_av1 listinvites_clist[] = { &listinvite_msgtab, &listinvites_msgtab, NULL };

DECLARE_MODULE_AV1(listinvites, NULL, NULL, listinvites_clist, NULL, NULL, "List current invites on a channel or a user.");

void
show_invite_list_user(struct Client *source_p, struct Client *target_p)
{
	struct Channel *listed;
	rb_dlink_node *ptr;

	if(source_p == target_p)
		sendto_one_notice(source_p, ":You have been invited to the following channels:");
	else
		sendto_one_notice(source_p, ":%s (%s@%s) has been invited to the following channels:",
			target_p->name, target_p->username, target_p->orighost);

	RB_DLINK_FOREACH(ptr, target_p->user->invited.head)
	{
		listed = ptr->data;
		sendto_one_notice(source_p, ":%s", listed->chname);
	};

	sendto_one_notice(source_p, ":End of user invite list for: %s (%s@%s)",
		target_p->name, target_p->username, target_p->orighost);
}

static int
m_listinvites(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	/* No arguments given, show own list of invited channels. */
	if(EmptyString(parv[1]))
	{
		show_invite_list_user(source_p, source_p);
		return 0;
	}

	if(IsOper(source_p))
	{
		struct Client *target_p;
		int chasing = 0;

		if((target_p = find_chasing(source_p, parv[1], &chasing)) == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					form_str(ERR_NOSUCHNICK), parv[1]);

			return 0;
		}
		
		// Is the user local?  If not, request from the target server.
		if(!MyClient(target_p))
		{
			struct Client *cptr = target_p->servptr;

			sendto_one(cptr, ":%s ENCAP %s LISTINVITE %s",
				get_id(source_p, cptr), cptr->name, get_id(target_p, cptr));

			return 0;
		}

		show_invite_list_user(source_p, target_p);

		return 0;
	}
	else
		show_invite_list_user(source_p, source_p);

	return 0;
}

static int
me_listinvites(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	int chasing;

	if((target_p = find_chasing(source_p, parv[1], &chasing)) == NULL)
		return 0;

	// If the user isn't on this server, pass it on.
	if(!MyClient(target_p))
	{
		struct Client *cptr = target_p->servptr;

		sendto_one(cptr, ":%s ENCAP %s LISTINVITE %s",
			get_id(source_p, cptr), cptr->name, get_id(target_p, cptr));

		return 0;
	}

	show_invite_list_user(source_p, target_p);

	return 0;
}