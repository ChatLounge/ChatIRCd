/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_part.c: Parts a user from a channel.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2015-2016 ChatLounge IRC Network Development Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
 *  USA
 *
 *  $Id: m_part.c 98 2005-09-11 03:37:47Z nenolod $
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "common.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "s_serv.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "s_conf.h"
#include "packet.h"
#include "inline/stringops.h"
#include "hook.h"

static int m_part(struct Client *, struct Client *, int, const char **);

struct Message part_msgtab = {
	"PART", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_part, 2}, {m_part, 2}, mg_ignore, mg_ignore, {m_part, 2}}
};

mapi_clist_av1 part_clist[] = { &part_msgtab, NULL };

DECLARE_MODULE_AV1(part, NULL, NULL, part_clist, NULL, NULL, "$Revision: 98 $");

static void part_one_client(struct Client *client_p,
			    struct Client *source_p, char *name,
				const char *reason);
static int can_send_part(struct Client *source_p, struct Channel *chptr, struct membership *msptr);
static int do_message_hook(struct Client *source_p, struct Channel *chptr, const char **reason);

/*
** m_part
**      parv[1] = channel
**      parv[2] = reason
*/
static int
m_part(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	char *p, *name;
	char reason[REASONLEN + 1];
	char *s = LOCAL_COPY(parv[1]);

	reason[0] = '\0';

	if(parc > 2)
		rb_strlcpy(reason, parv[2], sizeof(reason));

	name = rb_strtok_r(s, ",", &p);

	/* Finish the flood grace period... */
	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);

	strip_colour(reason);

	while(name)
	{
		/* If static_parts is enabled, set the reason to static_part_reason. - Ben */
		if(ConfigFileEntry.static_parts)
		{
			part_one_client(client_p, source_p, name, ConfigFileEntry.static_part_reason);
		}
		else
			part_one_client(client_p, source_p, name, reason);
		name = rb_strtok_r(NULL, ",", &p);
	}
	return 0;
}

/*
 * part_one_client
 *
 * inputs	- pointer to server
 * 		- pointer to source client to remove
 *		- char pointer of name of channel to remove from
 * output	- none
 * side effects	- remove ONE client given the channel name 
 */
static void
part_one_client(struct Client *client_p, struct Client *source_p, char *name, const char *reason)
{
	struct Channel *chptr;
	struct membership *msptr;

	if((chptr = find_channel(name)) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL, form_str(ERR_NOSUCHCHANNEL), name);
		return;
	}

	msptr = find_channel_membership(chptr, source_p);
	if(msptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOTONCHANNEL, form_str(ERR_NOTONCHANNEL), name);
		return;
	}

	if(MyConnect(source_p) && !IsOper(source_p) && !IsExemptSpambot(source_p))
		check_spambot_warning(source_p, NULL);

	/*
	 *  Remove user from the old channel (if any)
	 *  only allow /part reasons in -m chans
	 */
	if(!EmptyString(reason) &&
		(!MyConnect(source_p) ||
		(can_send_part(source_p, chptr, msptr) && do_message_hook(source_p, chptr, &reason))
		)
	)
	{
		sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
			      ":%s PART %s :%s", use_id(source_p), chptr->chname, reason);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s PART %s :%s",
				     source_p->name, source_p->username,
				     source_p->host, chptr->chname, reason);
	}
	else
	{
		sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
			      ":%s PART %s", use_id(source_p), chptr->chname);
		sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s PART %s",
				     source_p->name, source_p->username,
				     source_p->host, chptr->chname);
	}
	remove_user_from_channel(msptr);
}

/*
 * can_send_part - whether a part message can be sent.
 *
 * inputs:
 * - client parting
 * - channel being parted
 * - membership pointer
 * outputs:
 * - 1 if message allowed
 * - 0 if message denied
 * side effects:
 * - none.
 */
static int
can_send_part(struct Client *source_p, struct Channel *chptr, struct membership *msptr)
{
	if (!can_send(chptr, source_p, msptr))
		return 0;
	/* Allow chanops to bypass anti_spam_exit_message_time for part messages. */
	if (is_any_op(msptr))
		return 1;
	return (source_p->localClient->firsttime + ConfigFileEntry.anti_spam_exit_message_time) < rb_current_time();
}

/*
 * do_message_hook - execute the message hook on a part message reason.
 *
 * inputs:
 * - client parting
 * - channel being parted
 * - pointer to reason
 * outputs:
 * - 1 if message is allowed
 * - 0 if message is denied or message is now empty
 * side effects:
 * - reason may be modified.
 */
static int
do_message_hook(struct Client *source_p, struct Channel *chptr, const char **reason)
{
	hook_data_privmsg_channel hdata;

	hdata.msgtype = MESSAGE_TYPE_PART;
	hdata.source_p = source_p;
	hdata.chptr = chptr;
	hdata.text = *reason;
	hdata.approved = 0;

	call_hook(h_privmsg_channel, &hdata);

	/* The reason may have been changed by a hook... */
	*reason = hdata.text;

	return (hdata.approved == 0 && !EmptyString(*reason));
}