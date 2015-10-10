/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_invite.c: Invites the user to join a channel.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
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
 *  $Id: m_invite.c 3438 2007-05-06 14:46:45Z jilles $
 */

#include "stdinc.h"
#include "common.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "s_serv.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"
#include "packet.h"
#include "tgchange.h"

static int m_invite(struct Client *, struct Client *, int, const char **);
static int me_invitenotice(struct Client *, struct Client *, int, const char **);

struct Message invite_msgtab = {
	"INVITE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_invite, 3}, {m_invite, 3}, mg_ignore, mg_ignore, {m_invite, 3}}
};

struct Message invitenotice_msgtab = {
	"INVITENOTICE", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_invitenotice, 2}, mg_ignore}
};

mapi_clist_av1 invite_clist[] = { &invite_msgtab, &invitenotice_msgtab, NULL };

DECLARE_MODULE_AV1(invite, NULL, NULL, invite_clist, NULL, NULL, "$Revision: 3438 $");

static void add_invite(struct Channel *, struct Client *);
static void send_invite_notification(struct Client *, struct Client *, struct Channel *);

/* m_invite()
 *      parv[1] - user to invite
 *      parv[2] - channel name
 */
static int
m_invite(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	struct Channel *chptr;
	struct membership *msptr;
	int store_invite = 0;

	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);

	if(MyClient(source_p))
		target_p = find_named_person(parv[1]);
	else
		target_p = find_person(parv[1]);
	if(target_p == NULL)
	{
		if(!MyClient(source_p) && IsDigit(parv[1][0]))
			sendto_one_numeric(source_p, ERR_NOSUCHNICK, 
					   "* :Target left IRC. Failed to invite to %s", 
					   parv[2]);
		else
			sendto_one_numeric(source_p, ERR_NOSUCHNICK, 
					   form_str(ERR_NOSUCHNICK), 
					   parv[1]);
		return 0;
	}

	if(check_channel_name(parv[2]) == 0)
	{
		sendto_one_numeric(source_p, ERR_BADCHANNAME,
				   form_str(ERR_BADCHANNAME),
				   parv[2]);
		return 0;
	}

	if(((MyConnect(source_p) && !IsExemptResv(source_p)) ||
			(MyConnect(target_p) && !IsExemptResv(target_p))) &&
		hash_find_resv(parv[2]))
	{
		sendto_one_numeric(source_p, ERR_BADCHANNAME,
				   form_str(ERR_BADCHANNAME),
				   parv[2]);
		return 0;
	}

	if((chptr = find_channel(parv[2])) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), parv[2]);
		return 0;
	}

	msptr = find_channel_membership(chptr, source_p);
	if(MyClient(source_p) && (msptr == NULL))
	{
		sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
				   form_str(ERR_NOTONCHANNEL), parv[2]);
		return 0;
	}

	if(IsMember(target_p, chptr))
	{
		sendto_one_numeric(source_p, ERR_USERONCHANNEL,
				   form_str(ERR_USERONCHANNEL),
				   target_p->name, parv[2]);
		return 0;
	}

	/* unconditionally require ops, unless the channel is +g */
	/* treat remote clients as chanops */
	if(MyClient(source_p) && !is_any_op(msptr) &&
			!(chptr->mode.mode & MODE_FREEINVITE))
	{
		if(IsSetOverride(source_p))
		{
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
				"%s is using oper override to invite %s (%s@%s) to [%s]",
				get_oper_name(source_p), target_p->name,
				target_p->username, target_p->orighost, chptr->chname);
		}
		else
		{
			sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
				   me.name, source_p->name, parv[2]);
			return 0;
		}
	}

	/* store invites when they could affect the ability to join
	 * for +l/+j just check if the mode is set, this varies over time
	 */
	if(chptr->mode.mode & MODE_INVITEONLY ||
			(chptr->mode.mode & MODE_REGONLY && EmptyString(target_p->user->suser)) ||
			chptr->mode.limit || chptr->mode.join_num)
		store_invite = 1;

	if(MyConnect(source_p))
	{
		if (ConfigFileEntry.target_change && !IsOper(source_p) &&
				!find_allowing_channel(source_p, target_p) &&
				!add_target(source_p, target_p))
		{
			sendto_one(source_p, form_str(ERR_TARGCHANGE),
				   me.name, source_p->name, target_p->name);
			return 0;
		}
		sendto_one(source_p, form_str(RPL_INVITING), 
			   me.name, source_p->name,
			   target_p->name, parv[2]);
		if(target_p->user->away)
			sendto_one_numeric(source_p, RPL_AWAY, form_str(RPL_AWAY),
					   target_p->name, target_p->user->away);
	}
	/* invite timestamp */
	else if(parc > 3 && !EmptyString(parv[3]))
	{
		/* this should never be less than */
		if(atol(parv[3]) > chptr->channelts)
			return 0;
	}

	if(MyConnect(target_p))
	{
		if(!IsOper(source_p) && (IsSetCallerId(target_p) || (IsSetRegOnlyMsg(target_p) && !source_p->user->suser[0]) ||
			(IsSetSslOnlyMsg(target_p) && !IsSSLClient(source_p)))
			)
		{
			if (IsSetRegOnlyMsg(target_p) && !source_p->user->suser[0])
			{
				sendto_one_numeric(source_p, ERR_NONONREG,
						form_str(ERR_NONONREG),
						target_p->name);
				return 0;
			}
			if ((IsSetSslOnlyMsg(target_p) && !IsSSLClient(source_p)))
			{
				sendto_one_numeric(source_p, ERR_NONONSSL,
						form_str(ERR_NONONSSL),
						target_p->name);
				return 0;
			}
			else
			{
				/* instead of sending RPL_UMODEGMSG,
				 * just let the invite through
				 */
				if((target_p->localClient->last_caller_id_time +
				    ConfigFileEntry.caller_id_wait) >= rb_current_time())
				{
					sendto_one_numeric(source_p, ERR_TARGUMODEG,
							   form_str(ERR_TARGUMODEG),
							   target_p->name);
					return 0;
				}
				target_p->localClient->last_caller_id_time = rb_current_time();
			}
		}
		add_reply_target(target_p, source_p);
		sendto_one(target_p, ":%s!%s@%s INVITE %s :%s", 
			source_p->name, source_p->username, source_p->host, 
			target_p->name, chptr->chname);
		
		send_invite_notification(source_p, target_p, chptr);

		sendto_match_servs(source_p, "*", CAP_ENCAP, NOCAPS, "ENCAP * INVITENOTICE %s %s",
				target_p->name, chptr->chname);

		if(store_invite)
			add_invite(chptr, target_p);
	}
	else if(target_p->from != client_p)
	{
		sendto_one_prefix(target_p, source_p, "INVITE", "%s %lu",
				  chptr->chname, (unsigned long) chptr->channelts);
	}

	return 0;
}

static int
me_invitenotice(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *inviter_p;
	struct Client *target_p;
	struct Channel *chptr;

	if((inviter_p = find_named_person(parv[0])) == NULL)
		return 0;

	if((target_p = find_named_person(parv[1])) == NULL)
		return 0;

	if((chptr = find_channel(parv[2])) == NULL)
		return 0;

	send_invite_notification(inviter_p, target_p, chptr);

	return 0;
}

/* add_invite()
 *
 * input	- channel to add invite to, client to add
 * output	-
 * side effects - client is added to invite list.
 */
static void
add_invite(struct Channel *chptr, struct Client *who)
{
	rb_dlink_node *ptr;

	/* already invited? */
	RB_DLINK_FOREACH(ptr, who->user->invited.head)
	{
		if(ptr->data == chptr)
			return;
	}

	/* ok, if their invite list is too long, remove the tail */
	if((int)rb_dlink_list_length(&who->user->invited) >= 
	   ConfigChannel.max_chans_per_user)
	{
		ptr = who->user->invited.tail;
		del_invite(ptr->data, who);
	}

	/* add user to channel invite list */
	rb_dlinkAddAlloc(who, &chptr->invites);

	/* add channel to user invite list */
	rb_dlinkAddAlloc(chptr, &who->user->invited);
}

/* Function to send the invite notifications to others in the channel.
 * Args:
 *   Source - Client who invited.
 *   Target - Client who was invited.
 *   Channel - Channel the target was invited to.
 */
static void
send_invite_notification(struct Client *source_p, struct Client *target_p, struct Channel *chptr)
{
	/* Full format of channel notice sent on invite:
	 * :*** Notice -- SourceNick (SrcIdent@Source.Visible.Host) has invited TargetNick (TargIdent@Target.Visible.Host) to #Channel
	 */
	char invitenotice[BUFSIZE] = "";

	// Ugh, limited to nine args but really need more.  " to #Channel" added in the sendto function.
	rb_snprintf(invitenotice, sizeof(invitenotice), ":*** Notice -- %s (%s@%s) has invited %s (%s@%s)",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host);

	// Send messages to everyone, if everyone can invite.
	if(chptr->mode.mode & MODE_FREEINVITE)
		sendto_channel_local_with_capability_butone(source_p, ALL_MEMBERS, CLICAP_INVITE_NOTIFY, NOCAPS, chptr,
								":%s!%s@%s INVITE %s %s",
								source_p->name, source_p->username, source_p->host,
								target_p->name, chptr->chname);
	else
		sendto_channel_local_with_capability_butone(source_p, ONLY_CHANOPS, CLICAP_INVITE_NOTIFY, NOCAPS, chptr,
								":%s!%s@%s INVITE %s %s",
								source_p->name, source_p->username, source_p->host,
								target_p->name, chptr->chname);

	if(chptr->mode.mode & MODE_FREEINVITE)
		sendto_channel_local(ALL_MEMBERS, chptr,
								":%s NOTICE %s %s to %s", me.name,
								chptr->chname, invitenotice, chptr->chname);
	else
		sendto_channel_local(ONLY_CHANOPS, chptr,
								":%s NOTICE %s %s to %s", me.name,
								chptr->chname, invitenotice, chptr->chname);
}


