/*
 *  Copyright (c) 2015 - Chat Lounge IRC Network Development
 *
 *      UNINVITE command
 *
 *      When executed, it will "uninvite" a user from a channel.
 *
 *  Syntax:
 *    /uninvite SomeNick #Channel
 *
 */

#include "stdinc.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "modules.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_serv.h"
#include "send.h"

static int m_uninvite(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[]);
static int me_uninvite(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[]);
static int me_uninvitenotice(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[]);

struct Message uninvite_msgtab = {
	"UNINVITE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_uninvite, 3}, mg_ignore, mg_ignore, {me_uninvite, 3}, {m_uninvite, 3}}
};

struct Message uninvitenotice_msgtab = {
	"UNINVITENOTICE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, mg_ignore, mg_ignore, mg_ignore, {me_uninvitenotice, 2}, mg_ignore}
};

mapi_clist_av1 uninvite_clist[] = { &uninvite_msgtab, &uninvitenotice_msgtab, NULL };

DECLARE_MODULE_AV1(uninvite, NULL, NULL, uninvite_clist, NULL, NULL, "Provides the channel uninvite command.");

static void send_uninvite_notification(struct Client *, struct Client *, struct Channel *);

static int
m_uninvite(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	struct Channel *chptr;
	struct Client *target_p;
	int chasing = 0;
	int wasinvited = 0;
	rb_dlink_node *ptr;
	char *user;
	
	struct membership *msptr;
	
	user = LOCAL_COPY(parv[1]);
	
	if((target_p = find_chasing(source_p, user, &chasing)) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK,
					form_str(ERR_NOSUCHNICK), user);
		return 0;
	}
	
	chptr = find_channel(parv[2]);
	msptr = find_channel_membership(chptr, source_p); // Segfaulting here sometimes.

	if(chptr == NULL || msptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
					form_str(ERR_NOTONCHANNEL), (char *)parv[2]);
		return 0;
	};
	
	if(!(chptr->mode.mode & MODE_FREEINVITE) && !is_any_op(msptr))
	{
		if(IsSetOverride(source_p))
		{
			sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
				"%s is using oper override to uninvite %s (%s@%s) from %s",
				get_oper_name(source_p), target_p->name,
				target_p->username, target_p->orighost, chptr->chname);
		}
		else
		{
			sendto_one(source_p, form_str(ERR_CHANOPRIVSNEEDED),
				me.name, source_p->name, chptr->chname);
			return 0;
		}
	}

	// User might not be local, but del_invite only works on local users.
	if(!MyClient(target_p))
	{
		struct Client *cptr = target_p->servptr;
		sendto_one(cptr, ":%s ENCAP %s UNINVITE %s :%s",
				get_id(source_p, cptr), cptr->name, get_id(target_p, cptr), chptr->chname);
		return 0;
	}

	/* Check to see if the user was even invited.  Bail if not.
	 * Channel invite lists only include local users.
	 */
	/*RB_DLINK_FOREACH(ptr, chptr->invites.head)
	{
		if(ptr->data == target_p)
			wasinvited = 1;
	} */
	
	/*if(!wasinvited)
	{
		sendto_one_notice(source_p, "%s (%s@%s) isn't invited to %s and can't be uninvited.",
				target_p->name, target_p->username, target_p->host, chptr->chname);
		return 0;
	} */
	
	/* The client is on our server.  Send out the respective messages before
	 * removing the invite.
	 */
	/*sendto_channel_local_with_capability_butone(target_p, ONLY_CHANOPS, CLICAP_INVITE_NOTIFY, NOCAPS, chptr,
							":%s!%s@%s UNINVITE %s %s",
							source_p->name, source_p->username, source_p->host,
							target_p->name, chptr->chname); */

	/* Full format of notice sent to clients without invite-notify:
		 * :Notice -- SourceNick (SrcIdent@Source.Visible.Host) has uninvited TargetNick (TargIdent@Target.Visible.Host) from #Channel
		 */
	char uninvitenotice[BUFSIZE] = "";

	// Ugh, limited to nine args but really need more.  " to #Channel" added in the sendto function.
	rb_snprintf(uninvitenotice, sizeof(uninvitenotice), ":*** Notice -- %s (%s@%s) has uninvited %s (%s@%s)",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host);

	/*sendto_channel_local_with_capability(ONLY_CHANOPS, NOCAPS, CLICAP_INVITE_NOTIFY,
	chptr,
						":%s NOTICE %s %s from %s", me.name,
						chptr->chname, uninvitenotice, chptr->chname); */

	send_uninvite_notification(source_p, target_p, chptr);

	sendto_match_servs(source_p, "*", CAP_ENCAP, NOCAPS, "ENCAP * UNINVITENOTICE %s %s",
				target_p->name, chptr->chname);

	del_invite(chptr, target_p);

	return 0;
}

static int
me_uninvite(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[])
{
	struct Channel *chptr;
	struct Client *target_p;
	int chasing = 0;
	int wasinvited = 0;
	rb_dlink_node *ptr;
	char *user;
	
	user = LOCAL_COPY(parv[1]);
	
	if((target_p = find_chasing(source_p, user, &chasing)) == NULL)
		return 0;
	
	chptr = find_channel(parv[2]);
	
	// If the client isn't on this server, pass it on.
	if(!MyClient(target_p))
	{
		struct Client *cptr = target_p->servptr;
		sendto_one(cptr, ":%s ENCAP %s UNINVITE %s :%s",
				get_id(source_p, cptr), cptr->name, get_id(target_p, cptr), chptr->chname);
		return 0;
	}
	
	/* Check to see if the user was even invited.  Bail if not.
	 * Channel invite lists only include local users.
	 */
	/*RB_DLINK_FOREACH(ptr, chptr->invites.head)
	{
		if(ptr->data == target_p)
			wasinvited = 1;
	} */
	
	/*if(!wasinvited)
	{
		sendto_one_notice(source_p, ":%s (%s@%s) isn't invited to %s and can't be uninvited.",
				target_p->name, target_p->username, target_p->host, chptr->chname);
		return 0;
	} */
	
	/* The client is on our server.  Send out the respective messages before
	 * removing the invite.
	 */
	/*sendto_channel_local_with_capability_butone(target_p, ONLY_CHANOPS, CLICAP_INVITE_NOTIFY, NOCAPS, chptr,
							":%s!%s@%s UNINVITE %s %s",
							source_p->name, source_p->username, source_p->host,
							target_p->name, chptr->chname); */

	/* Full format of notice sent to clients without invite-notify:
	 * :Notice -- SourceNick (SrcIdent@Source.Visible.Host) has uninvited TargetNick (TargIdent@Target.Visible.Host) from #Channel
	 */
	char uninvitenotice[BUFSIZE] = "";

	// Ugh, limited to nine args but really need more.  " to #Channel" added in the sendto function.
	rb_snprintf(uninvitenotice, sizeof(uninvitenotice), ":*** Notice -- %s (%s@%s) has uninvited %s (%s@%s)",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host);

	/*sendto_channel_local_with_capability(ONLY_CHANOPS, NOCAPS, CLICAP_INVITE_NOTIFY,
	chptr,
						":%s NOTICE %s %s from %s", me.name,
						chptr->chname, uninvitenotice, chptr->chname); */

	send_uninvite_notification(source_p, target_p, chptr);

	sendto_match_servs(source_p, "*", CAP_ENCAP, NOCAPS, "ENCAP * UNINVITENOTICE %s %s",
				target_p->name, chptr->chname);

	del_invite(chptr, target_p);

	return 0;
}

static int
me_uninvitenotice(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *uninviter_p;
	struct Client *target_p;
	struct Channel *chptr;

	if((uninviter_p = find_named_person(parv[0])) == NULL)
		return 0;

	if((target_p = find_named_person(parv[1])) == NULL)
		return 0;

	if((chptr = find_channel(parv[2])) == NULL)
		return 0;

	send_uninvite_notification(uninviter_p, target_p, chptr);

	return 0;
}

/* Function to send the uninvite notifications to others in the channel.
 * Args:
 *   Source - Client who invited.
 *   Target - Client who was invited.
 *   Channel - Channel the target was invited to.
 */
static void
send_uninvite_notification(struct Client *source_p, struct Client *target_p, struct Channel *chptr)
{
	/* Full format of channel notice sent on uninvite:
	 * :*** Notice -- SourceNick (SrcIdent@Source.Visible.Host) has uninvited TargetNick (TargIdent@Target.Visible.Host) from #Channel
	 */
	char uninvitenotice[BUFSIZE] = "";

	// Send messages to everyone, if everyone can invite.
	if(chptr->mode.mode & MODE_FREEINVITE)
		sendto_channel_local_with_capability_butone(source_p, ALL_MEMBERS, CLICAP_INVITE_NOTIFY, NOCAPS, chptr,
								":%s!%s@%s UNINVITE %s %s",
								source_p->name, source_p->username, source_p->host,
								target_p->name, chptr->chname);
	else
		sendto_channel_local_with_capability_butone(source_p, ONLY_CHANOPS, CLICAP_INVITE_NOTIFY, NOCAPS, chptr,
								":%s!%s@%s UNINVITE %s %s",
								source_p->name, source_p->username, source_p->host,
								target_p->name, chptr->chname);

	// Ugh, limited to nine args but really need more.  " from #Channel" added in the sendto function.
	rb_snprintf(uninvitenotice, sizeof(uninvitenotice), ":*** Notice -- %s (%s@%s) has uninvited %s (%s@%s)",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host);

	if(chptr->mode.mode & MODE_FREEINVITE)
		sendto_channel_local(ALL_MEMBERS, chptr,
								":%s NOTICE %s %s from %s", me.name,
								chptr->chname, uninvitenotice, chptr->chname);
	else
		sendto_channel_local(ONLY_CHANOPS, chptr,
								":%s NOTICE %s %s from %s", me.name,
								chptr->chname, uninvitenotice, chptr->chname);
}