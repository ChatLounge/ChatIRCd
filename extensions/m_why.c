/*
 * Copyright (c) 2015 - Chat Lounge IRC Network Development
 *
 *     Server-side "WHY" command.
 *
 *     When executed, it will tell you why the target is banned from a channel.
 * It's useful for cases where the matching ban may not be obviously apparent.
 * It will also mention what ban exceptions (+e) and/or (+I) the user matches.
 *
 *     To execute the command, it requires being either a channel op on the
 * channel, or an IRC operator.
 *
 *     The command is rate-limited because it involves cycling through the
 * entire ban list, invite list, and exceptions list.  This is unlike actual
 * channel bans, where only one positive ban must be found.
 *
 * Syntax: /why #Channel TargetNick
 *
 * - Ben
 *
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "ipv4_from_ipv6.h"
#include "ircd.h"
#include "logger.h"
#include "match.h"
#include "modules.h"
#include "msg.h"
#include "numeric.h"
#include "packet.h"
#include "parse.h"
#include "s_conf.h"
#include "s_user.h"
#include "send.h"


static int m_why(struct Client *client_p, struct Client *source_p,
			int parc, const char *parv[]);

struct Message why_msgtab = {
	"WHY", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_why, 2}, mg_ignore, mg_ignore, mg_ignore, {m_why, 2}}
};

mapi_clist_av1 why_clist[] = { &why_msgtab, NULL };

DECLARE_MODULE_AV1(why, NULL, NULL, why_clist, NULL, NULL, "Display why a user is banned from a channel.");

void
show_result(struct Client *source_p, struct Channel *chptr, const char *targetnick)
{
	struct Client *target_p;
	rb_dlink_node *rb_dlink;
	
	target_p = find_named_person(targetnick);
	
	if(target_p == NULL)
	{
		sendto_one_notice(source_p, ":*** That user is not online.");
		return;
	}

	char *s = NULL;
	char *s2 = NULL;
	char *s3 = NULL;
	char *s4 = NULL;
	char src_host[NICKLEN + USERLEN + HOSTLEN + 6];
	char src_iphost[NICKLEN + USERLEN + HOSTLEN + 6];
	char src_althost[NICKLEN + USERLEN + HOSTLEN + 6];
	char src_ip4host[NICKLEN + USERLEN + HOSTLEN + 6];
	struct sockaddr_in ip4;
	struct Ban *actualBan = NULL;
	char tbuf[26];
	int didmatch = 0; /* Is set to 1 if there are any matches, set back to 0 before the next list. */
	
	rb_sprintf(src_host, "%s!%s@%s", target_p->name, target_p->username, target_p->host);
	rb_sprintf(src_iphost, "%s!%s@%s", target_p->name, target_p->username, target_p->sockhost);
	
	s = src_host;
	s2 = src_iphost;
	
	if(target_p->localClient->mangledhost != NULL)
	{
		/* if host mangling mode enabled, also check the real host */
		if(!strcmp(target_p->host, target_p->localClient->mangledhost))
		{
			rb_sprintf(src_althost, "%s!%s@%s", target_p->name, target_p->username, target_p->orighost);
			s3 = src_althost;
		}
		/* if host mangling mode not enabled and no other spoof,
		 * also check the mangled form of their host */
		else if (!IsDynSpoof(target_p))
		{
			rb_sprintf(src_althost, "%s!%s@%s", target_p->name, target_p->username, target_p->localClient->mangledhost);
			s3 = src_althost;
		}
	}
#ifdef RB_IPV6
	if(target_p->localClient->ip.ss_family == AF_INET6 &&
			ipv4_from_ipv6((const struct sockaddr_in6 *)&target_p->localClient->ip, &ip4))
	{
		rb_sprintf(src_ip4host, "%s!%s@", target_p->name, target_p->username);
		s4 = src_ip4host + strlen(src_ip4host);
		rb_inet_ntop_sock((struct sockaddr *)&ip4,
				s4, src_ip4host + sizeof src_ip4host - s4);
		s4 = src_ip4host;
	}
#endif
	/* List matching bans, if any. */
	sendto_one_notice(source_p, ":*** Matching bans (+b) for %s (%s@%s) in %s:",
					targetnick, target_p->username, target_p->host, chptr->chname);
	
	RB_DLINK_FOREACH(rb_dlink, chptr->banlist.head)
	{
		actualBan = rb_dlink->data;
		if(match(actualBan->banstr, s) ||
		   match(actualBan->banstr, s2) ||
		   match_cidr(actualBan->banstr, s2) ||
		   match_extban(actualBan->banstr, target_p, chptr, CHFL_BAN) ||
		   (s3 != NULL && match(actualBan->banstr, s3))
#ifdef RB_IPV6
		   ||
		   (s4 != NULL && (match(actualBan->banstr, s4) || match_cidr(actualBan->banstr, s4)))
#endif
		)
		{
			didmatch = 1;
			sendto_one_notice(source_p, ":*** Ban: %s set by %s on %s.",
							actualBan->banstr, actualBan->who,
							rb_ctime(actualBan->when, tbuf, sizeof(tbuf)));
		}
	}
	
	if(didmatch == 0)
		sendto_one_notice(source_p, ":*** No matching bans for %s.",
							targetnick);

	didmatch = 0;

	/* List matching quiets, if any. */
	sendto_one_notice(source_p, ":*** Matching quiets (+q) for %s (%s@%s) in %s:",
					targetnick, target_p->username, target_p->host, chptr->chname);
	
	RB_DLINK_FOREACH(rb_dlink, chptr->quietlist.head)
	{
		actualBan = rb_dlink->data;
		if(match(actualBan->banstr, s) ||
		   match(actualBan->banstr, s2) ||
		   match_cidr(actualBan->banstr, s2) ||
		   match_extban(actualBan->banstr, target_p, chptr, CHFL_QUIET) ||
		   (s3 != NULL && match(actualBan->banstr, s3))
#ifdef RB_IPV6
		   ||
		   (s4 != NULL && (match(actualBan->banstr, s4) || match_cidr(actualBan->banstr, s4)))
#endif
		)
		{
			didmatch = 1;
			sendto_one_notice(source_p, ":*** Quiet: %s set by %s on %s.",
							actualBan->banstr, actualBan->who,
							rb_ctime(actualBan->when, tbuf, sizeof(tbuf)));
		}
	}
	
	if(didmatch == 0)
		sendto_one_notice(source_p, ":*** No matching quiets for %s.",
							targetnick);
	
	/* If channel ban exceptions (+e) are enabled, check those too. */
	if(ConfigChannel.use_except)
	{
		sendto_one_notice(source_p, ":*** Matching ban exceptions (+b) for %s (%s@%s) in %s:",
					targetnick, target_p->username, target_p->host, chptr->chname);

		didmatch = 0;

		RB_DLINK_FOREACH(rb_dlink, chptr->exceptlist.head)
		{
			actualBan = rb_dlink->data;
			if(match(actualBan->banstr, s) ||
			   match(actualBan->banstr, s2) ||
			   match_cidr(actualBan->banstr, s2) ||
			   match_extban(actualBan->banstr, target_p, chptr, CHFL_EXCEPTION) ||
			   (s3 != NULL && match(actualBan->banstr, s3))
#ifdef RB_IPV6
			   ||
			   (s4 != NULL && (match(actualBan->banstr, s4) || match_cidr(actualBan->banstr, s4)))
#endif
			)
			{
				didmatch = 1;
				sendto_one_notice(source_p, ":*** Except: %s set by %s on %s.",
								actualBan->banstr, actualBan->who,
								rb_ctime(actualBan->when, tbuf, sizeof(tbuf)));
			}
		}

		if(didmatch == 0)
		sendto_one_notice(source_p, ":*** No matching ban exceptions for %s.",
							targetnick);
	}

	/* If channel invite exceptions (+I) are enabled, check those too. */
	if(ConfigChannel.use_invex)
	{
		sendto_one_notice(source_p, ":*** Matching invite exceptions (+b) for %s (%s@%s) in %s:",
					targetnick, target_p->username, target_p->host, chptr->chname);

		didmatch = 0;

		RB_DLINK_FOREACH(rb_dlink, chptr->exceptlist.head)
		{
			actualBan = rb_dlink->data;
			if(match(actualBan->banstr, s) ||
			   match(actualBan->banstr, s2) ||
			   match_cidr(actualBan->banstr, s2) ||
			   match_extban(actualBan->banstr, target_p, chptr, CHFL_INVEX) ||
			   (s3 != NULL && match(actualBan->banstr, s3))
#ifdef RB_IPV6
			   ||
			   (s4 != NULL && (match(actualBan->banstr, s4) || match_cidr(actualBan->banstr, s4)))
#endif
			)
			{
				didmatch = 1;
				sendto_one_notice(source_p, ":*** Invite Except: %s set by %s on %s.",
								actualBan->banstr, actualBan->who,
								rb_ctime(actualBan->when, tbuf, sizeof(tbuf)));
			}
		}

		if(didmatch == 0)
		sendto_one_notice(source_p, ":*** No matching invite exceptions for %s.",
							targetnick);
	}

	return;
}

static int
m_why(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static time_t lastused = 0;
	struct Channel *chptr;
	struct membership *msptr;
	
	chptr = find_channel(parv[1]);
	
	/* Does the channel exist? */
	if(chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return 0;
	}
	
	/* Is the user on the channel, or an IRC operator? */
	/*if(!IsOper(source_p) || msptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
					form_str(ERR_NOTONCHANNEL), parv[1]);
		return 0;
	} */
	
	/* If the user is an IRC operator, he doesn't need to be a channel operator. */
	if(!IsOper(source_p))
	{
		/* The user isn't an IRC operator. */

		/* Has the command been used too recently? */
		if((lastused + ConfigFileEntry.pace_wait) > rb_current_time())
		{
			sendto_one(source_p, form_str(RPL_LOAD2HI),
					me.name, source_p->name, "WHY");
			return 0;
		}
		else
			lastused = rb_current_time();

		// msptr = find_channel_membership(chptr, source_p);

		/* Is the user on the channel? */
		if((msptr = find_channel_membership(chptr, source_p)) == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOTONCHANNEL,
					form_str(ERR_NOTONCHANNEL), chptr->chname);
			return 0;
		}
		
		/* The user isn't an IRC operator.  Is he a channel operator? */
		if(!is_chanop(msptr))
		{
			sendto_one_numeric(source_p, ERR_CHANOPRIVSNEEDED,
					form_str(ERR_CHANOPRIVSNEEDED), me.name, source_p->name, chptr->chname);
			return 0;
		}
		else
		{
			show_result(source_p, chptr, parv[2]);
			return 0;
		}
	}
	else
	{
		show_result(source_p, chptr, parv[2]);
		return 0;
	}
}