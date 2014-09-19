/*
 * Extended ban type "u": Unidentified users.  Bans unidentified users matching the specified n!u@h.
 * Example: +b $u:*!webchat@*
 *
 * - Ben (Ben @ irc.chatlounge.net, #ChatLounge-Dev @ irc.chatlounge.net)
 *	September 18th, 2014
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "match.h"

static int _modinit(void);
static void _moddeinit(void);
static int eb_unidentified(const char *data, struct Client *client_p, struct Channel *chptr, long mode_type);

DECLARE_MODULE_AV1(extb_unidentified, _modinit, _moddeinit, NULL, NULL, NULL, "Ban Unidentified Users with matching hostmask.");

static int
_modinit(void)
{
	extban_table['u'] = eb_unidentified;

	return 0;
}

static void
_moddeinit(void)
{
	extban_table['u'] = NULL;
}

static int eb_unidentified(const char *data, struct Client *client_p,
		struct Channel *chptr, long mode_type)
{

	(void)chptr;
	// $u alone should match all unidentified users.
	if (data == NULL)
	{
		return EXTBAN_INVALID;
	}
	// $u has an argument, check it.  It should be n!u@h .
	else
	{
		char buf[BUFSIZE];

		rb_snprintf(buf, BUFSIZE, "%s!%s@%s",
			client_p->name, client_p->username, client_p->host);

		if ((match(data, buf) != 0) && EmptyString(client_p->user->suser))
		{
			return EXTBAN_MATCH;
		}
		else
		{
			return EXTBAN_NOMATCH;
		}
	}
}
