/* Provides the PARTALL command.
 *
 *     Replaces /join 0 with a more intuitively named command.
 * Especially useful if /join 0 is disabled but /join 0 (part all
 * channels) is desired.  Just calls the built-in do_join_0 function.
 *
 *     - Ben
 *
 * Copyright (c) 2015 - Chat Lounge IRC Network Development
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "modules.h"

static int m_partall(struct Client *client_p, struct Client *source_p,
	int parc, const char *parv[]);

struct Message partall_msgtab = {
	"PARTALL", 0, 0, 0, MFLG_SLOW,
	{{m_partall, 0}, {m_partall, 0}, mg_ignore, mg_ignore, mg_ignore, {m_partall, 0}}
};

mapi_clist_av1 partall_clist[] = { &partall_msgtab, NULL };

DECLARE_MODULE_AV1(partall, NULL, NULL, partall_clist, NULL, NULL, "Provides PARTALL - Leave all channels.");

static int
m_partall(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	do_join_0(client_p, source_p);
	return 0;
}